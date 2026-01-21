/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/tree.h>
#include <sys/wait.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <siphash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "got_lib_poll.h"
#include "got_lib_hash.h"

#include "gotsysd.h"
#include "log.h"
#include "listen.h"
#include "auth.h"
#include "helpers.h"
#include "sysconf.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct gotsysd gotsysd;

struct gotsysd_child_proc {
	pid_t				 pid;
	enum gotsysd_procid		 type;
	int				 pipe[2];
	struct gotsysd_imsgev		 iev;
	struct event			 tmo;
	uint32_t			 client_id;

	TAILQ_ENTRY(gotsysd_child_proc)	 entry;
};
static TAILQ_HEAD(gotsysd_procs, gotsysd_child_proc) procs;

enum gotsysd_client_state {
	GOTSYSD_CLIENT_STATE_NEW = -1,
	GOTSYSD_CLIENT_STATE_ACCESS_GRANTED = 1,
	GOTSYSD_CLIENT_STATE_SYSCONF_STARTED,
};

struct gotsysd_client {
	STAILQ_ENTRY(gotsysd_client)	 entry;
	enum gotsysd_client_state	 state;
	uint32_t			 id;
	int				 fd;
	struct gotsysd_imsgev		 iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	char				*username;
	struct gotsysd_child_proc	*auth;
};
STAILQ_HEAD(gotsysd_clients, gotsysd_client);

static struct gotsysd_clients gotsysd_clients[GOTSYSD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
volatile int client_cnt;

const char *gotsysd_proc_names[GOTSYSD_PROC_MAX] = {
	"parent",
	"listen",
	"auth",
	"priv",
	"libexec",
	"sysconf",
};

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-f config-file]\n",
	    getprogname());
	exit(1);
}

static void
kill_proc(struct gotsysd_child_proc *proc, int fatal)
{
	struct timeval tv = { 5, 0 };

	log_debug("kill -%d %d", fatal ? SIGKILL : SIGTERM, proc->pid);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		imsgbuf_clear(&proc->iev.ibuf);
		close(proc->iev.ibuf.fd);
		proc->iev.ibuf.fd = -1;
	}

	if (!evtimer_pending(&proc->tmo, NULL) && !fatal)
		evtimer_add(&proc->tmo, &tv);

	if (fatal) {
		log_warnx("sending SIGKILL to PID %d", proc->pid);
		kill(proc->pid, SIGKILL);
	} else
		kill(proc->pid, SIGTERM);
}

static void
kill_proc_timeout(int fd, short ev, void *d)
{
	struct gotsysd_child_proc *proc = d;

	log_warnx("timeout waiting for PID %d to terminate;"
	    " retrying with force", proc->pid);
	kill_proc(proc, 1);
}

static void
free_proc(struct gotsysd_child_proc *proc)
{
	TAILQ_REMOVE(&procs, proc, entry);

	evtimer_del(&proc->tmo);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		imsgbuf_clear(&proc->iev.ibuf);
		close(proc->iev.ibuf.fd);
	}

	free(proc);
}

static pid_t
start_child(enum gotsysd_procid proc_id, char *argv0, const char *confpath,
    int fd, int daemonize, int verbosity, char *commit_id_str)
{
	const char	*argv[8];
	int		 argc = 0;
	pid_t		 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return pid;
	}

	if (fd != GOTSYSD_FILENO_MSG_PIPE) {
		if (dup2(fd, GOTSYSD_FILENO_MSG_PIPE) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (proc_id) {
	case GOTSYSD_PROC_LISTEN:
		argv[argc++] = "-TL";
		break;
	case GOTSYSD_PROC_AUTH:
		argv[argc++] = "-TA";
		break;
	case GOTSYSD_PROC_PRIV:
		argv[argc++] = "-TP";
		break;
	case GOTSYSD_PROC_LIBEXEC:
		argv[argc++] = "-TE";
		break;
	case GOTSYSD_PROC_SYSCONF:
		argv[argc++] = "-TS";
		break;
	default:
		fatalx("invalid process id %d", proc_id);
	}

	argv[argc++] = "-f";
	argv[argc++] = confpath;

	if (!daemonize)
		argv[argc++] = "-d";
	if (verbosity > 0)
		argv[argc++] = "-v";
	if (verbosity > 1)
		argv[argc++] = "-v";
	if (commit_id_str)
		argv[argc++] = commit_id_str;
	argv[argc++] = NULL;

	execvp(argv0, (char * const *)argv);
	fatal("execvp");
}

static void
clients_init(void)
{
	uint64_t slot;

	arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));

	for (slot = 0; slot < nitems(gotsysd_clients); slot++)
		STAILQ_INIT(&gotsysd_clients[slot]);
}

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct gotsysd_client *client)
{
	uint64_t slot = client_hash(client->id) % nitems(gotsysd_clients);
	STAILQ_INSERT_HEAD(&gotsysd_clients[slot], client, entry);
	client_cnt++;
}

static struct gotsysd_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct gotsysd_client *c;

	slot = client_hash(client_id) % nitems(gotsysd_clients);
	STAILQ_FOREACH(c, &gotsysd_clients[slot], entry) {
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

static void
client_sysconf_done(uint32_t client_id, int exit_status)
{
	struct gotsysd_client *client;
	int imsg_code;

	client = find_client(client_id);
	if (client == NULL)
		return;

	if (client->state != GOTSYSD_CLIENT_STATE_SYSCONF_STARTED)
		return;

	if (exit_status == 0)
	    imsg_code = GOTSYSD_IMSG_SYSCONF_SUCCESS;
	else
	    imsg_code = GOTSYSD_IMSG_SYSCONF_FAILURE;

	if (gotsysd_imsg_compose_event(&client->iev, imsg_code,
	    GOTSYSD_PROC_GOTSYSD, -1, NULL, 0) == -1)
		log_warn("imsg compose %d", imsg_code);
}

static void
disconnect(struct gotsysd_client *client)
{
	struct gotsysd_imsg_disconnect idisconnect;
	struct gotsysd_child_proc *listen_proc = gotsysd.listen_proc;
	uint64_t slot;

	log_debug("uid %d: disconnecting", client->euid);

	if (listen_proc) {
		idisconnect.client_id = client->id;
		if (gotsysd_imsg_compose_event(&listen_proc->iev,
		    GOTSYSD_IMSG_DISCONNECT, GOTSYSD_PROC_GOTSYSD, -1,
		    &idisconnect, sizeof(idisconnect)) == -1)
			log_warn("imsg compose DISCONNECT");
	}

	slot = client_hash(client->id) % nitems(gotsysd_clients);
	STAILQ_REMOVE(&gotsysd_clients[slot], client, gotsysd_client, entry);
	imsgbuf_clear(&client->iev.ibuf);
	event_del(&client->iev.ev);
	evtimer_del(&client->tmo);
	if (client->fd != -1)
		close(client->fd);
	else if (client->iev.ibuf.fd != -1)
		close(client->iev.ibuf.fd);
	free(client->username);
	free(client);
	client_cnt--;
}

static void
disconnect_on_error(struct gotsysd_client *client, const struct got_error *err)
{
	struct imsgbuf ibuf;

	if (err->code != GOT_ERR_EOF) {
		log_warnx("uid %d: %s", client->euid, err->msg);
		if (client->fd != -1) {
			if (imsgbuf_init(&ibuf, client->fd) != -1) {
				gotsysd_imsg_send_error(&ibuf, 0,
				GOTSYSD_PROC_GOTSYSD, err);
				imsgbuf_clear(&ibuf);
			} else
				log_warn("%s: imsgbuf_init failed", __func__);
		}
	}

	disconnect(client);
}

static const struct got_error *
send_info(struct gotsysd_client *client)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_info info;
	size_t hexsize;
	struct got_object_id commit_id;

	log_debug("info request from %s", client->username);

	memset(&info, 0, sizeof(info));
	info.pid = gotsysd.pid;
	info.verbosity = gotsysd.verbosity;
	strlcpy(info.repository_directory, gotsysd.repos_path,
	    sizeof(info.repository_directory));
	info.uid_start = gotsysd.uid_start;
	info.uid_end = gotsysd.uid_end;

	hexsize = gotsysd.gotsys_conf_commit_id_len + 1;
	if (hexsize == SHA1_DIGEST_STRING_LENGTH &&
	    got_parse_object_id(&commit_id, gotsysd.gotsys_conf_commit_id,
	        GOT_HASH_SHA1))
		memcpy(&info.commit_id, &commit_id, sizeof(info.commit_id));
	else if (hexsize == SHA256_DIGEST_STRING_LENGTH &&
	    got_parse_object_id(&commit_id, gotsysd.gotsys_conf_commit_id,
	        GOT_HASH_SHA256))
		memcpy(&info.commit_id, &commit_id, sizeof(info.commit_id));

	if (gotsysd_imsg_compose_event(&client->iev, GOTSYSD_IMSG_INFO,
	    GOTSYSD_PROC_GOTSYSD, -1, &info, sizeof(info)) == -1) {
		err = got_error_from_errno("imsg compose INFO");
		if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
connect_proc(struct gotsysd_child_proc *proc1,
    struct gotsysd_child_proc *proc2)
{
	const struct got_error *err;
	struct gotsysd_imsg_connect_proc ireq;
	int pipe[2];

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	memset(&ireq, 0, sizeof(ireq));

	ireq.procid = proc1->type;
	if (gotsysd_imsg_compose_event(&proc2->iev, GOTSYSD_IMSG_CONNECT_PROC,
	    GOTSYSD_PROC_GOTSYSD, pipe[0], &ireq, sizeof(ireq)) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_PROC");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	ireq.procid = proc2->type;
	if (gotsysd_imsg_compose_event(&proc1->iev, GOTSYSD_IMSG_CONNECT_PROC,
	    GOTSYSD_PROC_GOTSYSD, pipe[1], &ireq, sizeof(ireq)) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_PROC");
		close(pipe[0]);
		return err;
	}

	return NULL;
}

static const struct got_error *
write_gotsys_db_file(void)
{
	char buf[GOT_OBJECT_ID_HEX_MAXLEN];
	ssize_t w;
	size_t len;
	int ret;

	if (gotsysd.sysconf_commit_id_str == NULL) {
		log_warn("sysconf succeeded with unknown commit ID");
		return NULL;
	}

	if (lseek(gotsysd.db_commit_fd, 0L, SEEK_SET) == -1)
		return got_error_from_errno2("lseek", GOTSYSD_DB_COMMIT_PATH);

	len = strlen(gotsysd.sysconf_commit_id_str);
	if (len == 0 || len > GOT_OBJECT_ID_HEX_MAXLEN)
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);

	ret = snprintf(buf, sizeof(buf), "%s\n", gotsysd.sysconf_commit_id_str);
	if (ret == -1)
		return got_error_from_errno("snprintf");
	if (ret != len + 1)
		return got_error(GOT_ERR_NO_SPACE);

	w = write(gotsysd.db_commit_fd, buf, len + 1);
	if (w == -1)
		return got_error_from_errno2("write", GOTSYSD_DB_COMMIT_PATH);
	if (w != len + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s, wrote "
		    "only %zd of %zu bytes", GOTSYSD_DB_COMMIT_PATH, w, len);

	if (fsync(gotsysd.db_commit_fd) == -1)
		return got_error_from_errno2("fsync", GOTSYSD_DB_COMMIT_PATH);

	gotsysd.gotsys_conf_commit_id_len = len;
	memcpy(gotsysd.gotsys_conf_commit_id, gotsysd.sysconf_commit_id_str,
	    gotsysd.gotsys_conf_commit_id_len);
	free(gotsysd.sysconf_commit_id_str);
	gotsysd.sysconf_commit_id_str = NULL;
	return NULL;
}

static void
gotsysd_dispatch_sysconf_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_child_proc *proc = gotsysd.sysconf_proc;
	struct gotsysd_child_proc *priv_proc = gotsysd.priv_proc;
	struct gotsysd_child_proc *libexec_proc = gotsysd.libexec_proc;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (priv_proc == NULL) {
		log_warn("priv process has died");
		shut = 1;
		goto done;
	}

	if (libexec_proc == NULL) {
		log_warn("libexec process has died");
		shut = 1;
		goto done;
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			log_debug("%s: pipe is dead", __func__);
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_READY:
			err = connect_proc(gotsysd.sysconf_proc, libexec_proc);
			if (err)
				break;
			err = connect_proc(gotsysd.sysconf_proc, priv_proc);
			if (err)
				break;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_FD, GOTSYSD_PROC_GOTSYSD,
			    gotsysd.sysconf_fd, NULL, 0) == -1) {
				err = got_error_from_errno("imsg compose "
				    "SYSCONF_FD");
				break;
			}
			gotsysd.sysconf_fd = -1;
			break;
		case GOTSYSD_IMSG_SYSCONF_SUCCESS:
			err = write_gotsys_db_file();
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);

		if (err)
			log_warnx("sysconf %d: %s", proc->pid, err->msg);
	}
done:
	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		struct timeval tv = { 1, 0 };

		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		kill_proc(proc, 0);
		gotsysd.sysconf_proc = NULL;
		if (gotsysd.sysconf_fd != -1)
			close(gotsysd.sysconf_fd);
		gotsysd.sysconf_fd = -1;

		/* Schedule another sysconf run if any are pending. */
		if (libexec_proc && priv_proc &&
		    !STAILQ_EMPTY(&gotsysd.sysconf_pending) &&
		    !evtimer_pending(&gotsysd.sysconf_tmo, NULL)) {
			if (evtimer_add(&gotsysd.sysconf_tmo, &tv) == -1) {
				log_warn("could not reschedule "
				    "pending sysconf timer: %s",
				    strerror(errno));
			}
		}
	}
}

static const struct got_error *
start_sysconf_child(int sysconf_fd, struct got_object_id *commit_id,
    uint32_t client_id)
{
	const struct got_error *err = NULL;
	struct gotsysd_child_proc *proc;
	char *commit_id_str;

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err)
		return err;

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL) {
		err = got_error_from_errno("calloc");
		free(commit_id_str);
		return err;
	}

	TAILQ_INSERT_HEAD(&procs, proc, entry);
	evtimer_set(&proc->tmo, kill_proc_timeout, proc);

	proc->type = GOTSYSD_PROC_SYSCONF;
	proc->client_id = client_id;

	log_debug("running system configuration tasks for gotsys.conf from "
	    "gotsys.git commit %s", commit_id_str);

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, gotsysd.argv0,
	    gotsysd.confpath, proc->pipe[1], gotsysd.daemonize,
	    gotsysd.verbosity, commit_id_str);

	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&proc->iev.ibuf);

	log_debug("proc %s is on fd %d", gotsysd_proc_names[proc->type],
	    proc->pipe[0]);

	proc->iev.handler = gotsysd_dispatch_sysconf_child;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotsysd_dispatch_sysconf_child, &proc->iev);
	gotsysd_imsg_event_add(&proc->iev);

	gotsysd.sysconf_proc = proc;
	gotsysd.sysconf_fd = sysconf_fd;
	gotsysd.sysconf_commit_id_str = commit_id_str;
	return NULL;
}

static void
sysconf_cmd_timeout(int fd, short ev, void *d)
{
	const struct got_error *err;
	struct gotsysd_pending_sysconf_cmd *cmd;
	struct timeval tv = { 10, 0 };

	log_debug("%s", __func__);

	/* Try again later if sysconf is still running. */
	if (gotsysd.sysconf_proc != NULL)
		goto reschedule;

	cmd = STAILQ_FIRST(&gotsysd.sysconf_pending);
	if (cmd == NULL)
		return;

	STAILQ_REMOVE_HEAD(&gotsysd.sysconf_pending, entry);
	
	err = start_sysconf_child(cmd->fd, &cmd->commit_id, cmd->client_id);
	if (err) {
		log_warn("could not start sysconf child process: %s",
		    err->msg);
		close(cmd->fd);
	}
	free(cmd);

reschedule:
	if (!STAILQ_EMPTY(&gotsysd.sysconf_pending)) {
		if (evtimer_add(&gotsysd.sysconf_tmo, &tv) == -1) {
			log_warn("could not reschedule "
			    "pending sysconf timer: %s",
			    strerror(errno));
		}
	}
}

static const struct got_error *
run_sysconf(struct gotsysd_client *client, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	size_t datalen;
	struct gotsysd_imsg_cmd_sysconf sysconf_cmd;
	int sysconf_fd;

	log_debug("sysconf request from %s", client->username);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(sysconf_cmd))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&sysconf_cmd, imsg->data, sizeof(sysconf_cmd));
	
	sysconf_fd = imsg_get_fd(imsg);
	if (sysconf_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	/* Hash parsing code will abort() if it sees other values. */
	if (sysconf_cmd.commit_id.algo != GOT_HASH_SHA1 &&
	    sysconf_cmd.commit_id.algo != GOT_HASH_SHA256)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	if (gotsysd.sysconf_proc == NULL) {
		err = start_sysconf_child(sysconf_fd, &sysconf_cmd.commit_id,
		    client->id);
		if (err) {
			close(sysconf_fd);
			return err;
		}
	} else {
		/*
		 * A sysconf process is already running
		 * Queue this command for the future.
		 */
		struct gotsysd_pending_sysconf_cmd *cmd;
		struct timeval tv = { 10, 0 };

		log_debug("%s: queue sysconf cmd", __func__);
		cmd = calloc(1, sizeof(*cmd));
		if (cmd == NULL) {
			close(sysconf_fd);
			return got_error_from_errno("calloc");
		}
		cmd->fd = sysconf_fd;
		memcpy(&cmd->commit_id, &sysconf_cmd.commit_id,
		    sizeof(cmd->commit_id));
		cmd->client_id = client->id;
		STAILQ_INSERT_TAIL(&gotsysd.sysconf_pending, cmd, entry);
		evtimer_add(&gotsysd.sysconf_tmo, &tv);
	}

	/* Acknowledge receipt of sysconf command to the client. */
	if (gotsysd_imsg_compose_event(&client->iev,
	    GOTSYSD_IMSG_SYSCONF_STARTED,
	    GOTSYSD_PROC_GOTSYSD, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose SYSCONF_STARTED");
	} else
		client->state = GOTSYSD_CLIENT_STATE_SYSCONF_STARTED;

	return NULL;
}

static void
gotsysd_request(int fd, short events, void *arg)
{
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_client *client = iev->handler_arg;
	const struct got_error *err = NULL;
	struct imsg imsg;
	ssize_t n;

	if (events & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			/*
			 * The client has closed its socket while we
			 * had messages queued for it.
			 */
			disconnect_on_error(client, err);
			return;
		}
	}

	if (events & EV_READ) {
		n = imsgbuf_read(ibuf);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_read");
			disconnect_on_error(client, err);
			return;
		}
		if (n == 0) {
			 err = got_error(GOT_ERR_EOF);
			 disconnect_on_error(client, err);
			 return;
		}
	}

	while (err == NULL) {
		n = imsg_get(ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsg_get");
			break;
		}
		if (n == 0)
			break;

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_CMD_INFO:
			err = send_info(client);
			break;
		case GOTSYSD_IMSG_CMD_SYSCONF:
			err = run_sysconf(client, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err) {
		disconnect_on_error(client, err);
	} else {
		gotsysd_imsg_event_add(&client->iev);
	}
}

static void
gotsysd_auth_timeout(int fd, short events, void *arg)
{
	struct gotsysd_client *client = arg;

	log_debug("disconnecting uid %d due to authentication timeout",
	    client->euid);
	disconnect(client);
}

static struct gotsysd_client *
find_client_by_proc_fd(int fd)
{
	uint64_t slot;

	for (slot = 0; slot < nitems(gotsysd_clients); slot++) {
		struct gotsysd_client *c;

		STAILQ_FOREACH(c, &gotsysd_clients[slot], entry) {
			if (c->auth && c->auth->iev.ibuf.fd == fd)
				return c;
		}
	}

	return NULL;
}

static void
kill_auth_proc(struct gotsysd_client *client)
{
	if (client->auth == NULL)
		return;

	kill_proc(client->auth, 0);
	client->auth = NULL;
}

static void
gotsysd_dispatch_auth_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_client *client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;
	uint32_t client_id = 0;
	int do_disconnect = 0;
	size_t datalen;

	client = find_client_by_proc_fd(fd);
	if (client == NULL) {
		/* Can happen during process teardown. */
		log_warn("cannot find client for fd %d", fd);
		shut = 1;
		goto done;
	}

	if (client->auth == NULL)
		fatalx("cannot find auth child process for fd %d", fd);

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	if (client->auth->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if ((n = imsg_get(ibuf, &imsg)) == -1)
		fatal("%s: imsg_get error", __func__);
	if (n == 0)	/* No more messages. */
		return;

	evtimer_del(&client->tmo);

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOTSYSD_IMSG_ERROR:
		do_disconnect = 1;
		err = gotsysd_imsg_recv_error(&client_id, &imsg);
		break;
	case GOTSYSD_IMSG_ACCESS_GRANTED:
		if (client->state != GOTSYSD_CLIENT_STATE_NEW) {
			do_disconnect = 1;
			err = got_error(GOT_ERR_PRIVSEP_MSG);
		}
		break;
	default:
		do_disconnect = 1;
		log_debug("unexpected imsg %d", imsg.hdr.type);
		break;
	}

	if (do_disconnect) {
		if (err)
			disconnect_on_error(client, err);
		else
			disconnect(client);
		imsg_free(&imsg);
		return;
	}

	client->state = GOTSYSD_CLIENT_STATE_ACCESS_GRANTED;
	if (datalen > 0)
		client->username = strndup(imsg.data, datalen);
	imsg_free(&imsg);
	if (client->username == NULL &&
	    asprintf(&client->username, "uid %d", client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	kill_auth_proc(client);

	log_debug("%s: user %s auhenticated on fd %d", __func__,
	    client->username, client->fd);

	if (imsgbuf_init(&client->iev.ibuf, client->fd) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&client->iev.ibuf);
	client->iev.handler = gotsysd_request;
	client->iev.events = EV_READ;
	client->iev.handler_arg = client;

	event_set(&client->iev.ev, client->fd, EV_READ, gotsysd_request,
	    &client->iev);
	gotsysd_imsg_event_add(&client->iev);
done:
	if (err)
		log_warnx("uid %d: %s", client->euid, err->msg);

	/* We might have killed the auth process by now. */
	if (client->auth != NULL) {
		if (!shut) {
			gotsysd_imsg_event_add(iev);
		} else {
			/* This pipe is dead. Remove its event handler */
			event_del(&iev->ev);
		}
	}
}

static const struct got_error *
start_auth_child(struct gotsysd_client *client, char *argv0,
    const char *confpath, int daemonize, int verbosity)
{
	const struct got_error *err = NULL;
	struct gotsysd_child_proc *proc;
	struct gotsysd_imsg_auth iauth;
	int fd;

	memset(&iauth, 0, sizeof(iauth));

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL) {
		err = got_error_from_errno("calloc");
		close(fd);
		return err;
	}

	TAILQ_INSERT_HEAD(&procs, proc, entry);
	evtimer_set(&proc->tmo, kill_proc_timeout, proc);

	proc->type = GOTSYSD_PROC_AUTH;

	log_debug("starting auth for uid %d", client->euid);

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity, NULL);

	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&proc->iev.ibuf);

	log_debug("proc %s is on fd %d", gotsysd_proc_names[proc->type],
	    proc->pipe[0]);

	proc->iev.handler = gotsysd_dispatch_auth_child;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotsysd_dispatch_auth_child, &proc->iev);
	gotsysd_imsg_event_add(&proc->iev);

	iauth.euid = client->euid;
	iauth.egid = client->egid;
	iauth.client_id = client->id;
	if (gotsysd_imsg_compose_event(&proc->iev, GOTSYSD_IMSG_AUTHENTICATE,
	    GOTSYSD_PROC_GOTSYSD, fd, &iauth, sizeof(iauth)) == -1) {
		log_warn("imsg compose AUTHENTICATE");
		close(fd);
		/* Let the auth_timeout handler tidy up. */
	}

	client->auth = proc;
	return NULL;
}

static const struct got_error *
recv_connect(uint32_t *client_id, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_connect iconnect;
	size_t datalen;
	struct gotsysd_client *client = NULL;

	*client_id = 0;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iconnect, imsg->data, sizeof(iconnect));

	if (find_client(iconnect.client_id)) {
		err = got_error_msg(GOT_ERR_CLIENT_ID, "duplicate client ID");
		goto done;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	*client_id = iconnect.client_id;

	client->state = GOTSYSD_CLIENT_STATE_NEW;
	client->id = iconnect.client_id;
	/* The auth process will verify UID/GID for us. */
	client->euid = iconnect.euid;
	client->egid = iconnect.egid;

	client->fd = imsg_get_fd(imsg);
	if (client->fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	err = start_auth_child(client, gotsysd.argv0, gotsysd.confpath,
	    gotsysd.daemonize, gotsysd.verbosity);
	if (err)
		goto done;

	evtimer_set(&client->tmo, gotsysd_auth_timeout, client);

	add_client(client);
done:
	if (err && client) {
		struct gotsysd_child_proc *listen_proc = gotsysd.listen_proc;
		struct gotsysd_imsg_disconnect idisconnect;

		if (listen_proc) {
			idisconnect.client_id = client->id;
			if (gotsysd_imsg_compose_event(&listen_proc->iev,
			    GOTSYSD_IMSG_DISCONNECT, GOTSYSD_PROC_GOTSYSD, -1,
			    &idisconnect, sizeof(idisconnect)) == -1)
				log_warn("imsg compose DISCONNECT");
		}

		if (client->fd != -1)
			close(client->fd);
		free(client);
	}

	return err;
}

static void
gotsysd_dispatch_listener(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_child_proc *proc = gotsysd.listen_proc;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (proc->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;
		struct gotsysd_client *client = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;

		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotsysd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTSYSD_IMSG_CONNECT:
			err = recv_connect(&client_id, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		client = find_client(client_id);
		if (client == NULL) {
			log_warnx("%s: client not found", __func__);
			imsg_free(&imsg);
			continue;
		}

		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		gotsysd.listen_proc = NULL;
		event_loopexit(NULL);
	}
}

static void
start_listener(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotsysd_child_proc *proc;

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		fatal("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);

	/* proc->tmo is initialized in main() after event_init() */

	proc->type = GOTSYSD_PROC_LISTEN;

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity, NULL);
	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&proc->iev.ibuf);
	proc->iev.handler = gotsysd_dispatch_listener;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;

	gotsysd.listen_proc = proc;
}

static int
unix_socket_listen(const char *unix_socket_path, uid_t uid, gid_t gid)
{
	struct sockaddr_un sun;
	int fd = -1;
	mode_t old_umask, mode;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK| SOCK_CLOEXEC, 0);
	if (fd == -1) {
		log_warn("socket");
		return -1;
	}

	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, unix_socket_path,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		log_warnx("%s: name too long", unix_socket_path);
		close(fd);
		return -1;
	}

	if (unlink(unix_socket_path) == -1) {
		if (errno != ENOENT) {
			log_warn("unlink %s", unix_socket_path);
			close(fd);
			return -1;
		}
	}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("bind: %s", unix_socket_path);
		close(fd);
		umask(old_umask);
		return -1;
	}

	umask(old_umask);

	if (chmod(unix_socket_path, mode) == -1) {
		log_warn("chmod %o %s", mode, unix_socket_path);
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	if (chown(unix_socket_path, uid, gid) == -1) {
		log_warn("chown %s uid=%d gid=%d", unix_socket_path, uid, gid);
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	if (listen(fd, GOTSYSD_UNIX_SOCKET_BACKLOG) == -1) {
		log_warn("listen");
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	return fd;
}

static void
gotsysd_dispatch_priv(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_child_proc *proc = gotsysd.priv_proc;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (proc->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		gotsysd.priv_proc = NULL;
		event_loopexit(NULL);
	}
}

static void
start_priv(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotsysd_child_proc *proc;

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		fatal("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);

	/* proc->tmo is initialized in main() after event_init() */

	proc->type = GOTSYSD_PROC_PRIV;

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity, NULL);
	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&proc->iev.ibuf);
	proc->iev.handler = gotsysd_dispatch_priv;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;

	gotsysd.priv_proc = proc;
}

static void
gotsysd_dispatch_libexec(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_child_proc *proc = gotsysd.libexec_proc;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (proc->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		gotsysd.libexec_proc = NULL;
		event_loopexit(NULL);
	}
}

static void
start_libexec(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotsysd_child_proc *proc;

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		fatal("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);

	/* proc->tmo is initialized in main() after event_init() */

	proc->type = GOTSYSD_PROC_LIBEXEC;

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity, NULL);
	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&proc->iev.ibuf);
	proc->iev.handler = gotsysd_dispatch_libexec;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;

	gotsysd.libexec_proc = proc;
}

static void
apply_unveil_selfexec(void)
{
	if (unveil(gotsysd.argv0, "x") == -1)
		fatal("unveil %s", gotsysd.argv0);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
apply_unveil_none(void)
{
	if (unveil("/", "") == -1)
		fatal("unveil");

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static const struct got_error *
apply_unveil_priv_helpers(void)
{
	/* Helper programs which require root privileges. */
	const char *helpers[] = {
	    GOTSYSD_PATH_PROG_REPO_CREATE, /* switches UID to _gotd user */
	    GOTSYSD_PATH_PROG_USERADD,
	    GOTSYSD_PATH_PROG_USERHOME,
	    GOTSYSD_PATH_PROG_USERKEYS, /* switches UID to owner of homedir */
	    GOTSYSD_PATH_PROG_RMKEYS,
	    GOTSYSD_PATH_PROG_GROUPADD,
	    GOTSYSD_PATH_PROG_WRITE_CONF,
	    GOTSYSD_PATH_PROG_APPLY_CONF,
	    GOTSYSD_PATH_PROG_APPLY_WEBCONF,
	};
	size_t i;

	for (i = 0; i < nitems(helpers); i++) {
		if (unveil(helpers[i], "x") == 0)
			continue;
		return got_error_from_errno2("unveil", helpers[i]);
	}

	return NULL;
}

static const struct got_error *
apply_unveil_unpriv_helpers(void)
{
	/* Helper programs which do not require root privileges. */
	const char *helpers[] = {
	    GOTSYSD_PATH_PROG_READ_CONF,
	};
	size_t i;

	for (i = 0; i < nitems(helpers); i++) {
		if (unveil(helpers[i], "x") == 0)
			continue;
		return got_error_from_errno2("unveil", helpers[i]);
	}

	return NULL;
}

static void
gotsysd_shutdown(void)
{
	struct gotsysd_child_proc *proc, *tmp;
	uint64_t slot;

	log_debug("shutting down");
	for (slot = 0; slot < nitems(gotsysd_clients); slot++) {
		struct gotsysd_client *c, *tmp;

		STAILQ_FOREACH_SAFE(c, &gotsysd_clients[slot], entry, tmp)
			disconnect(c);
	}

	TAILQ_FOREACH_SAFE(proc, &procs, entry, tmp) {
		kill_proc(proc, 0);
		free_proc(proc);
	}

	while (!STAILQ_EMPTY(&gotsysd.sysconf_pending)) {
		struct gotsysd_pending_sysconf_cmd *cmd;

		cmd = STAILQ_FIRST(&gotsysd.sysconf_pending);
		STAILQ_REMOVE_HEAD(&gotsysd.sysconf_pending, entry);
		close(cmd->fd);
		free(cmd);
	}

	if (gotsysd.db_commit_fd != -1)
		close(gotsysd.db_commit_fd);

	free(gotsysd.global_repo_access_rules);

	log_info("terminating");
	exit(0);
}

static struct gotsysd_child_proc *
find_proc_by_pid(pid_t pid)
{
	struct gotsysd_child_proc *proc = NULL;

	TAILQ_FOREACH(proc, &procs, entry)
		if (proc->pid == pid)
			break;

	return proc;
}

static void
gotsysd_sighdlr(int sig, short event, void *arg)
{
	struct gotsysd_child_proc *proc;
	pid_t pid;
	int status;

	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		gotsysd_shutdown();
		break;
	case SIGCHLD:
		for (;;) {
			pid = waitpid(WAIT_ANY, &status, WNOHANG);
			if (pid == -1) {
				if (errno == EINTR)
					continue;
				if (errno == ECHILD)
					break;
				fatal("waitpid");
			}
			if (pid == 0)
				break;

			log_debug("reaped pid %d", pid);
			proc = find_proc_by_pid(pid);
			if (proc == NULL) {
				log_info("caught exit of unknown child %d",
				    pid);
				continue;
			}

			if (WIFSIGNALED(status)) {
				log_warnx("child PID %d terminated with"
				    " signal %d", pid, WTERMSIG(status));
			}

			if (proc->type == GOTSYSD_PROC_SYSCONF) {
				client_sysconf_done(proc->client_id,
				    WEXITSTATUS(status));
			}

			if (proc == gotsysd.sysconf_proc) {
				gotsysd.sysconf_proc = NULL;
				if (gotsysd.sysconf_fd != -1) {
					close(gotsysd.sysconf_fd);
					gotsysd.sysconf_fd = -1;
				}
				free(gotsysd.sysconf_commit_id_str);
				gotsysd.sysconf_commit_id_str = NULL;
			}

			if (proc == gotsysd.priv_proc) 
				gotsysd.priv_proc = NULL;

			if (proc == gotsysd.libexec_proc) 
				gotsysd.libexec_proc = NULL;

			if (proc == gotsysd.libexec_proc) 
				gotsysd.listen_proc = NULL;

			free_proc(proc);
		}
		break;
	default:
		fatalx("unexpected signal");
	}
}

static void
open_gotsysd_db(void)
{
	char hex[GOT_OBJECT_ID_HEX_MAXLEN];
	char digest[GOT_OBJECT_ID_MAXLEN];
	ssize_t r;

	if (mkdir(GOTSYSD_DB_PATH, 0700) == -1 && errno != EEXIST)
		fatal("mkdir %s", GOTSYSD_DB_PATH);

	gotsysd.db_commit_fd = open(GOTSYSD_DB_COMMIT_PATH,
	    O_RDWR | O_NOFOLLOW | O_CREAT | O_NONBLOCK | O_EXLOCK | O_CLOEXEC,
	    0600);
	if (gotsysd.db_commit_fd == -1)
		fatal("open %s", GOTSYSD_DB_COMMIT_PATH);

	r = read(gotsysd.db_commit_fd, hex, sizeof(hex));
	if (r == -1)
	    fatal("read %s", GOTSYSD_DB_COMMIT_PATH);
	if (r <= 0 || hex[r - 1] != '\n')
		return;
	hex[r - 1] = '\0';

	if (r == SHA1_DIGEST_STRING_LENGTH &&
	    got_parse_hash_digest(digest, hex, GOT_HASH_SHA1)) {
		gotsysd.gotsys_conf_commit_id_len = strlcpy(
		    gotsysd.gotsys_conf_commit_id, hex,
		     sizeof(gotsysd.gotsys_conf_commit_id));
		if (gotsysd.gotsys_conf_commit_id_len >=
		     sizeof(gotsysd.gotsys_conf_commit_id))
			fatal("commit id buffer  too small");
	} else if (r == SHA256_DIGEST_STRING_LENGTH &&
	    got_parse_hash_digest(digest, hex, GOT_HASH_SHA256)) {
		gotsysd.gotsys_conf_commit_id_len = strlcpy(
		    gotsysd.gotsys_conf_commit_id, hex,
		     sizeof(gotsysd.gotsys_conf_commit_id));
		if (gotsysd.gotsys_conf_commit_id_len >=
		     sizeof(gotsysd.gotsys_conf_commit_id))
			fatal("commit id buffer  too small");
	}
}

int
main(int argc, char **argv)
{
	const char *confpath = GOTSYSD_CONF_PATH;
	enum gotsysd_procid proc_id = GOTSYSD_PROC_GOTSYSD;
	struct event evsigint, evsigterm, evsighup, evsigusr1, evsigchld;
	char *argv0 = argv[0];
	char title[2048];
	struct passwd *pw = NULL;
	uid_t uid;
	const char *errstr;
	char *commit_id_str = NULL;
	int ch, fd = -1, daemonize = 1, verbosity = 0, noaction = 0;

	log_init(1, LOG_DAEMON); /* Log to stderr until daemonized. */

	while ((ch = getopt(argc, argv, "df:nT:v")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = 0;
			break;
		case 'f':
			confpath = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'T':
			switch (*optarg) {
			case 'L':
				proc_id = GOTSYSD_PROC_LISTEN;
				break;
			case 'A':
				proc_id = GOTSYSD_PROC_AUTH;
				break;
			case 'P':
				proc_id = GOTSYSD_PROC_PRIV;
				break;
			case 'E':
				proc_id = GOTSYSD_PROC_LIBEXEC;
				break;
			case 'S':
				proc_id = GOTSYSD_PROC_SYSCONF;
				break;
			default:
				fatalx("unknown proc type %s", optarg);
			}
			break;
		case 'v':
			if (verbosity < 3)
				verbosity++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (proc_id == GOTSYSD_PROC_SYSCONF) {
		if (argc != 1)
			usage();
		commit_id_str = argv[0];
	} else if (argc != 0)
		usage();

	if (geteuid() && (proc_id == GOTSYSD_PROC_GOTSYSD ||
	    proc_id == GOTSYSD_PROC_LISTEN || proc_id == GOTSYSD_PROC_PRIV))
		fatalx("need root privileges");

	if (gotsysd_parse_config(confpath, proc_id, &gotsysd) != 0)
		return 1;

	if (noaction) {
		fprintf(stderr, "configuration OK\n");
		return 0;
	}

	gotsysd.argv0 = argv0;
	gotsysd.daemonize = daemonize;
	gotsysd.verbosity = verbosity;
	gotsysd.confpath = confpath;
	gotsysd.sysconf_fd = -1;
	gotsysd.sysconf_commit_id_str = commit_id_str;
	STAILQ_INIT(&gotsysd.sysconf_pending);

	/* Require an absolute path in argv[0] for reliable re-exec. */
	if (!got_path_is_absolute(argv0))
		fatalx("bad path \"%s\": must be an absolute path", argv0);

	pw = getpwnam(gotsysd.gotd_username);
	if (pw == NULL) {
		uid = strtonum(gotsysd.gotd_username, 0, UID_MAX - 1, &errstr);
		if (errstr == NULL) {
			pw = getpwuid(uid);
			if (pw && strlcpy(gotsysd.gotd_username, pw->pw_name,
			    sizeof(gotsysd.gotd_username)) >=
			    sizeof(gotsysd.gotd_username)) {
				fatalx("%s: user name too long",
				    pw->pw_name);
			}
		}
	}
	if (pw == NULL)
		fatalx("user %s not found", gotsysd.gotd_username);
	if (pw->pw_uid == 0)
		fatalx("gotd user %s must not be a superuser",
		    gotsysd.gotd_username);

	pw = getpwnam(gotsysd.user_name);
	if (pw == NULL) {
		uid = strtonum(gotsysd.user_name, 0, UID_MAX - 1, &errstr);
		if (errstr == NULL) {
			pw = getpwuid(uid);
			if (pw && strlcpy(gotsysd.user_name, pw->pw_name,
			    sizeof(gotsysd.user_name)) >=
			    sizeof(gotsysd.user_name)) {
				fatalx("%s: user name too long",
				    pw->pw_name);
			}
		}
	}
	if (pw == NULL)
		fatalx("user %s not found", gotsysd.user_name);

	if (pw->pw_uid == 0)
		fatalx("cannot run %s as the superuser", getprogname());

	log_init(daemonize ? 0 : 1, LOG_DAEMON);
	log_setverbose(verbosity);

	if (proc_id == GOTSYSD_PROC_GOTSYSD) {
		open_gotsysd_db();
		snprintf(title, sizeof(title), "%s",
		    gotsysd_proc_names[proc_id]);
		clients_init();
		if (daemonize && daemon(1, 0) == -1)
			fatal("daemon");
		gotsysd.pid = getpid();
		start_listener(argv0, confpath, daemonize, verbosity);
		start_priv(argv0, confpath, daemonize, verbosity);
		start_libexec(argv0, confpath, daemonize, verbosity);
	} else if (proc_id == GOTSYSD_PROC_LISTEN) {
		snprintf(title, sizeof(title), "%s",
		    gotsysd_proc_names[proc_id]);
		if (verbosity) {
			log_info("socket: %s", gotsysd.unix_socket_path);
			log_info("user: %s", pw->pw_name);
		}

		fd = unix_socket_listen(gotsysd.unix_socket_path, pw->pw_uid,
		    pw->pw_gid);
		if (fd == -1) {
			fatal("cannot listen on unix socket %s",
			    gotsysd.unix_socket_path);
		}
	} else if (proc_id == GOTSYSD_PROC_AUTH ||
	    proc_id == GOTSYSD_PROC_PRIV || proc_id == GOTSYSD_PROC_LIBEXEC ||
	    proc_id == GOTSYSD_PROC_SYSCONF) {
		snprintf(title, sizeof(title), "%s",
		    gotsysd_proc_names[proc_id]);
	} else
		fatal("invalid process id %d", proc_id);

	setproctitle("%s", title);
	log_procinit(title);

	if (proc_id != GOTSYSD_PROC_PRIV) {
		/* Drop root privileges. */
		if (setgid(pw->pw_gid) == -1)
			fatal("setgid %d failed", pw->pw_gid);
		if (setuid(pw->pw_uid) == -1)
			fatal("setuid %d failed", pw->pw_uid);
	}

	event_init();

	switch (proc_id) {
	case GOTSYSD_PROC_GOTSYSD:
#ifndef PROFILE
		/* "exec" promise will be limited to argv[0] via unveil(2). */
		if (pledge("stdio wpath proc exec sendfd recvfd unveil",
		    NULL) == -1)
			fatal("pledge");
#endif
		apply_unveil_selfexec();
		break;
	case GOTSYSD_PROC_LISTEN:
#ifndef PROFILE
		if (pledge("stdio sendfd unix unveil", NULL) == -1)
			fatal("pledge");
#endif
		/*
		 * Ensure that AF_UNIX bind(2) cannot be used with any other
		 * sockets by revoking all filesystem access via unveil(2).
		 */
		apply_unveil_none();

		listen_main(title, fd);
		/* NOTREACHED */
		break;
	case GOTSYSD_PROC_AUTH:
#ifndef PROFILE
		if (pledge("stdio getpw recvfd unix unveil", NULL) == -1)
			fatal("pledge");
#endif
		/*
		 * We need the "unix" pledge promise for getpeername(2) only.
		 * Ensure that AF_UNIX bind(2) cannot be used by revoking all
		 * filesystem access via unveil(2). Access to password database
		 * files will still work since "getpw" bypasses unveil(2).
		 */
		apply_unveil_none();

		auth_main(title, &gotsysd.access_rules);
		/* NOTREACHED */
		break;
	case GOTSYSD_PROC_PRIV:
#ifndef PROFILE
		/*
		 * The "exec" promise will be limited to priv helpers
		 * via unveil(2).
		 */
		if (pledge("stdio recvfd proc exec unveil", NULL) == -1)
			fatal("pledge");
#endif
		apply_unveil_priv_helpers();

		helpers_main(title, pw->pw_uid, pw->pw_gid,
		    gotsysd.gotd_username, proc_id, gotsysd.repos_path,
		    gotsysd.uid_start, gotsysd.uid_end);
		/* NOTREACHED */
		break;
	case GOTSYSD_PROC_LIBEXEC:
#ifndef PROFILE
		/*
		 * The "exec" promise will be limited to unpriv helpers
		 * via unveil(2).
		 */
		if (pledge("stdio recvfd proc exec unveil", NULL) == -1)
			fatal("pledge");
#endif
		apply_unveil_unpriv_helpers();

		helpers_main(title, pw->pw_uid, pw->pw_gid,
		    gotsysd.gotd_username, proc_id, gotsysd.repos_path,
		    gotsysd.uid_start, gotsysd.uid_end);
		/* NOTREACHED */
		break;
	case GOTSYSD_PROC_SYSCONF:
#ifndef PROFILE
		/*
		 * The "recvfd" promise is only needed during setup and
		 * will be removed in a later pledge(2) call.
		 */
		if (pledge("stdio recvfd sendfd unveil", NULL) == -1)
			fatal("pledge");
#endif
		apply_unveil_none();

		sysconf_main(title, gotsysd.uid_start, gotsysd.uid_end,
		    gotsysd.global_repo_access_rules, &gotsysd.web);
		/* NOTREACHED */
		break;
	default:
		fatal("invalid process id %d", proc_id);
	}

	if (proc_id != GOTSYSD_PROC_GOTSYSD)
		fatal("invalid process id %d", proc_id);

	evtimer_set(&gotsysd.listen_proc->tmo, kill_proc_timeout,
	    gotsysd.listen_proc);
	evtimer_set(&gotsysd.priv_proc->tmo, kill_proc_timeout,
	    gotsysd.priv_proc);
	evtimer_set(&gotsysd.libexec_proc->tmo, kill_proc_timeout,
	    gotsysd.libexec_proc);
	evtimer_set(&gotsysd.sysconf_tmo, sysconf_cmd_timeout, NULL);

	signal_set(&evsigint, SIGINT, gotsysd_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, gotsysd_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, gotsysd_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, gotsysd_sighdlr, NULL);
	signal_set(&evsigchld, SIGCHLD, gotsysd_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);
	signal_add(&evsigchld, NULL);

	gotsysd_imsg_event_add(&gotsysd.listen_proc->iev);
	gotsysd_imsg_event_add(&gotsysd.priv_proc->iev);

	event_dispatch();

	gotsysd_shutdown();
	return 0;
}
