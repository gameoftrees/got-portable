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

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <pwd.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "log.h"
#include "helpers.h"

struct gotsysd_helper_proc {
	pid_t				 pid;
	enum gotsysd_imsg_type	         type;
	char				 progname[_POSIX_PATH_MAX];
	int				 pipe[2];
	int				 fd;
	struct gotsysd_imsgev		 iev;
	struct event			 kill_tmo;
	struct event			 startup_tmo;

	TAILQ_ENTRY(gotsysd_helper_proc)	 entry;
};
TAILQ_HEAD(gotsysd_helper_procs, gotsysd_helper_proc);

static struct gotsysd_helpers {
	pid_t pid;
	const char *title;
	enum gotsysd_procid proc_id;
	const char *gotd_username;
	const char *repos_path;
	struct gotsysd_helper_procs procs;
	struct gotsysd_imsgev sysconf_iev;
	uid_t uid_start;
	uid_t uid_end;
} gotsysd_helpers;

static void
kill_proc(struct gotsysd_helper_proc *proc, int fatal)
{
	struct timeval tv = { 5, 0 };

	log_debug("kill -%d %d", fatal ? SIGKILL : SIGTERM, proc->pid);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		imsgbuf_clear(&proc->iev.ibuf);
		close(proc->iev.ibuf.fd);
		proc->iev.ibuf.fd = -1;
	}

	if (!evtimer_pending(&proc->kill_tmo, NULL) && !fatal)
		evtimer_add(&proc->kill_tmo, &tv);

	if (fatal) {
		log_warnx("sending SIGKILL to PID %d", proc->pid);
		kill(proc->pid, SIGKILL);
	} else
		kill(proc->pid, SIGTERM);
}

static void
free_proc(struct gotsysd_helper_proc *proc)
{
	TAILQ_REMOVE(&gotsysd_helpers.procs, proc, entry);

	evtimer_del(&proc->kill_tmo);
	evtimer_del(&proc->startup_tmo);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		imsgbuf_clear(&proc->iev.ibuf);
		close(proc->iev.ibuf.fd);
	}

	if (proc->fd != -1)
		close(proc->fd);
	free(proc);
}

static void
helpers_shutdown(void)
{
	struct gotsysd_helper_proc *proc, *tmp;

	log_debug("%s: shutting down", gotsysd_helpers.title);

	TAILQ_FOREACH_SAFE(proc, &gotsysd_helpers.procs, entry, tmp) {
		kill_proc(proc, 0);
		free_proc(proc);
	}

	exit(0);
}

static struct gotsysd_helper_proc *
find_proc_by_pid(pid_t pid)
{
	struct gotsysd_helper_proc *proc;

	TAILQ_FOREACH(proc, &gotsysd_helpers.procs, entry) {
		if (proc->pid == pid)
			return proc;
	}

	return NULL;
}

static struct gotsysd_helper_proc *
find_proc_by_fd(int fd)
{
	struct gotsysd_helper_proc *proc;

	TAILQ_FOREACH(proc, &gotsysd_helpers.procs, entry) {
		if (proc->iev.ibuf.fd == fd)
			return proc;
	}

	return NULL;
}

static const char *
get_helper_prog_name(int imsg_type)
{
	switch (imsg_type) {
	case GOTSYSD_IMSG_START_PROG_REPO_CREATE:
		return GOTSYSD_PATH_PROG_REPO_CREATE;
	case GOTSYSD_IMSG_START_PROG_USERADD:
		return GOTSYSD_PATH_PROG_USERADD;
	case GOTSYSD_IMSG_START_PROG_USERHOME:
		return GOTSYSD_PATH_PROG_USERHOME;
	case GOTSYSD_IMSG_START_PROG_RMKEYS:
		return GOTSYSD_PATH_PROG_RMKEYS;
	case GOTSYSD_IMSG_START_PROG_USERKEYS:
		return GOTSYSD_PATH_PROG_USERKEYS;
	case GOTSYSD_IMSG_START_PROG_GROUPADD:
		return GOTSYSD_PATH_PROG_GROUPADD;
	case GOTSYSD_IMSG_START_PROG_READ_CONF:
		return GOTSYSD_PATH_PROG_READ_CONF;
	case GOTSYSD_IMSG_START_PROG_WRITE_CONF:
		return GOTSYSD_PATH_PROG_WRITE_CONF;
	case GOTSYSD_IMSG_START_PROG_APPLY_CONF:
		return GOTSYSD_PATH_PROG_APPLY_CONF;
	case GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF:
		return GOTSYSD_PATH_PROG_APPLY_WEBCONF;
	default:
		return NULL;
	}
}

static struct gotsysd_helper_proc *
find_proc(enum gotsysd_imsg_type type, int need_running_proc)
{
	struct gotsysd_helper_proc *proc;
	const char *prog;

	prog = get_helper_prog_name(type);
	if (prog == NULL)
		fatalx("no helper defined for imsg %d", type);

	TAILQ_FOREACH(proc, &gotsysd_helpers.procs, entry) {
		if (proc->type == type && proc->iev.ibuf.fd != -1) {
			if (!need_running_proc)
				log_warnx("proc %s already running", prog);
			return proc;
		}
	}

	if (need_running_proc)
		log_warnx("proc %s not running", prog);
	return NULL;
}

static void
helpers_sighdlr(int sig, short event, void *arg)
{
	struct gotsysd_imsgev *sysconf_iev = &gotsysd_helpers.sysconf_iev;
	struct gotsysd_helper_proc *proc;
	pid_t pid;
	int status;

	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		break;
	case SIGUSR1:
		break;
	case SIGTERM:
	case SIGINT:
		helpers_shutdown();
		/* NOTREACHED */
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

			log_debug("proc %s pid %d has exited with status %d",
			    proc->progname, proc->pid, WEXITSTATUS(status));

			if (WEXITSTATUS(status) != 0 &&
			    sysconf_iev->ibuf.fd != -1) {
				const struct got_error *err;

				err = got_error_fmt(GOT_ERR_PRIVSEP_EXIT,
				    "proc %s pid %d has exited with status %d",
				    proc->progname, proc->pid,
				    WEXITSTATUS(status));
				if (gotsysd_imsg_send_error_event(sysconf_iev,
				    gotsysd_helpers.proc_id, 0, err) == -1)
					log_warn("imsg send error");
			}

			free_proc(proc);
		}
		break;
	default:
		fatalx("unexpected signal");
	}
}

static pid_t
start_child(const char *argv0, const char *argv1, const char *argv2,
    int fd, int stdin_fd)
{
	const char	*argv[4];
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

	if (stdin_fd != -1) {
		if (stdin_fd != STDIN_FILENO) {
			if (dup2(stdin_fd, STDIN_FILENO) == -1)
				fatal("cannot setup stdin fd");
		} else if (fcntl(stdin_fd, F_SETFD, 0) == -1)
			fatal("cannot setup stdin fd");
	}

	argv[argc++] = argv0;
	if (argv1 != NULL)
		argv[argc++] = argv1;
	if (argv2 != NULL)
		argv[argc++] = argv2;
	argv[argc++] = NULL;

	execvp(argv0, (char * const *)argv);
	fatal("execvp: %s", argv0);
}

static void
kill_proc_timeout(int fd, short ev, void *d)
{
	struct gotsysd_helper_proc *proc = d;

	log_warnx("timeout waiting for PID %d to terminate;"
	    " retrying with force", proc->pid);
	kill_proc(proc, 1);
}

static void
proc_startup_timeout(int fd, short ev, void *d)
{
	struct gotsysd_helper_proc *proc = d;

	log_warnx("timeout waiting for PID %d to start up", proc->pid);
//	kill_proc(proc, 0);
}

static const struct got_error *
read_conf(struct gotsysd_helper_proc *proc)
{
	const struct got_error *err = NULL;

	if (gotsysd_imsg_compose_event(&proc->iev,
	    GOTSYSD_IMSG_SYSCONF_PARSE_REQUEST, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("gotsysd_imsg_compose_event");
	}
	
	return err;
}

static const struct got_error *
send_useradd_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_USERADD_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose USERADD_READY");
	
	return NULL;
}

static const struct got_error *
send_userhome_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_USERHOME_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose USERHOME_READY");
	
	return NULL;
}

static const struct got_error *
send_rmkeys_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_RMKEYS_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose RMKEYS_READY");
	
	return NULL;
}

static const struct got_error *
send_userkeys_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_USERKEYS_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose USERKEYS_READY");
	
	return NULL;
}

static const struct got_error *
send_groupadd_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GROUPADD_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose GROUPADD_READY");
	
	return NULL;
}

static const struct got_error *
send_repo_create_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_REPO_CREATE_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose REPO_CREATE_READY");
	
	return NULL;
}

static const struct got_error *
send_write_conf_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose WRITE_CONF_READY");
	
	return NULL;
}

static const struct got_error *
send_apply_conf_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_APPLY_CONF_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose APPLY_CONF_READY");
	
	return NULL;
}

static const struct got_error *
send_apply_webconf_ready(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_READY, gotsysd_helpers.proc_id,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose APPLY_WEBCONF_READY");
	
	return NULL;
}

static const struct got_error *
proc_ready(struct gotsysd_helper_proc *proc)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *sysconf_iev = &gotsysd_helpers.sysconf_iev;

	if (sysconf_iev->ibuf.fd == -1) {
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "no sysconf process running");
	}

	switch (proc->type) {
	case GOTSYSD_IMSG_START_PROG_READ_CONF:
		err = read_conf(proc);
		break;
	case GOTSYSD_IMSG_START_PROG_USERADD:
		err = send_useradd_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_USERHOME:
		err = send_userhome_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_RMKEYS:
		err = send_rmkeys_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_USERKEYS:
		err = send_userkeys_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_GROUPADD:
		err = send_groupadd_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_REPO_CREATE:
		err = send_repo_create_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_WRITE_CONF:
		err = send_write_conf_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_APPLY_CONF:
		err = send_apply_conf_ready(sysconf_iev);
		break;
	case GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF:
		err = send_apply_webconf_ready(sysconf_iev);
		break;
	default:
		err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
		    "unexpected proc type %d\n", proc->type);
		break;
	}

	return err;
}

static void
dispatch_helper_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct gotsysd_imsgev *sysconf_iev = &gotsysd_helpers.sysconf_iev;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_helper_proc *proc = NULL;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	proc = find_proc_by_fd(fd);
	if (proc == NULL) {
		log_warn("no process found for fd %d\n", fd);
		shut = 1;
		goto done;
	}

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
		goto done;
	}

	if (sysconf_iev->ibuf.fd == -1) {
		err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "no sysconf process running");
		shut = 1;
		goto done;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			evtimer_del(&proc->startup_tmo);
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			if (err && gotsysd_imsg_send_error_event(sysconf_iev,
			    gotsysd_helpers.proc_id, 0, err) == -1)
				log_warn("imsg send error");
			break;
		case GOTSYSD_IMSG_PROG_READY:
			log_debug("%s is ready", proc->progname);
			evtimer_del(&proc->startup_tmo);
			err = proc_ready(proc);
			if (err && gotsysd_imsg_send_error_event(sysconf_iev,
			    gotsysd_helpers.proc_id, 0, err) == -1)
				log_warn("imsg send error");
			break;
		case GOTSYSD_IMSG_SYSCONF_PARSE_SUCCESS:
		case GOTSYSD_IMSG_SYSCONF_USERS:
		case GOTSYSD_IMSG_SYSCONF_USERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USER:
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS:
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_DONE:
		case GOTSYSD_IMSG_SYSCONF_GROUP:
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS:
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_GROUPS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVER:
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_REPO:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE:
		case GOTSYSD_IMSG_SYSCONF_REPOS_DONE:
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE:
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE:
		case GOTSYSD_IMSG_SYSCONF_PARSE_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_READ_CONF) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (imsg.hdr.type == GOTSYSD_IMSG_SYSCONF_PARSE_DONE) {
				shut = 1;
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_USERADD_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_USERADD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_USERHOME) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_USERKEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_RMKEYS_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_RMKEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPADD_DONE:
			if (proc->type != GOTSYSD_IMSG_START_PROG_GROUPADD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE:
			if (proc->type !=
			    GOTSYSD_IMSG_START_PROG_REPO_CREATE) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_DONE:
			if (proc->type !=
			    GOTSYSD_IMSG_START_PROG_WRITE_CONF) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_CONF_DONE:
			if (proc->type !=
			    GOTSYSD_IMSG_START_PROG_APPLY_CONF) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_DONE:
			if (proc->type !=
			    GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unexpected message type %d from helper "
				        "process type %d pid %u\n",
				    imsg.hdr.type, proc->type, proc->pid);
				break;
			}
			if (gotsysd_imsg_forward(sysconf_iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			shut = 1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (err) {
			log_warnx("%s: %s: %s",
			    gotsysd_proc_names[gotsysd_helpers.proc_id],
			    proc->progname, err->msg);
			err = NULL;
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		struct timeval tv = { 5, 0 };

		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		imsgbuf_clear(&iev->ibuf);
		if (close(iev->ibuf.fd) == -1)
			log_warn("close proc PID %u fd", proc->pid);
		iev->ibuf.fd = -1;

		/* Kill the process in case it does not self-terminate. */
		if (!evtimer_pending(&proc->kill_tmo, NULL))
			evtimer_add(&proc->kill_tmo, &tv);
	}
}

static const struct got_error *
start_helper_child(const char *argv0, const char *argv1, const char *argv2,
    struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_helper_proc *proc;
	struct timeval tv = { 5, 0 };

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	proc->fd = -1;

	log_debug("starting %s", argv0);

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	proc->type = imsg->hdr.type;
	switch (proc->type) {
	case GOTSYSD_IMSG_START_PROG_READ_CONF:
		proc->fd = imsg_get_fd(imsg);
		if (proc->fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}
		break;
	default:
		break;
	}

	proc->pid = start_child(argv0, argv1, argv2, proc->pipe[1], proc->fd);
	proc->pipe[1] = -1;
	strlcpy(proc->progname, argv0, sizeof(proc->progname));

	if (imsgbuf_init(&proc->iev.ibuf, proc->pipe[0]) == -1) {
		close(proc->pipe[0]);
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
#if 0 /* currently, no helper requires fd-passing */
	imsgbuf_allow_fdpass(&proc->iev.ibuf);
#endif
	log_debug("proc %s pid %d is on fd %d", argv0, proc->pid,
	    proc->pipe[0]);

	proc->iev.handler = dispatch_helper_child;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    dispatch_helper_child, &proc->iev);
	gotsysd_imsg_event_add(&proc->iev);

	TAILQ_INSERT_HEAD(&gotsysd_helpers.procs, proc, entry);
	evtimer_set(&proc->kill_tmo, kill_proc_timeout, proc);

	evtimer_set(&proc->startup_tmo, proc_startup_timeout, proc);
	evtimer_add(&proc->startup_tmo, &tv);
done:
	if (err) {
		if (proc->fd != -1)
			close(proc->fd);
		free(proc);
	}
	return err;
}

static void
helpers_dispatch_sysconf(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	const char *prog;
	struct gotsysd_helper_proc *proc;
	char *username = NULL;
	const char *repos_path = NULL;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_START_PROG_USERKEYS: {
			struct gotsysd_imsg_start_prog_userkeys param;
			size_t datalen;

			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen < sizeof(param)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&param, imsg.data, sizeof(param));
			if (param.username_len > _PW_NAME_LEN ||
			    sizeof(param) + param.username_len > datalen) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			username = strndup(imsg.data + sizeof(param),
			    param.username_len);
			if (username == NULL) {
				err = got_error_from_errno("strdup");
				break;
			}
			err = gotsys_conf_validate_name(username, "user");
			if (err) {
				free(username);
				username = NULL;
				break;
			}
			/* FALLTHROUGH */
		}
		case GOTSYSD_IMSG_START_PROG_REPO_CREATE:
			if (imsg.hdr.type ==
			    GOTSYSD_IMSG_START_PROG_REPO_CREATE) {
				username = strdup(
				    gotsysd_helpers.gotd_username);
				if (username == NULL) {
					err = got_error_from_errno("strdup");
					break;
				}
				repos_path = gotsysd_helpers.repos_path;
			}
			/* FALLTHROUGH */
		case GOTSYSD_IMSG_START_PROG_USERADD:
		case GOTSYSD_IMSG_START_PROG_USERHOME:
		case GOTSYSD_IMSG_START_PROG_RMKEYS:
		case GOTSYSD_IMSG_START_PROG_GROUPADD:
		case GOTSYSD_IMSG_START_PROG_WRITE_CONF:
		case GOTSYSD_IMSG_START_PROG_APPLY_CONF:
		case GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF:
			prog = get_helper_prog_name(imsg.hdr.type);
			if (prog == NULL)
				fatalx("no helper defined for imsg %d",
				    imsg.hdr.type);
			if (geteuid()) {
				log_warnx("cannot run %s without "
				    "root privileges", prog);
				free(username);
				username = NULL;
				repos_path = NULL;
				break;
			}
			proc = find_proc(imsg.hdr.type, 0);
			if (proc != NULL) {
				free(username);
				username = NULL;
				repos_path = NULL;
				break;
			}
			err = start_helper_child(prog, username, repos_path,
			    &imsg);
			free(username);
			username = NULL;
			repos_path = NULL;
			if (err) {
				log_warnx("starting %s: %s", prog, err->msg);
				if (gotsysd_imsg_send_error_event(iev,
				    gotsysd_helpers.proc_id, 0, err) == -1)
					log_warn("imsg send error");
			}
			break;
		case GOTSYSD_IMSG_START_PROG_READ_CONF:
			prog = get_helper_prog_name(imsg.hdr.type);
			if (prog == NULL)
				fatalx("no helper defined for imsg %d",
				    imsg.hdr.type);
			if (geteuid() == 0) {
				log_warnx("will not run %s with "
				    "root privileges", prog);
				break;
			}
			proc = find_proc(imsg.hdr.type, 0);
			if (proc != NULL)
				break;
			err = start_helper_child(prog, NULL, NULL, &imsg);
			if (err) {
				log_warnx("starting %s: %s", prog, err->msg);
				if (gotsysd_imsg_send_error_event(iev,
				    gotsysd_helpers.proc_id, 0, err) == -1)
					log_warn("imsg send error");
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_USERADD_PARAM:
		case GOTSYSD_IMSG_SYSCONF_USERS:
		case GOTSYSD_IMSG_SYSCONF_USERS_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_USERADD, 1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPADD_PARAM:
		case GOTSYSD_IMSG_SYSCONF_GROUP:
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS:
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_GROUPS_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_GROUPADD, 1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_USERHOME, 1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS:
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_USERKEYS, 1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_RMKEYS_PARAM:
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS:
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_RMKEYS, 1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE:
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_REPO_CREATE,
			    1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG:
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDR:
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDRS_DONE:
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVER:
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG_DONE:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUPS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_REPO:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE:
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE:
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULE:
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE:
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE:
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE:
		case GOTSYSD_IMSG_SYSCONF_REPOS_DONE:
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVER:
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE:
			proc = find_proc(GOTSYSD_IMSG_START_PROG_WRITE_CONF,
			    1);
			if (proc == NULL)
				break;
			if (gotsysd_imsg_forward(&proc->iev, &imsg, -1) == -1)
				err = got_error_from_errno("imsg_forward");
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (err) {
			log_warn("imsg %d: %s", imsg.hdr.type, err->msg);
			if (gotsysd_imsg_send_error_event(iev,
			    gotsysd_helpers.proc_id, 0, err) == -1)
				log_warn("imsg send error");
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		close(iev->ibuf.fd);
		iev->ibuf.fd = -1;
	}
}

static const struct got_error *
connect_sysconf(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *sysconf_iev = &gotsysd_helpers.sysconf_iev;
	struct gotsysd_imsg_connect_proc proc;
	size_t datalen;
	int fd = -1;

	if (sysconf_iev->ibuf.fd != -1) {
		log_warn("sysconf proc already connected");
		return got_error(GOT_ERR_PRIVSEP_MSG);
	}

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(proc))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&proc, imsg->data, sizeof(proc));

	if (proc.procid != GOTSYSD_PROC_SYSCONF) {
		return got_error_fmt(GOT_ERR_PRIVSEP_MSG,
		    "unexpected proc type %d", proc.procid);
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&sysconf_iev->ibuf, fd) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}

	fd = -1;
	imsgbuf_allow_fdpass(&sysconf_iev->ibuf);
	sysconf_iev->handler = helpers_dispatch_sysconf;
	sysconf_iev->events = EV_READ;
	sysconf_iev->handler_arg = NULL;
	event_set(&sysconf_iev->ev, sysconf_iev->ibuf.fd, EV_READ,
	    helpers_dispatch_sysconf, sysconf_iev);
	gotsysd_imsg_event_add(sysconf_iev);
done:
	if (fd != -1)
		close(fd);

	return err;
}

static void
helpers_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_CONNECT_PROC:
			err = connect_sysconf(&imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (err)
			log_warn("imsg %d: %s", imsg.hdr.type, err->msg);

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
helpers_main(const char *title, uid_t uid, gid_t gid, const char *username,
    enum gotsysd_procid proc_id, const char *repos_path,
    uid_t uid_start, uid_t uid_end)
{
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1, evsigchld;

	gotsysd_helpers.title = title;
	gotsysd_helpers.pid = getpid();
	gotsysd_helpers.proc_id = proc_id;
	gotsysd_helpers.gotd_username = username;
	gotsysd_helpers.repos_path = repos_path;
	TAILQ_INIT(&gotsysd_helpers.procs);
	gotsysd_helpers.sysconf_iev.ibuf.fd = -1;
	gotsysd_helpers.uid_start = uid_start;
	gotsysd_helpers.uid_end = uid_end;

	signal_set(&evsigint, SIGINT, helpers_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, helpers_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, helpers_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, helpers_sighdlr, NULL);
	signal_set(&evsigchld, SIGCHLD, helpers_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);
	signal_add(&evsigchld, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = helpers_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, helpers_dispatch, &iev);
	if (event_add(&iev.ev, NULL) == -1)
		fatalx("event add");

	event_dispatch();

	helpers_shutdown();
}
