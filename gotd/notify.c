/*
 * Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <event.h>
#include <siphash.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "gotd.h"
#include "log.h"
#include "notify.h"
#include "secrets.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct gotd_secrets	secrets;

static struct gotd_notify {
	pid_t pid;
	const char *title;
	struct gotd_imsgev parent_iev;
	struct gotd_repolist repos;
} gotd_notify;

struct gotd_notify_session {
	STAILQ_ENTRY(gotd_notify_session) entry;
	uint32_t id;
	struct gotd_imsgev iev;
};
STAILQ_HEAD(gotd_notify_sessions, gotd_notify_session);

static struct gotd_notify_sessions gotd_notify_sessions[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY sessions_hash_key;

static void gotd_notify_shutdown(void);

static void
sessions_init(void)
{
	uint64_t slot;

	arc4random_buf(&sessions_hash_key, sizeof(sessions_hash_key));

	for (slot = 0; slot < nitems(gotd_notify_sessions); slot++)
		STAILQ_INIT(&gotd_notify_sessions[slot]);
}

static uint64_t
session_hash(uint32_t session_id)
{
	return SipHash24(&sessions_hash_key, &session_id, sizeof(session_id));
}

static void
add_session(struct gotd_notify_session *session)
{
	uint64_t slot;

	slot = session_hash(session->id) % nitems(gotd_notify_sessions);
	STAILQ_INSERT_HEAD(&gotd_notify_sessions[slot], session, entry);
}

static struct gotd_notify_session *
find_session(uint32_t session_id)
{
	uint64_t slot;
	struct gotd_notify_session *s;

	slot = session_hash(session_id) % nitems(gotd_notify_sessions);
	STAILQ_FOREACH(s, &gotd_notify_sessions[slot], entry) {
		if (s->id == session_id)
			return s;
	}

	return NULL;
}

static struct gotd_notify_session *
find_session_by_fd(int fd)
{
	uint64_t slot;
	struct gotd_notify_session *s;

	for (slot = 0; slot < nitems(gotd_notify_sessions); slot++) {
		STAILQ_FOREACH(s, &gotd_notify_sessions[slot], entry) {
			if (s->iev.ibuf.fd == fd)
				return s;
		}
	}

	return NULL;
}

static void
remove_session(struct gotd_notify_session *session)
{
	uint64_t slot;

	slot = session_hash(session->id) % nitems(gotd_notify_sessions);
	STAILQ_REMOVE(&gotd_notify_sessions[slot], session,
	    gotd_notify_session, entry);
	close(session->iev.ibuf.fd);
	free(session);
}

static uint32_t
get_session_id(void)
{
	int duplicate = 0;
	uint32_t id;

	do {
		id = arc4random();
		duplicate = (find_session(id) != NULL);
	} while (duplicate || id == 0);

	return id;
}

static void
gotd_notify_sighdlr(int sig, short event, void *arg)
{
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
		gotd_notify_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static void
run_notification_helper(const char *prog, const char **argv, int fd,
    const char *user, const char *pass, const char *hmac_secret)
{
	const struct got_error *err = NULL;
	pid_t pid;
	int child_status;

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		log_warn("%s", err->msg);
		return;
	} else if (pid == 0) {
		signal(SIGQUIT, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);

		if (dup2(fd, STDIN_FILENO) == -1) {
			fprintf(stderr, "%s: dup2: %s\n", getprogname(),
			    strerror(errno));
			_exit(1);
		}

		closefrom(STDERR_FILENO + 1);

		if (user != NULL && pass != NULL) {
			setenv("GOT_NOTIFY_HTTP_USER", user, 1);
			setenv("GOT_NOTIFY_HTTP_PASS", pass, 1);
		} else {
			unsetenv("GOTD_NOTIFY_HTTP_USER");
			unsetenv("GOTD_NOTIFY_HTTP_PASS");
		}

		if (hmac_secret)
			setenv("GOT_NOTIFY_HTTP_HMAC_SECRET", hmac_secret, 1);
		else
			unsetenv("GOT_NOTIFY_HTTP_HMAC_SECRET");

		if (execv(prog, (char *const *)argv) == -1) {
			fprintf(stderr, "%s: exec %s: %s\n", getprogname(),
			    prog, strerror(errno));
			_exit(1);
		}

		/* not reached */
	}

	if (waitpid(pid, &child_status, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (!WIFEXITED(child_status)) {
		err = got_error(GOT_ERR_PRIVSEP_DIED);
		goto done;
	}

	if (WEXITSTATUS(child_status) != 0)
		err = got_error(GOT_ERR_PRIVSEP_EXIT);
done:
	if (err)
		log_warnx("%s: child %s pid %d: %s", gotd_notify.title,
		    prog, pid, err->msg);
}

static void
notify_email(struct gotd_notification_target *target, const char *subject_line,
    int fd)
{
	const char *argv[13];
	int i = 0;

	argv[i++] = GOTD_PATH_PROG_NOTIFY_EMAIL;

	argv[i++] = "-f";
	argv[i++] = target->conf.email.sender;

	if (target->conf.email.responder) {
		argv[i++] = "-r";
		argv[i++] = target->conf.email.responder;
	}

	if (target->conf.email.hostname) {
		argv[i++] = "-h";
		argv[i++] = target->conf.email.hostname;
	}

	if (target->conf.email.port) {
		argv[i++] = "-p";
		argv[i++] = target->conf.email.port;
	}

	argv[i++] = "-s";
	argv[i++] = subject_line;

	argv[i++] = target->conf.email.recipient;

	argv[i] = NULL;

	run_notification_helper(GOTD_PATH_PROG_NOTIFY_EMAIL, argv, fd,
	    NULL, NULL, NULL);
}

static void
notify_http(struct gotd_notification_target *target, const char *repo,
    const char *username, int fd)
{
	struct gotd_secret *secret;
	const char *http_user = NULL, *http_pass = NULL, *hmac = NULL;
	const char *argv[12];
	int argc = 0;

	argv[argc++] = GOTD_PATH_PROG_NOTIFY_HTTP;
	if (target->conf.http.tls)
		argv[argc++] = "-c";

	argv[argc++] = "-r";
	argv[argc++] = repo;
	argv[argc++] = "-h";
	argv[argc++] = target->conf.http.hostname;
	argv[argc++] = "-p";
	argv[argc++] = target->conf.http.port;
	argv[argc++] = "-u";
	argv[argc++] = username;

	argv[argc++] = target->conf.http.path;

	argv[argc] = NULL;

	if (target->conf.http.auth) {
		secret = gotd_secrets_get(&secrets, GOTD_SECRET_AUTH,
		    target->conf.http.auth);
		http_user = secret->user;
		http_pass = secret->pass;
	}
	if (target->conf.http.hmac) {
		secret = gotd_secrets_get(&secrets, GOTD_SECRET_HMAC,
		    target->conf.http.hmac);
		hmac = secret->hmac;
	}

	run_notification_helper(GOTD_PATH_PROG_NOTIFY_HTTP, argv, fd,
	    http_user, http_pass, hmac);
}

static const struct got_error *
send_notification(struct imsg *imsg, struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_notify inotify;
	size_t datalen;
	struct gotd_repo *repo;
	struct gotd_notification_target *target;
	int fd;
	char *username = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(inotify))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&inotify, imsg->data, sizeof(inotify));
	if (datalen != sizeof(inotify) + inotify.username_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	repo = gotd_find_repo_by_name(inotify.repo_name, &gotd_notify.repos);
	if (repo == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	username = strndup(imsg->data + sizeof(inotify), inotify.username_len);
	if (username == NULL)
		return got_error_from_errno("strndup");

	STAILQ_FOREACH(target, &repo->notification_targets, entry) {
		if (lseek(fd, 0, SEEK_SET) == -1) {
			err = got_error_from_errno("lseek");
			goto done;
		}
		switch (target->type) {
		case GOTD_NOTIFICATION_VIA_EMAIL:
			notify_email(target, inotify.subject_line, fd);
			break;
		case GOTD_NOTIFICATION_VIA_HTTP:
			notify_http(target, repo->name, username, fd);
			break;
		}
	}

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_NOTIFICATION_SENT,
	    GOTD_PROC_NOTIFY, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose NOTIFY");
		goto done;
	}
done:
	close(fd);
	free(username);
	return err;
}

static void
notify_dispatch_session(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

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
		err = gotd_imsg_flush(ibuf);
		if (err) {
			if (err->code != GOT_ERR_ERRNO || errno != EPIPE)
				fatalx("%s", err->msg);
			shut = 1;
			goto done;
		}
	}

	for (;;) {
		const struct got_error *err = NULL;

		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_NOTIFY:
			err = send_notification(&imsg, iev);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);

		if (err)
			log_warnx("%s: %s", __func__, err->msg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		struct gotd_notify_session *session;

		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		imsgbuf_clear(&iev->ibuf);

		session = find_session_by_fd(fd);
		if (session)
			remove_session(session);
	}
}

static const struct got_error *
recv_session(struct imsg *imsg)
{
	struct gotd_notify_session *session;
	size_t datalen;
	int fd;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		close(fd);
		return got_error_from_errno("calloc");
	}

	session->id = get_session_id();
	if (imsgbuf_init(&session->iev.ibuf, fd) == -1) {
		close(fd);
		return got_error_from_errno("imsgbuf_init");
	}
	imsgbuf_allow_fdpass(&session->iev.ibuf);
	session->iev.handler = notify_dispatch_session;
	session->iev.events = EV_READ;
	session->iev.handler_arg = NULL;
	event_set(&session->iev.ev, session->iev.ibuf.fd, EV_READ,
	    notify_dispatch_session, &session->iev);
	gotd_imsg_event_add(&session->iev);
	add_session(session);

	return NULL;
}

static const struct got_error *
notify_ibuf_get_str(char **ret, struct ibuf *ibuf)
{
	const char	*str, *end;
	size_t		 len;

	*ret = NULL;

	str = ibuf_data(ibuf);
	len = ibuf_size(ibuf);

	end = memchr(str, '\0', len);
	if (end == NULL)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	*ret = strdup(str);
	if (*ret == NULL)
		return got_error_from_errno("strdup");

	if (ibuf_skip(ibuf, end - str + 1) == -1) {
		free(*ret);
		*ret = NULL;
		return got_error(GOT_ERR_PRIVSEP_LEN);
	}

	return NULL;
}

static const struct got_error *
add_notification_target(const char *repo_name,
    struct gotd_notification_target *target)
{
	const struct got_error *err = NULL;
	struct gotd_repo *repo;

	repo = gotd_find_repo_by_name(repo_name, &gotd_notify.repos);
	if (repo == NULL) {
		err = gotd_conf_new_repo(&repo, repo_name);
		if (err)
			return err;
		TAILQ_INSERT_TAIL(&gotd_notify.repos, repo, entry);
	}

	STAILQ_INSERT_TAIL(&repo->notification_targets, target, entry);
	return NULL;
}
static void
notify_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *imsgbuf = &iev->ibuf;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;
	struct ibuf ibuf;
	struct gotd_secret *s;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(imsgbuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(imsgbuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;

		if ((n = imsgbuf_get(imsgbuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_NOTIFICATION_TARGET_EMAIL: {
			struct gotd_notification_target *target;
			char *repo_name;

			err = gotd_imsg_recv_notification_target_email(
			    &repo_name, &target, &imsg);
			if (err)
				break;
			err = add_notification_target(repo_name, target);
			if (err)
				gotd_free_notification_target(target);
			break;
		}
		case GOTD_IMSG_NOTIFICATION_TARGET_HTTP: {
			struct gotd_notification_target *target;
			char *repo_name;

			err = gotd_imsg_recv_notification_target_http(
			    &repo_name, &target, &imsg);
			if (err)
				break;
			err = add_notification_target(repo_name, target);
			if (err)
				gotd_free_notification_target(target);
			break;
		}
		case GOTD_IMSG_CONNECT_SESSION:
			err = recv_session(&imsg);
			break;
		case GOTD_IMSG_SECRETS:
			if (secrets.cap != 0)
				fatal("unexpected GOTD_IMSG_SECRETS");
			if (imsg_get_data(&imsg, &secrets.cap,
			    sizeof(secrets.cap)) == -1)
				fatalx("corrupted GOTD_IMSG_SECRETS");
			if (secrets.cap == 0)
				break;
			secrets.secrets = calloc(secrets.cap,
			    sizeof(*secrets.secrets));
			if (secrets.secrets == NULL)
				fatal("calloc");
			break;
		case GOTD_IMSG_SECRET:
			if (secrets.len == secrets.cap)
				fatalx("unexpected GOTD_SECRET_AUTH");
			s = &secrets.secrets[secrets.len++];
			if (imsg_get_ibuf(&imsg, &ibuf) == -1)
				fatal("imsg_get_ibuf");
			if (ibuf_get(&ibuf, &s->type, sizeof(s->type)) == -1)
				fatalx("corrupted GOTD_IMSG_SECRET");
			err = notify_ibuf_get_str(&s->label, &ibuf);
			if (err)
				break;
			if (s->type == GOTD_SECRET_AUTH) {
				err = notify_ibuf_get_str(&s->user, &ibuf);
				if (err)
					break;
				err = notify_ibuf_get_str(&s->pass, &ibuf);
				if (err)
					break;
			} else {
				err = notify_ibuf_get_str(&s->hmac, &ibuf);
				if (err)
					break;
			}
			if (ibuf_size(&ibuf) != 0)
				fatalx("unexpected extra data in "
				    "GOTD_IMSG_SECRET");
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);

		if (err)
			log_warnx("%s: %s", __func__, err->msg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}

}

void
notify_main(const char *title)
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	sessions_init();

	gotd_notify.title = title;
	gotd_notify.pid = getpid();
	TAILQ_INIT(&gotd_notify.repos);

	signal_set(&evsigint, SIGINT, gotd_notify_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, gotd_notify_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, gotd_notify_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, gotd_notify_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&gotd_notify.parent_iev.ibuf, GOTD_FILENO_MSG_PIPE)
	    == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&gotd_notify.parent_iev.ibuf);
	gotd_notify.parent_iev.handler = notify_dispatch;
	gotd_notify.parent_iev.events = EV_READ;
	gotd_notify.parent_iev.handler_arg = NULL;
	event_set(&gotd_notify.parent_iev.ev, gotd_notify.parent_iev.ibuf.fd,
	    EV_READ, notify_dispatch, &gotd_notify.parent_iev);
	if (gotd_imsg_compose_event(&gotd_notify.parent_iev,
	    GOTD_IMSG_NOTIFIER_READY, GOTD_PROC_NOTIFY, -1, NULL, 0) == -1)
		fatal("imsg compose NOTIFIER_READY");

	event_dispatch();

	if (err)
		log_warnx("%s: %s", title, err->msg);
	gotd_notify_shutdown();
}

void
gotd_notify_shutdown(void)
{
	log_debug("%s: shutting down", gotd_notify.title);
	exit(0);
}
