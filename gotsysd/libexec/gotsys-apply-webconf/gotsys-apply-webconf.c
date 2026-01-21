/*
 * Copyright (c) 2026 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <event.h>
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
#include "got_opentemp.h"
#include "got_reference.h"

#include "media.h"
#include "gotsysd.h"
#include "gotwebd.h"
#include "gotsys.h"

static struct gotsysd_imsgev gotsysd_iev;
static struct gotsysd_imsgev gotwebd_iev;
static int gotwebd_sock = -1;
static char *gotwebd_sockpath = NULL;
static int gotwebd_stop_sent;
static int flush_and_exit;

static void
sighdlr(int sig, short event, void *arg)
{
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
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

static const struct got_error *
start_child(pid_t *pid,
    const char *argv0, const char *argv1, const char *argv2)
{
	const char	*argv[4];
	int		 argc = 0;

	switch (*pid = fork()) {
	case -1:
		return got_error_from_errno("fork");
	case 0:
		break;
	default:
		return NULL;
	}

	argv[argc++] = argv0;
	if (argv1 != NULL)
		argv[argc++] = argv1;
	if (argv2 != NULL)
		argv[argc++] = argv2;
	argv[argc++] = NULL;

	execvp(argv0, (char * const *)argv);
	err(1, "execvp: %s", argv0);

	/* NOTREACHED */
	return NULL;
}

static const struct got_error *
connect_gotwebd(const char *socket_path)
{
	const struct got_error *err = NULL;
	struct sockaddr_un sun;

	gotwebd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (gotwebd_sock == -1)
		return got_error_from_errno("socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(gotwebd_sock);
		gotwebd_sock = -1;
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "gotwebd socket path too long");
	}
	if (connect(gotwebd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		err = got_error_from_errno2("connect", socket_path);
		close(gotwebd_sock);
		gotwebd_sock = -1;
	}

	return err;
}

static const struct got_error *
start_gotwebd(void)
{
	pid_t pid;

	/* TODO: fetch gotwebd_flags from rc.conf.local and pass them in? */
	return start_child(&pid, GOTSYSD_PATH_PROG_GOTWEBD, NULL, NULL);
}

static const struct got_error *
send_done(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_DONE,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose "
		    "SYSCONF_APPLY_WEBCONF_DONE");
	}

	return NULL;
}

static void
dispatch_gotwebd(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto loopexit;
		}

		if (imsgbuf_queuelen(ibuf) == 0 && flush_and_exit)
			event_del(&iev->ev);
	}

	if (flush_and_exit)
		return;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto loopexit;
		}
		if (n == 0) {	/* Connection closed. */
			err = start_gotwebd();
			if (err)
				warn("%s", err->msg);

			err = send_done(&gotsysd_iev);
			if (err)
				warn("%s", err->msg);
			event_del(&iev->ev);
			flush_and_exit = 1;
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto loopexit;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			flush_and_exit = 1;
		}

		imsg_free(&imsg);
	}

	gotsysd_imsg_event_add(iev);
	return;

loopexit:
	/* This pipe is dead. Remove its event handler */
	event_del(&iev->ev);
	event_loopexit(NULL);
}

static void
dispatch_gotsysd(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto loopexit;
		}

		if (imsgbuf_queuelen(ibuf) == 0)
			event_del(&iev->ev);
		else
			gotsysd_imsg_event_add(iev);

		if (gotwebd_sock != -1 && !gotwebd_stop_sent) {
			if (gotsysd_imsg_compose_event(&gotwebd_iev,
			    GOTWEBD_IMSG_CTL_STOP, 0, -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "CTL_STOP");
				gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
				flush_and_exit = 1;
			}

			gotwebd_stop_sent = 1;
		}
	}
	
	if (flush_and_exit)
		return;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto loopexit;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto loopexit;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			flush_and_exit = 1;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
loopexit:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-s socket]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	int ch;

	gotsysd_iev.ibuf.fd = -1;
	gotwebd_iev.ibuf.fd = -1;

#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			gotwebd_sockpath = realpath(optarg, NULL);
			if (gotwebd_sockpath == NULL) {
				err = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (gotwebd_sockpath == NULL) {
		gotwebd_sockpath = strdup(GOTWEBD_CONTROL_SOCKET);
		if (gotwebd_sockpath == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	event_init();

	signal_set(&evsigint, SIGINT, sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&gotsysd_iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}

#ifndef PROFILE
	if (pledge("stdio proc exec unix unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (unveil(gotwebd_sockpath, "w") != 0) {
		err = got_error_from_errno2("unveil", gotwebd_sockpath);
		goto done;
	}

	if (unveil(GOTSYSD_PATH_PROG_GOTWEBD, "x") != 0) {
		err = got_error_from_errno2("unveil",
		    GOTSYSD_PATH_PROG_GOTWEBD);
		goto done;
	}

	if (unveil(NULL, NULL) != 0) {
		err = got_error_from_errno("unveil");
		goto done;
	}

	/*
	 * If we cannot conncet to the control socket then gotwebd might have
	 * crashed and restarting it could have bad consequences (such as
	 * leaking info to a remote attacker). Log a warning and send 'done'
	 * to gotsysd which can then proceed with system configuration tasks.
	 */
	err = connect_gotwebd(gotwebd_sockpath);
	if (err) {
		if (err->code != GOT_ERR_ERRNO ||
		    (errno != ENOENT && errno != ECONNREFUSED))
			goto done;

		warnx("%s: %s", gotwebd_sockpath, err->msg);
		err = NULL;
#ifndef PROFILE
		/* We will not attempt to restart gotwebd. */
		if (pledge("stdio", NULL) == -1) {
			err = got_error_from_errno("pledge");
			goto done;
		}
#endif
	} else {
#ifndef PROFILE
		/* We will attempt to restart gotwebd. */
		if (pledge("stdio proc exec", NULL) == -1) {
			err = got_error_from_errno("pledge");
			goto done;
		}
#endif
		if (imsgbuf_init(&gotwebd_iev.ibuf, gotwebd_sock) == -1) {
			err = got_error_from_errno("imsgbuf_init");
			goto done;
		}

		gotwebd_iev.handler = dispatch_gotwebd;
		gotwebd_iev.events = EV_READ;
		gotwebd_iev.handler_arg = NULL;
		event_set(&gotwebd_iev.ev, gotwebd_iev.ibuf.fd, EV_READ,
		    dispatch_gotwebd, &gotwebd_iev);
	}

	gotsysd_iev.handler = dispatch_gotsysd;
	gotsysd_iev.events = EV_READ;
	gotsysd_iev.handler_arg = NULL;
	event_set(&gotsysd_iev.ev, gotsysd_iev.ibuf.fd, EV_READ,
	    dispatch_gotsysd, &gotsysd_iev);

	if (gotsysd_imsg_compose_event(&gotsysd_iev,
	    GOTSYSD_IMSG_PROG_READY, 0, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose PROG_READY");
		goto done;
	}

	if (gotwebd_sock == -1) {
		/* If gotwebd is not running then we are done. */
		err = send_done(&gotsysd_iev);
		if (err)
			goto done;
		flush_and_exit = 1;
	}

	event_dispatch();
done:
	free(gotwebd_sockpath);
	if (gotwebd_iev.ibuf.fd != -1)
		imsgbuf_clear(&gotwebd_iev.ibuf);
	if (gotwebd_sock != -1 && close(gotwebd_sock) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err)
		gotsysd_imsg_send_error(&gotsysd_iev.ibuf, 0, 0, err);

	if (gotsysd_iev.ibuf.fd != -1)
		imsgbuf_clear(&gotsysd_iev.ibuf);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err)
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	return err ? 1 : 0;
}
