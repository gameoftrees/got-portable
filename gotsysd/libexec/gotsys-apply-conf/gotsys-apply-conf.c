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
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
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

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "gotd.h"

static struct gotsysd_imsgev gotsysd_iev;
static struct gotsysd_imsgev gotd_iev;
static int gotd_sock = -1;

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
connect_gotd(const char *socket_path)
{
	const struct got_error *err = NULL;
	struct sockaddr_un sun;

	gotd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (gotd_sock == -1)
		return got_error_from_errno("socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "gotd socket path too long");
	}
	if (connect(gotd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		err = got_error_from_errno2("connect", socket_path);
		close(gotd_sock);
		gotd_sock = -1;
	}

	return err;
}

static const struct got_error *
send_done(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_APPLY_CONF_DONE,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose "
		    "SYSCONF_WRITE_CONF_DONE");
	}

	return NULL;
}

static void
dispatch_gotd(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	static int flush_and_exit;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0) {	/* Connection closed. */
			err = send_done(&gotsysd_iev);
			if (err)
				warn("%s", err->msg);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (imsgbuf_flush(ibuf) == -1) {
			warn("imsgbuf_flush");
			goto fatal;
		} else if (imsgbuf_queuelen(ibuf) == 0 && flush_and_exit) {
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1) {
			warn("%s: imsgbuf_get", __func__);
			goto fatal;
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
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
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
	static int flush_and_exit;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto fatal;
		}

		if (imsgbuf_queuelen(ibuf) == 0 && flush_and_exit) {
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1) {
			warn("%s: imsgbuf_get", __func__);
			goto fatal;
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
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static const struct got_error *
apply_unveil(const char *unix_socket_path)
{
	if (unveil(unix_socket_path, "w") != 0)
		return got_error_from_errno2("unveil w", unix_socket_path);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

__dead static void
usage(void)
{
	/* TODO: add -f gotd-socket option */
	fprintf(stderr, "usage: %s [-c config-file] [-s secrets]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	char *confpath = NULL, *secretspath = NULL;
	int ch, conf_fd = -1, secrets_fd = -1;

	gotsysd_iev.ibuf.fd = -1;
	gotd_iev.ibuf.fd = -1;

#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	while ((ch = getopt(argc, argv, "c:s:")) != -1) {
		switch (ch) {
		case 'c':
			if (unveil(optarg, "r") != 0) {
				err = got_error_from_errno("unveil");
				goto done;
			}
			confpath = realpath(optarg, NULL);
			if (confpath == NULL) {
				err = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			break;
		case 's':
			if (unveil(optarg, "r") != 0) {
				err = got_error_from_errno("unveil");
				goto done;
			}
			secretspath = realpath(optarg, NULL);
			if (secretspath == NULL) {
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

	if (confpath == NULL) {
		confpath = strdup(GOTD_CONF_PATH);
		if (confpath == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (unveil(confpath, "r") == -1) {
		err = got_error_from_errno2("unveil", confpath);
		goto done;
	}

	if (unveil(secretspath ? secretspath : GOTD_SECRETS_PATH, "r") == -1) {
		err = got_error_from_errno2("unveil",
		    secretspath ? secretspath : GOTD_SECRETS_PATH);
		goto done;
	}

	secrets_fd = open(secretspath ? secretspath : GOTD_SECRETS_PATH,
	    O_RDONLY | O_NOFOLLOW);
	if (secrets_fd == -1) {
		if (secretspath != NULL || errno != ENOENT) {
			err = got_error_from_errno2("open",
			    secretspath ? secretspath : GOTD_SECRETS_PATH);
			goto done;
		}
	} else if (secretspath == NULL) {
		secretspath = strdup(GOTD_SECRETS_PATH);
		if (secretspath == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	conf_fd = open(confpath, O_RDONLY | O_NOFOLLOW);
	if (conf_fd == -1) {
		err = got_error_from_errno2("open", confpath);
		goto done;
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
	if (pledge("stdio unix sendfd unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	/* TODO: make gotd socket path configurable -- pass via argv[1] */
	err = apply_unveil(GOTD_UNIX_SOCKET);
	if (err)
		goto done;

	err = connect_gotd(GOTD_UNIX_SOCKET);
	if (err)
		goto done;
#ifndef PROFILE
	if (pledge("stdio sendfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (imsgbuf_init(&gotd_iev.ibuf, gotd_sock) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&gotd_iev.ibuf);

	gotd_iev.handler = dispatch_gotd;
	gotd_iev.events = EV_READ;
	gotd_iev.handler_arg = NULL;
	event_set(&gotd_iev.ev, gotd_iev.ibuf.fd, EV_READ,
	    dispatch_gotd, &gotd_iev);

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

	if (secrets_fd != -1) {
		if (gotsysd_imsg_compose_event(&gotd_iev,
		    GOTD_IMSG_RELOAD_SECRETS, 0, secrets_fd,
		    secretspath, strlen(secretspath)) == -1) {
			err = got_error_from_errno("imsg_compose "
			    "RELOAD_SECRETS");
			goto done;
		}
		secrets_fd = -1;
	} else {
		if (gotsysd_imsg_compose_event(&gotd_iev,
		    GOTD_IMSG_RELOAD_SECRETS, 0, -1, NULL, 0) == -1) {
			err = got_error_from_errno("imsg_compose "
			    "RELOAD_SECRETS");
			goto done;
		}
	}
	if (gotsysd_imsg_compose_event(&gotd_iev, GOTD_IMSG_RELOAD,
	    0, conf_fd, confpath, strlen(confpath)) == -1) {
		err = got_error_from_errno("imsg_compose "
		    "RELOAD");
		goto done;
	}
	conf_fd = -1;

	event_dispatch();
done:
	free(confpath);
	free(secretspath);
	if (conf_fd != -1 && close(conf_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (secrets_fd != -1 && close(secrets_fd) == -1 && err == NULL)
		err = got_error_from_errno("close"); 
	if (gotd_iev.ibuf.fd != -1)
		imsgbuf_clear(&gotd_iev.ibuf);
	if (gotd_sock != -1 && close(gotd_sock) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		if (gotsysd_iev.ibuf.fd != -1)
			gotsysd_imsg_send_error(&gotsysd_iev.ibuf, 0, 0, err);
	}
	if (gotsysd_iev.ibuf.fd != -1)
		imsgbuf_clear(&gotsysd_iev.ibuf);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	return err ? 1 : 0;
}
