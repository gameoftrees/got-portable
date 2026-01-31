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
#include <sys/signal.h>
#include <sys/stat.h>

#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
#include <limits.h>
#include <locale.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "got_error.h"
#include "got_version.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"

#include "got_lib_poll.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "gotd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

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
gotsys_check(struct gotd_imsgev *iev, struct imsg *imsg) 
{
	const struct got_error *err;
	char *configfile = NULL;
	struct gotsys_conf gotsysconf;
	size_t datalen;
	int fd;
	struct stat sb;

	gotsys_conf_init(&gotsysconf);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen > 0) {
		configfile = strndup(imsg->data, datalen);
		if (configfile == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
	} else {
		configfile = strdup("gotsys.conf");
		if (configfile == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno2("fstat", configfile);
		goto done;
	}

	if (!S_ISREG(sb.st_mode)) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "%s is not a regular file", configfile);
		goto done;
	}

	if (sb.st_size == 0) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "%s is empty", configfile);
		goto done;
	}

	if (lseek(fd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	err = gotsys_conf_parse(configfile, &gotsysconf, &fd);
	if (err)
		goto done;

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_GOTSYS_CFG_OK,
	    0, -1, NULL, 0) == -1)
		err = got_error_from_errno("imsg_compose");
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", configfile);
	free(configfile);
	return err;
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
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
		err = gotd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto fatal;
		}

		if (flush_and_exit) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	while (err == NULL && !flush_and_exit) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_GOTSYS_CHECK:
			err = gotsys_check(iev, &imsg);
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotd_imsg_send_error(&iev->ibuf, 0, 0, err);
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct gotd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif
	iev.ibuf.fd = -1;

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

	if (imsgbuf_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}

	imsgbuf_allow_fdpass(&iev.ibuf);

#ifndef PROFILE
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);
	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_GOTSYS_READY, 0, -1,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose");
		goto done;
	}

	event_dispatch();
done:
	if (close(GOTD_FILENO_MSG_PIPE) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err && iev.ibuf.fd != -1)
		gotd_imsg_send_error(&iev.ibuf, 0, 0, err);
	imsgbuf_clear(&iev.ibuf);
	if (iev.ibuf.fd != -1)
		close(iev.ibuf.fd);
	return err ? 1 : 0;
}
