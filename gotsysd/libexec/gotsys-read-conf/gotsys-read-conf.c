/*
 * Copyright (c) 2020, 2025 Stefan Sperling <stsp@openbsd.org>
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

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

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

static struct gotsys_conf gotsysconf;

static const struct got_error *
send_success(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_PARSE_SUCCESS,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose "
		    "SYSCONF_PARSE_SUCCESS");
	}

	return NULL;
}

static const struct got_error *
send_done(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_PARSE_DONE,
	    0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose SYSCONF_PARSE_DONE");

	return NULL;
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0, sysconf_fd = -1;
	size_t datalen;
	static int flush_and_exit;
	struct gotsys_user *user;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
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
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_SYSCONF_PARSE_REQUEST:
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			sysconf_fd = dup(STDIN_FILENO);
			if (sysconf_fd == -1){
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}

			gotsys_conf_clear(&gotsysconf);
			err = gotsys_conf_init_media_types(
			    &gotsysconf.mediatypes);
			if (err)
				break;
			if (gotsys_conf_parse(GOTSYSD_SYSCONF_FILENAME,
			    &gotsysconf, &sysconf_fd))
				err = got_error(GOT_ERR_PARSE_CONFIG);
			close(sysconf_fd);
			if (err)
				break;
			err = send_success(iev);
			if (err)
				break;
			err = gotsys_imsg_send_users(iev, &gotsysconf.users,
			    GOTSYSD_IMSG_SYSCONF_USERS,
			    GOTSYSD_IMSG_SYSCONF_USERS_DONE, 1);
			if (err)
				break;
			STAILQ_FOREACH(user, &gotsysconf.users, entry) {
				if (STAILQ_EMPTY(&user->authorized_keys))
					continue;
				err = gotsys_imsg_send_authorized_keys_user(
				    iev, user->name,
				    GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USER);
				if (err)
					goto next;
				err = gotsys_imsg_send_authorized_keys(iev,
				    &user->authorized_keys,
				    GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS);
				if (err)
					goto next;
			}
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "AUTHORIZED_KEYS_DONE");
				break;
			}
			err = gotsys_imsg_send_groups(iev, &gotsysconf.groups,
			    GOTSYSD_IMSG_SYSCONF_GROUP,
			    GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS,
			    GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE,
			    GOTSYSD_IMSG_SYSCONF_GROUPS_DONE);
			if (err)
				break;
			err = gotsys_imsg_send_repositories(iev,
			    &gotsysconf.repos);
			if (err)
				break;
			err = gotsys_imsg_send_mediatypes(iev,
			    &gotsysconf.mediatypes,
			    GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE,
			    GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE);
			if (err)
				break;
			err = gotsys_imsg_send_webservers(iev,
			    &gotsysconf.webservers);
			if (err)
				break;
			err = send_done(iev);
			if (err)
				break;
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}
next:
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

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	gotsys_conf_init(&gotsysconf);

	err = gotsys_conf_init_media_types(&gotsysconf.mediatypes);
	if (err) {
		warnx("could not initialize media types: %s", err->msg);
		return 1;
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

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1) {
		warn("imsgbuf_init");
		return 1;
	}

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);
	if (gotsysd_imsg_compose_event(&iev, GOTSYSD_IMSG_PROG_READY, 0,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("gotsysd_imsg_compose_event");
		goto done;
	}

	event_dispatch();
done:
	imsgbuf_clear(&iev.ibuf);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	return err ? 1 : 0;
}
