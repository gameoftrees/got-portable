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
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <util.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

static int lockfd = -1;
static uid_t rmkeys_uid_start = GOTSYSD_UID_DEFAULT_START;
static uid_t rmkeys_uid_end = GOTSYSD_UID_DEFAULT_END;
static struct gotsys_userlist gotsysconf_users;

enum gotsys_rmkeys_state {
	RMKEYS_STATE_EXPECT_PARAM = 0,
	RMKEYS_STATE_EXPECT_USERS,
	RMKEYS_STATE_DONE,
};

static enum gotsys_rmkeys_state rmkeys_state = RMKEYS_STATE_EXPECT_PARAM;

static void
sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
		if (lockfd != -1) {
			pw_abort();;
			lockfd = -1;
		}
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

static const struct got_error *
remove_keys(void)
{
	const struct got_error *err = NULL;
	struct passwd *pw = NULL;
	char authorized_keys_path[_POSIX_PATH_MAX];

	/*
	 * Remove keys of users in our UID range no longer mentioned
	 * in gotsys.conf.
	 */
	setpwent();
	while ((pw = getpwent()) != NULL) {
		struct gotsys_user *user;
		int ret;

		if (pw->pw_uid < rmkeys_uid_start ||
		    pw->pw_uid > rmkeys_uid_end ||
		    strcmp(pw->pw_shell, GOTSYSD_PATH_GOTSH) != 0)
			continue;

		STAILQ_FOREACH(user, &gotsysconf_users, entry) {
			if (strcmp(user->name, pw->pw_name) == 0)
				break;
		}
		if (user != NULL)
			continue;

		ret = snprintf(authorized_keys_path,
		    sizeof(authorized_keys_path),
		    "/%s/.ssh/authorized_keys", pw->pw_dir);
		if (ret == -1) {
			err = got_error_from_errno("snprintf");
			break;
		}
		if ((size_t)ret >= sizeof(authorized_keys_path)) {
			err = got_error_msg(GOT_ERR_NO_SPACE,
			    "authorized keys path too long");
			break;
		}
		if (unlink(authorized_keys_path) == -1 && errno != ENOENT) {
			err = got_error_from_errno2("unlink",
			    authorized_keys_path);
			break;
		}
	}

	endpwent();
	return err;
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

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
		} else if (imsgbuf_queuelen(ibuf) == 0 &&
		    rmkeys_state == RMKEYS_STATE_DONE) {
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
		case GOTSYSD_IMSG_SYSCONF_RMKEYS_PARAM: {
			struct gotsysd_imsg_sysconf_rmkeys_param param;
			size_t datalen;

			if (rmkeys_state != RMKEYS_STATE_EXPECT_PARAM) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}

			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != sizeof(param)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&param, imsg.data, sizeof(param));

			if (param.uid_start >= GOTSYSD_UID_MIN &&
			    param.uid_end >= GOTSYSD_UID_MIN &&
			    param.uid_start < param.uid_end) {
				rmkeys_uid_start = param.uid_start;
				rmkeys_uid_end = param.uid_end;
			}
			rmkeys_state = RMKEYS_STATE_EXPECT_USERS;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS:
			if (rmkeys_state != RMKEYS_STATE_EXPECT_USERS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, &gotsysconf_users);
			break;
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS_DONE:
			if (rmkeys_state != RMKEYS_STATE_EXPECT_USERS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = remove_keys();
			if (err)
				break;
			rmkeys_state = RMKEYS_STATE_DONE;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_RMKEYS_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "RMKEYS_DONE");
				break;
			}
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			err = NULL;
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
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigterm;
	sigset_t fullset;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	STAILQ_INIT(&gotsysconf_users);

	if (geteuid())
		errx(1, "need root privileges");

	event_init();

	/* Block signals except SIGTERM. */
	setuid(0);
	sigfillset(&fullset);
	sigdelset(&fullset, SIGTERM);
	sigprocmask(SIG_BLOCK, &fullset, NULL);

	signal_set(&evsigterm, SIGTERM, sighdlr, NULL);
	signal_add(&evsigterm, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1) {
		warn("imsgbuf_init");
		return 1;
	}
#ifndef PROFILE
	if (pledge("stdio rpath cpath getpw unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (unveil(GOTSYSD_HOMEDIR, "rc") == -1) {
		err = got_error_from_errno("unveil");
		goto done;
	}

	if (unveil(NULL, NULL) == -1) {
		err = got_error_from_errno("unveil");
		goto done;
	}

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
	gotsys_userlist_purge(&gotsysconf_users);
	imsgbuf_clear(&iev.ibuf);
	if (err)
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	return err ? 1 : 0;
}
