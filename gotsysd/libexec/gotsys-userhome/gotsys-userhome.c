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
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

enum gotsys_userhome_state {
	USERHOME_STATE_EXPECT_PARAM = 0,
	USERHOME_STATE_DONE,
};
static enum gotsys_userhome_state userhome_state = USERHOME_STATE_EXPECT_PARAM;
static uid_t userhome_uid_start = GOTSYSD_UID_DEFAULT_START;
static uid_t userhome_uid_end = GOTSYSD_UID_DEFAULT_END;

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
createhome(const char *username, uid_t uid, gid_t gid)
{
	const struct got_error *err = NULL;
	char path[_POSIX_PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "%s/%s", GOTSYSD_HOMEDIR,
	    username);
	if (ret == -1)
		return got_error_from_errno("snprintf");
	if ((size_t)ret >= sizeof(path))
		return got_error_fmt(GOT_ERR_NO_SPACE, "home directory path "
		    "for user %s is too long", username);

	err = got_path_mkdir(path);
	if (err) {
		if (!(err->code == GOT_ERR_ERRNO && errno == EEXIST))
			return err;
		err = NULL;
	}
	
	if (chown(path, uid, gid) == -1) {
		return got_error_from_errno_fmt("chown %u:%u %s",
		    uid, gid, path);
	}

	if (chmod(path, GOT_DEFAULT_DIR_MODE) == -1) {
		return got_error_from_errno_fmt("chmod %o %s",
		    GOT_DEFAULT_DIR_MODE, path);
	}

	if (strlcat(path, "/.ssh", sizeof(path)) >= sizeof(path)) {
		return got_error_fmt(GOT_ERR_NO_SPACE, "~/.ssh directory "
		    "path for user %s is too long", username);
	}

	if (mkdir(path, S_IRWXU) == -1) {
		if (errno != EEXIST)
			return got_error_from_errno2("mkdir", path);
		/* Don't let EEXIST confuse our getpwent() error checking, */
		errno = 0;
	}

	if (chown(path, uid, gid) == -1) {
		return got_error_from_errno_fmt("chown %u:%u %s",
		    uid, gid, path);
	}

	if (chmod(path, S_IRWXU) == -1)
		return got_error_from_errno_fmt("chmod %o %s", S_IRWXU, path);

	return NULL;
}

static const struct got_error *
create_homedirs(void)
{
	const struct got_error *err = NULL;
	struct passwd *pw;

	/* sanity checks -- should not happen */
#if GOTSYSD_UID_MIN == 0
#error "UID 0 must not be used as GOTSYSD_UID_MIN"
#endif
#if GOTSYSD_UID_MIN == UID_MAX
#error "UID UID_MAX must not be used as GOTSYSD_UID_MIN"
#endif
	if (userhome_uid_start == 0 || userhome_uid_start >= userhome_uid_end)
		abort();

	setpwent();
	pw = getpwent();
	if (pw == NULL) {
		if (errno)
			err = got_error_from_errno("getpwent");
		else
			err = got_error_msg(GOT_ERR_BAD_FILETYPE,
			    "no entries found in password database");
		goto done;
	}

	while (pw) {
		if (pw->pw_uid > GOTSYSD_UID_MIN &&
		    pw->pw_gid > GOTSYSD_UID_MIN &&
		    pw->pw_uid >= userhome_uid_start &&
		    pw->pw_gid >= userhome_uid_start &&
		    pw->pw_uid <= userhome_uid_end &&
		    pw->pw_gid <= userhome_uid_end) {
			err = gotsys_conf_validate_name(pw->pw_name, "user");
			if (err) {
				if (err->code != GOT_ERR_PARSE_CONFIG)
					break;
				/*
				 * Ignore existing users with invalid names
				 * except "anonymous".
				 * Such users were not created by us.
				 */
				err = NULL;
				if (strcmp(pw->pw_name, "anonymous") != 0)
					goto next;
			}
			/*
			 * Ignore existing users in our UID range which do
			 * not use gotsh. Such users were not created by us.
			 */
			if (strcmp(pw->pw_shell, GOTSYSD_PATH_GOTSH) != 0)
				goto next;

			err = createhome(pw->pw_name, pw->pw_uid, pw->pw_gid);
			if (err)
				break;
		}
next:
		pw = getpwent();
		if (pw == NULL && errno)
			err = got_error_from_errno("getpwent");
	}
done:
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
		    userhome_state == USERHOME_STATE_DONE) {
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
		case GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE: {
			struct gotsysd_imsg_sysconf_userhome_create param;
			size_t datalen;

			if (userhome_state != USERHOME_STATE_EXPECT_PARAM) {
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
				userhome_uid_start = param.uid_start;
				userhome_uid_end = param.uid_end;
			}

			err = create_homedirs();
			if (err)
				break;

			userhome_state = USERHOME_STATE_DONE;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "HOMEDIR_CREATE_DONE");
			}
			break;
		}
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

static const struct got_error *
apply_unveil_home(void)
{
	if (unveil(GOTSYSD_HOMEDIR, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    GOTSYSD_HOMEDIR);

	if (unveil(NULL, NULL) == -1)
		return got_error_from_errno("unveil");

	return NULL;
}

int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	if (geteuid())
		errx(1, "need root privileges");

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
	if (pledge("stdio rpath cpath fattr chown getpw unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	err = apply_unveil_home();
	if (err)
		goto done;

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
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	imsgbuf_clear(&iev.ibuf);
	return err ? 1 : 0;
}
