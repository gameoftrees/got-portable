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
#include "got_opentemp.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

static char authorized_keys_path[_POSIX_PATH_MAX];
static char *authorized_keys_tmppath;
static int authorized_keys_tmpfd = -1;
struct gotsys_authorized_keys_list authorized_keys;
static int ignore_user;

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
write_authorized_keys_file(void)
{
	const struct got_error *err = NULL;
	int ret;
	ssize_t w;
	struct gotsys_authorized_key *key;
	char buf[GOTSYS_AUTHORIZED_KEY_MAXLEN];
	const char *options = "restrict";

	if (STAILQ_EMPTY(&authorized_keys)) {
		if (truncate(authorized_keys_path, 0) == -1 && errno != ENOENT)
			return got_error_from_errno2("truncate",
			    authorized_keys_path);
		return NULL;
	}

	STAILQ_FOREACH(key, &authorized_keys, entry) {
		ret = snprintf(buf, sizeof(buf),
		    "%s %s %s%s%s\n",
		    options,
		    key->keytype, key->key,
		    key->comment ? " " : "",
		    key->comment ? key->comment : "");
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(buf))
			return got_error(GOT_ERR_NO_SPACE);
		w = write(authorized_keys_tmpfd, buf, ret);
		if (w == -1) {
			return got_error_from_errno2("write",
			    authorized_keys_tmppath);
		}
		if (w != ret)
			return got_error_fmt(GOT_ERR_IO, "short write to %s: "
			    "wrote %zd instead of %d bytes",
			    authorized_keys_tmppath, w, ret);
	}

	if (rename(authorized_keys_tmppath, authorized_keys_path) == -1) {
		err = got_error_from_errno3("rename", authorized_keys_tmppath,
		    authorized_keys_path);
		unlink(authorized_keys_tmppath);
		free(authorized_keys_tmppath);
		authorized_keys_tmppath = NULL;
		return err;
	}

	close(authorized_keys_tmpfd);
	authorized_keys_tmpfd = -1;

	free(authorized_keys_tmppath);
	authorized_keys_tmppath = NULL;

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
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS:
			err = gotsys_imsg_recv_authorized_keys(&imsg,
			    &authorized_keys);
			break;
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE:
			if (!ignore_user) {
				err = write_authorized_keys_file();
				if (err)
					break;
			}
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE,
			    0, -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg compose "
				    "INSTALL_AUTHORIZED_KEYS_DONE");
				break;
			}
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			shut = 1;
			break;
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
apply_unveil_authorized_keys(void)
{
	if (unveil(authorized_keys_tmppath, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    authorized_keys_tmppath);
	
	if (unveil(authorized_keys_path, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    authorized_keys_path);

	if (unveil(NULL, NULL) == -1)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
apply_unveil_none(void)
{
	if (unveil("/", "") == -1)
		return got_error_from_errno("unveil /");

	if (unveil(NULL, NULL) == -1)
		return got_error_from_errno("unveil");

	return NULL;
}

int
main(int argc, char **argv)
{
	const struct got_error *error = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	struct passwd *pw;
	uid_t uid;
	gid_t gid;
	char *usershell = NULL, *userhome = NULL;
	char *username;
	int ret;

	STAILQ_INIT(&authorized_keys);
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr getpw id unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (geteuid())
		errx(1, "need root privileges");

	if (argc != 2)
		errx(1, "usage: %s username", getprogname());

	username = argv[1];

	error = gotsys_conf_validate_name(username, "user");
	if (error)
		errx(1, "%s", error->msg);

	pw = getpwnam(username);
	if (pw == NULL)
		err(1, "getpwnam %s", username);

	uid = pw->pw_uid;
	gid = pw->pw_gid;
	usershell = strdup(pw->pw_shell);
	if (usershell == NULL)
		err(1, "strdup");
	userhome = strdup(pw->pw_dir);
	if (userhome == NULL)
		err(1, "strdup");

	endpwent();
	pw = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr id unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (uid == 0)
		errx(1, "user %s is a root user", username);
	if (gid == 0)
		errx(1, "user %s has GID 0", username);

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
	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		err(1, "imsgbuf_init");

	ret = snprintf(authorized_keys_path, sizeof(authorized_keys_path),
	    "/%s/.ssh/authorized_keys", userhome);
	if (ret == -1) {
		error = got_error_from_errno("snprintf");
		goto done;
	}
	if ((size_t)ret >= sizeof(authorized_keys_path)) {
		error = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	/*
	 * Skip users mentioned in gotsys.conf yet outside our UID range.
	 * Such users may be mentioned in gotsys.conf and obtain repository
	 * access rights but their account is otherwise unmanaged by gotsysd.
	 * Because the sysconf process lacks access to the password database
	 * it cannot do a UID range check and will always try to install
	 * authorized keys for such users.
	 */
	/* TODO: This check needs the actual UID start/end from gotsysd.conf */
	if (uid < GOTSYSD_UID_MIN || gid < GOTSYSD_UID_MIN ||
	    strcmp(usershell, GOTSYSD_PATH_GOTSH) != 0) {
		warnx("skipping authorized_keys installation for user %s with "
		    "UID %u and shell %s", username, uid, usershell);
		ignore_user = 1;
	}

	if (setgid(gid) == -1)
		err(1, "setgid %d failed", gid);
	if (setuid(uid) == -1)
		err(1, "setuid %d failed", uid);

	if (ignore_user) {
		if (pledge("stdio unveil", NULL) == -1) {
			error = got_error_from_errno("pledge");
			goto done;
		}

		error = apply_unveil_none();
		if (error)
			goto done;
	} else {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr unveil",
		    NULL) == -1) {
			error = got_error_from_errno("pledge");
			goto done;
		}
#endif
		if (!got_path_is_absolute(authorized_keys_path)) {
			error = got_error(GOT_ERR_BAD_PATH);
			goto done;
		}

		error = got_opentemp_named_fd(&authorized_keys_tmppath,
		    &authorized_keys_tmpfd, authorized_keys_path, "");
		if (error)
			goto done;

		if (fchown(authorized_keys_tmpfd, uid, gid) == -1) {
			error = got_error_from_errno_fmt("chown %u:%u %s",
			    uid, gid, authorized_keys_path);
			goto done;
		}

		if (fchmod(authorized_keys_tmpfd, S_IRWXU) == -1) {
			error = got_error_from_errno_fmt("chmod %o %s", S_IRWXU,
			    authorized_keys_path);
			goto done;
		}

		error = apply_unveil_authorized_keys();
		if (error)
			goto done;
	}

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);

	if (gotsysd_imsg_compose_event(&iev, GOTSYSD_IMSG_PROG_READY, 0,
	    -1, NULL, 0) == -1) {
		error = got_error_from_errno("gotsysd_imsg_compose_event");
		goto done;
	}

	event_dispatch();
done:
	free(usershell);
	free(userhome);
	if (authorized_keys_tmppath && unlink(authorized_keys_tmppath) == -1 &&
	    error == NULL) {
		error = got_error_from_errno2("unlink",
		    authorized_keys_tmppath);
	}
	if (authorized_keys_tmpfd != -1 &&
	    close(authorized_keys_tmpfd) == -1 && error == NULL)
		error = got_error_from_errno2("close", authorized_keys_tmppath);
	if (error) {
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, error);
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
	}
	free(authorized_keys_tmppath);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && error == NULL) {
		error = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
	}
	imsgbuf_clear(&iev.ibuf);
	return error ? 1 : 0;
}
