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

/* Parts based on src/usr.sbin/user/user.c:
 *
 * Copyright (c) 1999 Alistair G. Crooks.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <err.h>
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
#include "pwd_mkdb.h"

/*
 * Quoting passwd(5):
 *
 *   There is nothing special about ‘*’, it is just one of many characters
 *   that cannot occur in a valid encrypted password (see crypt(3)).
 *   Similarly, login accounts not allowing password authentication but
 *   allowing other authentication methods, for example public key
 *   authentication, conventionally have 13 asterisks in the password field.
 */
#define GOTSYS_PASSWORD_DISABLED "*************"

static int lockfd = -1;
static uid_t useradd_uid_start = GOTSYSD_UID_DEFAULT_START;
static uid_t useradd_uid_end = GOTSYSD_UID_DEFAULT_END;
static struct gotsys_userlist adduser_users;
#if 0
static FILE *mp_db_temp = NULL;
static FILE *smp_db_temp = NULL;
#endif
static FILE *group_temp = NULL;
#if 0
static char *mp_db_temp_path = NULL;
static char *smp_db_temp_path = NULL;
#endif
static char *group_temp_path = NULL;

enum gotsys_useradd_state {
	USERADD_STATE_EXPECT_PARAM = 0,
	USERADD_STATE_EXPECT_USERS,
	USERADD_STATE_DONE,
};

static enum gotsys_useradd_state useradd_state = USERADD_STATE_EXPECT_PARAM;

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
assign_uid(uid_t *uid, struct gotsys_uidset *uids)
{
	const struct got_error *err = NULL;
	uid_t u;

	/* Assign new UIDs (and primary/secondary GIDs) sequentially. */
	u = gotsys_uidset_max_uid(uids, useradd_uid_start);
	for (; u <= useradd_uid_end; u++) {
		if (!gotsys_uidset_contains(uids, u) &&
		    user_from_uid(u, 1) == NULL &&
		    group_from_gid(u, 1) == NULL)
			break;
	}

	/* sanity checks -- should not happen */
	if (useradd_uid_start == 0 || useradd_uid_start >= useradd_uid_end ||
	    u < GOTSYSD_UID_MIN || u < useradd_uid_start || u == UID_MAX) {
		pw_abort();
		abort();
	}

	if (u > useradd_uid_end) {
		return got_error_msg(GOT_ERR_RANGE,
		    "gotsysd has run out of free user/group IDs to assign");
	}

	/* final sanity check */
	if (u == 0) {
		pw_abort();
		abort();
	}

	err = gotsys_uidset_add(uids, u);
	if (err)
		return err;

	*uid = u;
	return NULL;
}

static const struct got_error *
write_user_entry(struct gotsys_user *user, uid_t uid)
{
	char buf[LINE_MAX];
	int ret;
	ssize_t w;

	/* sanity */
	if (uid == 0 || uid == UID_MAX) {
		pw_abort();
		abort();
	}

	ret = snprintf(buf, sizeof(buf),
	    "%s:%s:%u:%u:%s:%lld:%lld:%s:%s/%s:%s\n",
	    user->name,
	    user->password ? user->password : GOTSYS_PASSWORD_DISABLED,
	    uid,
	    uid,
	    "",
	    0LL,
	    0LL,
	    "gotsys user account",
	    GOTSYSD_HOMEDIR, user->name,
	    GOTSYSD_PATH_GOTSH);
	if (ret == -1)
		return got_error_from_errno("snprintf");
	if ((size_t)ret >= sizeof(buf)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "password line too long");
	}

	w = write(lockfd, buf, ret);
	if (w != ret) {
		return got_error_fmt(GOT_ERR_IO, "short write "
		    "to %s, wrote only %zd of %d bytes",
		    _PATH_MASTERPASSWD_LOCK, w, ret);
	}

	return NULL;
}

/* create a group entry with gid `gid' */
static const struct got_error *
create_login_groups(struct gotsys_userlist *new_users,
    struct gotsys_userlist *existing_users)
{
	const struct got_error *err = NULL;
	struct stat	st;
	FILE		*from = NULL;
	char		*line = NULL;
	size_t		linesize = 0;
	ssize_t		linelen;
	char *		ypline = NULL;
	struct gotsys_user *user;

	from = fopen(_PATH_GROUP, "r");
	if (from == NULL)
		return got_error_from_errno2("fopen", _PATH_GROUP);

	if (flock(fileno(from), LOCK_EX | LOCK_NB) == -1) {
		err = got_error_from_errno2("flock", _PATH_GROUP);
		goto done;
	}

	if (fstat(fileno(from), &st) == -1) {
		err = got_error_from_errno2("fstat", _PATH_GROUP);
		goto done;
	}

	/* Cpoy existing groups up to the YP entry. */
	while ((linelen = getline(&line, &linesize, from)) != -1) {
		/*
		 * Stop copying the file at a yp entry; we want to
		 * put the new groups before it, and preserve entries
		 * after the yp entry.
		 */
		if (line[0] == '+') {
			ypline = strdup(line);
			if (ypline == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}

			break;
		}

		if (fwrite(line, 1, linelen, group_temp) != linelen) {
			err = got_error_fmt(GOT_ERR_IO,
			    "short write to `%s'", group_temp_path);
			goto done;
		}
	}
	free(line);
	line = NULL;
	linesize = 0;
	if (ferror(from)) {
		err = got_ferror(from, GOT_ERR_IO);
		goto done;
	}
	STAILQ_FOREACH(user, new_users, entry) {
		gid_t existing_gid;
		struct passwd *pw;
		int ret;

		if (gid_from_group(user->name, &existing_gid) == 0) {
			err = got_error_fmt(GOT_ERR_GROUP_EXISTS,
			    "cannot add group `%s' due to name "
			    "collision with existing GID %d\n", user->name,
			    existing_gid);
			goto done;
		}

		pw = getpwnam(user->name);
		if (pw == NULL) {
			err = got_error_fmt(GOT_ERR_USER, "%s", user->name);
			goto done;
		}

		ret = fprintf(group_temp, "%s:*:%u:\n",
		    user->name, pw->pw_gid);
		if (ret == -1) {
			err = got_error_fmt(GOT_ERR_IO, "short write to `%s'",
			    group_temp_path);
			goto done;
		}
	}

	/*
	 * Create missing login groups for any of our pre-existing users.
	 * Just in case an earlier run failed for some reason.
	 */
	STAILQ_FOREACH(user, existing_users, entry) {
		gid_t existing_gid;
		struct passwd *pw;
		int ret;

		if (gid_from_group(user->name, &existing_gid) == 0)
			continue;

		pw = getpwnam(user->name);
		if (pw == NULL) {
			err = got_error_fmt(GOT_ERR_USER, "%s", user->name);
			goto done;
		}
	
		if (group_from_gid(pw->pw_gid, 1) != NULL)
			continue;

		ret = fprintf(group_temp, "%s:*:%u:\n",
		    user->name, pw->pw_gid);
		if (ret == -1) {
			err = got_error_fmt(GOT_ERR_IO, "short write to `%s'",
			    group_temp_path);
			goto done;
		}
	}
	if (ypline) {
		size_t yplen = strlen(ypline);
		if (fwrite(ypline, 1, yplen, group_temp) != yplen) {
			err = got_error_fmt(GOT_ERR_IO,
			    "short write to `%s'", group_temp_path);
			goto done;
		}

		while ((linelen = getline(&line, &linesize, from)) != -1) {
			if (fwrite(line, 1, linelen, group_temp) != linelen) {
				err = got_error_fmt(GOT_ERR_IO,
				    "short write to `%s'", group_temp_path);
				goto done;
			}
		}
		free(line);
		line = NULL;
		linesize = 0;
		if (ferror(from)) {
			err = got_ferror(from, GOT_ERR_IO);
			goto done;
		}
	}

	if (fclose(group_temp) == EOF) {
		err = got_error_from_errno2("fclose", group_temp_path);
		goto done;
	}
	group_temp = NULL;

	if (chmod(group_temp_path, st.st_mode & 0777) == -1) {
		err = got_error_from_errno_fmt("chmod %o %s",
		    st.st_mode & 0777, group_temp_path);
		goto done;
	}
		
	if (rename(group_temp_path, _PATH_GROUP) == -1) {
		err = got_error_from_errno_fmt("rename %s to %s",
		    group_temp_path, _PATH_GROUP);
		goto done;
	}
	free(group_temp_path);
	group_temp_path = NULL;

	if (fclose(from) == EOF) {
		err = got_error_from_errno2("fclose", _PATH_GROUP);
		goto done;
	}
	from = NULL;

	STAILQ_FOREACH(user, new_users, entry) {
		struct passwd *pw;

		pw = getpwnam(user->name);
		if (pw == NULL)
			continue; /* should not happen */

		syslog(LOG_INFO, "new group added: name=%s, gid=%u",
		    user->name, pw->pw_gid);
	}
done:
	if (from && fclose(from) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", _PATH_GROUP);
	return err;
}

static const struct got_error *
add_users(void)
{
	const struct got_error *err = NULL;
	int masterfd = -1;
	FILE *f = NULL;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int yp = 0;
	struct stat sb;
	struct gotsys_userlist new_users, existing_users, removed_users;
	struct gotsys_user *user, *tmp;
	int pwdb_open = 0, pwdb_updated = 0;
	struct passwd *pw;
	struct gotsys_uidset *uids;

	STAILQ_INIT(&new_users);
	STAILQ_INIT(&existing_users);
	STAILQ_INIT(&removed_users);

	uids = gotsys_uidset_alloc();
	if (uids == NULL)
		return got_error_from_errno("gotsys_uidset_alloc");

	/*
	 * Collect existing users in our UID range no longer mentioned
	 * in gotsys.conf.
	 */
	setpwent();
	while ((pw = getpwent()) != NULL) {
		if (pw->pw_uid < useradd_uid_start ||
		    pw->pw_uid > useradd_uid_end ||
		    strcmp(pw->pw_shell, GOTSYSD_PATH_GOTSH) != 0)
			continue;

		err = gotsys_uidset_add(uids, pw->pw_uid);
		if (err)
			goto done;

		STAILQ_FOREACH(user, &adduser_users, entry) {
			if (strcmp(user->name, pw->pw_name) == 0)
				break;
		}
		if (user != NULL)
			continue; /* will go on existing_users list */

		if (strcmp(pw->pw_name, "anonymous") != 0) {
			err = gotsys_conf_validate_name(pw->pw_name, "user");
			if (err) {
				goto done;
			}
		}
 
		err = gotsys_conf_new_user(&user, pw->pw_name);
		if (err)
			goto done;

		/* Removed users will have password login disabled, */
		user->password = NULL;

		STAILQ_INSERT_TAIL(&removed_users, user, entry);
	}
	endpwent();

	if (setpassent(1) == 0) {
		err = got_error_from_errno("setpassent");
		goto done;
	}

	pwdb_open = 1;

	STAILQ_FOREACH_SAFE(user, &adduser_users, entry, tmp) {
		uid_t uid;

		if (strcmp(user->name, "anonymous") == 0) {
			if (user->password == NULL ||
			    user->password[0] != '\0') {
				err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
				    "the \"anonymous\" user must use an "
				    "empty password");
				goto done;
			}
		} else {
			err = gotsys_conf_validate_name(user->name, "user");
			if (err)
				goto done;
			if (user->password) {
				err = gotsys_conf_validate_password(user->name,
				    user->password);
				if (err)
					goto done;
			}
		}

		STAILQ_REMOVE(&adduser_users, user, gotsys_user, entry);
		if (uid_from_user(user->name, &uid) == 0) {
			/* Ignore existing users outside our UID range. */
			if (uid < useradd_uid_start || uid > useradd_uid_end) {
				gotsys_user_free(user);
				continue;
			}
			/*
			 * Ignore existing users in our UID range which do not
			 * use gotsh as login shell.
			 */
			pw = getpwuid(uid);
			if (pw && strcmp(pw->pw_shell, GOTSYSD_PATH_GOTSH)) {
				gotsys_user_free(user);
				continue;
			}
			STAILQ_INSERT_TAIL(&existing_users, user, entry);
		} else
			STAILQ_INSERT_TAIL(&new_users, user, entry);
	}

	masterfd = open(_PATH_MASTERPASSWD, O_RDONLY);
	if (masterfd == -1) {
		err = got_error_from_errno2("open", _PATH_MASTERPASSWD);
		goto done;
	}
	
	if (flock(masterfd, LOCK_EX | LOCK_NB) == -1) {
		err = got_error_from_errno2("flock", _PATH_MASTERPASSWD);
		goto done;
	}

	lockfd = pw_lock(5);
	if (lockfd == -1) {
		err = got_error_from_errno("pw_lock");
		goto done;
	}

	/* From here on, pw_abort() must be called before returning. */

	f = fdopen(masterfd, "r");
	if (f == NULL) {
		err = got_error_from_errno2("fdopen", _PATH_MASTERPASSWD);
		goto done;
	}
	masterfd = -1;

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		char *colon;
		size_t colonc;
		ssize_t w;

		/*
		 * Stop copying the file at the yp entry; we want to
		 * put the new users before it, and preserve entries
		 * after the yp entry.
		 */
		 if (linelen > 1 && line[0] == '+' & line[1] == ':') {
			yp = 1;
			break;
		}

		colon = strchr(line, ':');
		if (colon == NULL)
			continue; /* malformed entry, drop it */

		colonc = (size_t)(colon - line);
		STAILQ_FOREACH_SAFE(user, &existing_users, entry, tmp) {
			size_t loginc = strlen(user->name);

			if (loginc == colonc &&
			    strncmp(user->name, line, loginc) == 0) {
				/* No need to check for this user again. */
				STAILQ_REMOVE(&existing_users, user,
				    gotsys_user, entry);
				break;
			}
		}

		if (user == NULL) {
			STAILQ_FOREACH_SAFE(user, &removed_users, entry, tmp) {
				size_t loginc = strlen(user->name);

				if (loginc == colonc &&
				    strncmp(user->name, line, loginc) == 0) {
					STAILQ_REMOVE(&removed_users, user,
					    gotsys_user, entry);
					break;
				}
			}
		}

		if (user) {
			uid_t uid;

			if (uid_from_user(user->name, &uid) != 0) {
				err = got_error_fmt(GOT_ERR_USER,
				   "user %s has disappeared from pw cache",
				   user->name);
				gotsys_user_free(user);
				user = NULL;
				goto done;
			}

			/*
			 * Update this user's entry. Only matters if the
			 * password has changed. Otherwise this is a no-op.
			 */
			err = write_user_entry(user, uid);
			if (err) {
				gotsys_user_free(user);
				user = NULL;
				goto done;
			}

			gotsys_user_free(user);
			user = NULL;
		} else {
			w = write(lockfd, line, linelen);
			if (w != linelen) {
				err = got_error_fmt(GOT_ERR_IO, "short write "
				    "to %s, wrote only %zd of %zd bytes",
				    _PATH_MASTERPASSWD_LOCK, w, linelen);
				goto done;
			}
		}
	}
	free(line);
	line = NULL;
	if (ferror(f)) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	STAILQ_FOREACH(user, &new_users, entry) {
		uid_t uid;

		if (uid_from_user(user->name, &uid) == 0)
			continue; /* user suddenly cached; should not happen */

		/* Assign a free UID/GID from our range . */
		err = assign_uid(&uid, uids);
		if (err)
			goto done;

		/* Add the new user's entry. */
		err = write_user_entry(user, uid);
		if (err)
			goto done;
	}

	if (yp) {
		const char yp_entry[] = "+:*::::::::\n";
		ssize_t w;

		w = write(lockfd, yp_entry, strlen(yp_entry));
		if (w != linelen) {
			err = got_error_fmt(GOT_ERR_IO,
			    "short write to %s, wrote only %zd of %zd bytes",
			    _PATH_MASTERPASSWD_LOCK, w, linelen);
			goto done;
		}

		while ((linelen = getline(&line, &linesize, f)) != -1) {
			w = write(lockfd, line, linelen);
			if (w != linelen) {
				err = got_error_fmt(GOT_ERR_IO, "short write "
				    "to %s, wrote only %zd of %zd bytes",
				    _PATH_MASTERPASSWD_LOCK, w, linelen);
				goto done;
			}
		}
	}
	free(line);
	line = NULL;
	if (ferror(f)) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	/* A zero length passwd file is never ok */
	if (fstat(lockfd, &sb) == 0 && sb.st_size == 0) {
		err = got_error_fmt(GOT_ERR_EOF,
		    "%s is zero length", _PATH_MASTERPASSWD_LOCK);
		goto done;
	}

	close(lockfd);
	lockfd = -1;

	err = gotsys_pw_mkdb();
	if (err)
		goto done;

	/* pw_abort() is no longer necessary. */
	pwdb_updated = 1;

	/* Log user accounts which have been added to the system. */
	STAILQ_FOREACH(user, &new_users, entry) {
		uid_t uid;

		if (uid_from_user(user->name, &uid) != 0)
			continue; /* user suddenly cached; should not happen */

		syslog(LOG_INFO, "new user added: name=%s, uid=%u, gid=%u, "
		    "home=%s/%s, shell=%s", user->name, uid, uid,
		    GOTSYSD_HOMEDIR, user->name, GOTSYSD_PATH_GOTSH);
	}

	/* Re-open password database in order to read newly added entries. */
	endpwent();
	pwdb_open = 0;
	if (setpassent(1) == 0) {
		err = got_error_from_errno("setpassent");
		goto done;
	}
	pwdb_open = 1;

	/* Create login groups for all users. */
	err = create_login_groups(&new_users, &existing_users);
done:
	gotsys_uidset_free(uids);
	gotsys_userlist_purge(&removed_users);
	if (pwdb_open)
		endpwent();
	free(line);
	if (err && !pwdb_updated) {
		pw_abort();
		lockfd = -1;
	}
	if (masterfd != -1)
		close(masterfd);
	if (f != NULL && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
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
		    useradd_state == USERADD_STATE_DONE) {
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
		case GOTSYSD_IMSG_SYSCONF_USERADD_PARAM: {
			struct gotsysd_imsg_sysconf_useradd_param param;
			size_t datalen;

			if (useradd_state != USERADD_STATE_EXPECT_PARAM) {
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
				useradd_uid_start = param.uid_start;
				useradd_uid_end = param.uid_end;
			}
			useradd_state = USERADD_STATE_EXPECT_USERS;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_USERS:
			if (useradd_state != USERADD_STATE_EXPECT_USERS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, &adduser_users);
			break;
		case GOTSYSD_IMSG_SYSCONF_USERS_DONE:
			if (useradd_state != USERADD_STATE_EXPECT_USERS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = add_users();
			if (err)
				break;
			useradd_state = USERADD_STATE_DONE;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_USERADD_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "USERADD_DONE");
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

static const struct got_error *
apply_unveil_passwd(void)
{
	if (unveil(_PATH_PASSWD, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_PASSWD);

	if (unveil(_PATH_MASTERPASSWD, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_MASTERPASSWD);

	if (unveil(_PATH_MASTERPASSWD_LOCK, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_MASTERPASSWD_LOCK);
	if (unveil(_PATH_MASTERPASSWD_LOCK ".orig", "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_MASTERPASSWD_LOCK ".orig");

	if (unveil(_PATH_MP_DB, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_MP_DB);
	if (unveil(_PATH_SMP_DB, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_SMP_DB);
#if 0
	if (unveil(mp_db_temp_path, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    mp_db_temp_path);
	if (unveil(smp_db_temp_path, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    smp_db_temp_path);
#else
	/* XXX Create unguessable tempfiles and pass them into pwd_mkdb? */
	if (unveil(_PATH_MP_DB".tmp", "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_MP_DB".tmp");
	if (unveil(_PATH_SMP_DB".tmp", "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_SMP_DB".tmp");
#endif

	if (unveil(_PATH_GROUP, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    _PATH_GROUP);
	if (unveil(group_temp_path, "rwc") == -1)
		return got_error_from_errno_fmt("unveil 'rwc' %s",
		    group_temp_path);

	if (unveil(NULL, NULL) == -1)
		return got_error_from_errno("unveil");

	return NULL;
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
	STAILQ_INIT(&adduser_users);

	if (geteuid())
		errx(1, "need root privileges");

	event_init();

	pw_init();

	/*
	 * Block signals except SIGTERM to avoid a DoS where the password
	 * database lock file is left in place on exit.
	 */
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
	if (pledge("stdio rpath wpath cpath getpw fattr flock unveil",
	    NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	/* Open some required temporary files before unveil(2). */
#if 0
	err = got_opentemp_named(&mp_db_temp_path, &mp_db_temp,
	    _PATH_MP_DB, "");
	if (err)
		goto done;
	err = got_opentemp_named(&smp_db_temp_path, &smp_db_temp,
	    _PATH_SMP_DB, "");
	if (err)
		goto done;
#endif
	err = got_opentemp_named(&group_temp_path, &group_temp,
	    _PATH_GROUP, "");
	if (err)
		goto done;

	err = apply_unveil_passwd();
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
	gotsys_userlist_purge(&adduser_users);
#if 0
	if (mp_db_temp && fclose(mp_db_temp) == EOF && err == NULL) {
		err = got_error_from_errno2("fclose", mp_db_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
	if (smp_db_temp && fclose(smp_db_temp) == EOF && err == NULL) {
		err = got_error_from_errno2("fclose", smp_db_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
#endif
	if (group_temp && fclose(group_temp) == EOF && err == NULL) {
		err = got_error_from_errno2("fclose", group_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
#if 0
	if (mp_db_temp_path && unlink(mp_db_temp_path) == -1 && err == NULL) {
		err = got_error_from_errno2("unlink", mp_db_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
	if (smp_db_temp_path && unlink(smp_db_temp_path) == -1 && err == NULL) {
		err = got_error_from_errno2("unlink", smp_db_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
#endif
	if (group_temp_path && unlink(group_temp_path) == -1 && err == NULL) {
		err = got_error_from_errno2("unlink", group_temp_path);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
#if 0
	free(mp_db_temp_path);
	free(smp_db_temp_path);
#endif
	free(group_temp_path);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	imsgbuf_clear(&iev.ibuf);
	return err ? 1 : 0;
}
