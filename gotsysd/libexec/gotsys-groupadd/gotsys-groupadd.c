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

static gid_t groupadd_gid_start = GOTSYSD_UID_DEFAULT_START;
static gid_t groupadd_gid_end = GOTSYSD_UID_DEFAULT_END;
static FILE *group_temp = NULL;
static char *group_temp_path = NULL;
static struct gotsys_grouplist groupadd_groups;
static struct gotsys_group *groupadd_group_cur;

enum gotsys_groupadd_state {
	GROUPADD_STATE_EXPECT_PARAM = 0,
	GROUPADD_STATE_EXPECT_GROUPS,
	GROUPADD_STATE_DONE,
};

static enum gotsys_groupadd_state groupadd_state = GROUPADD_STATE_EXPECT_PARAM;

static void
sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

static const struct got_error *
assign_gid(gid_t *gid, struct gotsys_uidset *gids)
{
	const struct got_error *err = NULL;
	gid_t g;

	/* Assign new GIDs sequentially. */
	g = gotsys_uidset_max_uid(gids, groupadd_gid_start);
	for (; g <= groupadd_gid_end; g++) {
		uid_t u = (uid_t)g;
		if (!gotsys_uidset_contains(gids, u) &&
		    user_from_uid(u, 1) == NULL &&
		    group_from_gid(g, 1) == NULL)
			break;
	}

	/* sanity checks -- should not happen */
	if (groupadd_gid_start == 0 || groupadd_gid_start >= groupadd_gid_end ||
	    g < GOTSYSD_UID_MIN || g < groupadd_gid_start || g == GID_MAX)
		abort();

	if (g > groupadd_gid_end) {
		return got_error_msg(GOT_ERR_RANGE,
		    "gotsysd has run out of free user/group IDs to assign");
	}

	/* final sanity check */
	if (g == 0)
		abort();

	err = gotsys_uidset_add(gids, g);
	if (err)
		return err;

	*gid = g;
	return NULL;
}

static const struct got_error *
recv_group(struct gotsys_group **group, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_group igroup;
	size_t datalen;
	char *groupname = NULL;
	gid_t gid;

	*group = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(igroup))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&igroup, imsg->data, sizeof(igroup));
	if (datalen != sizeof(igroup) + igroup.name_len ||
	    igroup.name_len > _PW_NAME_LEN)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	groupname = strndup(imsg->data + sizeof(igroup), igroup.name_len);
	if (groupname == NULL)
		return got_error_from_errno("strndup");

	err = gotsys_conf_validate_name(groupname, "group");
	if (err)
		goto done;

	err = gotsys_conf_new_group(group, groupname);
	if (err)
		goto done;
	free(groupname);
	groupname = NULL;

	if (gid_from_group((*group)->name, &gid) == 0 &&
	    (gid < groupadd_gid_start || gid > groupadd_gid_end)) {
		err = got_error_fmt(GOT_ERR_GROUP_EXISTS,
		    "cannot add group `%s' due to name collision with "
		    "existing GID %d\n", (*group)->name, gid);
		goto done;
	}
done:
	if (err) {
		free(groupname);
		gotsys_group_free(*group);
		*group = NULL;
	}
	return err;
}

static const struct got_error *
recv_group_members(struct imsg *imsg, struct gotsys_group *group)
{
	return gotsys_imsg_recv_users(imsg, &group->members);
}

static const struct got_error *
write_group_entry(struct gotsys_group *group, gid_t gid)
{
	struct gotsys_user *member;
	int ret;

	ret = fprintf(group_temp, "%s:*:%u:", group->name, gid);
	if (ret == -1) {
		return got_error_fmt(GOT_ERR_IO, "short write to `%s'",
		    group_temp_path);
	}

	STAILQ_FOREACH(member, &group->members, entry) {
		ret = fprintf(group_temp, "%s%s", member->name,
		    STAILQ_NEXT(member, entry) ? "," : "");
		if (ret == -1) {
			return got_error_fmt(GOT_ERR_IO, "short write to `%s'",
			    group_temp_path);
		}
	}

	if (fputc('\n', group_temp) == EOF) {
		return got_error_from_errno_fmt("write to `%s'",
		    group_temp_path);
	}

	return NULL;
}

/* create a secondary groups */
static const struct got_error *
create_groups(void)
{
	const struct got_error *err = NULL;
	struct stat	st;
	FILE		*from = NULL;
	char		*line = NULL;
	size_t		linesize = 0;
	ssize_t		linelen;
	char *		ypline = NULL;
	gid_t		gid;
	struct gotsys_grouplist existing_groups, new_groups, removed_groups;
	struct gotsys_group *group, *tmp;
	struct gotsys_uidset *gids;
	struct group *gr;

	STAILQ_INIT(&existing_groups);
	STAILQ_INIT(&new_groups);
	STAILQ_INIT(&removed_groups);

	gids = gotsys_uidset_alloc();
	if (gids == NULL)
		return got_error_from_errno("gotsys_uidset_alloc");

	/*
	 * Collect existing groups in our GID range no longer mentioned
	 * in gotsys.conf.
	 */
	setgroupent(1);
	while ((gr = getgrent()) != NULL) {
		if (gr->gr_gid < groupadd_gid_start ||
		    gr->gr_gid > groupadd_gid_end)
			continue;

		err = gotsys_uidset_add(gids, gr->gr_gid);
		if (err)
			goto done;

		STAILQ_FOREACH(group, &groupadd_groups, entry) {
			if (strcmp(group->name, gr->gr_name) == 0)
				break;
		}
		if (group != NULL)
			continue; /* will go on existing_groups list */
 
		err = gotsys_conf_new_group(&group, gr->gr_name);
		if (err)
			goto done;

		STAILQ_INSERT_TAIL(&removed_groups, group, entry);
	}

	STAILQ_FOREACH_SAFE(group, &groupadd_groups, entry, tmp) {
		err = gotsys_conf_validate_name(group->name, "group");
		if (err)
			goto done;

		STAILQ_REMOVE(&groupadd_groups, group, gotsys_group, entry);
		if (gid_from_group(group->name, &gid) == 0) {
			/* Ignore existing groups outside our GID range. */
			if (gid < groupadd_gid_start ||
			    gid > groupadd_gid_end) {
				gotsys_group_free(group);
				continue;
			}
			STAILQ_INSERT_TAIL(&existing_groups, group, entry);
		} else
			STAILQ_INSERT_TAIL(&new_groups, group, entry);
	}

	from = fopen(_PATH_GROUP, "r");
	if (from == NULL) {
		err = got_error_from_errno2("fopen", _PATH_GROUP);
		goto done;
	}

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
		char *colon;
		size_t colonc;

		/*
		 * Stop copying the file at a yp entry; we want to
		 * put the new group before it, and preserve entries
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

		colon = strchr(line, ':');
		if (colon == NULL)
			continue; /* malformed entry, drop it */

		colonc = (size_t)(colon - line);
		STAILQ_FOREACH(group, &existing_groups, entry) {
			size_t loginc = strlen(group->name);

			if (loginc == colonc &&
			    strncmp(group->name, line, loginc) == 0)
				break;
		}

		if (group == NULL) {
			/* Removed groups will become memberless. */
			STAILQ_FOREACH(group, &removed_groups, entry) {
				size_t loginc = strlen(group->name);

				if (loginc == colonc &&
				    strncmp(group->name, line, loginc) == 0)
					break;
			}
		}

		if (group) {
			if (gid_from_group(group->name, &gid) != 0) {
				err = got_error_fmt(GOT_ERR_USER,
				   "group %s has disappeared from pw cache",
				   group->name);
				goto done;
			}
			err = write_group_entry(group, gid);
			if (err)
				goto done;
		} else if (fwrite(line, 1, linelen, group_temp) != linelen) {
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

	STAILQ_FOREACH(group, &new_groups, entry) {
		if (gid_from_group(group->name, &gid) == 0)
			continue; /* group suddenly cached; should not happen */

		/* Assign a free GID from our range . */
		err = assign_gid(&gid, gids);
		if (err)
			goto done;

		/* Add the new group's entry. */
		err = write_group_entry(group, gid);
		if (err)
			goto done;
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
		err = got_error_from_errno2("fclose", group_temp_path);
		goto done;
	}
	from = NULL;

	endgrent();
	setgroupent(1);
	STAILQ_FOREACH(group, &new_groups, entry) {
		struct group *gr = getgrnam(group->name);

		if (gr == NULL)
			continue; /* should not happen */

		syslog(LOG_INFO, "new group added: name=%s, gid=%u",
		    group->name, gr->gr_gid);
	}
done:
	endgrent();
	gotsys_uidset_free(gids);
	gotsys_grouplist_purge(&removed_groups);
	if (from && fclose(from) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", _PATH_GROUP);
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
		    groupadd_state == GROUPADD_STATE_DONE) {
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
		case GOTSYSD_IMSG_SYSCONF_GROUPADD_PARAM: {
			struct gotsysd_imsg_sysconf_groupadd_param param;
			size_t datalen;

			if (groupadd_state != GROUPADD_STATE_EXPECT_PARAM) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}

			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != sizeof(param)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&param, imsg.data, sizeof(param));

			if (param.gid_start >= GOTSYSD_UID_MIN &&
			    param.gid_end >= GOTSYSD_UID_MIN &&
			    param.gid_start < param.gid_end) {
				groupadd_gid_start = param.gid_start;
				groupadd_gid_end = param.gid_end;
			}
			groupadd_state = GROUPADD_STATE_EXPECT_GROUPS;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GROUP: {
			struct gotsys_group *group;

			if (groupadd_state != GROUPADD_STATE_EXPECT_GROUPS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = recv_group(&group, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&groupadd_groups, group, entry);
			groupadd_group_cur = group;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS:
			if (groupadd_group_cur == NULL ||
			    groupadd_state != GROUPADD_STATE_EXPECT_GROUPS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = recv_group_members(&imsg, groupadd_group_cur);
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE:
			if (groupadd_group_cur == NULL ||
			    groupadd_state != GROUPADD_STATE_EXPECT_GROUPS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			groupadd_group_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPS_DONE:
			if (groupadd_state != GROUPADD_STATE_EXPECT_GROUPS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = create_groups();
			if (err)
				break;
			groupadd_state = GROUPADD_STATE_DONE;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_GROUPADD_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "GROUPADD_DONE");
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
apply_unveil_etc_group(void)
{
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

	STAILQ_INIT(&groupadd_groups);

	if (geteuid())
		errx(1, "need root privileges");

	event_init();

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
	/* Open required temporary file before unveil(2). */
	err = got_opentemp_named(&group_temp_path, &group_temp,
	    _PATH_GROUP, "");
	if (err)
		goto done;

	err = apply_unveil_etc_group();
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
	if (group_temp && fclose(group_temp) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", group_temp_path);
	if (group_temp_path && unlink(group_temp_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", group_temp_path);
	if (err) {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	}
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	free(group_temp_path);
	imsgbuf_clear(&iev.ibuf);
	return err ? 1 : 0;
}
