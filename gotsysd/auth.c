/*
 * Copyright (c) 2022, 2025 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "gotsysd.h"
#include "log.h"
#include "auth.h"

static struct gotsysd_auth {
	pid_t pid;
	const char *title;
	struct gotsysd_access_rule_list *rules;
} gotsysd_auth;

static void auth_shutdown(void);

static void
auth_sighdlr(int sig, short event, void *arg)
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
		auth_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (gotsysd_parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match_identifier(const char *identifier, gid_t *groups, int ngroups,
    uid_t euid, gid_t egid)
{
	int i;

	if (identifier[0] == ':') {
		gid_t rgid;
		if (parsegid(identifier + 1, &rgid) == -1)
			return 0;
		if (rgid == egid)
			return 1;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else if (uidcheck(identifier, euid) != 0)
		return 0;

	return 1;
}

static const struct got_error *
auth_check(char **username, struct gotsysd_access_rule_list *rules,
    uid_t euid, gid_t egid)
{
	struct gotsysd_access_rule *rule;
	enum gotsysd_access access = GOTSYSD_ACCESS_DENIED;
	struct passwd *pw;
	gid_t groups[NGROUPS_MAX];
	int ngroups = NGROUPS_MAX;

	*username = NULL;

	pw = getpwuid(euid);
	if (pw == NULL) {
		if (errno)
			return got_error_from_errno("getpwuid");
		else
			return got_error_set_errno(EACCES, getprogname());
	}

	*username = strdup(pw->pw_name);
	if (*username == NULL)
		return got_error_from_errno("strdup");

	if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) == -1)
		log_warnx("group membership list truncated");

	STAILQ_FOREACH(rule, rules, entry) {
		if (!match_identifier(rule->identifier, groups, ngroups,
		    euid, egid))
			continue;

		access = rule->access;
	}

	if (access == GOTSYSD_ACCESS_DENIED)
		return got_error_set_errno(EACCES, getprogname());

	if (access == GOTSYSD_ACCESS_PERMITTED)
		return NULL;

	/* should not happen, this would be a bug */
	return got_error_msg(GOT_ERR_NOT_IMPL, "bad access rule");
}

static const struct got_error *
recv_authreq(struct imsg *imsg, struct gotsysd_imsgev *iev)
{
	const struct got_error *err;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotsysd_imsg_auth iauth;
	size_t datalen;
	uid_t euid;
	gid_t egid;
	char *username = NULL;
	size_t len;
	const size_t maxlen = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
	int fd = -1;

	log_debug("authentication request received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iauth))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&iauth, imsg->data, datalen);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (getpeereid(fd, &euid, &egid) == -1)
		return got_error_from_errno("getpeerid");

	if (iauth.euid != euid)
		return got_error(GOT_ERR_UID);
	if (iauth.egid != egid)
		return got_error(GOT_ERR_GID);

	log_debug("authenticating uid %d gid %d", euid, egid);

	err = auth_check(&username, gotsysd_auth.rules, iauth.euid, iauth.egid);
	if (err) {
		gotsysd_imsg_send_error(ibuf, GOTSYSD_PROC_AUTH,
		    iauth.client_id, err);
		goto done;
	}

	len = strlen(username);
	if (len > maxlen)
		len = maxlen;

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_ACCESS_GRANTED,
	    GOTSYSD_PROC_AUTH, -1, username, len) == -1)
		err = got_error_from_errno("imsg compose ACCESS_GRANTED");
done:
	free(username);
	return err;
}

static void
auth_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_AUTHENTICATE:
			err = recv_authreq(&imsg, iev);
			if (err)
				log_warnx("%s", err->msg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
auth_main(const char *title, struct gotsysd_access_rule_list *rules)
{
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	gotsysd_auth.title = title;
	gotsysd_auth.pid = getpid();
	gotsysd_auth.rules = rules;

	signal_set(&evsigint, SIGINT, auth_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, auth_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, auth_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, auth_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = auth_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, auth_dispatch, &iev);
	if (event_add(&iev.ev, NULL) == -1)
		fatalx("event add");

	event_dispatch();

	auth_shutdown();
}

static void
auth_shutdown(void)
{
	struct gotsysd_access_rule *rule;

	log_debug("%s: shutting down", gotsysd_auth.title);

	while (!STAILQ_EMPTY(gotsysd_auth.rules)) {
		rule = STAILQ_FIRST(gotsysd_auth.rules);
		STAILQ_REMOVE_HEAD(gotsysd_auth.rules, entry);
		free(rule);
	}

	exit(0);
}
