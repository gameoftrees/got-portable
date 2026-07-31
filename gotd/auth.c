/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
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

#include "gotd.h"
#include "log.h"
#include "auth.h"

static struct gotd_auth {
	pid_t pid;
	const char *title;
	struct gotd_access_rule_list rules;
} gotd_auth;

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

	if (gotd_parseuid(s, &uid) != 0)
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
auth_check(char **username, struct gotd_access_rule_list *rules,
    const char *repo_name, uid_t euid, gid_t egid, int required_auth)
{
	struct gotd_access_rule *rule;
	enum gotd_access access = GOTD_ACCESS_DENIED;
	struct passwd *pw;
	gid_t groups[NGROUPS_MAX];
	int ngroups = NGROUPS_MAX;
	int matched_user = 0;

	*username = NULL;

	pw = getpwuid(euid);
	if (pw == NULL) {
		if (errno)
			return got_error_from_errno("getpwuid");
		else
			return got_error_set_errno(EACCES, repo_name);
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

		matched_user = 1;
		access = rule->access;
		if (rule->access == GOTD_ACCESS_PERMITTED &&
		    (rule->authorization & required_auth) != required_auth)
			access = GOTD_ACCESS_DENIED;
	}

	if (access == GOTD_ACCESS_DENIED) {
		/*
		 * If a user has no explicit read or write access then
		 * do not leak the existence of a repository to them.
		 */
		if (!matched_user)
			return got_error(GOT_ERR_NOT_GIT_REPO);
		else
			return got_error_set_errno(EACCES, repo_name);
	}

	if (access == GOTD_ACCESS_PERMITTED)
		return NULL;

	/* should not happen, this would be a bug */
	return got_error_msg(GOT_ERR_NOT_IMPL, "bad access rule");
}

static const struct got_error *
recv_authreq(struct imsg *imsg, struct gotd_imsgev *iev)
{
	const struct got_error *err;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_imsg_auth iauth;
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

	len = strnlen(iauth.repo_name, sizeof(iauth.repo_name));
	if (len == 0 || len >= sizeof(iauth.repo_name))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	iauth.repo_name[len] = '\0';

	log_debug("authenticating uid %d gid %d", euid, egid);

	err = auth_check(&username, &gotd_auth.rules,
	    iauth.repo_name, iauth.euid, iauth.egid, iauth.required_auth);
	if (err) {
		gotd_imsg_send_error(ibuf, GOTD_PROC_AUTH,
		    iauth.client_id, err);
		goto done;
	}

	len = strlen(username);
	if (len > maxlen)
		len = maxlen;

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_ACCESS_GRANTED,
	    GOTD_PROC_AUTH, -1, username, len) == -1)
		err = got_error_from_errno("imsg compose ACCESS_GRANTED");
done:
	free(username);
	return err;
}

static const struct got_error *
recv_access_rule(struct imsg *imsg)
{
	const struct got_error *err;
	struct gotd_imsg_auth_access_rule irule;
	enum gotd_access access;
	size_t datalen;
	char *identifier = NULL;
	struct gotd_access_rule *rule = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(irule))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&irule, imsg->data, sizeof(irule));
	if (datalen != sizeof(irule) + irule.identifier_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (irule.identifier_len == 0) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "empty access rule identifier");
	}
	if (irule.identifier_len > _PW_NAME_LEN) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "access rule identifier too long");
	}

	switch (irule.access) {
	case GOTD_ACCESS_PERMITTED:
		if (irule.authorization == 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "permit access rule without read or write "
			    "authorization");
		}
		access = GOTD_ACCESS_PERMITTED;
		break;
	case GOTD_ACCESS_DENIED:
		if (irule.authorization != 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "deny access rule with read or write "
			    "authorization");
		}
		access = GOTD_ACCESS_DENIED;
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule");
	}

	if (irule.authorization & ~(GOTD_AUTH_READ | GOTD_AUTH_WRITE)) {
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule authorization flags");
	}
	
	identifier = strndup(imsg->data + sizeof(irule), irule.identifier_len);
	if (identifier == NULL)
		return got_error_from_errno("strndup");
	if (strlen(identifier) != irule.identifier_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		free(identifier);
		return err;
	}

	rule = calloc(1, sizeof(*rule));
	if (rule == NULL)
		return got_error_from_errno("calloc");

	rule->access = access;
	rule->authorization = irule.authorization;
	rule->identifier = identifier;
	STAILQ_INSERT_TAIL(&gotd_auth.rules, rule, entry);
	return NULL;
}

static void
auth_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
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
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_AUTH_ACCESS_RULE:
			err = recv_access_rule(&imsg);
			break;
		case GOTD_IMSG_AUTHENTICATE:
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
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
auth_main(const char *title)
{
	struct gotd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	gotd_auth.title = title;
	gotd_auth.pid = getpid();
	STAILQ_INIT(&gotd_auth.rules);

	signal_set(&evsigint, SIGINT, auth_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, auth_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, auth_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, auth_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = auth_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, auth_dispatch, &iev);

	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_AUTH_READY,
	    GOTD_PROC_AUTH, -1, NULL, 0) == -1)
		fatal("imsg compose AUTH_READY");

	event_dispatch();

	auth_shutdown();
}

static void
auth_shutdown(void)
{
	log_debug("%s: shutting down", gotd_auth.title);
	exit(0);
}
