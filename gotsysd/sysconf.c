
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "log.h"

#include "sysconf.h"

enum gotsysd_sysconf_state {
	SYSCONF_STATE_EXPECT_PARSING_SUCCESS = 0,
	SYSCONF_STATE_EXPECT_USERS,
	SYSCONF_STATE_EXPECT_AUTHORIZED_KEYS,
	SYSCONF_STATE_EXPECT_GROUPS,
	SYSCONF_STATE_EXPECT_REPOS,
	SYSCONF_STATE_EXPECT_MEDIA_TYPES,
	SYSCONF_STATE_EXPECT_WEB_SERVERS,
	SYSCONF_STATE_ADD_USERS,
	SYSCONF_STATE_CREATE_HOMEDIRS,
	SYSCONF_STATE_INSTALL_AUTHORIZED_KEYS,
	SYSCONF_STATE_REMOVE_AUTHORIZED_KEYS,
	SYSCONF_STATE_ADD_GROUPS,
	SYSCONF_STATE_CREATE_REPOS,
	SYSCONF_STATE_CREATE_CONF_FILES,
	SYSCONF_STATE_RESTART_GOTD,
	SYSCONF_STATE_RESTART_GOTWEBD,
	SYSCONF_STATE_DONE,
};

static struct gotsysd_sysconf {
	pid_t pid;
	uid_t uid;
	const char *title;
	struct gotsysd_imsgev parent_iev;
	struct gotsysd_imsgev libexec_iev;
	struct gotsysd_imsgev priv_iev;
	struct gotsys_userlist *users_cur;
	struct gotsys_user *user_cur;
	struct gotsys_repo *repo_cur;
	enum gotsysd_sysconf_state state;
	uid_t uid_start;
	uid_t uid_end;
	int have_anonymous_user;
	struct got_pathlist_head *protected_refs_cur;
	size_t *nprotected_refs_cur;
	size_t nprotected_refs_needed;
	size_t nprotected_refs_received;
	struct gotsys_access_rule_list *global_repo_access_rules;
	struct got_pathlist_head *notif_refs_cur;
	size_t *num_notif_refs_cur;
	size_t num_notif_refs_needed;
	size_t num_notif_refs_received;
	struct gotsys_website *site_cur;
	struct gotsysd_web_config *web;
} gotsysd_sysconf;

static struct gotsys_conf gotsysconf;

static void
sysconf_shutdown(void)
{
	log_debug("%s: shutting down", gotsysd_sysconf.title);

	gotsys_conf_clear(&gotsysconf);

	exit(0);
}

static void
sysconf_sighdlr(int sig, short event, void *arg)
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
		sysconf_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static const struct got_error *
start_useradd(void)
{
	if (gotsysd_imsg_compose_event(&gotsysd_sysconf.priv_iev,
	    GOTSYSD_IMSG_START_PROG_USERADD, GOTSYSD_PROC_SYSCONF, -1,
	    NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose START_PROG_USERADD");
	}

	return NULL;
}

static const struct got_error *
add_anonymous_user(struct gotsys_userlist *users)
{
	const struct got_error *err;
	struct gotsys_user *user;

	err = gotsys_conf_new_user(&user, "anonymous");
	if (err)
		return err;
	user->password = strdup("");
	if (user->password == NULL) {
		err = got_error_from_errno("strdup");
		gotsys_user_free(user);
		return err;
	}

	STAILQ_INSERT_TAIL(&gotsysconf.users, user, entry);
	return NULL;
}

static void
sysconf_dispatch_libexec(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	size_t npaths;
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
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_PARSE_SUCCESS:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_PARSING_SUCCESS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("gotsys.conf parsed successfully");
			gotsysd_sysconf.state = SYSCONF_STATE_EXPECT_USERS;
			gotsysd_sysconf.users_cur = &gotsysconf.users;
			break;
		case GOTSYSD_IMSG_SYSCONF_USERS:
			if (gotsysd_sysconf.users_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg,
			    gotsysd_sysconf.users_cur);
			break;
		case GOTSYSD_IMSG_SYSCONF_USERS_DONE:
			if (gotsysd_sysconf.users_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving users");
			gotsysd_sysconf.state =
			    SYSCONF_STATE_EXPECT_AUTHORIZED_KEYS;
			gotsysd_sysconf.users_cur = NULL;
			gotsysd_sysconf.user_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USER: {
			char *username = NULL;
			struct gotsys_user *user;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.user_cur = NULL;
			err = gotsys_imsg_recv_authorized_keys_user(&username,
			    &imsg);
			if (err)
				break;
			STAILQ_FOREACH(user, &gotsysconf.users, entry) {
				if (strcmp(user->name, username) == 0)
					break;
			}
			if (user == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "unknown username received in imsg");
				break;
			}
			gotsysd_sysconf.user_cur = user;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS:
			if (gotsysd_sysconf.user_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_authorized_keys(&imsg,
			    &gotsysd_sysconf.user_cur->authorized_keys);
			break;
		case GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving authorized_keys");
			gotsysd_sysconf.state = SYSCONF_STATE_EXPECT_GROUPS;
			gotsysd_sysconf.users_cur = NULL;
			gotsysd_sysconf.user_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUP: {
			struct gotsys_group *group;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_group(&imsg, &group);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&gotsysconf.groups, group, entry);
			gotsysd_sysconf.users_cur = &group->members;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS:
			if (gotsysd_sysconf.users_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg,
			    gotsysd_sysconf.users_cur);
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE:
			if (gotsysd_sysconf.users_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.users_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPS_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving groups");
			gotsysd_sysconf.state = SYSCONF_STATE_EXPECT_REPOS;
			gotsysd_sysconf.users_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO: {
			struct gotsys_repo *repo;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_repository(&repo, &imsg);
			if (err)
				break;
			log_debug("received repository %s", repo->name);
			TAILQ_INSERT_TAIL(&gotsysconf.repos, repo, entry);
			gotsysd_sysconf.repo_cur = repo;
			gotsysd_sysconf.site_cur = NULL;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("receiving access rule");
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			if (!gotsysd_sysconf.have_anonymous_user &&
			    strcmp(rule->identifier, "anonymous") == 0) {
				err = add_anonymous_user(&gotsysconf.users);
				if (err)
					break;
				gotsysd_sysconf.have_anonymous_user = 1;
			}
			rules = &gotsysd_sysconf.repo_cur->access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving access rules");
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.protected_refs_cur != NULL ||
			    gotsysd_sysconf.nprotected_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {

				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotsysd_sysconf.protected_refs_cur =
			    &gotsysd_sysconf.repo_cur->protected_tag_namespaces;
			gotsysd_sysconf.nprotected_refs_cur =
			    &gotsysd_sysconf.repo_cur->nprotected_tag_namespaces;
			gotsysd_sysconf.nprotected_refs_needed = npaths;
			gotsysd_sysconf.nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.protected_refs_cur != NULL ||
			    gotsysd_sysconf.nprotected_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotsysd_sysconf.protected_refs_cur =
			    &gotsysd_sysconf.repo_cur->protected_branch_namespaces;
			gotsysd_sysconf.nprotected_refs_cur =
			    &gotsysd_sysconf.repo_cur->nprotected_branch_namespaces;
			gotsysd_sysconf.nprotected_refs_needed = npaths;
			gotsysd_sysconf.nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.protected_refs_cur != NULL ||
			    gotsysd_sysconf.nprotected_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotsysd_sysconf.protected_refs_cur =
			    &gotsysd_sysconf.repo_cur->protected_branches;
			gotsysd_sysconf.nprotected_refs_cur =
			    &gotsysd_sysconf.repo_cur->nprotected_branches;
			gotsysd_sysconf.nprotected_refs_needed = npaths;
			gotsysd_sysconf.nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM:
			if (gotsysd_sysconf.protected_refs_cur == NULL ||
			    gotsysd_sysconf.nprotected_refs_cur == NULL ||
			    gotsysd_sysconf.nprotected_refs_needed == 0 ||
			    gotsysd_sysconf.nprotected_refs_received >=
			    gotsysd_sysconf.nprotected_refs_needed ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist_elem(&imsg,
			    gotsysd_sysconf.protected_refs_cur);
			if (err)
				break;
			if (++gotsysd_sysconf.nprotected_refs_received >=
			    gotsysd_sysconf.nprotected_refs_needed) {
				gotsysd_sysconf.protected_refs_cur = NULL;
				*gotsysd_sysconf.nprotected_refs_cur =
				    gotsysd_sysconf.nprotected_refs_received;
				gotsysd_sysconf.nprotected_refs_needed = 0;
				gotsysd_sysconf.nprotected_refs_received = 0;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.nprotected_refs_needed != 0 ||
			    gotsysd_sysconf.protected_refs_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving protected refs");
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotsysd_sysconf.notif_refs_cur =
			    &gotsysd_sysconf.repo_cur->notification_refs;
			gotsysd_sysconf.num_notif_refs_cur =
			    &gotsysd_sysconf.repo_cur->num_notification_refs;
			gotsysd_sysconf.num_notif_refs_needed = npaths;
			gotsysd_sysconf.num_notif_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotsysd_sysconf.notif_refs_cur =
			    &gotsysd_sysconf.repo_cur->notification_ref_namespaces;
			gotsysd_sysconf.num_notif_refs_cur =
			    &gotsysd_sysconf.repo_cur->num_notification_ref_namespaces;
			gotsysd_sysconf.num_notif_refs_needed = npaths;
			gotsysd_sysconf.num_notif_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM:
			if (gotsysd_sysconf.notif_refs_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed == 0 ||
			    gotsysd_sysconf.num_notif_refs_received >=
			    gotsysd_sysconf.num_notif_refs_needed ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist_elem(&imsg,
			    gotsysd_sysconf.notif_refs_cur);
			if (err)
				break;
			if (++gotsysd_sysconf.num_notif_refs_received >=
			    gotsysd_sysconf.num_notif_refs_needed) {
				gotsysd_sysconf.notif_refs_cur = NULL;
				*gotsysd_sysconf.num_notif_refs_cur =
				    gotsysd_sysconf.num_notif_refs_received;
				gotsysd_sysconf.num_notif_refs_needed = 0;
				gotsysd_sysconf.num_notif_refs_received = 0;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving notification refs");
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving notification ref namespaces");
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL: {
			struct gotsys_notification_target *target;

			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			err = gotsys_imsg_recv_notification_target_email(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(
			    &gotsysd_sysconf.repo_cur->notification_targets,
			    target, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP: {
			struct gotsys_notification_target *target;

			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.notif_refs_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			err = gotsys_imsg_recv_notification_target_http(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(
			    &gotsysd_sysconf.repo_cur->notification_targets,
			    target, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE:
			if (gotsysd_sysconf.repo_cur == NULL ||
			    gotsysd_sysconf.num_notif_refs_needed != 0 ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			gotsysd_sysconf.num_notif_refs_needed = 0;
			gotsysd_sysconf.notif_refs_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPOS_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving repositories");
			gotsysd_sysconf.repo_cur = NULL;
			gotsysd_sysconf.users_cur = NULL;
			gotsysd_sysconf.state =
			    SYSCONF_STATE_EXPECT_MEDIA_TYPES;
			break;
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE: {
			struct media_type media;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_MEDIA_TYPES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_recv_media_type(&media, &imsg);
			if (err)
				break;
			if (media_add(&gotsysconf.mediatypes, &media) == NULL)
				err = got_error_from_errno("media_add");
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_MEDIA_TYPES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state =
			    SYSCONF_STATE_EXPECT_WEB_SERVERS;
			break;
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVER: {
			struct gotsys_webserver *srv;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = calloc(1, sizeof(*srv));
			if (srv == NULL) {
				err = got_error_from_errno("calloc");
				break;
			}
			err = gotsys_imsg_recv_web_server(srv, &imsg);
			if (err) {
				free(srv);
				break;
			}
			log_debug("received web server");
			STAILQ_INSERT_TAIL(&gotsysconf.webservers, srv, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE: {
			struct gotsys_webserver *srv;
			struct gotsys_access_rule *rule;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			log_debug("receiving web access rule");
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			if (!gotsysd_sysconf.have_anonymous_user &&
			    strcmp(rule->identifier, "anonymous") == 0) {
				err = add_anonymous_user(&gotsysconf.users);
				if (err)
					break;
				gotsysd_sysconf.have_anonymous_user = 1;
			}

			STAILQ_INSERT_TAIL(&srv->access_rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving web access rules");
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBREPO: {
			struct gotsys_webserver *srv;
			struct gotsys_webrepo *webrepo;
			struct gotsys_repo *repo;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			webrepo = calloc(1, sizeof(*webrepo));
			if (webrepo == NULL) {
				err = got_error_from_errno("calloc");
				break;
			}

			err = gotsys_imsg_recv_webrepo(webrepo, &imsg);
			if (err)
				break;

			TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
				if (strcmp(repo->name, webrepo->repo_name) == 0)
					break;
			}
			if (repo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "web repository refers to nonexistent "
				    "repository %s while in state %d\n",
				    webrepo->repo_name, gotsysd_sysconf.state);
				break;
			}
			log_debug("received web server %s repo %s",
			    srv->server_name, webrepo->repo_name);
			STAILQ_INSERT_TAIL(&srv->repos, webrepo, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE: {
			struct gotsys_webserver *srv;
			struct gotsys_webrepo *webrepo;
			struct gotsys_access_rule *rule;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			webrepo = STAILQ_LAST(&srv->repos, gotsys_webrepo,
			    entry);
			if (webrepo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("receiving webrepo access rule");

			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			if (!gotsysd_sysconf.have_anonymous_user &&
			    strcmp(rule->identifier, "anonymous") == 0) {
				err = add_anonymous_user(&gotsysconf.users);
				if (err)
					break;
				gotsysd_sysconf.have_anonymous_user = 1;
			}
			STAILQ_INSERT_TAIL(&webrepo->access_rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving webrepo access rules");
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving webrepos");
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH: {
			struct gotsys_webserver *srv;
			struct gotsys_website *site;
			struct got_pathlist_entry *new;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			err = gotsys_imsg_recv_website_path(&site, &imsg);
			if (err)
				break;
			err = got_pathlist_insert(&new, &srv->websites,
			    site->url_path, site);
			if (err)
				break;
			if (new == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "duplicate web site '%s' in "
				    "repository '%s'", site->url_path,
				    gotsysd_sysconf.repo_cur->name);
				free(site);
				break;
			}
			gotsysd_sysconf.site_cur = site;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE: {
			struct gotsys_repo *repo;

			if (gotsysd_sysconf.site_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			err = gotsys_imsg_recv_website(
			    gotsysd_sysconf.site_cur, &imsg);
			if (err)
				break;

			TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
				if (strcmp(repo->name,
				    gotsysd_sysconf.site_cur->repo_name) == 0)
					break;
			}
			if (repo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "web repository refers to nonexistent "
				    "repository %s while in state %d\n",
				    gotsysd_sysconf.site_cur->repo_name,
				    gotsysd_sysconf.state);
				break;
			}
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (gotsysd_sysconf.site_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("receiving website access rule");
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			if (!gotsysd_sysconf.have_anonymous_user &&
			    strcmp(rule->identifier, "anonymous") == 0) {
				err = add_anonymous_user(&gotsysconf.users);
				if (err)
					break;
				gotsysd_sysconf.have_anonymous_user = 1;
			}
			rules = &gotsysd_sysconf.site_cur->access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE:
			if (gotsysd_sysconf.site_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving website access rules");
			gotsysd_sysconf.site_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE:
			if (gotsysd_sysconf.site_cur != NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("done receiving websites");
			break;
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE: {
			struct gotsys_webserver *srv;
			struct media_type media;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}

			err = gotsys_imsg_recv_media_type(&media, &imsg);
			if (err)
				break;
			if (media_add(&srv->mediatypes, &media) == NULL)
				err = got_error_from_errno("media_add");
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE:
			log_debug("done receiving web servers");
			gotsysd_sysconf.state = SYSCONF_STATE_ADD_USERS;
			err = start_useradd();
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err)
			fatalx("imsg %d: %s", imsg.hdr.type, err->msg);

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

static const struct got_error *
add_users(struct gotsysd_imsgev *iev)
{
	struct gotsysd_imsg_sysconf_useradd_param param;

	param.uid_start = gotsysd_sysconf.uid_start;
	param.uid_end = gotsysd_sysconf.uid_end;

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_USERADD_PARAM,
	    GOTSYSD_PROC_SYSCONF, -1, &param, sizeof(param)) == -1)
		return got_error_from_errno("imsg compose "
		    "SYSCONF_USERADD_PARAM");

	return gotsys_imsg_send_users(iev, &gotsysconf.users,
	    GOTSYSD_IMSG_SYSCONF_USERS,
	    GOTSYSD_IMSG_SYSCONF_USERS_DONE, 1);
}

static const struct got_error *
send_authorized_keys_users(struct gotsysd_imsgev *iev)
{
	struct gotsysd_imsg_sysconf_rmkeys_param param;

	param.uid_start = gotsysd_sysconf.uid_start;
	param.uid_end = gotsysd_sysconf.uid_end;

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_RMKEYS_PARAM,
	    GOTSYSD_PROC_SYSCONF, -1, &param, sizeof(param)) == -1)
		return got_error_from_errno("imsg compose "
		    "SYSCONF_RMKEYS_PARAM");

	return gotsys_imsg_send_users(iev, &gotsysconf.users,
	    GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS,
	    GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS_DONE, 0);
}

static const struct got_error *
create_homedirs(struct gotsysd_imsgev *iev)
{
	struct gotsysd_imsg_sysconf_userhome_create param;

	param.uid_start = gotsysd_sysconf.uid_start;
	param.uid_end = gotsysd_sysconf.uid_end;

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE,
	    GOTSYSD_PROC_SYSCONF, -1, &param, sizeof(param)) == -1)
		return got_error_from_errno("imsg compose "
		    "SYSCONF_USERHOME_PARAM");
	return NULL;
}

static const struct got_error *
start_userhome(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_START_PROG_USERHOME, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose START_USERHOME");

	return NULL;
}

static const struct got_error *
start_userkeys(struct gotsysd_imsgev *iev, struct gotsys_user *user)
{
	struct gotsysd_imsg_start_prog_userkeys param;
	struct ibuf *wbuf = NULL;

	wbuf = imsg_create(&iev->ibuf, GOTSYSD_IMSG_START_PROG_USERKEYS,
	    0, 0, sizeof(param));
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create START_PROG_USERKEYS");

	param.username_len = strlen(user->name);
	if (imsg_add(wbuf, &param, sizeof(param)) == -1)
		return got_error_from_errno("imsg_add START_PROG_USERKEYS");
	if (imsg_add(wbuf, user->name, param.username_len) == -1)
		return got_error_from_errno("imsg_add START_PROG_USERKEYS");
	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
add_groups(struct gotsysd_imsgev *iev)
{
	struct gotsysd_imsg_sysconf_groupadd_param param;

	param.gid_start = gotsysd_sysconf.uid_start;
	param.gid_end = gotsysd_sysconf.uid_end;

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GROUPADD_PARAM, GOTSYSD_PROC_SYSCONF, -1,
	    &param, sizeof(param)) == -1)
		return got_error_from_errno("imsg compose "
		    "SYSCONF_GROUPADD_PARAM");

	return gotsys_imsg_send_groups(iev, &gotsysconf.groups,
	    GOTSYSD_IMSG_SYSCONF_GROUP,
	    GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS,
	    GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE,
	    GOTSYSD_IMSG_SYSCONF_GROUPS_DONE);
}

static const struct got_error *
start_repo_create(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_START_PROG_REPO_CREATE, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose START_REPO_CREATE");

	return NULL;
}

static const struct got_error *
create_repos(struct gotsysd_imsgev *iev)
{
	struct gotsys_repo *repo;

	TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_REPO_CREATE, GOTSYSD_PROC_SYSCONF,
		    -1, repo->name, strlen(repo->name)) == -1)
			return got_error_from_errno("imsg compose "
			    "SYSCONF_REPO_CREATE");
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose "
		    "SYSCONF_REPO_CREATE_DONE");

	return NULL;
}

static const struct got_error *
start_rmkeys(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_START_PROG_RMKEYS,
	    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose START_PROG_RMKEYS");

	return NULL;
}

static const struct got_error *
start_groupadd(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_START_PROG_GROUPADD,
	    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose START_PROG_GROUPADD");

	return NULL;
}

static const struct got_error *
start_write_conf(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_START_PROG_WRITE_CONF, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose START_CONF_WRITE");

	return NULL;
}

static const struct got_error *
send_webaddr(struct gotsysd_imsgev *iev, struct gotsysd_web_address *addr)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDR, GOTSYSD_PROC_SYSCONF,
	    -1, addr, sizeof(*addr)) == -1)
		return got_error_from_errno("imsg compose SYSCONF_GOTWEB_ADDR");

	return NULL;
}

static const struct got_error *
send_webserver(struct gotsysd_imsgev *iev, struct gotsysd_web_server *srv)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVER, GOTSYSD_PROC_SYSCONF,
	    -1, srv, sizeof(*srv)) == -1)
		return got_error_from_errno("imsg compose SYSCONF_GOTWEB_ADDR");

	return NULL;
}

static const struct got_error *
send_web_config(struct gotsysd_imsgev *iev)
{
	const struct got_error *err;
	struct gotsysd_web_address *addr;
	struct gotsysd_web_server *srv;
	
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG, 0, -1,
	    gotsysd_sysconf.web, sizeof(*gotsysd_sysconf.web)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	TAILQ_FOREACH(addr, &gotsysd_sysconf.web->listen_addrs, entry) {
		err = send_webaddr(iev, addr);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDRS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	STAILQ_FOREACH(srv, &gotsysd_sysconf.web->servers, entry) {
		err = send_webserver(iev, srv);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVERS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

static const struct got_error *
send_gotsysconf(struct gotsysd_imsgev *iev)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	err = gotsys_imsg_send_users(iev, &gotsysconf.users,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS_DONE, 0);
	if (err)
		return err;

	err = gotsys_imsg_send_groups(iev, &gotsysconf.groups,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS_DONE,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUPS_DONE);
	if (err)
		return err;

	STAILQ_FOREACH(rule, gotsysd_sysconf.global_repo_access_rules, entry) {
		err = gotsys_imsg_send_access_rule(iev, rule,
		    GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULE);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULES_DONE, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	err = gotsys_imsg_send_repositories(iev, &gotsysconf.repos);
	if (err)
		return err;

	err = gotsys_imsg_send_mediatypes(iev, &gotsysconf.mediatypes,
	    GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE,
	    GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE);
	if (err)
		return err;
	
	err = gotsys_imsg_send_webservers(iev, &gotsysconf.webservers);
	if (err)
		return err;

	return NULL;
}

static const struct got_error *
start_apply_conf(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_START_PROG_APPLY_CONF, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose START_APPLY_CONF");

	return NULL;
}

static const struct got_error *
start_apply_webconf(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF, GOTSYSD_PROC_SYSCONF,
	    -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose START_APPLY_CONF");

	return NULL;
}

static void
sysconf_dispatch_priv(int fd, short event, void *arg)
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
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_USERADD_READY:
			if (gotsysd_sysconf.state != SYSCONF_STATE_ADD_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = add_users(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_USERADD_DONE:
			if (gotsysd_sysconf.state != SYSCONF_STATE_ADD_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state = SYSCONF_STATE_CREATE_HOMEDIRS;
			err = start_userhome(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_USERHOME_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_HOMEDIRS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = create_homedirs(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE_DONE: {
			struct gotsys_user *user;

			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_HOMEDIRS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state =
			    SYSCONF_STATE_INSTALL_AUTHORIZED_KEYS;
			user = STAILQ_FIRST(&gotsysconf.users);
			if (user && strcmp(user->name, "anonymous") == 0)
				user = STAILQ_NEXT(user, entry);
			if (user == NULL) {
				err = got_error_msg(GOT_ERR_PARSE_CONFIG,
				    "no users defined in configuration file");
				break;
			}
			err = start_userkeys(iev, user);
			if (err)
				break;
			gotsysd_sysconf.user_cur = user;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_USERKEYS_READY:
			if (gotsysd_sysconf.user_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_INSTALL_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = gotsys_imsg_send_authorized_keys(iev,
			    &gotsysd_sysconf.user_cur->authorized_keys,
			    GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS);
			if (err)
				break;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE,
			    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "AUTHORIZED_KEYS_DONE");
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE: {
			struct gotsys_user *user;

			if (gotsysd_sysconf.user_cur == NULL ||
			    gotsysd_sysconf.state !=
			    SYSCONF_STATE_INSTALL_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			log_debug("authorized keys installed for user %s",
			    gotsysd_sysconf.user_cur->name);
			user = STAILQ_NEXT(gotsysd_sysconf.user_cur, entry);
			if (user && strcmp(user->name, "anonymous") == 0)
				user = STAILQ_NEXT(user, entry);
			if (user) {
				err = start_userkeys(iev, user);
				if (err)
					break;
				gotsysd_sysconf.user_cur = user;
			} else {
				gotsysd_sysconf.user_cur = NULL;
				gotsysd_sysconf.state =
				    SYSCONF_STATE_REMOVE_AUTHORIZED_KEYS;
				err = start_rmkeys(iev);
			}
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_RMKEYS_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_REMOVE_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = send_authorized_keys_users(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_RMKEYS_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_REMOVE_AUTHORIZED_KEYS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state = SYSCONF_STATE_ADD_GROUPS;
			err = start_groupadd(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPADD_READY:
			if (gotsysd_sysconf.state != SYSCONF_STATE_ADD_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = add_groups(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_GROUPADD_DONE:
			if (gotsysd_sysconf.state != SYSCONF_STATE_ADD_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state = SYSCONF_STATE_CREATE_REPOS;
			err = start_repo_create(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = create_repos(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state = SYSCONF_STATE_CREATE_CONF_FILES;
			err = start_write_conf(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_CONF_FILES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			err = send_web_config(iev);
			if (err)
				break;
			err = send_gotsysconf(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_CREATE_CONF_FILES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
				break;
			}
			gotsysd_sysconf.state = SYSCONF_STATE_RESTART_GOTD;
			err = start_apply_conf(iev);
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_CONF_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_RESTART_GOTD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_CONF_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_RESTART_GOTD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
			}
			if (!STAILQ_EMPTY(&gotsysd_sysconf.web->servers)) {
				gotsysd_sysconf.state =
				    SYSCONF_STATE_RESTART_GOTWEBD;
				err = start_apply_webconf(iev);
			} else {
				gotsysd_sysconf.state = SYSCONF_STATE_DONE;
				if (gotsysd_imsg_compose_event(
				    &gotsysd_sysconf.parent_iev,
				    GOTSYSD_IMSG_SYSCONF_SUCCESS,
				    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1) {
					log_warnx("%s: %s",
					    gotsysd_sysconf.title,
					    strerror(errno));
				}
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_READY:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_RESTART_GOTWEBD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
			}
			log_debug("webconf ready received");
			break;
		case GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_DONE:
			if (gotsysd_sysconf.state !=
			    SYSCONF_STATE_RESTART_GOTWEBD) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    gotsysd_sysconf.state);
			}
			log_debug("webconf done received");
			gotsysd_sysconf.state = SYSCONF_STATE_DONE;
			if (gotsysd_imsg_compose_event(
			    &gotsysd_sysconf.parent_iev,
			    GOTSYSD_IMSG_SYSCONF_SUCCESS,
			    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1) {
				log_warnx("%s: %s", gotsysd_sysconf.title,
				    strerror(errno));
			}
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err)
			fatalx("imsg %d: %s", imsg.hdr.type, err->msg);

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

static const struct got_error *
connect_proc(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_connect_proc proc;
	struct gotsysd_imsgev *iev = NULL;
	size_t datalen;
	int fd = -1;
	void (*handler)(int, short, void *) = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(proc))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	memcpy(&proc, imsg->data, sizeof(proc));

	switch (proc.procid) {
	case GOTSYSD_PROC_LIBEXEC:
		if (gotsysd_sysconf.libexec_iev.ibuf.fd != -1) {
			log_warnx("libexec proc already connected");
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		iev = &gotsysd_sysconf.libexec_iev;
		handler = sysconf_dispatch_libexec;
		break;
	case GOTSYSD_PROC_PRIV:
		if (gotsysd_sysconf.priv_iev.ibuf.fd != -1) {
			log_warnx("priv proc already connected");
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		iev = &gotsysd_sysconf.priv_iev;
		handler = sysconf_dispatch_priv;
		break;
	default:
		log_debug("unexpected proc id %d", proc.procid);
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	if (imsgbuf_init(&iev->ibuf, fd) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}

	fd = -1;
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = handler;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ, handler, iev);
	gotsysd_imsg_event_add(iev);
done:
	if (fd != -1)
		close(fd);

	return err;
}

static void
sysconf_dispatch(int fd, short event, void *arg)
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

		if (gotsysd_sysconf.state == SYSCONF_STATE_DONE)
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = gotsysd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTSYSD_IMSG_CONNECT_PROC:
			err = connect_proc(&imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_FD: {
			int sysconf_fd;

			log_debug("%s: received sysconf fd", __func__);
			if (gotsysd_sysconf.libexec_iev.ibuf.fd == -1 ||
			    gotsysd_sysconf.priv_iev.ibuf.fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}

			sysconf_fd = imsg_get_fd(&imsg);
			if (sysconf_fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}

			/* Drop "recvfd" pledge promise. */
			if (pledge("stdio sendfd", NULL) == -1)
				fatal("pledge");

			if (gotsysd_imsg_compose_event(
			    &gotsysd_sysconf.libexec_iev,
			    GOTSYSD_IMSG_START_PROG_READ_CONF,
			    GOTSYSD_PROC_SYSCONF, sysconf_fd, NULL, 0) == -1) {
				log_warnx("%s: %s", gotsysd_sysconf.title,
				    strerror(errno));
			}
			break;
		}
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err)
			fatalx("imsg %d: %s", imsg.hdr.type, err->msg);

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		log_debug("%s: loop exit", __func__);
		event_loopexit(NULL);
	}
}

void
sysconf_main(const char *title, uid_t uid_start, uid_t uid_end,
    struct gotsys_access_rule_list *global_repo_access_rules,
    struct gotsysd_web_config *web)
{
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	struct gotsysd_imsgev *iev = &gotsysd_sysconf.parent_iev;

	gotsys_conf_init(&gotsysconf);

	gotsysd_sysconf.title = title;
	gotsysd_sysconf.pid = getpid();
	gotsysd_sysconf.uid = getuid();
	gotsysd_sysconf.libexec_iev.ibuf.fd = -1;
	gotsysd_sysconf.priv_iev.ibuf.fd = -1;
	gotsysd_sysconf.state = SYSCONF_STATE_EXPECT_PARSING_SUCCESS;
	gotsysd_sysconf.uid_start = uid_start;
	gotsysd_sysconf.uid_end = uid_end;
	gotsysd_sysconf.global_repo_access_rules = global_repo_access_rules;
	gotsysd_sysconf.web = web;

	signal_set(&evsigint, SIGINT, sysconf_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, sysconf_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, sysconf_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, sysconf_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev->ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = sysconf_dispatch;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ, sysconf_dispatch, iev);

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_READY,
	    GOTSYSD_PROC_SYSCONF, -1, NULL, 0) == -1) {
		log_warnx("%s: %s", title, strerror(errno));
	}

	event_dispatch();

	sysconf_shutdown();
}
