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
#include <sys/tree.h>
#include <sys/queue.h>

#include <ctype.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_reference.h"

#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef MINIMUM
#define MINIMUM(a, b)	((a) < (b) ? (a) : (b))
#endif

void
gotsys_conf_init(struct gotsys_conf *gotsysconf)
{
	memset(gotsysconf, 0, sizeof(*gotsysconf));

	STAILQ_INIT(&gotsysconf->users);
	STAILQ_INIT(&gotsysconf->groups);
	TAILQ_INIT(&gotsysconf->repos);
	STAILQ_INIT(&gotsysconf->webservers);
	RB_INIT(&gotsysconf->mediatypes);
}

const struct got_error *
gotsys_conf_new_webserver(struct gotsys_webserver **new, const char *name)
{
	const struct got_error *err;
	struct gotsys_webserver *srv;

	*new = NULL;

	err = gotsys_conf_validate_hostname(name);
	if (err)
		return err;

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		return got_error_from_errno("calloc");

	if (strlcpy(srv->server_name, name,
	    sizeof(srv->server_name)) >= sizeof(srv->server_name)) {
		err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "web server name '%s' too long, exceeds %zd bytes",
		    name, sizeof(srv->server_name) - 1);
		free(srv);
		return err;
	}

	RB_INIT(&srv->mediatypes);
	err = gotsys_conf_init_media_types(&srv->mediatypes);
	if (err) {
		free(srv);
		return err;
	}

	STAILQ_INIT(&srv->access_rules);
	STAILQ_INIT(&srv->repos);
	RB_INIT(&srv->websites);
	srv->hide_repositories = -1;

	*new = srv;
	return NULL;
}

const struct got_error *
gotsys_conf_new_webrepo(struct gotsys_webrepo **new, const char *name)
{
	const struct got_error *err;
	struct gotsys_webrepo *repo;

	*new = NULL;

	err = gotsys_conf_validate_repo_name(name);
	if (err)
		return err;

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		return got_error_from_errno("calloc");

	if (strlcpy(repo->repo_name, name,
	    sizeof(repo->repo_name)) >= sizeof(repo->repo_name)) {
		err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "repository name '%s' too long, exceeds %zd bytes",
		    name, sizeof(repo->repo_name) - 1);
		free(repo);
		return err;
	}

	STAILQ_INIT(&repo->access_rules);
	repo->hidden = -1;

	*new = repo;
	return NULL;
}

const struct got_error *
gotsys_conf_init_media_types(struct mediatypes *mediatypes)
{
	struct media_type defaults[] = {
		{
			.media_name = "css",
			.media_type = "text",
			.media_subtype = "css",
		},
		{
			.media_name = "gif",
			.media_type = "image",
			.media_subtype = "gif",
		},
		{
			.media_name = "html",
			.media_type = "text",
			.media_subtype = "html",
		},
		{
			.media_name = "ico",
			.media_type = "image",
			.media_subtype = "x-icon",
		},
		{
			.media_name = "png",
			.media_type = "image",
			.media_subtype = "png",
		},
		{
			.media_name = "jpeg",
			.media_type = "image",
			.media_subtype = "jpeg",
		},
		{
			.media_name = "jpg",
			.media_type = "image",
			.media_subtype = "jpeg",
		},
		{
			.media_name = "js",
			.media_type = "application",
			.media_subtype = "javascript",
		},
		{
			.media_name = "svg",
			.media_type = "image",
			.media_subtype = "svg+xml",
		},
		{
			.media_name = "txt",
			.media_type = "text",
			.media_subtype = "plain",
		},
		{
			.media_name = "webmanifest",
			.media_type = "application",
			.media_subtype = "manifest+json",
		},
		{
			.media_name = "xml",
			.media_type = "text",
			.media_subtype = "xml",
		},
	};
	size_t i;

	for (i = 0; i < nitems(defaults); ++i) {
		if (media_add(mediatypes, &defaults[i]) == NULL)
			return got_error_from_errno("media_add");
	}

	return NULL;
}

void
gotsys_authorized_key_free(struct gotsys_authorized_key *key)
{
	if (key == NULL)
		return;

	free(key->keytype);
	free(key->key);
	free(key->comment);
	free(key);
}

void
gotsys_authorized_keys_list_purge(struct gotsys_authorized_keys_list *keys)
{

	if (keys == NULL)
		return;

	while (!STAILQ_EMPTY(keys)) {
		struct gotsys_authorized_key *key;

		key = STAILQ_FIRST(keys);
		STAILQ_REMOVE_HEAD(keys, entry);
		gotsys_authorized_key_free(key);
	}
}

void
gotsys_user_free(struct gotsys_user *user)
{
	if (user == NULL)
		return;

	free(user->name);
	free(user->password);
	gotsys_authorized_keys_list_purge(&user->authorized_keys);
	free(user);
}

void
gotsys_group_free(struct gotsys_group *group)
{
	if (group == NULL)
		return;

	while (!STAILQ_EMPTY(&group->members)) {
		struct gotsys_user *member;

		member = STAILQ_FIRST(&group->members);
		STAILQ_REMOVE_HEAD(&group->members, entry);
		gotsys_user_free(member);
	}

	free(group->name);
	free(group);
}

void
gotsys_access_rule_free(struct gotsys_access_rule *rule)
{
	if (rule == NULL)
		return;

	free(rule->identifier);
	free(rule);
}

void
gotsys_notification_target_free(struct gotsys_notification_target *target)
{
	if (target == NULL)
		return;

	switch (target->type) {
	case GOTSYS_NOTIFICATION_VIA_EMAIL:
		free(target->conf.email.sender);
		free(target->conf.email.recipient);
		free(target->conf.email.responder);
		free(target->conf.email.hostname);
		free(target->conf.email.port);
		break;
	case GOTSYS_NOTIFICATION_VIA_HTTP:
		free(target->conf.http.hostname);
		free(target->conf.http.port);
		free(target->conf.http.path);
		free(target->conf.http.user);
		free(target->conf.http.password);
		free(target->conf.http.hmac_secret);
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	free(target);
}

void
gotsys_repo_free(struct gotsys_repo *repo)
{
	if (repo == NULL)
		return;

	while (!STAILQ_EMPTY(&repo->access_rules)) {
		struct gotsys_access_rule *rule;

		rule = STAILQ_FIRST(&repo->access_rules);
		STAILQ_REMOVE_HEAD(&repo->access_rules, entry);
		gotsys_access_rule_free(rule);
	}

	got_pathlist_free(&repo->protected_tag_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->protected_branch_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->protected_branches, GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->notification_refs, GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->notification_ref_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	
	while (!STAILQ_EMPTY(&repo->notification_targets)) {
		struct gotsys_notification_target *target;

		target = STAILQ_FIRST(&repo->notification_targets);
		STAILQ_REMOVE_HEAD(&repo->notification_targets, entry);
		gotsys_notification_target_free(target);
	}

	free(repo->headref);
	repo->headref = NULL;

	free(repo);
}

void
gotsys_userlist_purge(struct gotsys_userlist *users)
{
	while (!STAILQ_EMPTY(users)) {
		struct gotsys_user *user;

		user = STAILQ_FIRST(users);
		STAILQ_REMOVE_HEAD(users, entry);
		gotsys_user_free(user);
	}
}

void
gotsys_grouplist_purge(struct gotsys_grouplist *groups)
{
	while (!STAILQ_EMPTY(groups)) {
		struct gotsys_group *group;

		group = STAILQ_FIRST(groups);
		STAILQ_REMOVE_HEAD(groups, entry);
		gotsys_group_free(group);
	}
}

void
gotsys_webrepo_free(struct gotsys_webrepo *webrepo)
{
	if (webrepo == NULL)
		return;

	while (!STAILQ_EMPTY(&webrepo->access_rules)) {
		struct gotsys_access_rule *rule;

		rule = STAILQ_FIRST(&webrepo->access_rules);
		STAILQ_REMOVE_HEAD(&webrepo->access_rules, entry);
		gotsys_access_rule_free(rule);
	}

	free(webrepo);
}

void
gotsys_webserver_free(struct gotsys_webserver *srv)
{
	struct got_pathlist_entry *pe;

	if (srv == NULL)
		return;

	while (!STAILQ_EMPTY(&srv->access_rules)) {
		struct gotsys_access_rule *rule;

		rule = STAILQ_FIRST(&srv->access_rules);
		STAILQ_REMOVE_HEAD(&srv->access_rules, entry);
		gotsys_access_rule_free(rule);
	}

	media_purge(&srv->mediatypes);

	while (!STAILQ_EMPTY(&srv->repos)) {
		struct gotsys_webrepo *webrepo;

		webrepo = STAILQ_FIRST(&srv->repos);
		STAILQ_REMOVE_HEAD(&srv->repos, entry);
		gotsys_webrepo_free(webrepo);
	}

	RB_FOREACH(pe, got_pathlist_head, &srv->websites) {
		struct gotsys_website *site = pe->data;

		while (!STAILQ_EMPTY(&site->access_rules)) {
			struct gotsys_access_rule *rule;

			rule = STAILQ_FIRST(&srv->access_rules);
			STAILQ_REMOVE_HEAD(&srv->access_rules, entry);
			gotsys_access_rule_free(rule);
		}
	}
	got_pathlist_free(&srv->websites,
	    GOT_PATHLIST_FREE_PATH | GOT_PATHLIST_FREE_DATA);

	free(srv);
}

void
gotsys_conf_clear(struct gotsys_conf *gotsysconf)
{
	gotsys_userlist_purge(&gotsysconf->users);

	gotsys_grouplist_purge(&gotsysconf->groups);

	while (!TAILQ_EMPTY(&gotsysconf->repos)) {
		struct gotsys_repo *repo;

		repo = TAILQ_FIRST(&gotsysconf->repos);
		TAILQ_REMOVE(&gotsysconf->repos, repo, entry);
		gotsys_repo_free(repo);
	}

	while (!STAILQ_EMPTY(&gotsysconf->webservers)) {
		struct gotsys_webserver *srv;

		srv = STAILQ_FIRST(&gotsysconf->webservers);
		STAILQ_REMOVE_HEAD(&gotsysconf->webservers, entry);
		gotsys_webserver_free(srv);
	}

	media_purge(&gotsysconf->mediatypes);
}

static const char *wellknown_users[] = {
	"anonymous",
	"root",
	"daemon",
	"operator",
	"bin",
	"build",
	"sshd",
	"www",
	"nobody",
};

static const char *wellknown_groups[] = {
	"wheel",
	"daemon",
	"kmem",
	"sys",
	"tty",
	"operator",
	"bin",
	"wsrc",
	"users",
	"auth",
	"games",
	"staff",
	"wobj",
	"sshd",
	"guest",
	"utmp",
	"crontab",
	"www",
	"network",
	"authpf",
	"dialer",
	"nogroup",
	"nobody",
};

const struct got_error *
gotsys_conf_validate_name(const char *name, const char *type)
{
	size_t i, len;

	if (name[0] == '\0')
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "empty %s name", type);

	/* Forbid use of well-known names, regardless of requested type. */
	for (i = 0; i < nitems(wellknown_users); i++) {
		if (strcmp(name, wellknown_users[i]) == 0) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "%s name '%s' is reserved and cannot be used",
			    type, name);
		}
	}
	for (i = 0; i < nitems(wellknown_groups); i++) {
		if (strcmp(name, wellknown_groups[i]) == 0) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "%s name '%s' is reserved and cannot be used",
			    type, name);
		}
	}

	/*
	 * Quoting useradd(3):
	 *
	 * It is recommended that login names contain only lowercase
	 * characters and digits.  They may also contain uppercase
	 * characters, non-leading hyphens, periods, underscores, and a
	 * trailing ‘$’.  Login names may not be longer than 31 characters.
	 */
	len = strlen(name);
	if (len > _PW_NAME_LEN) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "%s name is too long (exceeds %d bytes): %s",
		    type, _PW_NAME_LEN, name);
	}

	/*
	 * In addition to the regular useradd(3) rules above, disallow
	 * leading digits to prevent a name from being misinterpreted
	 * as a number in any context by any tool.
	 */
	if (isdigit(name[0]))
		goto invalid;

	/*
	 * In addition to the regular useradd(3) rules above, disallow
	 * leading underscores to prevent collisions with system daemon
	 * accounts.
	 * Prevent leading periods as well, because we can.
	 * A trailing $ is required for compat with Samba. We prevent it
	 * for now until interaction with Samba is proven to be useful.
	 */
	for (i = 0; i < len; i++) {
		/*
		 * On non-OpenBSD systems, isalnum(3) can suffer from
		 * locale-dependent-behaviour syndrome.
		 * Prevent non-ASCII characters in a portable way.
		 */
		if (name[i] & 0x80)
			goto invalid;

		if (isalnum(name[i]) ||
		    (i > 0 && name[i] == '-') ||
		    (i > 0 && name[i] == '_') ||
		    (i > 0 && name[i] == '.'))
			continue;

		goto invalid;
	}

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "%s names may only contain alphabetic ASCII "
	    "characters, non-leading digits, non-leading hyphens, "
	    "non-leading underscores, or non-leading periods: %s",
	    type, name);
}

const struct got_error *
gotsys_conf_validate_repo_name(const char *name)
{
	size_t len, i;

	if (name[0] == '\0')
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "empty repository name");

	/*
	 * Disallow leading digits to prevent a name from being
	 * misinterpreted as a number in any context by any tool.
	 */
	if (isdigit(name[0]))
		goto invalid;

	len = strlen(name);
	for (i = 0; i < len; i++) {
		if (isalnum(name[i]) ||
		    (i > 0 && name[i] == '-') ||
		    (i > 0 && name[i] == '_') ||
		    (i > 0 && name[i] == '.'))
			continue;

		goto invalid;
	}

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "repository names may only contain alphabetic ASCII "
	    "characters, non-leading digits, non-leading hyphens, "
	    "non-leading underscores, or non-leading periods: %s",
	    name);
}

static int
validate_password(const char *s, size_t len)
{
	static const u_int8_t base64chars[] =
	    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	size_t i;

	for (i = 0; i < len; i++) {
		if (strchr(base64chars, s[i]) == NULL)
			return 0;
	}

	return 1;
}


const struct got_error *
gotsys_conf_validate_password(const char *username, const char *password)
{
	size_t len = strlen(password);

	if (len < 8 || len > _PASSWORD_LEN)
		goto invalid;

	if (password[0] != '$' ||
	    password[1] != '2' || /* bcrypt version */
	    !(password[2] == 'a' || password[2] == 'b') || /* minor versions */
	    password[3] != '$' ||
	    !(isdigit(password[4]) && isdigit(password[5])) || /* num rounds */
	    password[6] != '$')
		goto invalid;

	/* The remainder must be base64 data. */
	if (!validate_password(&password[7], len - 7))
		goto invalid;

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG, "password for user %s "
	    "was not encrypted with the encrypt(1) utility", username);
}

static const struct got_error *
validate_comment(const char *comment, size_t len)
{
	size_t i;

	/* Require printable ASCII characters. */	
	for (i = 0; i < len; i++) {
		/*
		 * On non-OpenBSD systems, isalnum(3) can suffer from
		 * locale-dependent-behaviour syndrome.
		 * Prevent non-ASCII characters in a portable way.
		 */
		if (comment[i] & 0x80)
			goto invalid;

		if (!isalnum(comment[i]) && !ispunct(comment[i]))
			goto invalid;
	}

	return NULL;
invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "authorized key comments may only contain "
	    "printable ASCII characters and no whitespace");
}

static int
validate_authorized_key(const char *s, size_t len)
{
	static const u_int8_t base64chars[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	size_t i;

	for (i = 0; i < len; i++) {
		if (strchr(base64chars, s[i]) == NULL)
			return 0;
	}

	return 1;
}

const struct got_error *
gotsys_conf_new_authorized_key(struct gotsys_authorized_key **key,
    char *keytype, char *keydata, char *comment)
{
	const struct got_error *err = NULL;
	static const char *known_keytypes[] = {
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com",
		"ssh-ed25519",
		"ssh-rsa"
	};
	size_t i, typelen, datalen, commentlen = 0, totlen;

	*key = NULL;

	for (i = 0; i < nitems(known_keytypes); i++) {
		if (strcmp(keytype, known_keytypes[i]) == 0)
			break;
	}
	if (i >= nitems(known_keytypes)) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "unknown authorized key type: %s", keytype);
	}

	typelen = strlen(keytype);
	if (typelen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key type too long: %s", keytype);
	}

	datalen = strlen(keydata);
	if (datalen == 0) {
		return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
		    "empty authorized key");
	}
	if (datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
	    typelen + datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key too long: %s:", keydata);
	}
	if (!validate_authorized_key(keydata, datalen)) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "authorized key data must be base64-encoded");
	}

	if (comment) {
		commentlen = strlen(comment);
		if (commentlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key comment too long: %s:",
			    comment);
		}

		err = validate_comment(comment, commentlen);
		if (err)
			return err;
	}

	/* Won't overflow since values are < GOTSYS_AUTHORIZED_KEY_MAXLEN. */
	totlen = typelen + datalen + commentlen;
	if (totlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key too long: %s %s %s",
		    keytype, keydata, comment ? comment : "");
	}

	*key = calloc(1, sizeof(**key));
	if (*key == NULL)
		return got_error_from_errno("calloc");

	(*key)->keytype = strdup(keytype);
	if ((*key)->keytype == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	(*key)->key = strdup(keydata);
	if ((*key)->key == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	if (comment) {
		(*key)->comment = strdup(comment);
		if ((*key)->comment == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
done:
	if (err) {
		gotsys_authorized_key_free(*key);
		*key = NULL;
	}
	return NULL;
}

const struct got_error *
gotsys_conf_new_user(struct gotsys_user **user, const char *username)
{
	const struct got_error *err;

	*user = calloc(1, sizeof(**user));
	if (*user == NULL)
		return got_error_from_errno("calloc");

	(*user)->name = strdup(username);
	if ((*user)->name == NULL) {
		err = got_error_from_errno("strdup");
		free(*user);
		*user = NULL;
		return err;
	}

	STAILQ_INIT(&(*user)->authorized_keys);
	return NULL;
}

const struct got_error *
gotsys_conf_new_group(struct gotsys_group **group, const char *groupname)
{
	const struct got_error *err;

	*group = calloc(1, sizeof(**group));
	if (*group == NULL)
		return got_error_from_errno("calloc");

	(*group)->name = strdup(groupname);
	if ((*group)->name == NULL) {
		err = got_error_from_errno("strdup");
		free(*group);
		*group = NULL;
		return err;
	}

	STAILQ_INIT(&(*group)->members);
	return NULL;
}

const struct got_error *
gotsys_conf_new_group_member(struct gotsys_grouplist *groups,
    const char *groupname, const char *username)
{
	struct gotsys_group *group = NULL;
	struct gotsys_user *member = NULL;

	STAILQ_FOREACH(group, groups, entry) {
		if (strcmp(group->name, groupname) == 0)
			break;
	}
	if (group == NULL) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "reference to undeclared group '%s' via user '%s'",
		    groupname, username);
	}

	STAILQ_FOREACH(member, &group->members, entry) {
		if (strcmp(member->name, username) == 0)
			break;
	}
	if (member)
		return NULL;

	member = calloc(1, sizeof(*member));
	if (member == NULL)
		return got_error_from_errno("calloc");

	member->name = strdup(username);
	if (member->name == NULL) {
		free(member);
		return got_error_from_errno("strdup");
	}

	STAILQ_INSERT_TAIL(&group->members, member, entry);
	return NULL;
}

const struct got_error *
gotsys_conf_new_repo(struct gotsys_repo **new_repo, const char *name)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;

	*new_repo = NULL;

	err = gotsys_conf_validate_repo_name(name);
	if (err)
		return err;

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		return got_error_from_errno("calloc");

	STAILQ_INIT(&repo->access_rules);
	RB_INIT(&repo->protected_tag_namespaces);
	RB_INIT(&repo->protected_branch_namespaces);
	RB_INIT(&repo->protected_branches);
	RB_INIT(&repo->notification_refs);
	RB_INIT(&repo->notification_ref_namespaces);
	STAILQ_INIT(&repo->notification_targets);

	if (strlcpy(repo->name, name, sizeof(repo->name)) >=
	    sizeof(repo->name)) {
		free(repo);
		return got_error_fmt(GOT_ERR_BAD_PATH,
		    "repository name too long: %s", name);
	}

	*new_repo = repo;
	return NULL;
}

const struct got_error *
gotsys_conf_new_access_rule(struct gotsys_access_rule **rule,
    enum gotsys_access access, int authorization, const char *identifier,
    struct gotsys_userlist *users, struct gotsys_grouplist *groups)
{
	const struct got_error *err = NULL;
	const char *name;

	*rule = NULL;

	switch (access) {
	case GOTSYS_ACCESS_PERMITTED:
		if (authorization == 0) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "permit access rule without read or write "
			    "authorization");
		}
		break;
	case GOTSYS_ACCESS_DENIED:
		if (authorization != 0) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "deny access rule with read or write "
			    "authorization");
		}
		break;
	default:
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "invalid access rule");
	}

	if (authorization & ~(GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE)) {
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "invalid access rule authorization flags");
	}

	name = identifier;
	if (name[0] == '\0')
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "empty identifier in access rule");

	if (name[0] == ':') {
		struct gotsys_group *group = NULL;

		name++;
		if (name[0] == '\0')
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "empty group name in access rule");

		if (groups) {
			STAILQ_FOREACH(group, groups, entry) {
				if (strcmp(group->name, name) == 0)
					break;
			}
			if (group == NULL) {
				return got_error_fmt(GOT_ERR_PARSE_CONFIG,
				    "reference to undeclared group '%s' via "
				    "access rule", name);
			}
		}
	} else if (strcmp(name, "anonymous") == 0) {
		if (access == GOTSYS_ACCESS_PERMITTED &&
		    (authorization & GOTSYS_AUTH_WRITE)) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "the \"anonymous\" user must not have write "
			    "permission");
		}
	} else if (users) {
		struct gotsys_user *user = NULL;

		STAILQ_FOREACH(user, users, entry) {
			if (strcmp(user->name, name) == 0)
				break;
		}
		if (user == NULL) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "reference to undeclared user '%s' via "
			    "access rule", name);
		}
	}

	*rule = calloc(1, sizeof(**rule));
	if (*rule == NULL)
		return got_error_from_errno("calloc");

	(*rule)->access = access;
	(*rule)->authorization = authorization;
	(*rule)->identifier = strdup(identifier);
	if ((*rule)->identifier == NULL) {
		err = got_error_from_errno("strdup");
		gotsys_access_rule_free(*rule);
		*rule = NULL;
	}

	return err;
}

const struct got_error *
gotsys_conf_new_website(struct gotsys_website **site, const char *url_path)
{
	const struct got_error *err = NULL;
	int i;

	*site = NULL;

	if (url_path[0] == '\0') {
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "empty URL path in configuration file");
	}

	for (i = 0; i < strlen(url_path); i++) {
		if (isalnum((unsigned char)url_path[i]) ||
		    url_path[i] == '-' || url_path[i] == '_' ||
		    url_path[i] == '/')
			continue;

		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "URL paths may only contain alphanumeric ASCII characters, "
		    "hyphens, underscores, and slashes: %s", url_path);
	}
	
	*site = calloc(1, sizeof(**site));
	if (*site == NULL)
		return got_error_from_errno("calloc");

	STAILQ_INIT(&(*site)->access_rules);

	if (!got_path_is_absolute(url_path)) {
		int ret;

		ret = snprintf((*site)->url_path, sizeof((*site)->url_path),
		    "/%s", url_path);
		if (ret == -1) {
			err = got_error_from_errno("snprintf");
			goto done;
		}
		if ((size_t)ret >= sizeof((*site)->url_path)) {
			err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "URL path too long (exceeds %zd bytes): %s",
			    sizeof((*site)->url_path) - 1, url_path);
			goto done;
		}
	} else {
		if (strlcpy((*site)->url_path, url_path,
		    sizeof((*site)->url_path)) >=
		    sizeof((*site)->url_path)) {
			err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "URL path too long (exceeds %zd bytes): %s",
			    sizeof((*site)->url_path) - 1, url_path);
			goto done;
		}
	}

done:
	if (err) {
		free(*site);
		*site = NULL;
	}

	return err;
}


const struct got_error *
gotsys_conf_validate_path(const char *path)
{
	size_t i;

	for (i = 0; i < strlen(path); i++) {
		if (isalnum((unsigned char)path[i]) ||
		    path[i] == '.' ||
		    path[i] == '-' ||
		    path[i] == '_' ||
		    path[i] == '/')
			continue;

		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "paths may only contain alphanumeric characters, dots, "
		    "hyphens, underscores, and slashes; bad path %s", path);
	}

	return NULL;
}

const struct got_error *
gotsys_conf_validate_hostname(const char *host)
{
	size_t i, len;

	len = strlen(host);
	if (len == 0) {
		return got_error_msg(GOT_ERR_PARSE_URI,
		    "hostname cannot be empty");
	}

	for (i = 0; i < len; i++) {
		if (isalnum((unsigned char)host[i]) ||
		    host[i] == '.' || host[i] == '-')
			continue;

		return got_error_fmt(GOT_ERR_PARSE_URI,
		    "hostnames may only contain alphanumeric characters, "
		    "dots, and hyphens; bad hostname %s", host);
	}

	return NULL;
}

static inline int
should_urlencode(int c)
{
	if (c <= ' ' || c >= 127)
		return 1;

	switch (c) {
		/* gen-delim */
	case ':':
	case '/':
	case '?':
	case '#':
	case '[':
	case ']':
	case '@':
		/* sub-delims */
	case '!':
	case '$':
	case '&':
	case '\'':
	case '(':
	case ')':
	case '*':
	case '+':
	case ',':
	case ';':
	case '=':
		/* needed because the URLs are embedded into gotd.conf */
	case '\"':
		return 1;
	default:
		return 0;
	}
}

static char *
urlencode(const char *str)
{
	const char *s;
	char *escaped;
	size_t i, len;
	int a, b;

	len = 0;
	for (s = str; *s; ++s) {
		len++;
		if (len == 1 && *s == '/')
			continue;
		if (should_urlencode(*s))
			len += 2;
	}

	escaped = calloc(1, len + 1);
	if (escaped == NULL)
		return NULL;

	i = 0;
	for (s = str; *s; ++s) {
		if (i == 0 && *s == '/') {
			escaped[i++] = *s;
			continue;
		}
		if (should_urlencode(*s)) {
			a = (*s & 0xF0) >> 4;
			b = (*s & 0x0F);

			escaped[i++] = '%';
			escaped[i++] = a <= 9 ? ('0' + a) : ('7' + a);
			escaped[i++] = b <= 9 ? ('0' + b) : ('7' + b);
		} else
			escaped[i++] = *s;
	}

	return escaped;
}

const struct got_error *
gotsys_conf_parse_url(char **proto, char **host, char **port,
    char **request_path, const char *url)
{
	const struct got_error *err = NULL;
	char *s, *p, *q;

	*proto = *host = *port = *request_path = NULL;

	p = strstr(url, "://");
	if (!p) {
		return got_error_msg(GOT_ERR_PARSE_URI,
		    "no protocol specified");
	}

	*proto = strndup(url, p - url);
	if (*proto == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	s = p + 3;

	p = strstr(s, "/");
	if (p == NULL)
		p = strchr(s, '\0');

	q = memchr(s, ':', p - s);
	if (q) {
		*host = strndup(s, q - s);
		if (*host == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if ((*host)[0] == '\0') {
			err = got_error(GOT_ERR_PARSE_URI);
			goto done;
		}
		*port = strndup(q + 1, p - (q + 1));
		if (*port == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if ((*port)[0] == '\0') {
			err = got_error(GOT_ERR_PARSE_URI);
			goto done;
		}
		if (strcmp(*port, "http") != 0 &&
		    strcmp(*port, "https") != 0) {
			const char *errstr;

			(void)strtonum(*port, 1, USHRT_MAX, &errstr);
			if (errstr != NULL) {
				err = got_error_fmt(GOT_ERR_PARSE_URI,
				    "port number '%s' is %s", *port, errstr);
				goto done;
			}
		}
	} else {
		*host = strndup(s, p - s);
		if (*host == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
	}

	err = gotsys_conf_validate_hostname(*host);
	if (err)
		goto done;

	while (p[0] == '/' && p[1] == '/')
		p++;
	if (p[0] == '\0') {
		*request_path = strdup("/");
		if (*request_path == NULL) {
			err = got_error_from_errno("strdup");
		}
	} else {
		*request_path = urlencode(p);
		if (*request_path == NULL)
			err = got_error_from_errno("calloc");
	}
done:
	if (err) {
		free(*proto);
		*proto = NULL;
		free(*host);
		*host = NULL;
		free(*port);
		*port = NULL;
		free(*request_path);
		*request_path = NULL;
	}
	return err;
}

const struct got_error *
gotsys_conf_validate_url(const char *url)
{
	const struct got_error *err;
	char *proto, *hostname, *port, *path;

	err = gotsys_conf_parse_url(&proto, &hostname, &port, &path, url);
	if (err)
		return err;

	if (strcmp(proto, "http") != 0 &&
	    strcmp(proto, "https") != 0) {
		err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "invalid protocol %s", proto);
		goto done;
	}

	err = gotsys_conf_validate_hostname(hostname);
	if (err)
		goto done;

	err = gotsys_conf_validate_path(path);
	if (err)
		goto done;
done:
	free(proto);
	free(hostname);
	free(port);
	free(path);
	return err;
}

const struct got_error *
gotsys_conf_validate_mediatype(const char *s)
{
	size_t i;

	for (i = 0; s[i] != '\0'; ++i) {
		if (!isalnum((unsigned char)s[i]) &&
		    s[i] != '-' && s[i] != '+' && s[i] != '.')
			return got_error_path(s, GOT_ERR_MEDIA_TYPE);
	}
	return (0);
}

const struct got_error *
gotsys_conf_validate_string(const char *s)
{
	int i;

	for (i = 0; s[i] != '\0'; ++i) {
		char x = s[i];

		/* keep in sync with gotwebd/parse.y allowed_in_string() */
		if (isalnum((unsigned char)x) ||
		    (ispunct((unsigned char)x) && x != '(' && x != ')' &&
		    x != '{' && x != '}' &&
		    x != '!' && x != '=' && x != '#' &&
		    x != ',' && x != '/'))
			continue;

		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "character '%c' (0x%.2x) is not allowed in %s", x, x, s);
	}

	return NULL;
}

struct gotsys_repo *
gotsys_find_repo_by_name(const char *repo_name, struct gotsys_repolist *repos)
{
	struct gotsys_repo *repo;
	size_t needle_len = strlen(repo_name);

	TAILQ_FOREACH(repo, repos, entry) {
		size_t haystack_len = strlen(repo->name);

		if (strncmp(repo->name, repo_name,
		    MINIMUM(needle_len, haystack_len)) != 0)
			continue;

		if (needle_len == haystack_len &&
		    repo_name[needle_len] == '\0' &&
		    repo->name[haystack_len] == '\0')
			return repo;

		if (repo_name[needle_len] == '\0' &&
		    haystack_len == needle_len + 4 &&
		    strcmp(&repo->name[haystack_len - 4], ".git") == 0)
			return repo;

		if (repo->name[haystack_len] == '\0' &&
		    needle_len == haystack_len + 4 && 
		    strcmp(&repo_name[needle_len - 4], ".git") == 0)
			return repo;
	}

	return NULL;
}

struct gotsys_webrepo *
gotsys_find_webrepo_by_name(const char *repo_name,
    struct gotsys_webrepolist *repos)
{
	struct gotsys_webrepo *webrepo;
	size_t needle_len = strlen(repo_name);

	STAILQ_FOREACH(webrepo, repos, entry) {
		size_t haystack_len = strlen(webrepo->repo_name);

		if (strncmp(webrepo->repo_name, repo_name,
		    MINIMUM(needle_len, haystack_len)) != 0)
			continue;

		if (needle_len == haystack_len &&
		    repo_name[needle_len] == '\0' &&
		    webrepo->repo_name[haystack_len] == '\0')
			return webrepo;

		if (repo_name[needle_len] == '\0' &&
		    haystack_len == needle_len + 4 &&
		    strcmp(&webrepo->repo_name[haystack_len - 4], ".git") == 0)
			return webrepo;

		if (webrepo->repo_name[haystack_len] == '\0' &&
		    needle_len == haystack_len + 4 && 
		    strcmp(&repo_name[needle_len - 4], ".git") == 0)
			return webrepo;
	}

	return NULL;
}
