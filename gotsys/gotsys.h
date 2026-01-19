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

struct gotsys_authorized_key {
	STAILQ_ENTRY(gotsys_authorized_key) entry;
	char *keytype;
	char *key;
	char *comment;
};
STAILQ_HEAD(gotsys_authorized_keys_list, gotsys_authorized_key);

/* Must fit into an imsg with some spare overhead. */
#define GOTSYS_AUTHORIZED_KEY_MAXLEN	(MAX_IMSGSIZE - IMSG_HEADER_SIZE - 512)

#define GOTSYS_SYSTEM_REPOSITORY_NAME	"gotsys"

struct gotsys_user {
	STAILQ_ENTRY(gotsys_user) entry;
	char *name;
	char *password;
	struct gotsys_authorized_keys_list authorized_keys;
};
STAILQ_HEAD(gotsys_userlist, gotsys_user);

struct gotsys_group {
	STAILQ_ENTRY(gotsys_group) entry;
	char *name;
	struct gotsys_userlist members;
};
STAILQ_HEAD(gotsys_grouplist, gotsys_group);

enum gotsys_notification_target_type {
	GOTSYS_NOTIFICATION_VIA_EMAIL,
	GOTSYS_NOTIFICATION_VIA_HTTP
};

struct gotsys_notification_target {
	STAILQ_ENTRY(gotsys_notification_target) entry;

	enum gotsys_notification_target_type type;
	union {
		struct {
			char *sender;
			char *recipient;
			char *responder;
			char *hostname;
			char *port;
		} email;
		struct {
			int   tls;
			char *hostname;
			char *port;
			char *path;
			char *user;
			char *password;
			char *hmac_secret;
		} http;
	} conf;
};
STAILQ_HEAD(gotsys_notification_targets, gotsys_notification_target);

enum gotsys_access {
	GOTSYS_ACCESS_DENIED = -1,
	GOTSYS_ACCESS_PERMITTED = 1
};

struct gotsys_access_rule {
	STAILQ_ENTRY(gotsys_access_rule) entry;

	enum gotsys_access access;

	int authorization;
#define GOTSYS_AUTH_READ		0x1
#define GOTSYS_AUTH_WRITE		0x2

	char *identifier;
};
STAILQ_HEAD(gotsys_access_rule_list, gotsys_access_rule);

enum gotsys_auth_config {
	GOTSYS_AUTH_UNSET	= 0,
	GOTSYS_AUTH_DISABLED	= 0xf00000ff,
	GOTSYS_AUTH_ENABLED	= 0x00808000,
};

struct gotsys_webrepo {
	STAILQ_ENTRY(gotsys_webrepo) entry;

	char repo_name[NAME_MAX];

	enum gotsys_auth_config auth_config;
	struct gotsys_access_rule_list access_rules;
	int hidden;
};
STAILQ_HEAD(gotsys_webrepolist, gotsys_webrepo);

struct gotsys_webserver {
	STAILQ_ENTRY(gotsys_webserver) entry;

	char server_name[MAX_SERVER_NAME];

	enum gotsys_auth_config auth_config;
	struct gotsys_access_rule_list access_rules;
	int hide_repositories;

	char css[PATH_MAX];
	char logo[PATH_MAX];
	char logo_url[GOTWEBD_MAXTEXT];
	char site_owner[GOTWEBD_MAXNAME];
	char repos_url_path[MAX_DOCUMENT_URI];

	struct mediatypes mediatypes;

	struct gotsys_webrepolist repos;
	struct got_pathlist_head websites;
};
STAILQ_HEAD(gotsys_webserverlist, gotsys_webserver);

struct gotsys_website {
	char repo_name[NAME_MAX];

	enum gotsys_auth_config auth_config;
	struct gotsys_access_rule_list access_rules;

	char url_path[MAX_DOCUMENT_URI];
	char branch_name[MAX_BRANCH_NAME];
	char path[PATH_MAX];
};

struct gotsys_repo {
	TAILQ_ENTRY(gotsys_repo) entry;

	char name[NAME_MAX];
	char *headref;
	char description[GOTWEBD_MAXDESCRSZ];

	struct gotsys_access_rule_list access_rules;

	struct got_pathlist_head protected_tag_namespaces;
	size_t nprotected_tag_namespaces;
	struct got_pathlist_head protected_branch_namespaces;
	size_t nprotected_branch_namespaces;
	struct got_pathlist_head protected_branches;
	size_t nprotected_branches;

	struct got_pathlist_head notification_refs;
	size_t num_notification_refs;
	struct got_pathlist_head notification_ref_namespaces;
	size_t num_notification_ref_namespaces;
	struct gotsys_notification_targets notification_targets;
};
TAILQ_HEAD(gotsys_repolist, gotsys_repo);

struct gotsys_conf {
	struct gotsys_userlist users;
	struct gotsys_grouplist groups;
	struct gotsys_repolist repos;
	int nrepos;
	struct gotsys_webserverlist webservers;
	struct mediatypes mediatypes;
};

void gotsys_conf_init(struct gotsys_conf *);
const struct got_error *gotsys_conf_new_webserver(struct gotsys_webserver **,
    const char *);
const struct got_error *gotsys_conf_new_webrepo(struct gotsys_webrepo **,
    const char *);
const struct got_error *gotsys_conf_init_media_types(struct mediatypes *);
const struct got_error *gotsys_conf_parse(const char *, struct gotsys_conf *,
    int *);
int gotsys_ref_name_is_valid(char *);
void gotsys_authorized_key_free(struct gotsys_authorized_key *);
void gotsys_authorized_keys_list_purge(struct gotsys_authorized_keys_list *);
void gotsys_user_free(struct gotsys_user *);
void gotsys_userlist_purge(struct gotsys_userlist *);
void gotsys_group_free(struct gotsys_group *);
void gotsys_grouplist_purge(struct gotsys_grouplist *);
void gotsys_webrepo_free(struct gotsys_webrepo *);
void gotsys_webserver_free(struct gotsys_webserver *);
void gotsys_access_rule_free(struct gotsys_access_rule *);
void gotsys_notification_target_free(struct gotsys_notification_target *);
void gotsys_repo_free(struct gotsys_repo *);
void gotsys_conf_clear(struct gotsys_conf *);
const struct got_error *gotsys_conf_new_authorized_key(
    struct gotsys_authorized_key **, char *, char *, char *);
const struct got_error *gotsys_conf_new_user(struct gotsys_user **,
    const char *);
const struct got_error *gotsys_conf_new_group(struct gotsys_group **,
    const char *);
const struct got_error *gotsys_conf_new_group_member(struct gotsys_grouplist *,
    const char *, const char *);
const struct got_error *gotsys_conf_new_repo(struct gotsys_repo **,
    const char *);
const struct got_error *gotsys_conf_new_website(struct gotsys_website **,
    const char *);
const struct got_error *gotsys_conf_validate_name(const char *, const char *);
const struct got_error *gotsys_conf_validate_repo_name(const char *);
const struct got_error *gotsys_conf_validate_password(const char *, const char *);
const struct got_error *gotsys_conf_validate_path(const char *);
const struct got_error *gotsys_conf_validate_hostname(const char *);
const struct got_error *gotsys_conf_validate_url(const char *);
const struct got_error *gotsys_conf_parse_url(char **, char **, char **,
    char **, const char *);
const struct got_error *gotsys_conf_validate_mediatype(const char *);
const struct got_error *gotsys_conf_validate_string(const char *);
const struct got_error *gotsys_conf_new_access_rule(
    struct gotsys_access_rule **, enum gotsys_access, int, const char *,
    struct gotsys_userlist *, struct gotsys_grouplist *);
