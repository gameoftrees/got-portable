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

#define GOTSYSD_CONF_PATH		"/etc/gotsysd.conf"
#define GOTSYSD_DB_PATH			"/var/db/gotsysd"
#define GOTSYSD_DB_COMMIT_PATH		GOTSYSD_DB_PATH "/commit"
#define GOTSYSD_UNIX_SOCKET		"/var/run/gotsysd.sock"
#define GOTSYSD_UNIX_SOCKET_BACKLOG	10
#define GOTSYSD_USER			"_gotsysd"
#define GOTSYSD_REPOSITORIES_PATH	"/git"
#define GOTSYSD_SYSCONF_FILENAME	"gotsys.conf"

#ifndef GOTD_UNIX_SOCKET
#define GOTD_UNIX_SOCKET "/var/run/gotd.sock"
#endif

#ifndef GOTD_CONF_PATH
#define GOTD_CONF_PATH	"/etc/gotd.conf"
#endif

#ifndef GOTD_SECRETS_PATH
#define GOTD_SECRETS_PATH "/etc/gotd-secrets.conf"
#endif

#ifndef GOTSYSD_PATH_GOTSH
#define GOTSYSD_PATH_GOTSH		"/usr/local/bin/gotsh"
#endif

#ifndef GOTD_PATH
#define GOTD_PATH		"/usr/local/bin/gotsh"
#endif

#ifndef GOTSYSD_HOMEDIR
#define GOTSYSD_HOMEDIR		"/home"
#endif

/* UID 1000 may be used by the OpenBSD installer so require at least 1001 */
#define GOTSYSD_UID_MIN		1001

/* Default UID range. Can be overridden in gotsysd.conf. */
#define GOTSYSD_UID_DEFAULT_START	5000
#define GOTSYSD_UID_DEFAULT_END		5999

#define GOTSYSD_MAXCLIENTS		8
#define GOTSYSD_MAX_CONN_PER_UID	4
#define GOTSYSD_FD_RESERVE		5
#define GOTSYSD_FD_NEEDED		6
#define GOTSYSD_FILENO_MSG_PIPE		3

#define GOTSYSD_DEFAULT_REQUEST_TIMEOUT	360

/* Client hash tables need some extra room. */
#define GOTSYSD_CLIENT_TABLE_SIZE (GOTSYSD_MAXCLIENTS * 4)

enum gotsysd_procid {
	GOTSYSD_PROC_GOTSYSD	= 0,
	GOTSYSD_PROC_LISTEN,
	GOTSYSD_PROC_AUTH,
	GOTSYSD_PROC_PRIV,
	GOTSYSD_PROC_LIBEXEC,
	GOTSYSD_PROC_SYSCONF,
	GOTSYSD_PROC_MAX,
};

extern const char *gotsysd_proc_names[GOTSYSD_PROC_MAX];

struct gotsysd_child_proc;

enum gotsysd_access {
	GOTSYSD_ACCESS_DENIED = -1,
	GOTSYSD_ACCESS_PERMITTED = 1
};

struct gotsysd_access_rule {
	STAILQ_ENTRY(gotsysd_access_rule) entry;
	enum gotsysd_access access;
	char *identifier;
};
STAILQ_HEAD(gotsysd_access_rule_list, gotsysd_access_rule);

struct gotsysd_pending_sysconf_cmd {
	STAILQ_ENTRY(gotsysd_pending_sysconf_cmd) entry;
	int fd;
	struct got_object_id commit_id;
	uint32_t client_id;
};
STAILQ_HEAD(gotsysd_pending_sysconf_cmd_list,
    gotsysd_pending_sysconf_cmd);

enum gotsysd_web_auth_config {
	GOTSYSD_WEB_AUTH_UNSET		= 0x0,
	GOTSYSD_WEB_AUTH_DISABLED	= 0xf00000ff,
	GOTSYSD_WEB_AUTH_SECURE		= 0x00808000,
	GOTSYSD_WEB_AUTH_INSECURE	= 0x0f7f7f00
};

enum gotsysd_web_address_family {
	GOTSYSD_LISTEN_ADDR_UNIX = 0,
	GOTSYSD_LISTEN_ADDR_INET,
};

struct gotsysd_web_inet_addr {
	char address[48];
	char port[8];
	char reserved[8];
};

struct gotsysd_web_address {
	TAILQ_ENTRY(gotsysd_web_address) entry;

	enum gotsysd_web_address_family family;
	union {
		char unix_socket_path[PATH_MAX];
		struct gotsysd_web_inet_addr inet;
		
	} addr;
};
TAILQ_HEAD(gotsysd_web_addresslist, gotsysd_web_address);

/* XXX redundant definitions, see gotwebd.h */
#ifndef MAX_DOCUMENT_URI
#define MAX_DOCUMENT_URI	 255
#endif
#ifndef MAX_IDENTIFIER_SIZE
#define MAX_IDENTIFIER_SIZE	 32
#endif
#ifndef MAX_SERVER_NAME
#define MAX_SERVER_NAME		 255
#endif

struct gotsysd_web_server {
	STAILQ_ENTRY(gotsysd_web_server) entry;

	char server_name[MAX_SERVER_NAME];

	char gotweb_url_root[MAX_DOCUMENT_URI];
	char htdocs_path[PATH_MAX];

	enum gotsysd_web_auth_config auth_config;
	int hide_repositories;
	int show_repo_age;
};
STAILQ_HEAD(gotsysd_web_serverlist, gotsysd_web_server);

struct gotsysd_web_config {
	char control_socket[PATH_MAX];

	char httpd_chroot[PATH_MAX];
	char htdocs_path[PATH_MAX];
	char repos_path[PATH_MAX];

	char gotwebd_user[MAX_IDENTIFIER_SIZE];
	char www_user[MAX_IDENTIFIER_SIZE];

	char login_hint_user[MAX_IDENTIFIER_SIZE];
	char login_hint_port[8];

	enum gotsysd_web_auth_config auth_config;
	struct gotsysd_web_addresslist listen_addrs;
	struct gotsysd_web_serverlist servers;

	uint16_t prefork;
};

struct gotsysd {
	pid_t pid;
	char unix_socket_path[_POSIX_PATH_MAX];
	char repos_path[_POSIX_PATH_MAX];
	char user_name[32];
	char gotd_username[32];
	char gotsys_conf_commit_id[GOT_OBJECT_ID_HEX_MAXLEN];
	size_t gotsys_conf_commit_id_len;
	int db_commit_fd;
	struct gotsysd_child_proc *listen_proc;
	struct gotsysd_child_proc *priv_proc;
	struct gotsysd_child_proc *libexec_proc;
	struct gotsysd_child_proc *sysconf_proc;
	int sysconf_fd;
	char *sysconf_commit_id_str;
	struct gotsysd_access_rule_list access_rules;
	struct gotsys_access_rule_list *global_repo_access_rules;
	struct event sysconf_tmo;
	struct gotsysd_pending_sysconf_cmd_list sysconf_pending;

	uid_t uid_start;
	uid_t uid_end;

	char *argv0;
	const char *confpath;
	int daemonize;
	int verbosity;

	struct gotsysd_web_config web;
};

enum gotsysd_imsg_type {
	/* An error occurred while processing a request. */
	GOTSYSD_IMSG_ERROR,

	/* Unix socket connections arriving/departing. */
	GOTSYSD_IMSG_CONNECT,
	GOTSYSD_IMSG_DISCONNECT,

	/* Authentication on unix socket. */
	GOTSYSD_IMSG_AUTHENTICATE,
	GOTSYSD_IMSG_ACCESS_GRANTED,

	/* Unix socket commands and responses. */
	GOTSYSD_IMSG_CMD_INFO,
	GOTSYSD_IMSG_INFO,
	GOTSYSD_IMSG_CMD_SYSCONF,
	GOTSYSD_IMSG_SYSCONF_STARTED,
	GOTSYSD_IMSG_SYSCONF_SUCCESS,
	GOTSYSD_IMSG_SYSCONF_FAILURE,

	/* Internal sysconf messages. */
	GOTSYSD_IMSG_SYSCONF_READY,
	GOTSYSD_IMSG_SYSCONF_FD,

	/* Child processes management. */
	GOTSYSD_IMSG_CONNECT_PROC,

	/* Starting libexec helpers. */
	GOTSYSD_IMSG_START_PROG_REPO_CREATE,
	GOTSYSD_IMSG_START_PROG_USERADD,
	GOTSYSD_IMSG_START_PROG_USERHOME,
	GOTSYSD_IMSG_START_PROG_RMKEYS,
	GOTSYSD_IMSG_START_PROG_USERKEYS,
	GOTSYSD_IMSG_START_PROG_GROUPADD,
	GOTSYSD_IMSG_START_PROG_READ_CONF,
	GOTSYSD_IMSG_START_PROG_WRITE_CONF,
	GOTSYSD_IMSG_START_PROG_APPLY_CONF,
	GOTSYSD_IMSG_START_PROG_APPLY_WEBCONF,
	GOTSYSD_IMSG_PROG_READY,

	/* gotsys.conf parsing */
	GOTSYSD_IMSG_SYSCONF_PARSE_REQUEST,
	GOTSYSD_IMSG_SYSCONF_PARSE_SUCCESS,
	GOTSYSD_IMSG_SYSCONF_USERS,
	GOTSYSD_IMSG_SYSCONF_USERS_DONE,
	GOTSYSD_IMSG_SYSCONF_GROUP,
	GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS,
	GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE,
	GOTSYSD_IMSG_SYSCONF_GROUPS_DONE,
	GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USER,
	GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS,
	GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_DONE,
	GOTSYSD_IMSG_SYSCONF_WEB_SERVER,
	GOTSYSD_IMSG_SYSCONF_WEBREPO,
	GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE,
	GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE,
	GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE,
	GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH,
	GOTSYSD_IMSG_SYSCONF_WEBSITE,
	GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE,
	GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE,
	GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE,
	GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE,
	GOTSYSD_IMSG_SYSCONF_REPO,
	GOTSYSD_IMSG_SYSCONF_REPOS_DONE,
	GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULE,
	GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULES_DONE,
	GOTSYSD_IMSG_SYSCONF_ACCESS_RULE,
	GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE,
	GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE,
	GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE,
	GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE,
	GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE,
	GOTSYSD_IMSG_SYSCONF_WEB_REPOS,
	GOTSYSD_IMSG_SYSCONF_WEB_REPOS_DONE,
	GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE,
	GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM,
	GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP,
	GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE,
	GOTSYSD_IMSG_SYSCONF_PARSE_DONE,

	/* Addition of users and groups. */
	GOTSYSD_IMSG_SYSCONF_USERADD_READY,
	GOTSYSD_IMSG_SYSCONF_USERADD_PARAM,
	GOTSYSD_IMSG_SYSCONF_ADD_USER,
	GOTSYSD_IMSG_SYSCONF_USERADD_DONE,
	GOTSYSD_IMSG_SYSCONF_USERHOME_READY,
	GOTSYSD_IMSG_SYSCONF_RMKEYS_READY,
	GOTSYSD_IMSG_SYSCONF_USERKEYS_READY,
	GOTSYSD_IMSG_SYSCONF_GROUPADD_READY,
	GOTSYSD_IMSG_SYSCONF_GROUPADD_PARAM,
	GOTSYSD_IMSG_SYSCONF_GROUPADD_DONE,

	/* Home directory creation. */
	GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE,
	GOTSYSD_IMSG_SYSCONF_HOMEDIR_CREATE_DONE,

	/* Authorized keys installation. */
	GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS,
	GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS_DONE,

	/* Authorized keys removal. */
	GOTSYSD_IMSG_SYSCONF_RMKEYS_PARAM,
	GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS,
	GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USERS_DONE,
	GOTSYSD_IMSG_SYSCONF_RMKEYS_DONE,

	/* Repository creation. */
	GOTSYSD_IMSG_SYSCONF_REPO_CREATE,
	GOTSYSD_IMSG_SYSCONF_REPO_CREATE_READY,
	GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE,

	/* gotd.conf creation. */
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_READY,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_DONE,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS_DONE,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS_DONE,
	GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUPS_DONE,

	/* Apply gotd configuration. */
	GOTSYSD_IMSG_SYSCONF_APPLY_CONF_READY,
	GOTSYSD_IMSG_SYSCONF_APPLY_CONF_DONE,

	/* gotwebd.conf creation. */
	GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG,
	GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDR,
	GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDRS_DONE,
	GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVER,
	GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVERS_DONE,
	GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG_DONE,

	/* Apply gotwebd configuration. */
	GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_READY,
	GOTSYSD_IMSG_SYSCONF_APPLY_WEBCONF_DONE,
};

/* Structure for GOTSYSD_IMSG_ERROR. */
struct gotsysd_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
	uint32_t client_id;
	char msg[GOT_ERR_MAX_MSG_SIZE];
};

/* Structure for GOTSYSD_IMSG_CONNECT. */
struct gotsysd_imsg_connect {
	uint32_t client_id;
	uid_t euid;
	gid_t egid;
	size_t username_len;

	/* Followed by username_len data bytes. */
};

/* Structure for GOTSYSD_IMSG_DISCONNECT data. */
struct gotsysd_imsg_disconnect {
	uint32_t client_id;
};

/* Structure for GOTSYSD_IMSG_AUTHENTICATE. */
struct gotsysd_imsg_auth {
	uid_t euid;
	gid_t egid;
	uint32_t client_id;
};

/* Structure for GOTSYSD_IMSG_INFO. */
struct gotsysd_imsg_info {
	pid_t pid;
	int verbosity;
	char repository_directory[_POSIX_PATH_MAX];
	uid_t uid_start;
	uid_t uid_end;
	struct got_object_id commit_id;
};

/* Structure for GOTSYSD_IMSG_CMD_SYSCONF */
struct gotsysd_imsg_cmd_sysconf {
	struct got_object_id commit_id;

	/* Configuration file descriptor is passed via imsg. */
};

struct gotsysd_imsg_connect_proc {
	enum gotsysd_procid procid;
	/* ibuf fd is passed via imsg */
};

/* Structure for GOTSYSD_IMSG_START_PROG_USERKEYS. */
struct gotsysd_imsg_start_prog_userkeys {
	size_t username_len;

	/* followed by name_len bytes. */
};

/* Structure for GOTSYSD_IMSG_SYSCONF_USERADD_PARAM. */
struct gotsysd_imsg_sysconf_useradd_param {
	uid_t uid_start;
	uid_t uid_end;
};

/* Structure for GOTSYSD_IMSG_SYSCONF_USERHOME_CREATE. */
struct gotsysd_imsg_sysconf_userhome_create {
	uid_t uid_start;
	uid_t uid_end;
};

/* Structure for GOTSYSD_IMSG_SYSCONF_GRPOUPADD_PARAM. */
struct gotsysd_imsg_sysconf_groupadd_param {
	uid_t gid_start;
	uid_t gid_end;
};

/* Structure for GOTSYSD_IMSG_SYSCONF_RMKEYS_PARAM. */
struct gotsysd_imsg_sysconf_rmkeys_param {
	uid_t uid_start;
	uid_t uid_end;
};

/* 
 * Structure for messages sent via gotsys_imsg_send_users():
 * GOTSYSD_IMSG_SYSCONF_USERS
 * GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS 
 * User data is potentially spread across multiple messages, with each
 * message containing a batch of users up to the maximum imsg data size.
 */
struct gotsysd_imsg_sysconf_user {
	size_t name_len;
	size_t password_len;

	/* Followed by name_len + password_len bytes. */

	/* Last users followed by an appropriate _DONE message. */
};

/* Structure for GOTSYSD_IMSG_SYSCONF_GROUP. */
struct gotsysd_imsg_sysconf_group {
	size_t name_len;

	/* Followed by name_len bytes. */

	/* Followed by GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS for members. */
	/* Last members followed by GOTSYSD_IMSG_SYSCONF_GROUP_MEMBERS_DONE. */
};

/*
 * Structure for GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS_USER.
 * This message defines the user for which authorized keys will be sent next.
 */
struct gotsysd_imsg_sysconf_authorized_keys_user {
	size_t name_len;

	/* Followed by name_len bytes. */

	/* Followed by messages containining authorized keys. */
};

/* 
 * Structure for messages sent via gotsys_imsg_send_authorized_keys():
 * GOTSYSD_IMSG_SYSCONF_AUTHORIZED_KEYS
 * GOTSYSD_IMSG_SYSCONF_INSTALL_AUTHORIZED_KEYS
 */
struct gotsysd_imsg_sysconf_authorized_key {
	size_t keytype_len;
	size_t keydata_len;
	size_t comment_len;
	
	/* Followed by keytype_len + keydata_len + comment_len bytes. */

	/*
	 * Followed by more authorized key messages, a new authorized key
	 * user message, or an appropriate _DONE message.
	 */
};

/* Structure for GOTSYSD_IMSG_SYSCONF_REPO, */
struct gotsysd_imsg_sysconf_repo {
	size_t name_len;
	size_t headref_len;
	size_t description_len;

	/* Followed by name_len + headref_len + description_len bytes. */

	/*
	 * Followed by GOTSYSD_IMSG_SYSCONF_ACCESS_RULE for access rules,
	 * or by GOTSYSD_IMSG_SYSCONF_REPOS_DONE.
	 */
};

enum gotsysd_imsg_access {
	GOTSYSD_IMSG_ACCESS_DENIED = -1,
	GOTSYSD_IMSG_ACCESS_PERMITTED = 1
};

/* Structure for GOTSYSD_IMSG_SYSCONF_ACCESS_RULE, */
struct gotsysd_imsg_sysconf_access_rule {
	enum gotsysd_imsg_access access;
	int authorization;
	size_t identifier_len;

	/* Followed by identifier_len bytes. */
};

/*
 * Structure for sending path lists over imsg. Used with:
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES
 * GOTSYSD_IMSG_SYSCONF_NOTIFY_BRANCHES
 * GOTSYSD_IMSG_SYSCONF_NOTIFY_REF_NAMESPACES
 */
struct gotsysd_imsg_pathlist {
	size_t nelem;

	/* Followed by nelem path list elements. */
};

/*
 * Structure for a path list element. Used with:
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM
 * GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM
 * GOTSYSD_IMSG_SYSCONF_NOTIFY_BRANCHES_ELEM
 * GOTSYSD_IMSG_SYSCONF_NOTIFY_REF_NAMESPACES_ELEM
 */
struct gotsysd_imsg_pathlist_elem {
	size_t path_len;
	size_t data_len;

	/* Followed by path_len bytes. */
	/* Followed by data_len bytes. */
};

/* Structure for GOTSYSD_IMSG_NOTIFICATION_TARGET_EMAIL. */
struct gotsysd_imsg_notitfication_target_email {
	size_t sender_len;
	size_t recipient_len;
	size_t responder_len;
	size_t hostname_len;
	size_t port_len;
	size_t repo_name_len;

	/*
	 * Followed by sender_len + responder_len + responder_len +
	 * hostname_len + port_len + repo_name_len bytes.
	 */
};

/* Structure for GOTD_IMSG_NOTIFICATION_TARGET_HTTP. */
struct gotsysd_imsg_notitfication_target_http {
	int tls;
	size_t hostname_len;
	size_t port_len;
	size_t path_len;
	size_t user_len;
	size_t password_len;
	size_t hmac_len;
	size_t repo_name_len;

	/*
	 * Followed by hostname_len + port_len + path_len + user_len + password_len +
	 * hmac_len + repo_name_len bytes.
	 */
};

#ifndef GOT_LIBEXECDIR
#define GOT_LIBEXECDIR /usr/libexec
#endif

#ifndef GOT_SBINDIR
#define GOT_SBINDIR /usr/sbin
#endif

#define GOTSYSD_STRINGIFY(x) #x
#define GOTSYSD_STRINGVAL(x) GOTSYSD_STRINGIFY(x)

#define GOTSYSD_PROG_REPO_CREATE	gotsys-repo-create
#define GOTSYSD_PROG_USERADD		gotsys-useradd
#define GOTSYSD_PROG_USERHOME		gotsys-userhome
#define GOTSYSD_PROG_RMKEYS		gotsys-rmkeys
#define GOTSYSD_PROG_USERKEYS		gotsys-userkeys
#define GOTSYSD_PROG_GROUPADD		gotsys-groupadd
#define GOTSYSD_PROG_READ_CONF		gotsys-read-conf
#define GOTSYSD_PROG_WRITE_CONF		gotsys-write-conf
#define GOTSYSD_PROG_APPLY_CONF		gotsys-apply-conf
#define GOTSYSD_PROG_APPLY_WEBCONF	gotsys-apply-webconf
#define GOTSYSD_PROG_GOTD		gotd
#define GOTSYSD_PROG_GOTWEBD		gotwebd

#define GOTSYSD_PATH_PROG_REPO_CREATE \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_REPO_CREATE)
#define GOTSYSD_PATH_PROG_USERADD \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_USERADD)
#define GOTSYSD_PATH_PROG_USERHOME \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_USERHOME)
#define GOTSYSD_PATH_PROG_RMKEYS \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_RMKEYS)
#define GOTSYSD_PATH_PROG_USERKEYS \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_USERKEYS)
#define GOTSYSD_PATH_PROG_GROUPADD \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_GROUPADD)
#define GOTSYSD_PATH_PROG_READ_CONF \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_READ_CONF)
#define GOTSYSD_PATH_PROG_WRITE_CONF \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_WRITE_CONF)
#define GOTSYSD_PATH_PROG_APPLY_CONF \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_APPLY_CONF)
#define GOTSYSD_PATH_PROG_APPLY_WEBCONF \
	GOTSYSD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_APPLY_WEBCONF)
#define GOTSYSD_PATH_PROG_GOTD \
	GOTSYSD_STRINGVAL(GOT_SBINDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_GOTD)
#define GOTSYSD_PATH_PROG_GOTWEBD \
	GOTSYSD_STRINGVAL(GOT_SBINDIR) "/" \
	GOTSYSD_STRINGVAL(GOTSYSD_PROG_GOTWEBD)

extern const char *gotsysd_priv_helpers[];
extern const size_t gotsysd_num_priv_helpers;

struct gotsysd_imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	void		*handler_arg;
	struct event	 ev;
	short		 events;
};

const struct got_error *gotsysd_imsg_flush(struct imsgbuf *);
const struct got_error *gotsysd_imsg_poll_recv(struct imsg *, struct imsgbuf *,
    size_t);
const struct got_error *gotsysd_imsg_recv_error(uint32_t *client_id,
    struct imsg *imsg);
int gotsysd_imsg_send_error(struct imsgbuf *ibuf, uint32_t, uint32_t,
    const struct got_error *);
int gotsysd_imsg_send_error_event(struct gotsysd_imsgev *, uint32_t, uint32_t,
    const struct got_error *);
void gotsysd_imsg_event_add(struct gotsysd_imsgev *);
int gotsysd_imsg_compose_event(struct gotsysd_imsgev *, uint16_t, uint32_t, int,
    void *, uint16_t);
int gotsysd_imsg_forward(struct gotsysd_imsgev *, struct imsg *, int);

int gotsysd_parse_config(const char *, enum gotsysd_procid, struct gotsysd *);
int gotsysd_parseuid(const char *s, uid_t *uid);

struct gotsys_user;
struct gotsys_group;
struct gotsys_userlist;
struct gotsys_grouplist;
struct gotsys_authorized_keys_list;
struct gotsys_repolist;
struct gotsys_repo;
struct gotsys_access_rule;
struct gotsys_notification_target;
struct gotsys_webserverlist;
struct gotsys_webserver;
struct gotsys_website;
struct gotsys_webrepo;
struct media_type;
struct mediatypes;
struct got_pathlist_head;

const struct got_error *gotsys_imsg_send_users(struct gotsysd_imsgev *,
    struct gotsys_userlist *, int, int, int);
const struct got_error *gotsys_imsg_recv_users(struct imsg *,
    struct gotsys_userlist *);
const struct got_error *gotsys_imsg_recv_group(struct imsg *,
    struct gotsys_group **);
const struct got_error *gotsys_imsg_send_groups(struct gotsysd_imsgev *,
    struct gotsys_grouplist *, int, int, int, int);
const struct got_error *gotsys_imsg_send_authorized_keys_user(
    struct gotsysd_imsgev *, const char *, int);
const struct got_error *gotsys_imsg_send_authorized_keys(
    struct gotsysd_imsgev *, struct gotsys_authorized_keys_list *, int);
const struct got_error *gotsys_imsg_recv_authorized_keys_user(char **,
    struct imsg *);
const struct got_error *gotsys_imsg_recv_authorized_keys(struct imsg *,
    struct gotsys_authorized_keys_list *); 
const struct got_error *gotsys_imsg_send_access_rule(struct gotsysd_imsgev *,
    struct gotsys_access_rule *, int);
const struct got_error *gotsys_imsg_recv_media_type(struct media_type *,
    struct imsg *);
const struct got_error *gotsys_imsg_send_webservers(struct gotsysd_imsgev *,
    struct gotsys_webserverlist *);
const struct got_error *gotsys_imsg_send_mediatypes(struct gotsysd_imsgev *,
    struct mediatypes *, int, int);
const struct got_error *gotsys_imsg_recv_web_cfg(struct gotsysd_web_config *,
    struct imsg *);
const struct got_error *gotsysd_conf_validate_inet_addr(const char *,
    const char *);
const struct got_error *gotsys_imsg_recv_webaddr(struct gotsysd_web_address **,
    struct imsg *);
const struct got_error *gotsys_imsg_recv_gotweb_server(
    struct gotsysd_web_server **, struct imsg *);
const struct got_error *gotsys_imsg_recv_web_server(
    struct gotsys_webserver *, struct imsg *);
const struct got_error *gotsys_imsg_send_repositories(struct gotsysd_imsgev *,
    struct gotsys_repolist *);
const struct got_error *gotsys_imsg_recv_repository(struct gotsys_repo **,
    struct imsg *);
const struct got_error *gotsys_imsg_recv_access_rule(
    struct gotsys_access_rule **, struct imsg *, struct gotsys_userlist *,
    struct gotsys_grouplist *);
const struct got_error *gotsys_imsg_recv_webrepo(
    struct gotsys_webrepo *, struct imsg *);
const struct got_error *gotsys_imsg_recv_website_path(struct gotsys_website **,
    struct imsg *);
const struct got_error *gotsys_imsg_recv_website(struct gotsys_website *,
    struct imsg *);
const struct got_error *gotsys_imsg_recv_pathlist(size_t *, struct imsg *);
const struct got_error *gotsys_imsg_recv_pathlist_elem(struct imsg *,
    struct got_pathlist_head *);
const struct got_error *gotsys_imsg_recv_notification_target_email(char **,
    struct gotsys_notification_target **, struct imsg *);
const struct got_error *gotsys_imsg_recv_notification_target_http(char **,
    struct gotsys_notification_target **, struct imsg *);

struct gotsys_uidset_element;
struct gotsys_uidset;

struct gotsys_uidset *gotsys_uidset_alloc(void);
void gotsys_uidset_free(struct gotsys_uidset *set);
const struct got_error *gotsys_uidset_add(struct gotsys_uidset *, uid_t);
const struct got_error *gotsys_uidset_remove(void **data,
    struct gotsys_uidset *, uid_t);
int gotsys_uidset_contains(struct gotsys_uidset *, uid_t);
uid_t gotsys_uidset_min_uid(struct gotsys_uidset *, uid_t);
uid_t gotsys_uidset_max_uid(struct gotsys_uidset *, uid_t);
const struct got_error *gotsys_uidset_for_each(struct gotsys_uidset *,
    const struct got_error *(*cb)(uid_t, void *), void *);
int gotsys_uidset_num_elements(struct gotsys_uidset *);
struct gotsys_uidset_element *gotsys_uidset_get_element(
    struct gotsys_uidset *, uid_t);
const struct got_error *gotsys_uidset_for_each_element(struct gotsys_uidset *,
    const struct got_error *(*cb)(struct gotsys_uidset_element *, void *),
    void *);
void gotsys_uidset_remove_element(struct gotsys_uidset *,
    struct gotsys_uidset_element *);
void gotsysd_web_config_init(struct gotsysd_web_config *);
