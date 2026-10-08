/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#define GOTD_UNIX_SOCKET "/var/run/gotd.sock"
#define GOTD_UNIX_SOCKET_BACKLOG 10
#define GOTD_USER	"_gotd"
#define GOTD_CONF_PATH	"/etc/gotd.conf"
#define GOTD_SECRETS_PATH "/etc/gotd-secrets.conf"
#ifndef GOTD_EMPTY_PATH
#define GOTD_EMPTY_PATH	"/var/empty"
#endif

#ifndef GOT_LIBEXECDIR
#define GOT_LIBEXECDIR /usr/libexec
#endif

#define GOTD_STRINGIFY(x) #x
#define GOTD_STRINGVAL(x) GOTD_STRINGIFY(x)

#define GOTD_PROG_NOTIFY_EMAIL	got-notify-email
#define GOTD_PROG_NOTIFY_HTTP	got-notify-http
#define GOTD_PROG_GOTSYS_CHECK	gotsys-check
#define GOTD_PROG_GOTSYS_APPLY	gotsys-apply

#define GOTD_PATH_PROG_NOTIFY_EMAIL \
	GOTD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTD_STRINGVAL(GOTD_PROG_NOTIFY_EMAIL)
#define GOTD_PATH_PROG_NOTIFY_HTTP \
	GOTD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTD_STRINGVAL(GOTD_PROG_NOTIFY_HTTP)
#define GOTD_PATH_PROG_GOTSYS_CHECK \
	GOTD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTD_STRINGVAL(GOTD_PROG_GOTSYS_CHECK)
#define GOTD_PATH_PROG_GOTSYS_APPLY \
	GOTD_STRINGVAL(GOT_LIBEXECDIR) "/" \
	GOTD_STRINGVAL(GOTD_PROG_GOTSYS_APPLY)

#define GOTD_MAXCLIENTS		1024
#define GOTD_MAX_CONN_PER_UID	4
#define GOTD_FD_RESERVE		5
#define GOTD_FD_NEEDED		6
#define GOTD_FILENO_MSG_PIPE	3

#define GOTD_DEFAULT_REQUEST_TIMEOUT	3600

/* Client hash tables need some extra room. */
#define GOTD_CLIENT_TABLE_SIZE (GOTD_MAXCLIENTS * 4)

enum gotd_procid {
	GOTD_PROC_GOTD	= 0,
	GOTD_PROC_LISTEN,
	GOTD_PROC_AUTH,
	GOTD_PROC_SESSION_READ,
	GOTD_PROC_SESSION_WRITE,
	GOTD_PROC_REPO_READ,
	GOTD_PROC_REPO_WRITE,
	GOTD_PROC_GITWRAPPER,
	GOTD_PROC_NOTIFY,
	GOTD_PROC_GOTSYS_CHECK,
	GOTD_PROC_GOTSYS_APPLY,
	GOTD_PROC_RELOAD,
	GOTD_PROC_GOTCTL,
	GOTD_PROC_MAX,
};

struct gotd_imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	void		*handler_arg;
	struct event	 ev;
	short		 events;
};

enum gotd_access {
	GOTD_ACCESS_DENIED = -1,
	GOTD_ACCESS_PERMITTED = 1
};

struct gotd_access_rule {
	STAILQ_ENTRY(gotd_access_rule) entry;

	enum gotd_access access;

	int authorization;
#define GOTD_AUTH_READ		0x1
#define GOTD_AUTH_WRITE		0x2

	char *identifier;
};
STAILQ_HEAD(gotd_access_rule_list, gotd_access_rule);

enum gotd_notification_target_type {
	GOTD_NOTIFICATION_VIA_EMAIL,
	GOTD_NOTIFICATION_VIA_HTTP
};

struct gotd_notification_target {
	STAILQ_ENTRY(gotd_notification_target) entry;

	enum gotd_notification_target_type type;
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
			char *auth;
			char *hmac;
		} http;
	} conf;
};
STAILQ_HEAD(gotd_notification_targets, gotd_notification_target);

struct gotd_repo {
	TAILQ_ENTRY(gotd_repo)	 entry;

	char name[NAME_MAX];
	char path[PATH_MAX];

	struct gotd_access_rule_list rules;
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
	struct gotd_notification_targets notification_targets;
};
TAILQ_HEAD(gotd_repolist, gotd_repo);

struct gotd_client_capability {
	char *key;
	char *value;
};

struct gotd_object_id_array {
	struct got_object_id		**ids;
	size_t				 nalloc;
	size_t				 nids;
};

struct gotd_uid_connection_limit {
	uid_t uid;
	int max_connections;
};

struct gotd_child_proc;

struct gotd_secrets;
struct gotd {
	pid_t pid;
	char unix_socket_path[PATH_MAX];
	char user_name[32];
	struct gotd_repolist repos;
	int nrepos;
	struct gotd_child_proc *listen_proc;
	struct gotd_child_proc *notify_proc;
	struct gotd_child_proc *reload_proc;
	int notifications_enabled;
	struct timeval request_timeout;
	struct timeval auth_timeout;
	struct gotd_uid_connection_limit *connection_limits;
	size_t nconnection_limits;
	struct gotd_secrets *secrets;
	char *default_sender;

	char *argv0;
	const char *confpath;
	int daemonize;
	int verbosity;
};

enum gotd_imsg_type {
	/* An error occurred while processing a request. */
	GOTD_IMSG_ERROR,

	/* Commands used by gotctl(8). */
	GOTD_IMSG_INFO,
	GOTD_IMSG_INFO_REPO,
	GOTD_IMSG_INFO_CLIENT,
	GOTD_IMSG_STOP,
	GOTD_IMSG_RELOAD,

	/* Request a list of references. */
	GOTD_IMSG_LIST_REFS,
	GOTD_IMSG_LIST_REFS_INTERNAL,

	/* References. */
	GOTD_IMSG_REFLIST,
	GOTD_IMSG_REF,
	GOTD_IMSG_SYMREF,

	/* Git protocol capabilities. */
	GOTD_IMSG_CAPABILITIES,
	GOTD_IMSG_CAPABILITY,

	/* Git protocol chatter. */
	GOTD_IMSG_WANT,		/* The client wants an object. */
	GOTD_IMSG_HAVE,		/* The client has an object. */
	GOTD_IMSG_ACK,		/* The server has an object or a reference. */
	GOTD_IMSG_NAK,		/* The server does not have an object/ref. */
	GOTD_IMSG_REF_UPDATE,	/* The client wants to update a reference. */
	GOTD_IMSG_REF_DELETE,	/* The client wants to delete a reference. */
	GOTD_IMSG_FLUSH,	/* The client sent a flush packet. */
	GOTD_IMSG_DONE,		/* The client is done chatting. */

	/* Sending or receiving a pack file. */
	GOTD_IMSG_SEND_PACKFILE, /* The server is sending a pack file. */
	GOTD_IMSG_RECV_PACKFILE, /* The server is receiving a pack file. */
	GOTD_IMSG_PACKFILE_RECEIVED,
	GOTD_IMSG_PACKIDX_FILE,  /* Temporary file handle for new pack index. */
	GOTD_IMSG_PACKFILE_PIPE, /* Pipe to send/receive a pack file stream. */
	GOTD_IMSG_PACKFILE_PROGRESS, /* Progress reporting. */
	GOTD_IMSG_PACKFILE_READY, /* Pack file is ready to be sent. */
	GOTD_IMSG_PACKFILE_STATUS, /* Received pack success/failure status. */
	GOTD_IMSG_PACKFILE_INSTALL, /* Received pack file can be installed. */
	GOTD_IMSG_PACKFILE_DONE, /* Pack file has been sent/received. */

	/* Pack file content verification. */
	GOTD_IMSG_PACKFILE_GET_CONTENT,
	GOTD_IMSG_PACKFILE_CONTENT_WRITTEN,
	GOTD_IMSG_RUN_GOTSYS_CHECK,
	GOTD_IMSG_PACKFILE_VERIFIED,

	/* Reference updates. */
	GOTD_IMSG_REF_UPDATES_START, /* Ref updates starting. */
	GOTD_IMSG_REF_UPDATE_OK, /* Update went OK. */
	GOTD_IMSG_REF_UPDATE_NG, /* Update was not good. */
	GOTD_IMSG_REFS_UPDATED, /* The server processed all ref updates. */

	/* Client connections. */
	GOTD_IMSG_LISTENER_READY,
	GOTD_IMSG_LISTEN_SOCKET,
	GOTD_IMSG_CONNECTION_LIMIT,
	GOTD_IMSG_REQUEST_TIMEOUT,
	GOTD_IMSG_DISCONNECT,
	GOTD_IMSG_CONNECT,

	/* Child process management. */
	GOTD_IMSG_CLIENT_SESSION_READY,
	GOTD_IMSG_REPO_CHILD_READY,
	GOTD_IMSG_CONNECT_REPO_CHILD,

	/* Reloading. */
	GOTD_IMSG_RELOAD_READY,
	GOTD_IMSG_RELOAD_SECRETS,
	GOTD_IMSG_GOTD_CONF,
	GOTD_IMSG_HALT,

	/* Auth child process. */
	GOTD_IMSG_AUTH_READY,
	GOTD_IMSG_AUTH_ACCESS_RULE,
	GOTD_IMSG_AUTHENTICATE,
	GOTD_IMSG_ACCESS_GRANTED,

	/* Protected references. */
	GOTD_IMSG_PROTECTED_TAG_NAMESPACES,
	GOTD_IMSG_PROTECTED_TAG_NAMESPACES_ELEM,
	GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES,
	GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES_ELEM,
	GOTD_IMSG_PROTECTED_BRANCHES,
	GOTD_IMSG_PROTECTED_BRANCHES_ELEM,

	/* Notify child process. */
	GOTD_IMSG_NOTIFIER_READY,
	GOTD_IMSG_NOTIFICATION_REFS,
	GOTD_IMSG_NOTIFICATION_REFS_ELEM,
	GOTD_IMSG_NOTIFICATION_REF_NAMESPACES,
	GOTD_IMSG_NOTIFICATION_REF_NAMESPACES_ELEM,
	GOTD_IMSG_NOTIFICATION_TARGET_EMAIL,
	GOTD_IMSG_NOTIFICATION_TARGET_HTTP,
	GOTD_IMSG_CONNECT_NOTIFIER,
	GOTD_IMSG_CONNECT_SESSION,
	GOTD_IMSG_NOTIFY,
	GOTD_IMSG_NOTIFICATION_SENT,

	/* Secrets. */
	GOTD_IMSG_SECRETS,	/* number of secrets */
	GOTD_IMSG_SECRET,

	/* gotsys.conf */
	GOTD_IMSG_GOTSYS_READY,
	GOTD_IMSG_GOTSYS_CHECK,
	GOTD_IMSG_GOTSYS_CFG_OK,
	GOTD_IMSG_GOTSYS_APPLY,
	GOTD_IMSG_SYSCONF_STARTED,
};

/* Structure for GOTD_IMSG_ERROR. */
struct gotd_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
	uint32_t client_id;
	char msg[GOT_ERR_MAX_MSG_SIZE];
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_INFO. */
struct gotd_imsg_info {
	pid_t pid;
	int verbosity;
	int nrepos;
	int nclients;

	/* Followed by nrepos GOTD_IMSG_INFO_REPO messages. */
	/* Followed by nclients GOTD_IMSG_INFO_CLIENT messages. */
};

/* Structure for GOTD_IMSG_INFO_REPO. */
struct gotd_imsg_info_repo {
	char repo_name[NAME_MAX];
	char repo_path[PATH_MAX];
};

/* Structure for GOTD_IMSG_INFO_CLIENT */
struct gotd_imsg_info_client {
	uid_t euid;
	gid_t egid;
	char repo_name[NAME_MAX];
	int is_writing;
	pid_t session_child_pid;
	pid_t repo_child_pid;
	time_t time_connected;
};

/* Structure for GOTD_IMSG_LIST_REFS. */
struct gotd_imsg_list_refs {
	char repo_name[NAME_MAX];
	int client_is_reading; /* 1 if reading, 0 if writing */
};

/* Structure for GOTD_IMSG_REFLIST. */
struct gotd_imsg_reflist {
	size_t nrefs;
	int algo;

	/* Followed by nrefs times of gotd_imsg_ref/gotd_imsg_symref data. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_REF data. */
struct gotd_imsg_ref {
	uint8_t id[GOT_OBJECT_ID_MAXLEN];
	int algo;
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_SYMREF data. */
struct gotd_imsg_symref {
	size_t name_len;
	size_t target_len;
	uint8_t target_id[GOT_OBJECT_ID_MAXLEN];
	int algo;

	/*
	 * Followed by name_len + target_len data bytes.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_CAPABILITIES data. */
struct gotd_imsg_capabilities {
	size_t ncapabilities;

	/*
	 * Followed by ncapabilities * GOTD_IMSG_CAPABILITY.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_CAPABILITY data. */
struct gotd_imsg_capability {
	size_t key_len;
	size_t value_len;

	/*
	 * Followed by key_len + value_len data bytes.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_WANT data. */
struct gotd_imsg_want {
	uint8_t object_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_HAVE data. */
struct gotd_imsg_have {
	uint8_t object_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_ACK data. */
struct gotd_imsg_ack {
	uint8_t object_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_NAK data. */
struct gotd_imsg_nak {
	uint8_t object_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_PACKFILE_STATUS data. */
struct gotd_imsg_packfile_status {
	size_t reason_len;

	/* Followed by reason_len data bytes. */
} __attribute__((__packed__));


/* Structure for GOTD_IMSG_REF_UPDATE data. */
struct gotd_imsg_ref_update {
	uint8_t old_id[GOT_OBJECT_ID_MAXLEN];
	uint8_t new_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
	int ref_is_new;
	int delete_ref;
	size_t name_len;

	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_PACKFILE_GET_CONTENT. */
struct gotd_imsg_packfile_get_content {
	size_t refname_len;
	size_t path_len;

	/* Followed by refname_len + path_len data bytes. */

	/* Content file descriptor is passed via imsg. */
};

/* Structure for GOTD_IMSG_PACKFILE_CONTENT_WRITTEN. */
struct gotd_imsg_packfile_content_written {
	/* If zero, the requested reference is not being updated. */
	int ref_found;

	/*
	 * If wrote_content is zero, nothing was found at the requested path.
	 *
	 * Else, content as it appears in the pack file was written to the
	 * file descriptor. If this content is empty, the file will be empty.
	 */
	int wrote_content;
};

/* Structure for GOTD_IMSG_REF_UPDATES_START data. */
struct gotd_imsg_ref_updates_start {
	int nref_updates;

	/* Followed by nref_updates GOT_IMSG_REF_UPDATE_OK/NG messages. */
};

/* Structure for GOTD_IMSG_REF_UPDATE_OK data. */
struct gotd_imsg_ref_update_ok {
	uint8_t old_id[GOT_OBJECT_ID_MAXLEN];
	uint8_t new_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
	int ref_is_new;
	size_t name_len;

	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_REF_UPDATE_NG data. */
struct gotd_imsg_ref_update_ng {
	uint8_t old_id[GOT_OBJECT_ID_MAXLEN];
	uint8_t new_id[GOT_OBJECT_ID_MAXLEN];
	int algo;
	size_t name_len;
	size_t reason_len;

	/* Followed by name_len + reason_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_SEND_PACKFILE data. */
struct gotd_imsg_send_packfile {
	int report_progress;

	/* delta cache file is sent as a file descriptor */

	/* followed by two GOTD_IMSG_PACKFILE_PIPE messages */
};

/* Structure for GOTD_IMSG_RECV_PACKFILE data. */
struct gotd_imsg_recv_packfile {
	int report_status;

	/* pack destination temp file is sent as a file descriptor */
};

/* Structure for GOTD_IMSG_PACKFILE_RECEIVED data. */
struct gotd_imsg_packfile_received {
	int pack_empty;
};

/*
 * Structure for GOTD_IMSG_PACKFILE_PROGRESS and
 * GOTD_IMSG_PACKFILE_READY data.
 */
struct gotd_imsg_packfile_progress {
	int ncolored;
	int nfound;
	int ntrees;
	off_t packfile_size;
	int ncommits;
	int nobj_total;
	int nobj_deltify;
	int nobj_written;
};

/* Structure for GOTD_IMSG_PACKFILE_INSTALL. */
struct gotd_imsg_packfile_install {
	uint8_t pack_hash[GOT_HASH_DIGEST_MAXLEN];
	int algo;
};

/* Structure for GOTD_IMSG_LISTEN_SOCKET data. */
struct gotd_imsg_listen_socket {
	size_t nconnection_limits;

	/* listen fd passed via imsg */
};

/* Structure for GOTD_IMSG_DISCONNECT data. */
struct gotd_imsg_disconnect {
	uint32_t client_id;
};

/* Structure for GOTD_IMSG_CONNECT. */
struct gotd_imsg_connect {
	uint32_t client_id;
	uid_t euid;
	gid_t egid;
	size_t username_len;

	/* Followed by username_len data bytes. */
};

/* Structure for GOTD_IMSG_CONNECT_REPO_CHILD. */
struct gotd_imsg_connect_repo_child {
	char repo_name[NAME_MAX];
	enum gotd_procid proc_id;

	/* repo child imsg pipe is passed via imsg fd */
};

/* Structure for GOTD_IMSG_AUTHENTICATE. */
struct gotd_imsg_auth {
	uid_t euid;
	gid_t egid;
	int required_auth;
	uint32_t client_id;
	char repo_name[NAME_MAX];
};

/* Structure for GOTD_IMSG_AUTH_ACCESS_RULE. */
struct gotd_imsg_auth_access_rule {
	enum gotd_access access;
	int authorization;
	size_t identifier_len;

	/* Followed by identifier_len bytes. */
};

/*
 * Structure for sending path lists over imsg. Used with:
 * GOTD_IMSG_PROTECTED_TAG_NAMESPACES
 * GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES
 * GOTD_IMSG_PROTECTED_BRANCHES
 * GOTD_IMSG_NOTIFY_BRANCHES
 * GOTD_IMSG_NOTIFY_REF_NAMESPACES
 */
struct gotd_imsg_pathlist {
	size_t nelem;

	/* Followed by nelem path list elements. */
};

/*
 * Structure for a path list element. Used with:
 * GOTD_IMSG_PROTECTED_TAG_NAMESPACES_ELEM
 * GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES_ELEM
 * GOTD_IMSG_PROTECTED_BRANCHES_ELEM
 * GOTD_IMSG_NOTIFY_BRANCHES_ELEM
 * GOTD_IMSG_NOTIFY_REF_NAMESPACES_ELEM
 */
struct gotd_imsg_pathlist_elem {
	size_t path_len;
	size_t data_len;

	/* Followed by path_len bytes. */
	/* Followed by data_len bytes. */
};

/* Structure for GOTD_IMSG_NOTIFICATION_TARGET_EMAIL. */
struct gotd_imsg_notitfication_target_email {
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
struct gotd_imsg_notitfication_target_http {
	int tls;
	size_t hostname_len;
	size_t port_len;
	size_t path_len;
	size_t auth_len;
	size_t hmac_len;;
	size_t repo_name_len;

	/*
	 * Followed by hostname_len + port_len + path_len + auth_len +
	 * hmac_len + repo_name_len bytes.
	 */
};

/* Structures for GOTD_IMSG_NOTIFY. */
enum gotd_notification_action {
	GOTD_NOTIF_ACTION_CREATED,
	GOTD_NOTIF_ACTION_REMOVED,
	GOTD_NOTIF_ACTION_CHANGED
};
/* IMSG_NOTIFY session <-> repo_write */
struct gotd_imsg_notification_content {
	enum gotd_notification_action action;
	struct got_object_id old_id;
	struct got_object_id new_id;
	size_t refname_len;
	/* Followed by refname_len data bytes. */
};
/* IMSG_NOTIFY session -> notify*/
struct gotd_imsg_notify {
	char repo_name[NAME_MAX];
	char subject_line[64];
	size_t username_len;
	/* Followed by username_len data bytes. */
};

int enter_chroot(const char *);
int gotd_parse_config(const char *, int, enum gotd_procid,
    struct gotd_secrets *, struct gotd *);
struct gotd_repo *gotd_find_repo_by_name(const char *, struct gotd_repolist *);
struct gotd_repo *gotd_find_repo_by_path(const char *, struct gotd *);
struct gotd_uid_connection_limit *gotd_find_uid_connection_limit(
    struct gotd_uid_connection_limit *limits, size_t nlimits, uid_t uid);
int gotd_parseuid(const char *s, uid_t *uid);
const struct got_error *gotd_parse_url(char **, char **, char **,
    char **, const char *);
const struct got_error *gotd_conf_new_repo(struct gotd_repo **, const char *);

/* imsg.c */
const struct got_error *gotd_imsg_flush(struct imsgbuf *);
const struct got_error *gotd_imsg_poll_recv(struct imsg *, struct imsgbuf *,
    size_t);
const struct got_error *gotd_imsg_recv_error(uint32_t *client_id,
    struct imsg *imsg);
int gotd_imsg_send_error(struct imsgbuf *ibuf, uint32_t, uint32_t,
    const struct got_error *);
int gotd_imsg_send_error_event(struct gotd_imsgev *, uint32_t, uint32_t,
    const struct got_error *);
void gotd_imsg_event_add(struct gotd_imsgev *);
int gotd_imsg_compose_event(struct gotd_imsgev *, uint16_t, uint32_t, int,
    void *, uint16_t);
int gotd_imsg_forward(struct gotd_imsgev *, struct imsg *, int);

void gotd_imsg_send_ack(struct got_object_id *, struct imsgbuf *,
    uint32_t, pid_t);
void gotd_imsg_send_nak(struct got_object_id *, struct imsgbuf *,
    uint32_t, pid_t);
const struct got_error *gotd_imsg_recv_pathlist(size_t *, struct imsg *);
const struct got_error *gotd_imsg_recv_pathlist_elem(struct imsg *,
    struct got_pathlist_head *);
void gotd_free_notification_target(struct gotd_notification_target *);
const struct got_error *gotd_imsg_recv_notification_target_email(char **,
    struct gotd_notification_target **, struct imsg *);
const struct got_error *gotd_imsg_recv_notification_target_http(char **,
    struct gotd_notification_target **, struct imsg *);
