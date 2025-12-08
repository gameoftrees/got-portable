/*
 * Copyright (c) 2016, 2019, 2020-2022 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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

#include <netinet/in.h>
#include <net/if.h>
#include <sys/queue.h>

#include <limits.h>
#include <stdio.h>

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/* GOTWEBD DEFAULTS */
#define GOTWEBD_CONF		 "/etc/gotwebd.conf"

#ifndef GOTWEBD_DEFAULT_USER
#define GOTWEBD_DEFAULT_USER	 "_gotwebd"
#endif

#ifndef GOTWEBD_WWW_USER
#define GOTWEBD_WWW_USER	 "www"
#endif

#define GOTWEBD_LOGIN_CMD	"weblogin"
#define GOTWEBD_LOGIN_SOCKET	 "/var/run/gotweb-login.sock"
#define GOTWEBD_LOGIN_TIMEOUT	 300 /* in seconds */

#define GOTWEBD_MAXDESCRSZ	 1024
#define GOTWEBD_MAXCLONEURLSZ	 1024
#define GOTWEBD_CACHESIZE	 1024
#define GOTWEBD_MAXCLIENTS	 1024
#define GOTWEBD_MAXTEXT		 511
#define GOTWEBD_MAXNAME		 64
#define GOTWEBD_MAXPORT		 6
#define GOTWEBD_NUMPROC		 3
#define GOTWEBD_SOCK_FILENO	 3

#define PROC_MAX_INSTANCES	 32

/* GOTWEB DEFAULTS */
#define MAX_QUERYSTRING		 2048
#define MAX_DOCUMENT_URI	 255
#define MAX_SERVER_NAME		 255
#define MAX_AUTH_COOKIE		 255
#define MAX_IDENTIFIER_SIZE	 32
#define MAX_BRANCH_NAME		 255

#define GOTWEB_GIT_DIR		 ".git"

#define D_HTTPD_CHROOT		 "/var/www"
#define D_HTDOCS_PATH		 "/htdocs/gotwebd"
#define D_UNIX_SOCKET		 "/run/gotweb.sock"
#define D_FCGI_PORT		 "9000"
#define D_GOTPATH		 "/got/public"
#define D_SITENAME		 "Gotweb"
#define D_SITEOWNER		 "Got Owner"
#define D_SITELINK		 "Repos"
#define D_GOTLOGO		 "got.png"
#define D_GOTURL		 "https://gameoftrees.org"
#define D_GOTWEBCSS		 "gotweb.css"

#define D_SHOWROWNER		 1
#define D_SHOWSOWNER		 1
#define D_SHOWAGE		 1
#define D_SHOWDESC		 1
#define D_SHOWURL		 1
#define D_RESPECTEXPORTOK	 0
#define D_HIDE_REPOSITORIES	 0
#define D_MAXREPODISP		 25
#define D_MAXSLCOMMDISP		 10
#define D_MAXCOMMITDISP		 25
#define D_MAXSLTAGDISP		 3

#define BUF			 8192

#define TIMEOUT_DEFAULT		 120

#define FCGI_CONTENT_SIZE	 65535
#define FCGI_PADDING_SIZE	 255
#define FCGI_RECORD_SIZE	 \
    (sizeof(struct fcgi_record_header) + FCGI_CONTENT_SIZE + FCGI_PADDING_SIZE)

#define FCGI_ALIGNMENT		 8
#define FCGI_ALIGN(n)		 \
    (((n) + (FCGI_ALIGNMENT - 1)) & ~(FCGI_ALIGNMENT - 1))

#define FD_RESERVE		 5

#define FCGI_BEGIN_REQUEST	 1
#define FCGI_ABORT_REQUEST	 2
#define FCGI_END_REQUEST	 3
#define FCGI_PARAMS		 4
#define FCGI_STDIN		 5
#define FCGI_STDOUT		 6
#define FCGI_STDERR		 7
#define FCGI_DATA		 8
#define FCGI_GET_VALUES		 9
#define FCGI_GET_VALUES_RESULT	10
#define FCGI_UNKNOWN_TYPE	11
#define FCGI_MAXTYPE		(FCGI_UNKNOWN_TYPE)

#define FCGI_REQUEST_COMPLETE	0
#define FCGI_CANT_MPX_CONN	1
#define FCGI_OVERLOADED		2
#define FCGI_UNKNOWN_ROLE	3

#define GOTWEB_PACK_NUM_TEMPFILES     (32 * 2)

/* Forward declaration */
struct got_blob_object;
struct got_tree_entry;
struct got_reflist_head;

enum gotwebd_proc_type {
	GOTWEBD_PROC_PARENT,
	GOTWEBD_PROC_SOCKETS,
	GOTWEBD_PROC_FCGI,
	GOTWEBD_PROC_LOGIN,
	GOTWEBD_PROC_AUTH,
	GOTWEBD_PROC_GOTWEB,
};

enum imsg_type {
	GOTWEBD_IMSG_CFG_SRV,
	GOTWEBD_IMSG_CFG_SOCK,
	GOTWEBD_IMSG_CFG_FD,
	GOTWEBD_IMSG_CFG_ACCESS_RULE,
	GOTWEBD_IMSG_CFG_MEDIA_TYPE,
	GOTWEBD_IMSG_CFG_REPO,
	GOTWEBD_IMSG_CFG_WEBSITE,
	GOTWEBD_IMSG_CFG_DONE,
	GOTWEBD_IMSG_CTL_PIPE,
	GOTWEBD_IMSG_CTL_START,
	GOTWEBD_IMSG_LOGIN_SECRET,
	GOTWEBD_IMSG_AUTH_SECRET,
	GOTWEBD_IMSG_AUTH_CONF,
	GOTWEBD_IMSG_FCGI_PARSE_PARAMS,
	GOTWEBD_IMSG_FCGI_PARAMS,
	GOTWEBD_IMSG_WWW_UID,
	GOTWEBD_IMSG_REQ_ABORT,
	GOTWEBD_IMSG_REQ_PROCESS,
};

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	void			*data;
	short			 events;
};

#define IMSG_DATA_SIZE(imsg)	((imsg)->hdr.len - IMSG_HEADER_SIZE)

struct env_val {
	SLIST_ENTRY(env_val)	 entry;
	char			*val;
};
SLIST_HEAD(env_head, env_val);

struct fcgi_record_header {
	uint8_t		version;
	uint8_t		type;
	uint16_t	id;
	uint16_t	content_len;
	uint8_t		padding_len;
	uint8_t		reserved;
}__attribute__((__packed__));

struct blame_line {
	int		 annotated;
	char		*id_str;
	char		*committer;
	char		 datebuf[11]; /* YYYY-MM-DD + NUL */
};

struct repo_dir {
	char			*name;
	char			*owner;
	char			*description;
	char			*url;
	time_t			 age;
	char			*path;
};

struct repo_tag {
	TAILQ_ENTRY(repo_tag)	 entry;
	char			*commit_id;
	char			*tag_name;
	char			*tag_commit;
	char			*commit_msg;
	char			*tagger;
	time_t			 tagger_time;
};

struct repo_commit {
	TAILQ_ENTRY(repo_commit)	 entry;
	char			*path;
	char			*refs_str;
	char			*commit_id; /* id_str1 */
	char			*parent_id; /* id_str2 */
	char			*tree_id;
	char			*author;
	char			*committer;
	char			*commit_msg;
	time_t			 committer_time;
};

struct got_repository;
struct transport {
	TAILQ_HEAD(repo_commits_head, repo_commit)	 repo_commits;
	TAILQ_HEAD(repo_tags_head, repo_tag)		 repo_tags;
	struct got_reflist_head	 refs;
	struct got_repository	*repo;
	struct repo_dir		*repo_dir;
	const struct querystring *qs;
	char			*more_id;
	char			*tags_more_id;
	unsigned int		 repos_total;
	unsigned int		 next_disp;
	unsigned int		 prev_disp;
	const struct got_error	*error;
	struct got_blob_object	*blob;
	int			 fd;
	FILE			*fp;
	struct dirent		**repos;
	int			 nrepos;
};

enum socket_priv_fds {
	DIFF_FD_1,
	DIFF_FD_2,
	DIFF_FD_3,
	DIFF_FD_4,
	DIFF_FD_5,
	BLAME_FD_1,
	BLAME_FD_2,
	BLAME_FD_3,
	BLAME_FD_4,
	BLAME_FD_5,
	BLAME_FD_6,
	BLOB_FD_1,
	BLOB_FD_2,
	PRIV_FDS__MAX,
};

struct gotwebd_fcgi_record {
	uint32_t			 request_id;
	uint8_t				 record[FCGI_RECORD_SIZE];
	size_t				 record_len;
};

enum query_actions {
	NO_ACTION = 0,
	BLAME,
	BLOB,
	BLOBRAW,
	BRIEFS,
	COMMITS,
	DIFF,
	ERR,
	INDEX,
	PATCH,
	SUMMARY,
	TAG,
	TAGS,
	TREE,
	RSS,
};

struct querystring {
	enum query_actions action;
	char		 commit[GOT_OBJECT_ID_HEX_MAXLEN];
	char		 file[NAME_MAX];
	char		 folder[PATH_MAX];
	char		 headref[MAX_DOCUMENT_URI];
	int		 index_page;
	char		 path[PATH_MAX];
	char		 login[MAX_AUTH_COOKIE];
};

struct gotwebd_fcgi_params {
	uint32_t			 request_id;
	struct querystring		 qs;
	char				 document_uri[MAX_DOCUMENT_URI];
	char				 server_name[MAX_SERVER_NAME];
	char				 auth_cookie[MAX_AUTH_COOKIE];
	int				 https;
};

struct template;
struct request {
	TAILQ_ENTRY(request)		entry;
	struct socket			*sock;
	struct server			*srv;
	struct transport		*t;
	struct template			*tp;
	struct event			 ev;
	struct event			 tmo;

	uint16_t			 id;
	int				 fd;
	int				 priv_fd[PRIV_FDS__MAX];
	int				 sock_id;
	uint32_t			 request_id;
	int				 worker_idx;

	uint8_t				 *buf;
	size_t				 buf_len;

	uint8_t				 *outbuf;

	struct gotwebd_fcgi_params	 fcgi_params;
	int				 nparams;
	int				 nparams_parsed;

	int				 client_status;

	uid_t				 client_uid;
	char				 access_identifier[MAX_IDENTIFIER_SIZE];
};
TAILQ_HEAD(requestlist, request);

struct fcgi_begin_request_body {
	uint16_t	role;
	uint8_t		flags;
	uint8_t		reserved[5];
}__attribute__((__packed__));

struct fcgi_end_request_body {
	uint32_t	app_status;
	uint8_t		protocol_status;
	uint8_t		reserved[3];
}__attribute__((__packed__));

struct address {
	TAILQ_ENTRY(address)	 entry;
	struct sockaddr_storage	 ss;
	socklen_t		 slen;
	int			 ai_family;
	int			 ai_socktype;
	int			 ai_protocol;
	in_port_t		 port;
	char			 ifname[IFNAMSIZ];
};
TAILQ_HEAD(addresslist, address);

enum gotwebd_auth_config {
	GOTWEBD_AUTH_DISABLED	= 0xf00000ff,
	GOTWEBD_AUTH_SECURE	= 0x00808000,
	GOTWEBD_AUTH_INSECURE	= 0x0f7f7f00
};

enum gotwebd_access {
	GOTWEBD_ACCESS_NO_MATCH = -2,
	GOTWEBD_ACCESS_DENIED = -1,
	GOTWEBD_ACCESS_PERMITTED = 1
};

struct gotwebd_access_rule {
	STAILQ_ENTRY(gotwebd_access_rule) entry;

	enum gotwebd_access access;
	char identifier[MAX_IDENTIFIER_SIZE];
};
STAILQ_HEAD(gotwebd_access_rule_list, gotwebd_access_rule);

struct gotwebd_repo {
	TAILQ_ENTRY(gotwebd_repo)	 entry;

	char name[NAME_MAX];

	enum gotwebd_auth_config	auth_config;
	struct gotwebd_access_rule_list access_rules;

	int				hidden;
};
TAILQ_HEAD(gotwebd_repolist, gotwebd_repo);

struct website {
	STAILQ_ENTRY(website) entry;
	char repo_name[NAME_MAX];
	char url_path[MAX_DOCUMENT_URI];
	char branch_name[MAX_BRANCH_NAME];
	char path[PATH_MAX];
};

struct server {
	TAILQ_ENTRY(server)	 entry;

	char		 name[GOTWEBD_MAXTEXT];
	char		 htdocs_path[PATH_MAX];
	char		 gotweb_url_root[MAX_DOCUMENT_URI];

	char		 repos_path[PATH_MAX];
	char		 repos_url_path[MAX_DOCUMENT_URI];
	char		 full_repos_url_path[MAX_DOCUMENT_URI * 2 + 2];
	char		 site_name[GOTWEBD_MAXNAME];
	char		 site_owner[GOTWEBD_MAXNAME];
	char		 site_link[GOTWEBD_MAXTEXT];
	char		 logo[GOTWEBD_MAXTEXT];
	char		 logo_url[GOTWEBD_MAXTEXT];
	char		 custom_css[PATH_MAX];
	char		 login_hint_user[MAX_IDENTIFIER_SIZE];

	size_t		 max_repos_display;
	size_t		 max_commits_display;
	size_t		 summary_commits_display;
	size_t		 summary_tags_display;

	int		 show_site_owner;
	int		 show_repo_owner;
	int		 show_repo_age;
	int		 show_repo_description;
	int		 show_repo_cloneurl;
	int		 respect_exportok;
	int		 hide_repositories;

	enum gotwebd_auth_config auth_config;
	struct gotwebd_access_rule_list access_rules;

	struct gotwebd_repolist	 repos;
	struct got_pathlist_head websites;
};
TAILQ_HEAD(serverlist, server);

enum client_action {
	CLIENT_CONNECT,
	CLIENT_FCGI_BEGIN,
	CLIENT_FCGI_PARAMS,
	CLIENT_FCGI_STDIN,
	CLIENT_REQUEST,
	CLIENT_DISCONNECT,
};

struct socket_conf {
	struct address	 addr;

	int		 id;
	int		 af_type;
	char		 unix_socket_name[PATH_MAX];
	in_port_t	 fcgi_socket_port;
};

struct socket {
	TAILQ_ENTRY(socket)	 entry;
	struct socket_conf	 conf;

	int		 fd;
	struct event	 evt;
	struct event	 ev;
	struct event	 pause;
};
TAILQ_HEAD(socketlist, socket);

struct passwd;
struct gotwebd {
	struct serverlist	servers;
	struct socketlist	sockets;
	struct addresslist	addresses;

	struct socket	*login_sock;
	struct event	 login_pause_ev;

	enum gotwebd_auth_config auth_config;
	struct gotwebd_access_rule_list access_rules;

	struct mediatypes mediatypes;

	int		 pack_fds[GOTWEB_PACK_NUM_TEMPFILES];
	int		 priv_fd[PRIV_FDS__MAX];

	char		*user;
	char		*www_user;
	const char	*gotwebd_conffile;

	int		 gotwebd_debug;
	int		 gotwebd_verbose;

	struct imsgev	*iev_parent;
	struct imsgev	*iev_sockets;
	struct imsgev	*iev_fcgi;
	struct imsgev	*iev_login;
	struct imsgev	*iev_gotsh;
	struct imsgev	*iev_auth;
	struct imsgev	*iev_gotweb;

	uint16_t	 prefork;
	int		 auth_pending;
	int		 gotweb_pending;
	int		 *worker_load;

	char		 httpd_chroot[PATH_MAX];
	char		 htdocs_path[PATH_MAX];
	char		 gotweb_url_root[MAX_DOCUMENT_URI];
	char		 repos_url_path[MAX_DOCUMENT_URI];
	uid_t		 www_uid;

	char		 login_hint_user[MAX_IDENTIFIER_SIZE];
};

/*
 * URL parameter for gotweb_render_url.  NULL values and int set to -1
 * are implicitly ignored, and string are properly escaped.
 */
struct gotweb_url {
	int		 action;
	int		 index_page;
	const char	*commit;
	const char	*file;
	const char	*folder;
	const char	*headref;
	const char	*path;
};

struct querystring_keys {
	const char	*name;
	int		 element;
};

struct action_keys {
	const char	*name;
	int		 action;
};

enum querystring_elements {
	ACTION,
	COMMIT,
	RFILE,
	FOLDER,
	HEADREF,
	INDEX_PAGE,
	PATH,
	LOGIN,
};

extern struct gotwebd	*gotwebd_env;

typedef int (*got_render_blame_line_cb)(struct template *, const char *,
    struct blame_line *, int, int);

/* gotwebd.c */
void	 imsg_event_add(struct imsgev *);
int	 imsg_compose_event(struct imsgev *, uint16_t, uint32_t,
	    pid_t, int, const void *, size_t);
int	 main_compose_sockets(struct gotwebd *, uint32_t, int,
	    const void *, uint16_t);
int	 main_compose_login(struct gotwebd *, uint32_t, int,
	    const void *, uint16_t);
int	 sockets_compose_main(struct gotwebd *, uint32_t,
	    const void *, uint16_t);
int	 main_compose_auth(struct gotwebd *, uint32_t, int,
	    const void *, uint16_t);
int	 main_compose_gotweb(struct gotwebd *, uint32_t, int,
	    const void *, uint16_t);

/* sockets.c */
void sockets(struct gotwebd *, int);
void sockets_parse_sockets(struct gotwebd *);
void sockets_socket_accept(int, short, void *);
struct socket *sockets_conf_new_socket(int, struct address *);
int sockets_privinit(struct gotwebd *, struct socket *, uid_t, gid_t);
void sockets_rlimit(int);

/* login.c */
char *login_gen_token(uint64_t, const char *, time_t, const char *, size_t,
    const char *);
int login_check_token(uid_t *, char **, const char *, const char *, size_t,
    const char *);
int login_privinit(struct gotwebd *, uid_t, gid_t);
void gotwebd_login(struct gotwebd *, int);

/* auth.c */
void gotwebd_auth(struct gotwebd *, int);

/* gotweb.c */
struct server *gotweb_get_server(const char *);
struct website *gotweb_get_website(struct server *, const char *);
struct gotwebd_repo * gotweb_get_repository(struct server *, const char *);
int gotweb_reply(struct request *c, int status, const char *ctype,
    struct gotweb_url *);
void gotweb_index_navs(struct request *, struct gotweb_url *, int *,
    struct gotweb_url *, int *);
int gotweb_render_age(struct template *, time_t);
const struct got_error *gotweb_init_transport(struct transport **);
const char *gotweb_action_name(int);
int gotweb_render_url(struct request *, struct gotweb_url *);
int gotweb_render_absolute_url(struct request *, struct gotweb_url *);
void gotweb_free_repo_commit(struct repo_commit *);
void gotweb_free_repo_tag(struct repo_tag *);
void gotweb_log_request(struct request *);
const struct got_error *gotweb_serve_htdocs(struct request *, const char *);
const struct got_error *gotweb_route_request(int *, struct website **,
    char **, struct request *);
int gotweb_process_request(struct request *);
void gotweb_free_transport(struct transport *);
void gotweb(struct gotwebd *, int);

/* pages.tmpl */
int	gotweb_render_page(struct template *, int (*)(struct template *));
int	gotweb_render_error(struct template *);
int	gotweb_render_repo_table_hdr(struct template *);
int	gotweb_render_repo_fragment(struct template *, struct repo_dir *);
int	gotweb_render_briefs(struct template *);
int	gotweb_render_navs(struct template *);
int	gotweb_render_commits(struct template *);
int	gotweb_render_blob(struct template *);
int	gotweb_render_tree(struct template *);
int	gotweb_render_tags(struct template *);
int	gotweb_render_tag(struct template *);
int	gotweb_render_diff(struct template *);
int	gotweb_render_branches(struct template *, struct got_reflist_head *);
int	gotweb_render_summary(struct template *);
int	gotweb_render_blame(struct template *);
int	gotweb_render_patch(struct template *);
int	gotweb_render_rss(struct template *);
int	gotweb_render_unauthorized(struct template *);

/* parse.y */
struct gotwebd_repo * gotwebd_new_repo(const char *);
int parse_config(const char *, struct gotwebd *);
int cmdline_symset(char *);

/* fcgi.c */
void fcgi_init_querystring(struct querystring *);
void fcgi_cleanup_request(struct request *);
void fcgi_create_end_record(struct request *);
int fcgi_write(void *, const void *, size_t);
void gotwebd_fcgi(struct gotwebd *, int);

/* got_operations.c */
const struct got_error *got_gotweb_closefile(FILE *);
const struct got_error *got_get_repo_owner(char **, struct request *);
const struct got_error *got_get_repo_age(time_t *, struct request *,
    const char *);
const struct got_error *got_get_repo_commits(struct request *, size_t);
const struct got_error *got_get_repo_tags(struct request *, size_t);
const struct got_error *got_get_repo_heads(struct request *);
const struct got_error *got_open_diff_for_output(FILE **, struct request *);
int got_output_repo_tree(struct request *, char **,
    int (*)(struct template *, struct got_tree_entry *));
const struct got_error *got_open_blob_for_output(struct got_blob_object **,
    int *, int *, struct request *, const char *, const char *, const char *);
int got_output_blob_by_lines(struct template *, struct got_blob_object *,
    int (*)(struct template *, const char *, size_t));
const struct got_error *got_output_file_blame(struct request *,
    got_render_blame_line_cb);

/* config.c */
int config_setserver(struct gotwebd *, struct server *);
int config_getmediatype(struct gotwebd *, struct imsg *);
int config_getserver(struct gotwebd *, struct imsg *);
int config_setsock(struct gotwebd *, struct socket *, uid_t, gid_t);
int config_getsock(struct gotwebd *, struct imsg *);
int config_setfd(struct gotwebd *);
int config_getfd(struct gotwebd *, struct imsg *);
int config_getcfg(struct gotwebd *, struct imsg *);
void config_set_access_rules(struct imsgev *,
    struct gotwebd_access_rule_list *);
void config_get_access_rule(struct gotwebd_access_rule_list *, struct imsg *);
void config_free_access_rules(struct gotwebd_access_rule_list *);
void config_set_repository(struct imsgev *, struct gotwebd_repo *);
void config_get_repository(struct gotwebd_repolist *, struct imsg *);
void config_free_repos(struct gotwebd_repolist *);
void config_free_websites(struct got_pathlist_head *);
void config_set_website(struct imsgev *, struct website *);
void config_get_website(struct got_pathlist_head *, struct imsg *);
int config_init(struct gotwebd *);
