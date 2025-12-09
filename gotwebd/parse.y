/*
 * Copyright (c) 2016-2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>
#include <sha1.h>
#include <sha2.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"
#include "got_error.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	unsigned char		*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
static int	 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

static int		 errors;

static struct gotwebd		*gotwebd;
static struct server		*new_srv;
static struct server		*conf_new_server(const char *);
int				 getservice(const char *);
int				 n;
struct media_type		 media;

int		 get_addrs(const char *, const char *);
struct address *get_unix_addr(const char *);
int		 addr_dup_check(struct addresslist *, struct address *);
void		 add_addr(struct address *);

static struct website	*new_website;
static struct website	*conf_new_website(struct server *, const char *);

static struct gotwebd_repo	*new_repo;
static struct gotwebd_repo	*conf_new_repo(struct server *, const char *);
static void			 conf_new_access_rule(
				    struct gotwebd_access_rule_list *,
				    enum gotwebd_access, char *);


typedef struct {
	union {
		long long	 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

static int
mediatype_ok(const char *s)
{
	size_t i;

	for (i = 0; s[i] != '\0'; ++i) {
		if (!isalnum((unsigned char)s[i]) &&
		    s[i] != '-' && s[i] != '+' && s[i] != '.' &&
		    s[i] != '/')
			return (-1);
	}
	return (0);
}

%}

%token	LISTEN GOTWEBD_LOGIN WWW SITE_NAME SITE_OWNER SITE_LINK LOGO
%token	LOGO_URL SHOW_REPO_OWNER SHOW_REPO_AGE SHOW_REPO_DESCRIPTION
%token	MAX_REPOS_DISPLAY REPOS_PATH MAX_COMMITS_DISPLAY ON ERROR
%token	SHOW_SITE_OWNER SHOW_REPO_CLONEURL PORT PREFORK RESPECT_EXPORTOK
%token	SERVER CHROOT CUSTOM_CSS SOCKET HINT HTDOCS GOTWEB_URL_ROOT
%token	SUMMARY_COMMITS_DISPLAY SUMMARY_TAGS_DISPLAY USER AUTHENTICATION
%token	ENABLE DISABLE INSECURE REPOSITORY REPOSITORIES PERMIT DENY HIDE
%token	WEBSITE PATH BRANCH REPOS_URL_PATH
%token	TYPES INCLUDE

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	boolean
%type	<v.string>	listen_addr
%type	<v.string>	numberstring

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar server '\n'
		| grammar types '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

varset		: STRING '=' STRING	{
			char *s = $1;
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

numberstring	: STRING
		| NUMBER {
			if (asprintf(&$$, "%lld", (long long)$1) == -1) {
				yyerror("asprintf: %s", strerror(errno));
				YYERROR;
			}
		}
		;


boolean		: STRING {
			if (strcasecmp($1, "1") == 0 ||
			    strcasecmp($1, "on") == 0)
				$$ = 1;
			else if (strcasecmp($1, "0") == 0 ||
			    strcasecmp($1, "off") == 0)
				$$ = 0;
			else {
				yyerror("invalid boolean value '%s'", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		| ON { $$ = 1; }
		| NUMBER {
			if ($1 != 0 && $1 != 1) {
				yyerror("invalid boolean value '%lld'", $1);
				YYERROR;
			}
			$$ = $1;
		}
		;

listen_addr	: '*' { $$ = NULL; }
		| STRING
		;

main		: PREFORK NUMBER {
			if ($2 <= 0 || $2 > PROC_MAX_INSTANCES) {
				yyerror("prefork is %s: %lld",
				    $2 <= 0 ? "too small" : "too large", $2);
				YYERROR;
			}
			gotwebd->prefork = $2;
		}
		| CHROOT STRING {
			if (*$2 == '\0') {
				yyerror("chroot path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			n = strlcpy(gotwebd->httpd_chroot, $2,
			    sizeof(gotwebd->httpd_chroot));
			if (n >= sizeof(gotwebd->httpd_chroot)) {
				yyerror("chroot path too long: %s", $2);
				free($2);
				YYERROR;
			}
			if (gotwebd->httpd_chroot[0] != '/') {
				yyerror("chroot path must be an absolute path: "
				    "bad path %s", gotwebd->httpd_chroot);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LISTEN ON listen_addr PORT STRING {
			if (get_addrs($3, $5) == -1) {
				yyerror("could not get addrs");
				YYERROR;
			}
			free($3);
			free($5);
		}
		| LISTEN ON listen_addr PORT NUMBER {
			char portno[32];
			int n;

			n = snprintf(portno, sizeof(portno), "%lld",
			    (long long)$5);
			if (n < 0 || (size_t)n >= sizeof(portno))
				fatalx("port number too long: %lld",
				    (long long)$5);

			if (get_addrs($3, portno) == -1) {
				yyerror("could not get addrs");
				YYERROR;
			}
			free($3);
		}
		| LISTEN ON SOCKET STRING {
			struct address *h;

			h = get_unix_addr($4);
			if (h == NULL) {
				yyerror("can't listen on %s", $4);
				free($4);
				YYERROR;
			}
			add_addr(h);
			free($4);
		}
		| USER STRING {
			if (gotwebd->user != NULL)
				yyerror("user already specified");
			free(gotwebd->user);
			gotwebd->user = $2;
		}
		| WWW USER STRING {
			if (gotwebd->www_user != NULL)
				yyerror("www user already specified");
			free(gotwebd->www_user);
			gotwebd->www_user = $3;
		}
		| DISABLE AUTHENTICATION {
			if (gotwebd->auth_config != 0) {
				yyerror("ambiguous global authentication "
				    "setting");
				YYERROR;
			}
			gotwebd->auth_config = GOTWEBD_AUTH_DISABLED;
		}
		| ENABLE AUTHENTICATION {
			if (gotwebd->auth_config != 0) {
				yyerror("ambiguous global authentication "
				    "setting");
				YYERROR;
			}
			gotwebd->auth_config = GOTWEBD_AUTH_SECURE;
		}
		| ENABLE AUTHENTICATION INSECURE {
			if (gotwebd->auth_config != 0) {
				yyerror("ambiguous global authentication "
				    "setting");
				YYERROR;
			}
			gotwebd->auth_config = GOTWEBD_AUTH_INSECURE;
		}
		| PERMIT numberstring {
			conf_new_access_rule(&gotwebd->access_rules,
			    GOTWEBD_ACCESS_PERMITTED, $2);
		}
		| DENY numberstring {
			conf_new_access_rule(&gotwebd->access_rules,
			    GOTWEBD_ACCESS_DENIED, $2);
		}
		| GOTWEBD_LOGIN SOCKET STRING {
			struct address *h;
			h = get_unix_addr($3);
			if (h == NULL) {
				yyerror("can't listen on %s", $3);
				free($3);
				YYERROR;
			}
			if (gotwebd->login_sock != NULL)
				free(gotwebd->login_sock);
			gotwebd->login_sock = sockets_conf_new_socket(-1, h);
			free(h);
			free($3);
		}
		| GOTWEBD_LOGIN HINT USER STRING {
			n = strlcpy(gotwebd->login_hint_user, $4,
			    sizeof(gotwebd->login_hint_user));
			if (n >= sizeof(gotwebd->login_hint_user)) {
				yyerror("login hint user name too long, "
				    "exceeds %zd bytes",
				    sizeof(gotwebd->login_hint_user) - 1);
				free($4);
				YYERROR;
			}
			free($4);
		}
		| GOTWEBD_LOGIN HINT PORT NUMBER {
			int n;

			if ($4 < 1 || $4 > USHRT_MAX) {
				fatalx("port number invalid: %lld",
				    (long long)$4);
			}

			n = snprintf(gotwebd->login_hint_port,
			    sizeof(gotwebd->login_hint_port), "%lld",
			    (long long)$4);
			if (n < 0) {
				fatal("snprintf: port number %lld:",
				    (long long)$4);
			}
			if ((size_t)n >= sizeof(gotwebd->login_hint_port)) {
				fatalx("port number too long: %lld",
				    (long long)$4);
			}
		}
		| HTDOCS STRING {
			if (*$2 == '\0') {
				yyerror("htdocs path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			n = strlcpy(gotwebd->htdocs_path, $2,
			    sizeof(gotwebd->htdocs_path));
			if (n >= sizeof(gotwebd->htdocs_path)) {
				yyerror("htdocs path too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| GOTWEB_URL_ROOT STRING {
			if (*$2 == '\0') {
				yyerror("gotweb_url_root can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			if (!got_path_is_root_dir($2))
				got_path_strip_trailing_slashes($2);

			n = strlcpy(gotwebd->gotweb_url_root, $2,
			    sizeof(gotwebd->gotweb_url_root));
			if (n >= sizeof(gotwebd->gotweb_url_root)) {
				yyerror("gotweb_url_root too long, exceeds "
				    "%zd bytes: %s",
				    sizeof(gotwebd->gotweb_url_root), $2);
				free($2);
				YYERROR;
			}

			if (gotwebd->gotweb_url_root[0] != '/') {
				yyerror("gotweb_url_root must be an absolute "
				    "path: bad path %s", $2);
				free($2);
				YYERROR;
			}


			free($2);
		}
		| REPOS_URL_PATH STRING {
			if (*$2 == '\0') {
				yyerror("repos_url_path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			if (!got_path_is_root_dir($2))
				got_path_strip_trailing_slashes($2);

			n = strlcpy(gotwebd->repos_url_path, $2,
			    sizeof(gotwebd->repos_url_path));
			if (n >= sizeof(gotwebd->repos_url_path)) {
				yyerror("repos_url_path too long, exceeds "
				    "%zd bytes: %s",
				    sizeof(gotwebd->repos_url_path), $2);
				free($2);
				YYERROR;
			}

			if (gotwebd->repos_url_path[0] != '/') {
				yyerror("repos_url_path must be an absolute "
				    "path: bad path %s", $2);
				free($2);
				YYERROR;
			}

			free($2);
		}
		;

server		: SERVER STRING {
			struct server *srv;

			TAILQ_FOREACH(srv, &gotwebd->servers, entry) {
				if (strcmp(srv->name, $2) == 0) {
					yyerror("server name exists '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			new_srv = conf_new_server($2);
			log_debug("adding server %s", $2);
			free($2);
		}
		| SERVER STRING {
			struct server *srv;

			TAILQ_FOREACH(srv, &gotwebd->servers, entry) {
				if (strcmp(srv->name, $2) == 0) {
					yyerror("server name exists '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			new_srv = conf_new_server($2);
			log_debug("adding server %s", $2);
			free($2);
		} '{' optnl serveropts2 '}' {
		}
		;

serveropts1	: REPOS_PATH STRING {
			n = strlcpy(new_srv->repos_path, $2,
			    sizeof(new_srv->repos_path));
			if (n >= sizeof(new_srv->repos_path)) {
				yyerror("%s: repos_path truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_NAME STRING {
			n = strlcpy(new_srv->site_name, $2,
			    sizeof(new_srv->site_name));
			if (n >= sizeof(new_srv->site_name)) {
				yyerror("%s: site_name truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_OWNER STRING {
			n = strlcpy(new_srv->site_owner, $2,
			    sizeof(new_srv->site_owner));
			if (n >= sizeof(new_srv->site_owner)) {
				yyerror("%s: site_owner truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_LINK STRING {
			n = strlcpy(new_srv->site_link, $2,
			    sizeof(new_srv->site_link));
			if (n >= sizeof(new_srv->site_link)) {
				yyerror("%s: site_link truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LOGO STRING {
			n = strlcpy(new_srv->logo, $2, sizeof(new_srv->logo));
			if (n >= sizeof(new_srv->logo)) {
				yyerror("%s: logo truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LOGO_URL STRING {
			n = strlcpy(new_srv->logo_url, $2,
			    sizeof(new_srv->logo_url));
			if (n >= sizeof(new_srv->logo_url)) {
				yyerror("%s: logo_url truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CUSTOM_CSS STRING {
			n = strlcpy(new_srv->custom_css, $2,
			    sizeof(new_srv->custom_css));
			if (n >= sizeof(new_srv->custom_css)) {
				yyerror("%s: custom_css truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SHOW_SITE_OWNER boolean {
			new_srv->show_site_owner = $2;
		}
		| SHOW_REPO_OWNER boolean {
			new_srv->show_repo_owner = $2;
		}
		| SHOW_REPO_AGE boolean {
			new_srv->show_repo_age = $2;
		}
		| SHOW_REPO_DESCRIPTION boolean {
			new_srv->show_repo_description = $2;
		}
		| SHOW_REPO_CLONEURL boolean {
			new_srv->show_repo_cloneurl = $2;
		}
		| RESPECT_EXPORTOK boolean {
			new_srv->respect_exportok = $2;
		}
		| HIDE REPOSITORIES boolean {
			new_srv->hide_repositories = $3;
		}
		| GOTWEBD_LOGIN HINT USER STRING {
			n = strlcpy(new_srv->login_hint_user, $4,
			    sizeof(new_srv->login_hint_user));
			if (n >= sizeof(new_srv->login_hint_user)) {
				yyerror("login hint user name too long, "
				    "exceeds %zd bytes",
				    sizeof(new_srv->login_hint_user) - 1);
				free($4);
				YYERROR;
			}
			free($4);
		}
		| GOTWEBD_LOGIN HINT PORT NUMBER {
			int n;

			if ($4 < 1 || $4 > USHRT_MAX) {
				fatalx("port number invalid: %lld",
				    (long long)$4);
			}

			n = snprintf(new_srv->login_hint_port,
			    sizeof(new_srv->login_hint_port), "%lld",
			    (long long)$4);
			if (n < 0) {
				fatal("snprintf: port number %lld:",
				    (long long)$4);
			}
			if ((size_t)n >= sizeof(new_srv->login_hint_port)) {
				fatalx("port number too long: %lld",
				    (long long)$4);
			}
		}
		| MAX_REPOS_DISPLAY NUMBER {
			if ($2 < 0) {
				yyerror("max_repos_display is too small: %lld",
				    $2);
				YYERROR;
			}
			new_srv->max_repos_display = $2;
		}
		| MAX_COMMITS_DISPLAY NUMBER {
			if ($2 <= 1) {
				yyerror("max_commits_display is too small:"
				    " %lld", $2);
				YYERROR;
			}
			new_srv->max_commits_display = $2;
		}
		| SUMMARY_COMMITS_DISPLAY NUMBER {
			if ($2 < 1) {
				yyerror("summary_commits_display is too small:"
				    " %lld", $2);
				YYERROR;
			}
			new_srv->summary_commits_display = $2;
		}
		| SUMMARY_TAGS_DISPLAY NUMBER {
			if ($2 < 1) {
				yyerror("summary_tags_display is too small:"
				    " %lld", $2);
				YYERROR;
			}
			new_srv->summary_tags_display = $2;
		}
		| DISABLE AUTHENTICATION {
			if (new_srv->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for server %s",
				    new_srv->name);
				YYERROR;
			}
			new_srv->auth_config = GOTWEBD_AUTH_DISABLED;
		}
		| ENABLE AUTHENTICATION {
			if (new_srv->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for server %s",
				    new_srv->name);
				YYERROR;
			}
			new_srv->auth_config = GOTWEBD_AUTH_SECURE;
		}
		| ENABLE AUTHENTICATION INSECURE {
			if (new_srv->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for server %s",
				    new_srv->name);
				YYERROR;
			}
			new_srv->auth_config = GOTWEBD_AUTH_INSECURE;
		}
		| PERMIT numberstring {
			conf_new_access_rule(&new_srv->access_rules,
			    GOTWEBD_ACCESS_PERMITTED, $2);
		}
		| DENY numberstring {
			conf_new_access_rule(&new_srv->access_rules,
			    GOTWEBD_ACCESS_DENIED, $2);
		}
		| HTDOCS STRING {
			if (*$2 == '\0') {
				yyerror("htdocs path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			n = strlcpy(new_srv->htdocs_path, $2,
			    sizeof(new_srv->htdocs_path));
			if (n >= sizeof(new_srv->htdocs_path)) {
				yyerror("htdocs path too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| GOTWEB_URL_ROOT STRING {
			if (*$2 == '\0') {
				yyerror("gotweb_url_root can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			if (!got_path_is_root_dir($2))
				got_path_strip_trailing_slashes($2);

			n = strlcpy(new_srv->gotweb_url_root, $2,
			    sizeof(new_srv->gotweb_url_root));
			if (n >= sizeof(new_srv->gotweb_url_root)) {
				yyerror("gotweb_url_root too long, exceeds "
				    "%zd bytes: %s",
				    sizeof(new_srv->gotweb_url_root), $2);
				free($2);
				YYERROR;
			}

			if (new_srv->gotweb_url_root[0] != '/') {
				yyerror("gotweb_url_root must be an absolute "
				    "path: bad path %s", $2);
				free($2);
				YYERROR;
			}

			free($2);
		}
		| REPOS_URL_PATH STRING {
			if (*$2 == '\0') {
				yyerror("repos_url_path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			if (!got_path_is_root_dir($2))
				got_path_strip_trailing_slashes($2);

			n = strlcpy(new_srv->repos_url_path, $2,
			    sizeof(new_srv->repos_url_path));
			if (n >= sizeof(new_srv->repos_url_path)) {
				yyerror("repos_url_path too long, exceeds "
				    "%zd bytes: %s",
				    sizeof(new_srv->repos_url_path), $2);
				free($2);
				YYERROR;
			}

			if (new_srv->repos_url_path[0] != '/') {
				yyerror("repos_url_path must be an absolute "
				    "path: bad path %s", $2);
				free($2);
				YYERROR;
			}

			free($2);
		}
		| repository
		| website
		;

serveropts2	: serveropts2 serveropts1 nl
		| serveropts1 optnl
		;

websiteopts2	: websiteopts2 websiteopts1 nl
		| websiteopts1 optnl

websiteopts1	: REPOSITORY STRING {
			n = strlcpy(new_website->repo_name, $2,
			    sizeof(new_website->repo_name));
			if (n >= sizeof(new_website->repo_name)) {
				yyerror("website repository name too long, "
				    "exceeds %zd bytes",
				    sizeof(new_website->repo_name) - 1);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| PATH STRING {
			n = strlcpy(new_website->path, $2,
			    sizeof(new_website->path));
			if (n >= sizeof(new_website->path)) {
				yyerror("website in-repository path too long, "
				    "exceeds %zd bytes",
				    sizeof(new_website->path) - 1);
				free($2);
				YYERROR;
			}

			if (new_website->path[0] != '/') {
				yyerror("a website path must be an absolute "
				    "path: bad path %s", $2);
				free($2);
				YYERROR;
			}

			free($2);
		}
		| BRANCH STRING {
			n = strlcpy(new_website->branch_name, $2,
			    sizeof(new_website->branch_name));
			if (n >= sizeof(new_website->branch_name)) {
				yyerror("website branch name too long, "
				    "exceeds %zd bytes",
				    sizeof(new_website->branch_name) - 1);
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

website		: WEBSITE STRING {
			new_website = conf_new_website(new_srv, $2);
			free($2);
		} '{' optnl websiteopts2 '}' {
		}
		;

repository	: REPOSITORY STRING {
			struct gotwebd_repo *repo;

			TAILQ_FOREACH(repo, &new_srv->repos, entry) {
				if (strcmp(repo->name, $2) == 0) {
					yyerror("duplicate repository "
					    "'%s' in server '%s'", $2,
					    new_srv->name);
					free($2);
					YYERROR;
				}
			}

			new_repo = conf_new_repo(new_srv, $2);
			free($2);
		} '{' optnl repoopts2 '}' {
		}
		;

repoopts2	: repoopts2 repoopts1 nl
		| repoopts1 optnl
		;

repoopts1	: DISABLE AUTHENTICATION {
			if (new_repo->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for repository %s",
				    new_repo->name);
				YYERROR;
			}
			new_repo->auth_config = GOTWEBD_AUTH_DISABLED;
		}
		| ENABLE AUTHENTICATION {
			if (new_repo->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for repository %s",
				    new_repo->name);
				YYERROR;
			}
			new_repo->auth_config = GOTWEBD_AUTH_SECURE;
		}
		| ENABLE AUTHENTICATION INSECURE {
			if (new_repo->auth_config != 0) {
				yyerror("ambiguous authentication "
				    "setting for repository %s",
				    new_repo->name);
				YYERROR;
			}
			new_repo->auth_config = GOTWEBD_AUTH_INSECURE;
		}
		| PERMIT numberstring {
			conf_new_access_rule(&new_repo->access_rules,
			    GOTWEBD_ACCESS_PERMITTED, $2);
		}
		| DENY numberstring {
			conf_new_access_rule(&new_repo->access_rules,
			    GOTWEBD_ACCESS_DENIED, $2);
		}
		| HIDE REPOSITORY boolean {
			new_repo->hidden = $3;
		}
		;

types		: TYPES	'{' optnl mediaopts_l '}'
		;

mediaopts_l	: mediaopts_l mediaoptsl nl
		| mediaoptsl nl
		;

mediaoptsl	: mediastring medianames_l optsemicolon
		| include
		;

mediastring	: STRING '/' STRING	{
			if (mediatype_ok($1) == -1 || mediatype_ok($3) != -1) {
				yyerror("malformed media type: %s/%s", $1, $3);
				free($1);
				free($3);
				YYERROR;
			}

			if (strlcpy(media.media_type, $1,
			    sizeof(media.media_type)) >=
			    sizeof(media.media_type) ||
			    strlcpy(media.media_subtype, $3,
			    sizeof(media.media_subtype)) >=
			    sizeof(media.media_subtype)) {
				yyerror("media type too long");
				free($1);
				free($3);
				YYERROR;
			}
			free($1);
			free($3);
		}
		;

medianames_l	: medianames_l medianamesl
		| medianamesl
		;

medianamesl	: numberstring				{
			if (mediatype_ok($1) == -1) {
				yyerror("malformed media name");
				free($1);
				YYERROR;
			}

			if (strlcpy(media.media_name, $1,
			    sizeof(media.media_name)) >=
			    sizeof(media.media_name)) {
				yyerror("media name too long");
				free($1);
				YYERROR;
			}
			free($1);

			if (media_add(&gotwebd->mediatypes, &media) == NULL) {
				yyerror("failed to add media type");
				YYERROR;
			}
		}
		;

nl		: '\n' optnl
		;

optsemicolon	: ';'
		| /* empty */
		;

optnl		: '\n' optnl		/* zero or more newlines */
		| /* empty */
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list ap;
	char *msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* This has to be sorted always. */
	static const struct keywords keywords[] = {
		{ "authentication",		AUTHENTICATION },
		{ "branch",			BRANCH },
		{ "chroot",			CHROOT },
		{ "custom_css",			CUSTOM_CSS },
		{ "deny",			DENY },
		{ "disable",			DISABLE },
		{ "enable",			ENABLE },
		{ "gotweb_url_root",		GOTWEB_URL_ROOT },
		{ "hide",			HIDE },
		{ "hint",			HINT },
		{ "htdocs",			HTDOCS },
		{ "include",			INCLUDE },
		{ "insecure",			INSECURE },
		{ "listen",			LISTEN },
		{ "login",			GOTWEBD_LOGIN },
		{ "logo",			LOGO },
		{ "logo_url",			LOGO_URL },
		{ "max_commits_display",	MAX_COMMITS_DISPLAY },
		{ "max_repos_display",		MAX_REPOS_DISPLAY },
		{ "on",				ON },
		{ "path",			PATH },
		{ "permit",			PERMIT },
		{ "port",			PORT },
		{ "prefork",			PREFORK },
		{ "repos_path",			REPOS_PATH },
		{ "repos_url_path",		REPOS_URL_PATH },
		{ "repositories",		REPOSITORIES },
		{ "repository",			REPOSITORY },
		{ "respect_exportok",		RESPECT_EXPORTOK },
		{ "server",			SERVER },
		{ "show_repo_age",		SHOW_REPO_AGE },
		{ "show_repo_cloneurl",		SHOW_REPO_CLONEURL },
		{ "show_repo_description",	SHOW_REPO_DESCRIPTION },
		{ "show_repo_owner",		SHOW_REPO_OWNER },
		{ "show_site_owner",		SHOW_SITE_OWNER },
		{ "site_link",			SITE_LINK },
		{ "site_name",			SITE_NAME },
		{ "site_owner",			SITE_OWNER },
		{ "socket",			SOCKET },
		{ "summary_commits_display",	SUMMARY_COMMITS_DISPLAY },
		{ "summary_tags_display",	SUMMARY_TAGS_DISPLAY },
		{ "types",			TYPES },
		{ "user",			USER },
		{ "website",			WEBSITE },
		{ "www",			WWW },
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return c;
}

int
lgetc(int quotec)
{
	int c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return EOF;
			return quotec;
		}
		return c;
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return '\n';
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return EOF;
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;
	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			fatal("reallocarray");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	unsigned char buf[8096];
	unsigned char *p, *val;
	int quotec, next, c;
	int token;

 top:
	p = buf;
	c = lgetc(0);
	while (c == ' ' || c == '\t')
		c = lgetc(0); /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#') {
		c = lgetc(0);
		while (c != '\n' && c != EOF)
			c = lgetc(0); /* nothing */
	}
	if (c == '$' && !expanding) {
		while (1) {
			c = lgetc(0);
			if (c == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			c = lgetc(quotec);
			if (c == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				next = lgetc(quotec);
				if (next == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
			c = lgetc(0);
		} while (c != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ',' && x != '/'))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
			c = lgetc(0);
		} while (c != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		token = lookup(buf);
		if (token == STRING) {
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL)
				err(1, "yylex: strdup");
		}
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file *nfile;

	nfile = calloc(1, sizeof(struct file));
	if (nfile == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	nfile->name = strdup(name);
	if (nfile->name == NULL) {
		log_warn("strdup");
		free(nfile);
		return (NULL);
	}
	nfile->stream = fopen(nfile->name, "r");
	if (nfile->stream == NULL) {
		/* no warning, we don't require a conf file */
		if (topfile != NULL)
			log_warn("can't open %s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = calloc(1, nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn("calloc");
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

static int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return file ? 0 : EOF;
}

static void
add_default_server(void)
{
	new_srv = conf_new_server(D_SITENAME);
	log_debug("%s: adding default server %s", __func__, D_SITENAME);
}

int
parse_config(const char *filename, struct gotwebd *env)
{
	struct sym *sym, *next;
	struct server *srv;
	struct gotwebd_repo *repo;

	if (config_init(env) == -1)
		fatalx("failed to initialize configuration");

	gotwebd = env;

	file = pushfile(filename, 0);
	if (file != NULL) {
		/* we don't require a config file */
		topfile = file;
		yyparse();
		errors = file->errors;
		while (popfile() != EOF)
			;
	}

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((gotwebd->gotwebd_verbose > 1) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not used\n",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	/* just add default server if no config specified */
	if (TAILQ_EMPTY(&gotwebd->servers))
		add_default_server();

	/* load default mimes */
	if (RB_EMPTY(&gotwebd->mediatypes)) {
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
			if (media_add(&gotwebd->mediatypes, &defaults[i]) == NULL) {
				fprintf(stderr, "failed to load default"
				    " MIME types\n");
				errors++;
				break;
			}
		}
	}

	/* add the implicit listen on socket */
	if (TAILQ_EMPTY(&gotwebd->addresses)) {
		char path[_POSIX_PATH_MAX];
		struct address *h;

		if (strlcpy(path, gotwebd->httpd_chroot, sizeof(path))
		    >= sizeof(path)) {
			yyerror("chroot path too long: %s",
			    gotwebd->httpd_chroot);
		}
		if (strlcat(path, D_UNIX_SOCKET, sizeof(path))
		    >= sizeof(path)) {
			yyerror("chroot path too long: %s",
			    gotwebd->httpd_chroot);
		}
		h = get_unix_addr(path);
		if (h == NULL)
			yyerror("can't listen on %s", path);
		else
			add_addr(h);
	}

	if (errors) {
		return (-1);
	}

	/* setup our listening sockets */
	sockets_parse_sockets(env);

	/* Add implicit login socket */
	if (gotwebd->login_sock == NULL) {
		struct address *h;
		h = get_unix_addr(GOTWEBD_LOGIN_SOCKET);
		if (h == NULL) {
			fprintf(stderr, "cannot listen on %s",
			    GOTWEBD_LOGIN_SOCKET);
			return (-1);
		}
		gotwebd->login_sock = sockets_conf_new_socket(-1, h);
		free(h);
	}

	/*
	 * Disable authentication if not explicitly configured.
	 * Authentication requires access rules to be configured, and we want
	 * gotwebd to work out of the box if no configuration file exists.
	 */
	switch (env->auth_config) {
	case GOTWEBD_AUTH_SECURE:
	case GOTWEBD_AUTH_INSECURE:
	case GOTWEBD_AUTH_DISABLED:
		break;
	default:
		env->auth_config = GOTWEBD_AUTH_DISABLED;
		break;
	}

	/* Inherit implicit configuration from parent scope. */
	TAILQ_FOREACH(srv, &env->servers, entry) {
		if (srv->auth_config == 0)
			srv->auth_config = env->auth_config;
		TAILQ_FOREACH(repo, &srv->repos, entry) {
			if (repo->auth_config == 0)
				repo->auth_config = srv->auth_config;
			if (repo->hidden == -1)
				repo->hidden = srv->hide_repositories;
		}

		if (srv->login_hint_user[0] == '\0') {
			if (strlcpy(srv->login_hint_user, env->login_hint_user,
			    sizeof(srv->login_hint_user)) >=
			    sizeof(srv->login_hint_user)) {
				yyerror("login hint user name too long, "
				    "exceeds %zd bytes",
				    sizeof(srv->login_hint_user) - 1);
			}
		}

		if (srv->login_hint_port[0] == '\0') {
			if (strlcpy(srv->login_hint_port, env->login_hint_port,
			    sizeof(srv->login_hint_port)) >=
			    sizeof(srv->login_hint_port)) {
				yyerror("login hint port number too long, "
				    "exceeds %zd bytes",
				    sizeof(srv->login_hint_port) - 1);
			}
		}

		if (srv->gotweb_url_root[0] == '\0') {
			if (strlcpy(srv->gotweb_url_root,
			    env->gotweb_url_root,
			    sizeof(srv->gotweb_url_root)) >=
			    sizeof(srv->gotweb_url_root)) {
				yyerror("gotweb_url_root too long, "
				    "exceeds %zd bytes",
				    sizeof(srv->gotweb_url_root) - 1);
			}
		}

		if (srv->repos_url_path[0] == '\0') {
			if (strlcpy(srv->repos_url_path,
			    env->repos_url_path,
			    sizeof(srv->repos_url_path)) >=
			    sizeof(srv->repos_url_path)) {
				yyerror("repos_url_path too long, "
				    "exceeds %zd bytes",
				    sizeof(srv->repos_url_path) - 1);
			}
		}
	}

	TAILQ_FOREACH(srv, &env->servers, entry) {
		const char *gotweb_url_root = srv->gotweb_url_root;
		const char *repos_url_path = srv->repos_url_path;
		struct got_pathlist_entry *pe;
		int ret;

		while (gotweb_url_root[0] == '/')
			gotweb_url_root++;

		while (repos_url_path[0] == '/')
			repos_url_path++;

		if (gotweb_url_root[0] == '\0' && repos_url_path[0] == '\0') {
			srv->full_repos_url_path[0] = '/';
			srv->full_repos_url_path[1] = '\0';
		} else {
			ret = snprintf(srv->full_repos_url_path,
			    sizeof(srv->full_repos_url_path),
			    "/%s%s%s", gotweb_url_root,
			    gotweb_url_root[0] ? "/" : "",
			    repos_url_path);
			if (ret == -1) {
				yyerror("snprintf");
			}
			if ((size_t)ret >= sizeof(srv->full_repos_url_path)) {
				yyerror("gotweb_url_root and "
				"repos_url_path too long, exceed %zd bytes",
				    sizeof(srv->full_repos_url_path) - 1);
			}
		}

		if (!got_path_is_root_dir(srv->full_repos_url_path)) {
			got_path_strip_trailing_slashes(
			    srv->full_repos_url_path);
		}

		RB_FOREACH(pe, got_pathlist_head, &srv->websites) {
			const char *url_path = pe->path;
			struct website *site = pe->data;

			if (site->repo_name[0] == '\0') {
				yyerror("no repository defined for website "
				    "'%s' on server %s", url_path, srv->name);
			}
		}
	}

	return (0);
}

struct server *
conf_new_server(const char *name)
{
	struct server *srv = NULL;

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		fatalx("%s: calloc", __func__);

	n = strlcpy(srv->name, name, sizeof(srv->name));
	if (n >= sizeof(srv->name))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->repos_path, gotwebd->httpd_chroot,
	    sizeof(srv->repos_path));
	if (n >= sizeof(srv->repos_path))
		fatalx("%s: strlcpy", __func__);
	n = strlcat(srv->repos_path, D_GOTPATH,
	    sizeof(srv->repos_path));
	if (n >= sizeof(srv->repos_path))
		fatalx("%s: strlcat", __func__);
	n = strlcpy(srv->htdocs_path, D_HTDOCS_PATH,
	    sizeof(srv->htdocs_path));
	if (n >= sizeof(srv->htdocs_path))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_name, D_SITENAME,
	    sizeof(srv->site_name));
	if (n >= sizeof(srv->site_name))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_owner, D_SITEOWNER,
	    sizeof(srv->site_owner));
	if (n >= sizeof(srv->site_owner))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_link, D_SITELINK,
	    sizeof(srv->site_link));
	if (n >= sizeof(srv->site_link))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->logo, D_GOTLOGO,
	    sizeof(srv->logo));
	if (n >= sizeof(srv->logo))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->logo_url, D_GOTURL, sizeof(srv->logo_url));
	if (n >= sizeof(srv->logo_url))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->custom_css, D_GOTWEBCSS, sizeof(srv->custom_css));
	if (n >= sizeof(srv->custom_css))
		fatalx("%s: strlcpy", __func__);

	srv->show_site_owner = D_SHOWSOWNER;
	srv->show_repo_owner = D_SHOWROWNER;
	srv->show_repo_age = D_SHOWAGE;
	srv->show_repo_description = D_SHOWDESC;
	srv->show_repo_cloneurl = D_SHOWURL;
	srv->respect_exportok = D_RESPECTEXPORTOK;
	srv->hide_repositories = D_HIDE_REPOSITORIES;

	srv->max_repos_display = D_MAXREPODISP;
	srv->max_commits_display = D_MAXCOMMITDISP;
	srv->summary_commits_display = D_MAXSLCOMMDISP;
	srv->summary_tags_display = D_MAXSLTAGDISP;

	STAILQ_INIT(&srv->access_rules);
	TAILQ_INIT(&srv->repos);
	RB_INIT(&srv->websites);

	TAILQ_INSERT_TAIL(&gotwebd->servers, srv, entry);

	return srv;
};

int
symset(const char *nam, const char *val, int persist)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	sym = calloc(1, sizeof(*sym));
	if (sym == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char *sym, *val;
	int ret;

	val = strrchr(s, '=');
	if (val == NULL)
		return (-1);

	sym = strndup(s, val - s);
	if (sym == NULL)
		fatal("%s: strndup", __func__);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

int
get_addrs(const char *hostname, const char *servname)
{
	struct addrinfo hints, *res0, *res;
	int error;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct address *h;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	error = getaddrinfo(hostname, servname, &hints, &res0);
	if (error) {
		log_warnx("%s: could not parse \"%s:%s\": %s", __func__,
		    hostname, servname, gai_strerror(error));
		return (-1);
	}

	for (res = res0; res; res = res->ai_next) {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);

		if (hostname == NULL) {
			strlcpy(h->ifname, "*", sizeof(h->ifname));
		} else {
			if (strlcpy(h->ifname, hostname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: address truncated: %s",
				    __func__, hostname);
				freeaddrinfo(res0);
				free(h);
				return (-1);
			}
		}

		h->ai_family = res->ai_family;
		h->ai_socktype = res->ai_socktype;
		h->ai_protocol = res->ai_protocol;
		memcpy(&h->ss, res->ai_addr, res->ai_addrlen);
		h->slen = res->ai_addrlen;

		switch (res->ai_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)res->ai_addr;
			h->port = ntohs(sin->sin_port);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)res->ai_addr;
			h->port = ntohs(sin6->sin6_port);
			break;
		default:
			fatalx("unknown address family %d", res->ai_family);
		}

		add_addr(h);
	}
	freeaddrinfo(res0);
	return (0);
}

struct address *
get_unix_addr(const char *path)
{
	struct address *h;
	struct sockaddr_un *sun;

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal("%s: calloc", __func__);

	h->ai_family = AF_UNIX;
	h->ai_socktype = SOCK_STREAM;
	h->ai_protocol = PF_UNSPEC;
	h->slen = sizeof(*sun);

	sun = (struct sockaddr_un *)&h->ss;
	sun->sun_family = AF_UNIX;
	if (strlcpy(sun->sun_path, path, sizeof(sun->sun_path)) >=
	    sizeof(sun->sun_path)) {
		log_warnx("socket path too long: %s", sun->sun_path);
		return NULL;
	}

	return h;
}

int
addr_dup_check(struct addresslist *al, struct address *h)
{
	struct address *a;

	TAILQ_FOREACH(a, al, entry) {
		if (a->ai_family != h->ai_family ||
		    a->ai_socktype != h->ai_socktype ||
		    a->ai_protocol != h->ai_protocol ||
		    a->slen != h->slen ||
		    memcmp(&a->ss, &h->ss, a->slen) != 0)
			continue;
		return -1;
	}

	return 0;
}

void
add_addr(struct address *h)
{
	if (addr_dup_check(&gotwebd->addresses, h) == 0) {
		TAILQ_INSERT_TAIL(&gotwebd->addresses, h, entry);
		return;
	}

	free(h);
}

static struct website *
conf_new_website(struct server *server, const char *url_path)
{
	const struct got_error *error;
	struct website *site;
	struct got_pathlist_entry *new;

	if (url_path[0] == '\0') {
		fatalx("syntax error: empty URL path found in %s",
		    file->name);
	}

	if (strchr(url_path, '\n') != NULL)
		fatalx("URL path must not contain linefeeds: %s", url_path);
	
	site = calloc(1, sizeof(*site));
	if (site == NULL)
		fatal("calloc");

	if (!got_path_is_absolute(url_path)) {
		int ret;

		ret = snprintf(site->url_path, sizeof(site->url_path),
		    "/%s", url_path);
		if (ret == -1)
			fatal("snprintf");
		if ((size_t)ret >= sizeof(site->url_path)) {
			fatalx("URL path too long (exceeds %zd bytes): %s",
			    sizeof(site->url_path) - 1, url_path);
		}
	} else {
		if (strlcpy(site->url_path, url_path,
		    sizeof(site->url_path)) >=
		    sizeof(site->url_path)) {
			fatalx("URL path too long (exceeds %zd bytes): %s",
			    sizeof(site->url_path) - 1, url_path);
		}
	}

	error = got_pathlist_insert(&new, &server->websites,
	    site->url_path, site);
	if (error)
		fatalx("%s: %s", __func__, error->msg);
	if (new == NULL) {
		fatalx("duplicate web site '%s' in server '%s'",
		    url_path, server->name);
	}

	return site;
}

struct gotwebd_repo *
gotwebd_new_repo(const char *name)
{
	struct gotwebd_repo *repo;

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		return NULL;

	STAILQ_INIT(&repo->access_rules);

	if (strlcpy(repo->name, name, sizeof(repo->name)) >=
	    sizeof(repo->name)) {
		free(repo);
		errno = ENOSPC;
		return NULL;
	}

	return repo;
}

static struct gotwebd_repo *
conf_new_repo(struct server *server, const char *name)
{
	struct gotwebd_repo *repo;

	if (name[0] == '\0') {
		fatalx("syntax error: empty repository name found in %s",
		    file->name);
	}

	if (strchr(name, '/') != NULL)
		fatalx("repository names must not contain slashes: %s", name);

	if (strchr(name, '\n') != NULL)
		fatalx("repository names must not contain linefeeds: %s", name);

	repo = gotwebd_new_repo(name);
	if (repo == NULL)
		fatal("gotwebd_new_repo");

	repo->hidden = -1;
	TAILQ_INSERT_TAIL(&server->repos, repo, entry);

	return repo;
};

static void
conf_new_access_rule(struct gotwebd_access_rule_list *rules,
    enum gotwebd_access access, char *identifier)
{
	struct gotwebd_access_rule *rule;

	rule = calloc(1, sizeof(*rule));
	if (rule == NULL)
		fatal("calloc");

	rule->access = access;
	if (strlcpy(rule->identifier, identifier,
	    sizeof(rule->identifier)) >= sizeof(rule->identifier))
		fatalx("identifier too long (max %zu bytes): %s",
		    sizeof(rule->identifier) - 1, identifier);

	STAILQ_INSERT_TAIL(rules, rule, entry);
}
