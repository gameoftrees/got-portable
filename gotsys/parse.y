/*
 * Copyright (c) 2022, 2025 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2016-2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <err.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_reference.h"

#include "log.h"
#include "gotsys.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct file {
	FILE			*stream;
	const char		*name;
	size_t	 		 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
} *file;
static const struct got_error*	newfile(struct file**, const char *, int *);
static void	 closefile(struct file *);
int		 yyparse(void);
int		 yylex(void);
void		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

static const struct got_error	*gerror;

static struct gotsys_conf	*gotsysconf;
static struct gotsys_repo	*new_repo;
static struct gotsys_user	*new_user;
static const struct got_error	*conf_new_repo(struct gotsys_repo **,
				    const char *);
static const struct got_error	*conf_user_password(char *,
				    struct gotsys_user *user);
static int			 conf_protect_ref_namespace(char **,
				    struct got_pathlist_head *, char *);
static int			 conf_protect_tag_namespace(
				    struct gotsys_repo *, char *);
static int			 conf_protect_branch_namespace(
				    struct gotsys_repo *, char *);
static int			 conf_protect_branch(struct gotsys_repo *,
				    char *);
static int			 conf_notify_branch(struct gotsys_repo *,
				    char *);
static int			 conf_notify_ref_namespace(struct gotsys_repo *,
				    char *);
static int			 conf_notify_email(struct gotsys_repo *,
				    char *, char *, char *, char *, char *);
static int			 conf_notify_http(struct gotsys_repo *,
				    char *, char *, char *, int, char *);

typedef struct {
	union {
		long long	 number;
		char		*string;
		struct timeval	 tv;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	ERROR USER GROUP REPOSITORY PERMIT DENY RO RW AUTHORIZED KEY
%token	PROTECT NAMESPACE BRANCH TAG REFERENCE PORT PASSWORD
%token	NOTIFY EMAIL FROM REPLY TO URL INSECURE HMAC HEAD

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.string>	numberstring

%%

grammar		:
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar repository '\n'
		;

numberstring	: STRING
		| NUMBER {
			if (asprintf(&$$, "%lld", (long long)$1) == -1) {
				yyerror("asprintf: %s", strerror(errno));
				YYERROR;
			}
		}
		;

main		: USER STRING {
			struct gotsys_user *user;
			const struct got_error *err = NULL;

			STAILQ_FOREACH(user, &gotsysconf->users, entry) {
				if (strcmp(user->name, $2) == 0) {
					yyerror("duplicate user '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			err = gotsys_conf_validate_name($2, "user");
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}

			err = gotsys_conf_new_user(&new_user, $2);
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}
			free($2);
			STAILQ_INSERT_TAIL(&gotsysconf->users, new_user, entry);
		} '{' optnl useropts2 '}' {
		}
		| GROUP STRING {
			const struct got_error *err;
			struct gotsys_group *group;

			STAILQ_FOREACH(group, &gotsysconf->groups, entry) {
				if (strcmp(group->name, $2) == 0) {
					yyerror("duplicate group '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			err = gotsys_conf_validate_name($2, "group");
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}

			err = gotsys_conf_new_group(&group, $2);
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}
			STAILQ_INSERT_TAIL(&gotsysconf->groups, group, entry);
			free($2);
		}
		;

useropts1	: GROUP STRING {
			if (new_user) {
				const struct got_error *err;

				err = gotsys_conf_new_group_member(
				    &gotsysconf->groups, $2, new_user->name);
				if (err) {
					yyerror("%s", err->msg);
					free($2);
					YYERROR;
				}
			}
		}
		| PASSWORD STRING {
			if (new_user) {
				const struct got_error *err;

				err = conf_user_password($2, new_user);
				if (err) {
					yyerror("%s", err->msg);
					free($2);
					YYERROR;
				}
			}
		}
		| AUTHORIZED KEY STRING STRING {
			if (new_user) {
				const struct got_error *err;

				err = conf_user_authorized_key($3, $4, NULL,
				    new_user);
				if (err) {
					yyerror("%s", err->msg);
					free($3);
					free($4);
					YYERROR;
				}
			}
		}
		| AUTHORIZED KEY STRING STRING STRING {
			if (new_user) {
				const struct got_error *err;

				err = conf_user_authorized_key($3, $4, $5,
				    new_user);
				if (err) {
					yyerror("%s", err->msg);
					free($3);
					free($4);
					free($5);
					YYERROR;
				}
			}
		}
		;

useropts2	: useropts2 useropts1 nl
		| useropts1 optnl
		;

protect		: PROTECT '{' optnl protectflags_l '}'
		| PROTECT protectflags

protectflags_l	: protectflags optnl protectflags_l
		| protectflags optnl
		;

protectflags	: TAG NAMESPACE STRING {
			if (conf_protect_tag_namespace(new_repo, $3)) {
				free($3);
				YYERROR;
			}
			free($3);
		}
		| BRANCH NAMESPACE STRING {
			if (conf_protect_branch_namespace(new_repo,
			    $3)) {
				free($3);
				YYERROR;
			}
			free($3);
		}
		| BRANCH STRING {
			if (conf_protect_branch(new_repo, $2)) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

notify		: NOTIFY '{' optnl notifyflags_l '}'
		| NOTIFY notifyflags

notifyflags_l	: notifyflags optnl notifyflags_l
		| notifyflags optnl
		;

notifyflags	: BRANCH STRING {
			if (conf_notify_branch(new_repo, $2)) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		| REFERENCE NAMESPACE STRING {
			if (conf_notify_ref_namespace(new_repo, $3)) {
				free($3);
				YYERROR;
			}
			free($3);
		}
		| EMAIL TO STRING {
			if (conf_notify_email(new_repo, NULL, $3,
			    NULL, NULL, NULL)) {
				free($3);
				YYERROR;
			}
			free($3);
		}
		| EMAIL FROM STRING TO STRING {
			if (conf_notify_email(new_repo, $3, $5,
			    NULL, NULL, NULL)) {
				free($3);
				free($5);
				YYERROR;
			}
			free($3);
			free($5);
		}
		| EMAIL TO STRING REPLY TO STRING {
			if (conf_notify_email(new_repo, NULL, $3,
			    $6, NULL, NULL)) {
				free($3);
				free($6);
				YYERROR;
			}
			free($3);
			free($6);
		}
		| EMAIL FROM STRING TO STRING REPLY TO STRING {
			if (conf_notify_email(new_repo, $3, $5,
			    $8, NULL, NULL)) {
				free($3);
				free($5);
				free($8);
				YYERROR;
			}
			free($3);
			free($5);
			free($8);
		}
		| URL STRING {
			if (conf_notify_http(new_repo, $2, NULL, NULL, 0,
			    NULL)) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		| URL STRING USER STRING PASSWORD STRING {
			if (conf_notify_http(new_repo, $2, $4, $6, 0, NULL)) {
				free($2);
				free($4);
				free($6);
				YYERROR;
			}
			free($2);
			free($4);
			free($6);
		}
		| URL STRING USER STRING PASSWORD STRING INSECURE {
			if (conf_notify_http(new_repo, $2, $4, $6, 1, NULL)) {
				free($2);
				free($4);
				free($6);
				YYERROR;
			}
			free($2);
			free($4);
			free($6);
		}
		| URL STRING HMAC STRING {
			if (conf_notify_http(new_repo, $2, NULL, NULL, 0, $4)) {
				free($2);
				free($4);
				YYERROR;
			}
			free($2);
			free($4);
		}
		| URL STRING USER STRING PASSWORD STRING HMAC STRING {
			if (conf_notify_http(new_repo, $2, $4, $6, 0, $8)) {
				free($2);
				free($4);
				free($6);
				free($8);
				YYERROR;
			}
			free($2);
			free($4);
			free($6);
			free($8);
		}
		| URL STRING USER STRING PASSWORD STRING INSECURE HMAC STRING {
			if (conf_notify_http(new_repo, $2, $4, $6, 1, $9)) {
				free($2);
				free($4);
				free($6);
				free($9);
				YYERROR;
			}
			free($2);
			free($4);
			free($6);
			free($9);
		}
		;

repository	: REPOSITORY STRING {
			const struct got_error *err;
			struct gotsys_repo *repo;

			TAILQ_FOREACH(repo, &gotsysconf->repos, entry) {
				if (strcmp(repo->name, $2) == 0) {
					yyerror("duplicate repository '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			err = conf_new_repo(&new_repo, $2);
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}
			free($2);
		} '{' optnl repoopts2 '}' {
		}
		;

repoopts1	: PERMIT RO numberstring {
			const struct got_error *err;
			struct gotsys_access_rule *rule;

			err = gotsys_conf_new_access_rule(&rule,
			    GOTSYS_ACCESS_PERMITTED, GOTSYS_AUTH_READ, $3,
			    &gotsysconf->users, &gotsysconf->groups);
			if (err) {
				yyerror("%s", err->msg);
				free($3);
				YYERROR;
			}
			STAILQ_INSERT_TAIL(&new_repo->access_rules, rule,
			    entry);
			free($3);
		}
		| PERMIT RW numberstring {
			const struct got_error *err;
			struct gotsys_access_rule *rule;

			err = gotsys_conf_new_access_rule(&rule,
			    GOTSYS_ACCESS_PERMITTED,
			    GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE, $3,
			    &gotsysconf->users, &gotsysconf->groups);
			if (err) {
				yyerror("%s", err->msg);
				free($3);
				YYERROR;
			}
			STAILQ_INSERT_TAIL(&new_repo->access_rules, rule,
			    entry);
			free($3);
		}
		| DENY numberstring {
			const struct got_error *err;
			struct gotsys_access_rule *rule;

			err = gotsys_conf_new_access_rule(&rule,
			    GOTSYS_ACCESS_DENIED, 0, $2,
			    &gotsysconf->users, &gotsysconf->groups);
			if (err) {
				yyerror("%s", err->msg);
				free($2);
				YYERROR;
			}
			STAILQ_INSERT_TAIL(&new_repo->access_rules, rule,
			    entry);
			free($2);
		}
		| protect
		| notify
		;

repoopts2	: repoopts2 repoopts1 nl
		| repoopts1 optnl
		;

nl		: '\n' optnl
		;

optnl		: '\n' optnl		/* zero or more newlines */
		| /* empty */
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

void
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;
	char		*errstr = NULL;

	if (gerror != NULL)
		return;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1) {
		gerror = got_error_from_errno("vasprintf");
		return;
	}
	va_end(ap);

	if (asprintf(&errstr, "%s: line %d: %s", file->name, yylval.lineno,
	    msg) == -1) {
		gerror = got_error_from_errno("asprintf");
		return;
	}

	gerror = got_error_msg(GOT_ERR_PARSE_CONFIG, errstr);
	free(msg);
	free(errstr);
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
		{ "authorized",			AUTHORIZED },
		{ "branch",			BRANCH },
		{ "deny",			DENY },
		{ "email",			EMAIL },
		{ "from",			FROM },
		{ "group",			GROUP },
		{ "hmac",			HMAC },
		{ "insecure",			INSECURE },
		{ "key",			KEY },
		{ "namespace",			NAMESPACE },
		{ "notify",			NOTIFY },
		{ "password",			PASSWORD },
		{ "permit",			PERMIT },
		{ "port",			PORT },
		{ "protect",			PROTECT },
		{ "reference",			REFERENCE },
		{ "reply",			REPLY },
		{ "repository",			REPOSITORY },
		{ "ro",				RO },
		{ "rw",				RW },
		{ "tag",			TAG },
		{ "to",				TO },
		{ "url",			URL },
		{ "user",			USER },
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

unsigned char pushback_buffer[MAXPUSHBACK];
int pushback_index = 0;

int
lgetc(int quotec)
{
	int c, next;

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		c = getc(file->stream);
		if (c == EOF)
			yyerror("reached end of file while parsing "
			    "quoted string");
		return (c);
	}

	c = getc(file->stream);
	while (c == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
		c = getc(file->stream);
	}

	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);

	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
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
	unsigned char *p;
	int quotec, next, c;
	int token;

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
		if (yylval.v.string == NULL) {
			fprintf(stderr, "%s: strdup: %s", getprogname(),
			    strerror(errno));
			exit(1);
		}
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
	(isalnum((unsigned char)x) || \
	(ispunct((unsigned char)x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '#' && \
	x != ','))

	if (isalnum((unsigned char)c) || c == ':' || c == '_') {
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
			if (yylval.v.string == NULL) {
				fprintf(stderr, "%s: strdup: %s\n",
				    getprogname(), strerror(errno));
				exit(1);
			}
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

static const struct got_error*
newfile(struct file **nfile, const char *filename, int *fd)
{
	const struct got_error* error = NULL;

	(*nfile) = calloc(1, sizeof(struct file));
	if ((*nfile) == NULL)
		return got_error_from_errno("calloc");
	(*nfile)->stream = fdopen(*fd, "r");
	if ((*nfile)->stream == NULL) {
		error = got_error_from_errno("fdopen");
		free((*nfile));
		return error;
	}
	*fd = -1; /* Stream owns the file descriptor now. */
	(*nfile)->name = filename;
	(*nfile)->lineno = 1;
	(*nfile)->ungetsize = 16;
	(*nfile)->ungetbuf = malloc((*nfile)->ungetsize);
	if ((*nfile)->ungetbuf == NULL) {
		error = got_error_from_errno("malloc");
		fclose((*nfile)->stream);
		free((*nfile));
		return error;
	}
	return NULL;
}

static void
closefile(struct file *xfile)
{
	fclose(file->stream);
	free(file->ungetbuf);
	free(file);
}

const struct got_error *
gotsys_conf_parse(const char *filename, struct gotsys_conf *pgotsysconf,
    int *fd)
{
	const struct got_error *error;
	struct gotsys_user *user;
	struct gotsys_repo *repo;
	struct gotsys_access_rule *rule;

	gotsysconf = pgotsysconf;

	error = newfile(&file, filename, fd);
	if (error)
		return error;

	yyparse();
	closefile(file);

	if (gerror)
		return gerror;

	if (TAILQ_EMPTY(&gotsysconf->repos)) {
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "no repositories defined in configuration file");
	}


	if (STAILQ_EMPTY(&gotsysconf->users)) {
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "no users defined in configuration file");
	}

	STAILQ_FOREACH(user, &gotsysconf->users, entry) {
		if (user->name == NULL) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "unnamed user found in configuration");
		}

		if (user->password == NULL &&
		    STAILQ_EMPTY(&user->authorized_keys)) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "user %s cannot authenticate, no password and "
			    "no authorized ssh public keys were specified",
			    user->name);
		}
	}

	TAILQ_FOREACH(repo, &gotsysconf->repos, entry) {
		if (strcmp(repo->name, GOTSYS_SYSTEM_REPOSITORY_NAME) == 0 ||
		    strcmp(repo->name, GOTSYS_SYSTEM_REPOSITORY_NAME ".git")
		    == 0)
			break;
	}
	if (repo == NULL) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "no %s.git repository defined in configuration file",
		    GOTSYS_SYSTEM_REPOSITORY_NAME);
	}

	if (STAILQ_EMPTY(&repo->access_rules)) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "no access rules defined for repository %s.git",
		    GOTSYS_SYSTEM_REPOSITORY_NAME);
	}
	STAILQ_FOREACH(rule, &repo->access_rules, entry) {
		if (rule->authorization & GOTSYS_AUTH_WRITE)
			break;
	}
	if (rule == NULL) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "at least one user must have write access to "
		    "repository %s.git", GOTSYS_SYSTEM_REPOSITORY_NAME);
	}

	return NULL;
}

static const struct got_error *
conf_new_repo(struct gotsys_repo **repo, const char *name)
{
	const struct got_error *err;

	err = gotsys_conf_new_repo(repo, name);
	if (err)
		return err;

	TAILQ_INSERT_TAIL(&gotsysconf->repos, *repo, entry);
	gotsysconf->nrepos++;

	return NULL;
};

static const struct got_error *
conf_user_password(char *password, struct gotsys_user *user)
{
	const struct got_error *err = NULL;
	size_t len;

	if (user->password != NULL) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "duplicate password specified for user %s",
		    user->name);
	}

	len = strlen(password);
	if (len > _PASSWORD_LEN) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "%s's password is too long, exceeds %d bytes",
		    user->name, _PASSWORD_LEN);
	}

	err = gotsys_conf_validate_password(user->name, password);
	if (err)
		return err;

	user->password = password;

	return NULL;
}

static const struct got_error *
conf_user_authorized_key(char *keytype, char *keydata, char *comment,
    struct gotsys_user *user)
{
	const struct got_error *err;
	struct gotsys_authorized_key *key, *k;

	err = gotsys_conf_new_authorized_key(&key, keytype, keydata, comment);
	if (err)
		return err;

	STAILQ_FOREACH(k, &user->authorized_keys, entry) {
		if (strcmp(k->keytype, keytype) == 0 &&
		    strcmp(k->key, keydata) == 0) {
			gotsys_authorized_key_free(key);
			return NULL;
		}
	}

	STAILQ_INSERT_TAIL(&user->authorized_keys, key, entry);
	return NULL;
}

/*
 * Reference name restrictions specific to gotsys.conf.
 * Exclude symbols which could be used to escape from strings and write
 * arbitrary gotd.conf snippets. Also exclude whitespace because newlines
 * are relevant to the parser.
 */
int
gotsys_ref_name_is_valid(char *refname)
{
	const char *s;
	const char forbidden[] = { '\'', '"', '{' , '}', '=', '$', '#' };
	size_t i;

	s = refname;
	while (*s) {
		for (i = 0; i < nitems(forbidden); i++) {
			if (*s == forbidden[i])
				return 0;
		}
		if (isspace((unsigned char)s[0]))
			return 0;
		s++;
	}

	return 1;
}

static int
refname_is_valid(char *refname)
{
	if (strncmp(refname, "refs/", 5) != 0) {
		yyerror("reference name must begin with \"refs/\": %s",
		    refname);
		return 0;
	}

	if (!got_ref_name_is_valid(refname) ||
	    !gotsys_ref_name_is_valid(refname)) {
		yyerror("invalid reference name: %s", refname);
		return 0;
	}

	return 1;
}

static int
conf_protect_ref_namespace(char **new, struct got_pathlist_head *refs,
    char *namespace)
{
	const struct got_error *error;
	struct got_pathlist_entry *pe;
	char *s;

	*new = NULL;

	got_path_strip_trailing_slashes(namespace);
	if (!refname_is_valid(namespace))
		return -1;
	if (asprintf(&s, "%s/", namespace) == -1) {
		yyerror("asprintf: %s", strerror(errno));
		return -1;
	}

	error = got_pathlist_insert(&pe, refs, s, NULL);
	if (error || pe == NULL) {
		free(s);
		if (error)
			yyerror("got_pathlist_insert: %s", error->msg);
		else
			yyerror("duplicate protected namespace %s", namespace);
		return -1;
	}

	*new = s;
	return 0;
}

static int
conf_protect_tag_namespace(struct gotsys_repo *repo, char *namespace)
{
	struct got_pathlist_entry *pe;
	char *new;

	if (conf_protect_ref_namespace(&new, &repo->protected_tag_namespaces,
	    namespace) == -1)
		return -1;
	repo->nprotected_tag_namespaces++;

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_branch_namespaces) {
		if (strcmp(pe->path, new) == 0) {
			yyerror("duplicate protected namespace %s", namespace);
			return -1;
		}
	}

	return 0;
}

static int
conf_protect_branch_namespace(struct gotsys_repo *repo, char *namespace)
{
	struct got_pathlist_entry *pe;
	char *new;

	if (conf_protect_ref_namespace(&new,
	    &repo->protected_branch_namespaces, namespace) == -1)
		return -1;
	repo->nprotected_branch_namespaces++;

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_tag_namespaces) {
		if (strcmp(pe->path, new) == 0) {
			yyerror("duplicate protected namespace %s", namespace);
			return -1;
		}
	}

	return 0;
}

static int
conf_protect_branch(struct gotsys_repo *repo, char *branchname)
{
	const struct got_error *error;
	struct got_pathlist_entry *new;
	char *refname;

	if (strncmp(branchname, "refs/heads/", 11) != 0) {
		if (asprintf(&refname, "refs/heads/%s", branchname) == -1) {
			yyerror("asprintf: %s", strerror(errno));
			return -1;
		}
	} else {
		refname = strdup(branchname);
		if (refname == NULL) {
			yyerror("strdup: %s", strerror(errno));
			return -1;
		}
	}

	if (!refname_is_valid(refname)) {
		free(refname);
		return -1;
	}

	error = got_pathlist_insert(&new, &repo->protected_branches,
	    refname, NULL);
	if (error || new == NULL) {
		free(refname);
		if (error)
			yyerror("got_pathlist_insert: %s", error->msg);
		else
			yyerror("duplicate protect branch %s", branchname);
		return -1;
	}
	repo->nprotected_branches++;

	return 0;
}

static int
conf_notify_branch(struct gotsys_repo *repo, char *branchname)
{
	const struct got_error *error;
	struct got_pathlist_entry *pe;
	char *refname;

	if (strncmp(branchname, "refs/heads/", 11) != 0) {
		if (asprintf(&refname, "refs/heads/%s", branchname) == -1) {
			yyerror("asprintf: %s", strerror(errno));
			return -1;
		}
	} else {
		refname = strdup(branchname);
		if (refname == NULL) {
			yyerror("strdup: %s", strerror(errno));
			return -1;
		}
	}

	if (!refname_is_valid(refname)) {
		free(refname);
		return -1;
	}

	error = got_pathlist_insert(&pe, &repo->notification_refs,
	    refname, NULL);
	if (error) {
		free(refname);
		yyerror("got_pathlist_insert: %s", error->msg);
		return -1;
	}
	if (pe == NULL)
		free(refname);
	else
		repo->num_notification_refs++;

	return 0;
}

static int
conf_notify_ref_namespace(struct gotsys_repo *repo, char *namespace)
{
	const struct got_error *error;
	struct got_pathlist_entry *pe;
	char *s;

	got_path_strip_trailing_slashes(namespace);
	if (!refname_is_valid(namespace))
		return -1;

	if (asprintf(&s, "%s/", namespace) == -1) {
		yyerror("asprintf: %s", strerror(errno));
		return -1;
	}

	error = got_pathlist_insert(&pe, &repo->notification_ref_namespaces,
	    s, NULL);
	if (error) {
		free(s);
		yyerror("got_pathlist_insert: %s", error->msg);
		return -1;
	}
	if (pe == NULL)
		free(s);
	else
		repo->num_notification_ref_namespaces++;

	return 0;
}

static int
email_address_is_valid(const char *s)
{
	const char allowed[] = {
	    '!', '%', '&', '*', '+', '-', '/', '?',
	    '^', '_', '`', '.', '{', '|', '}', '~'
	};
	size_t i, j, len = strlen(s);
	char *at;
	ptrdiff_t local_len;
	size_t domain_len;

	if (s[0] == '\0' || s[0] == '.')
		return 0;

	at = strchr(s, '@');
	if (at == NULL)
		return 0;

	local_len = at - s;
	if (local_len == 0 || local_len > 64)
		return 0;
	
	for (i = 0; i < local_len; i++) {
		if (isalnum((unsigned char)s[i]))
			continue;

		for (j = 0; j < nitems(allowed); j++) {
			if (s[i] == allowed[j])
				break;
		}
		if (j < nitems(allowed))
			continue;

		return 0;
	}

	if (s[local_len - 1] == '.')
		return 0;

	if (s[local_len + 1] == '-' || s[len - 1] == '-')
		return 0;

	domain_len = len - local_len;
	if (domain_len == 0 || domain_len > 255)
		return 0;

	for (i = local_len + 1; i < domain_len; i++) {
		if (isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '-')
			continue;

		return 0;
	}

	return 1;
}

static int
conf_notify_email(struct gotsys_repo *repo, char *sender, char *recipient,
    char *responder, char *hostname, char *port)
{
	struct gotsys_notification_target *target;

	STAILQ_FOREACH(target, &repo->notification_targets, entry) {
		if (target->type != GOTSYS_NOTIFICATION_VIA_EMAIL)
			continue;
		if (strcmp(target->conf.email.recipient, recipient) == 0) {
			yyerror("duplicate email notification for '%s' in "
			    "repository '%s'", recipient, repo->name);
			return -1;
		}
	}

	target = calloc(1, sizeof(*target));
	if (target == NULL) {
		yyerror("calloc: %s", strerror(errno));
		return -1;
	}
	target->type = GOTSYS_NOTIFICATION_VIA_EMAIL;
	if (sender) {
		if (!email_address_is_valid(sender)) {
			yyerror("invalid email address: %s", sender);
			goto free_target;
		}
		target->conf.email.sender = strdup(sender);
		if (target->conf.email.sender == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto free_target;
		}
	}

	if (!email_address_is_valid(recipient)) {
		yyerror("invalid email address: %s", recipient);
		goto free_target;
	}
	target->conf.email.recipient = strdup(recipient);
	if (target->conf.email.recipient == NULL) {
		yyerror("strdup: %s", strerror(errno));
		goto free_target;
	}
	if (responder) {
		if (!email_address_is_valid(responder)) {
			yyerror("invalid email address: %s", responder);
			goto free_target;
		}
		target->conf.email.responder = strdup(responder);
		if (target->conf.email.responder == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto free_target;
		}
	}
	if (hostname) {
		target->conf.email.hostname = strdup(hostname);
		if (target->conf.email.hostname == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto free_target;
		}
	}
	if (port) {
		target->conf.email.port = strdup(port);
		if (target->conf.email.port == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto free_target;
		}
	}

	STAILQ_INSERT_TAIL(&repo->notification_targets, target, entry);
	return 0;

free_target:
	gotsys_notification_target_free(target);
	return -1;
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

static const struct got_error *
parse_url(char **proto, char **host, char **port,
    char **request_path, const char *url)
{
	const struct got_error *err = NULL;
	char *s, *p, *q;
	size_t i, host_len;

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
		if ((*host)[0] == '\0') {
			err = got_error_msg(GOT_ERR_PARSE_URI,
			    "hostname cannot be empty");
			goto done;
		}
	}

	host_len = strlen(*host);
	for (i = 0; i < host_len; i++) {
		if (isalnum((unsigned char)(*host)[i]) ||
		    (*host)[i] == '.' || (*host)[i] == '-')
			continue;
		err = got_error_fmt(GOT_ERR_PARSE_URI,
		    "invalid hostname: %s", *host);
		goto done;

	}

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

static int
basic_auth_user_is_valid(const char *s)
{
	size_t i, len;

	if (s[0] == '\0')
		return 0;

	len = strlen(s);
	for (i = 0; i < len; i++) {
		if (s[i] & 0x80)
			return 0;

		if (isalnum((unsigned char)s[i]) ||
		    (i > 0 && s[i] == '-') ||
		    (i > 0 && s[i] == '_') ||
		    (i > 0 && s[i] == '.'))
			continue;

		return 0;
	}

	return 1;
}

static int
basic_auth_password_is_valid(const char *s)
{
	size_t i, len;

	if (s[0] == '\0')
		return 0;

	len = strlen(s);
	for (i = 0; i < len; i++) {
		if (s[i] & 0x80)
			return 0;
		if (iscntrl((unsigned char)s[i]))
			return 0;
		if (s[i] == '"')
			return 0;

	}

	return 1;
}

static int
validate_hmac_secret(const char *s, size_t len)
{
	static const uint8_t base64chars[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	size_t i;

	for (i = 0; i < len; i++) {
		if (strchr(base64chars, s[i]) == NULL)
			return 0;
	}

	return 1;
}

static int
conf_notify_http(struct gotsys_repo *repo, char *url, char *user,
    char *password, int insecure, char *hmac_secret)
{
	const struct got_error *error;
	struct gotsys_notification_target *target = NULL;
	char *proto, *hostname, *port, *path;
	int tls = 0, ret = -1;

	error = parse_url(&proto, &hostname, &port, &path, url);
	if (error) {
		yyerror("invalid HTTP notification URL '%s' in "
		    "repository '%s': %s", url, repo->name, error->msg);
		return -1;
	}

	tls = !strcmp(proto, "https");

	if (strcmp(proto, "http") != 0 && strcmp(proto, "https") != 0) {
		yyerror("invalid protocol '%s' in notification URL '%s' in "
		    "repository '%s", proto, url, repo->name);
		goto done;
	}

	if (port == NULL) {
		if (strcmp(proto, "http") == 0)
			port = strdup("80");
		if (strcmp(proto, "https") == 0)
			port = strdup("443");
		if (port == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto done;
		}
	}

	if ((user != NULL && password == NULL) ||
	    (user == NULL && password != NULL)) {
		yyerror("missing username or password");
		goto done;
	}

	if (!insecure && strcmp(proto, "http") == 0 &&
	    (user != NULL || password != NULL)) {
		yyerror("%s: HTTP notifications with basic authentication "
		    "over plaintext HTTP will leak credentials; add the "
		    "'insecure' config keyword if this is intentional", url);
		goto done;
	}

	STAILQ_FOREACH(target, &repo->notification_targets, entry) {
		if (target->type != GOTSYS_NOTIFICATION_VIA_HTTP)
			continue;
		if (target->conf.http.tls == tls &&
		    !strcmp(target->conf.http.hostname, hostname) &&
		    !strcmp(target->conf.http.port, port) &&
		    !strcmp(target->conf.http.path, path)) {
			yyerror("duplicate notification for URL '%s' in "
			    "repository '%s'", url, repo->name);
			goto done;
		}
	}

	target = calloc(1, sizeof(*target));
	if (target == NULL) {
		yyerror("calloc: %s", strerror(errno));
		goto done;
	}

	target->type = GOTSYS_NOTIFICATION_VIA_HTTP;
	target->conf.http.tls = tls;
	target->conf.http.hostname = hostname;
	hostname = NULL;
	target->conf.http.port = port;
	port = NULL;
	target->conf.http.path = path;
	path = NULL;

	if (user) {
		if (user[0] == '\0') {
			yyerror("%s: basic auth user names cannot be empty",
			    url);
			goto done;
		}
		if (!basic_auth_user_is_valid(user)) {
			yyerror("%s: basic auth user names may only "
			    "contain alphabetic ASCII characters,  "
			    "non-leading digits, non-leading hyphens, "
			    "non-leading underscores, or non-leading "
			    "periods", url);
			goto done;
		}
		target->conf.http.user = strdup(user);
		if (target->conf.http.user == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto done;
		}
		if (password[0] == '\0') {
			yyerror("%s: basic auth passwords cannot be empty",
			    url);
			goto done;
		}
		if (!basic_auth_password_is_valid(user)) {
			yyerror("%s: passwords for basic auth may only "
			    "contain ASCII characters, excluding control "
			    "characters and the \" (double quote) character",
			    url);
			goto done;
		}
		target->conf.http.password = strdup(password);
		if (target->conf.http.password == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto done;
		}
 	}

	if (hmac_secret) {
		if (hmac_secret[9] == '\0') {
			yyerror("hmac secrets cannot be empty");
			goto done;
		}
		if (!validate_hmac_secret(hmac_secret, strlen(hmac_secret))) {
			yyerror("hmac secrets must be base64-encoded; use "
			    "'openssl rand -base64 32' output instead of: %s",
			    hmac_secret);
			goto done;
		}
		target->conf.http.hmac_secret = strdup(hmac_secret);
		if (target->conf.http.hmac_secret == NULL) {
			yyerror("strdup: %s", strerror(errno));
			goto done;
		}
	}

	STAILQ_INSERT_TAIL(&repo->notification_targets, target, entry);
	ret = 0;
done:
	free(proto);
	if (ret) {
		gotsys_notification_target_free(target);
		free(hostname);
		free(port);
		free(target);
	}
	return ret;
}
