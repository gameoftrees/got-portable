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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "log.h"
#include "gotsysd.h"
#include "gotsys.h"

#ifndef GOTD_USER
#define GOTD_USER "_gotd"
#endif

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file;
struct file	*newfile(const char *, int, int);
static void	 closefile(struct file *);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
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

static struct gotsysd		*gotsysd;
static enum gotsysd_procid	gotsysd_proc_id;

static void conf_new_access_rule(enum gotsysd_access, char *);
static const struct got_error *conf_new_repo_access_rule(enum gotsys_access,
    int, const char *);

typedef struct {
	union {
		long long	 number;
		char		*string;
		struct timeval	 tv;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	ERROR LISTEN ON USER GOTD DIRECTORY REPOSITORY UID RANGE PERMIT
%token	DENY RO RW

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.string>	numberstring

%%

grammar		:
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
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

main		: LISTEN ON STRING {
			if (!got_path_is_absolute($3))
				yyerror("bad unix socket path \"%s\": "
				    "must be an absolute path", $3);

			if (realpath($3, gotsysd->unix_socket_path) == NULL) {
				if (errno != ENOENT && errno != EACCES) {
					yyerror("realpath %s: %s", $3,
					    strerror(errno));
					free($3);
					YYERROR;
				}

				if (strlcpy(gotsysd->unix_socket_path, $3,
				    sizeof(gotsysd->unix_socket_path)) >=
				    sizeof(gotsysd->unix_socket_path)) {
					yyerror("unix socket path too long: %s",
					    $3);
					free($3);
					YYERROR;
				}
			}
			free($3);
		}
		| USER numberstring {
			if (strlcpy(gotsysd->user_name, $2,
			    sizeof(gotsysd->user_name)) >=
			    sizeof(gotsysd->user_name)) {
				yyerror("user name too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| GOTD USER numberstring {
			if (strlcpy(gotsysd->gotd_username, $3,
			    sizeof(gotsysd->gotd_username)) >=
			    sizeof(gotsysd->gotd_username)) {
				yyerror("user name too long: %s", $3);
				free($3);
				YYERROR;
			}
			free($3);
		}
		| REPOSITORY DIRECTORY STRING {
			if (!got_path_is_absolute($3))
				yyerror("bad path \"%s\": "
				    "must be an absolute path", $3);

			if (realpath($3, gotsysd->repos_path) == NULL) {
				yyerror("realpath %s: %s", $3, strerror(errno));
				free($3);
				YYERROR;
			}
			free($3);
		}
		| UID RANGE NUMBER NUMBER {
			gotsysd->uid_start = $3;
			gotsysd->uid_end = $4;
#if GOTSYSD_UID_MIN == 0
#error "UID 0 must not be used as GOTSYSD_UID_MIN"
#endif
#if GOTSYSD_UID_MIN == UID_MAX
#error "UID UID_MAX must not be used as GOTSYSD_UID_MIN"
#endif
			if (gotsysd->uid_start < GOTSYSD_UID_MIN ||
			    gotsysd->uid_end < GOTSYSD_UID_MIN) {
				yyerror("%s: UIDs lower than %u are not "
				    "allowed in uid range", __func__,
				    GOTSYSD_UID_MIN);
				YYERROR;
			}

			if (gotsysd->uid_start == UID_MAX ||
			    gotsysd->uid_end == UID_MAX) {
				yyerror("%s: UID %u is not allowed in "
				    "uid range", __func__, UID_MAX);
				YYERROR;
			}

			if (gotsysd->uid_start >= gotsysd->uid_end) {
				yyerror("%s: start of the uid range must be "
				    "smaller than the end of the uid range",
				    __func__);
				YYERROR;
			}
		}
		| PERMIT numberstring {
			if (gotsysd_proc_id == GOTSYSD_PROC_AUTH) {
				conf_new_access_rule(GOTSYSD_ACCESS_PERMITTED,
				    $2);
			} else
				free($2);
		}
		| REPOSITORY DENY numberstring {
			const struct got_error *err;

			err = conf_new_repo_access_rule(GOTSYS_ACCESS_DENIED,
			    0, $3);
			if (err) {
				yyerror("%s", err->msg);
				free($3);
				YYERROR;
			}
			free($3);
		}
		| REPOSITORY PERMIT RO numberstring {
			const struct got_error *err;

			err = conf_new_repo_access_rule(GOTSYS_ACCESS_PERMITTED,
			    GOTSYS_AUTH_READ, $4);
			if (err) {
				yyerror("%s", err->msg);
				free($4);
				YYERROR;
			}
			free($4);
		}
		| REPOSITORY PERMIT RW numberstring {
			const struct got_error *err;

			err = conf_new_repo_access_rule(GOTSYS_ACCESS_PERMITTED,
			    GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE, $4);
			if (err) {
				yyerror("%s", err->msg);
				free($4);
				YYERROR;
			}
			free($4);
		}
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
		{ "deny",			DENY },
		{ "directory",			DIRECTORY },
		{ "gotd",			GOTD },
		{ "listen",			LISTEN },
		{ "on",				ON },
		{ "permit",			PERMIT },
		{ "range",			RANGE },
		{ "repository",			REPOSITORY },
		{ "ro",				RO },
		{ "rw",				RW },
		{ "uid",			UID },
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

unsigned char *parsebuf;
int parseindex;
unsigned char pushback_buffer[MAXPUSHBACK];
int pushback_index = 0;

int
lgetc(int quotec)
{
	int c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

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
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int c;

	parsebuf = NULL;

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
	if (c == '$' && parsebuf == NULL) {
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
		parsebuf = val;
		parseindex = 0;
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
	x != ','))

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

struct file *
newfile(const char *name, int secret, int required)
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
		if (required)
			log_warn("open %s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	return (nfile);
}

static void
closefile(struct file *xfile)
{
	fclose(xfile->stream);
	free(xfile->name);
	free(xfile);
}

int
gotsysd_parse_config(const char *filename, enum gotsysd_procid proc_id,
    struct gotsysd *pgotsysd)
{
	struct sym *sym, *next;
	int require_config_file = 0;
	struct gotsys_access_rule_list *global_repo_access_rules;

	memset(pgotsysd, 0, sizeof(*pgotsysd));

	gotsysd = pgotsysd;
	gotsysd_proc_id = proc_id;

	STAILQ_INIT(&gotsysd->access_rules);

	global_repo_access_rules = malloc(sizeof(*global_repo_access_rules));
	if (global_repo_access_rules == NULL) {
		fprintf(stderr, "%s: malloc: %s\n", __func__,
		    strerror(errno));
		return -1;
	}
	gotsysd->global_repo_access_rules = global_repo_access_rules;
	STAILQ_INIT(gotsysd->global_repo_access_rules);
	global_repo_access_rules = NULL;

	/* Apply default values. */
	if (strlcpy(gotsysd->unix_socket_path, GOTSYSD_UNIX_SOCKET,
	    sizeof(gotsysd->unix_socket_path)) >=
	    sizeof(gotsysd->unix_socket_path)) {
		fprintf(stderr, "%s: unix socket path too long", __func__);
		return -1;
	}
	if (strlcpy(gotsysd->repos_path, GOTSYSD_REPOSITORIES_PATH,
	    sizeof(gotsysd->repos_path)) >= sizeof(gotsysd->repos_path)) {
		fprintf(stderr, "%s: repos path too long", __func__);
		return -1;
	}
	if (strlcpy(gotsysd->user_name, GOTSYSD_USER,
	    sizeof(gotsysd->user_name)) >= sizeof(gotsysd->user_name)) {
		fprintf(stderr, "%s: user name too long", __func__);
		return -1;
	}
	if (strlcpy(gotsysd->gotd_username, GOTD_USER,
	    sizeof(gotsysd->gotd_username)) >= sizeof(gotsysd->gotd_username)) {
		fprintf(stderr, "%s: user name too long", __func__);
		return -1;
	}

	gotsysd->uid_start = GOTSYSD_UID_DEFAULT_START;
	gotsysd->uid_end = GOTSYSD_UID_DEFAULT_END;

	file = newfile(filename, 0, 0);
	if (file == NULL) {
		if (require_config_file)
			return -1;
	} else {
		yyparse();
		errors = file->errors;
		closefile(file);

		/* Free macros and check which have not been used. */
		TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
			if ((gotsysd->verbosity > 1) && !sym->used)
				fprintf(stderr,
				    "warning: macro '%s' not used\n", sym->nam);
			if (!sym->persist) {
				free(sym->nam);
				free(sym->val);
				TAILQ_REMOVE(&symhead, sym, entry);
				free(sym);
			}
		}

		if (errors)
			return (-1);
	}

	if (proc_id == GOTSYSD_PROC_AUTH &&
	    STAILQ_EMPTY(&gotsysd->access_rules)) {
		char *identifier = strdup("0"); /* root */
		if (identifier == NULL)
			fatal("strdup");
		conf_new_access_rule(GOTSYSD_ACCESS_PERMITTED, identifier);

		identifier = strdup(GOTD_USER);
		if (identifier == NULL)
			fatal("strdup");
		conf_new_access_rule(GOTSYSD_ACCESS_PERMITTED, identifier);
	}

	return (0);
}

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
gotsysd_parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static void
conf_new_access_rule(enum gotsysd_access access, char *identifier)
{
	struct gotsysd_access_rule *rule;

	rule = calloc(1, sizeof(*rule));
	if (rule == NULL)
		fatal("calloc");

	rule->access = access;
	rule->identifier = identifier;

	STAILQ_INSERT_TAIL(&gotsysd->access_rules, rule, entry);
}

static const struct got_error *
conf_new_repo_access_rule(enum gotsys_access access, int authorization,
    const char *identifier)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;
	const char *name = identifier;

	if (strcmp(name, "*") != 0) {
		if (name[0] == ':') {
			name++;
			err = gotsys_conf_validate_name(name, "group");
			if (err)
				return err;
		} else {
			err = gotsys_conf_validate_name(name, "user");
			if (err)
				return err;
		}
	}

	err = gotsys_conf_new_access_rule(&rule, access, authorization,
	    identifier, NULL, NULL);
	if (err)
		return err;

	STAILQ_INSERT_TAIL(gotsysd->global_repo_access_rules, rule, entry);
	return NULL;
}
