/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <sha1.h>
#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "got_opentemp.h"
#include "got_version.h"
#include "got_object.h"

#include "got_lib_hash.h"

#include "bufio.h"
#include "log.h"
#include "utf8d.h"

#define USERAGENT	 "got-notify-http/" GOT_VERSION_STR

static int		 http_timeout = 300;	/* 5 minutes in seconds */

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-c] -r repo -h host -p port -u user path\n",
	    getprogname());
	exit(1);
}

static int
dial(const char *host, const char *port)
{
	struct addrinfo	 hints, *res, *res0;
	const char	*cause = NULL;
	int		 s, error, save_errno;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "failed to resolve %s:%s: %s", host, port,
		    gai_strerror(error));

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);
	if (s == -1)
		fatal("%s %s:%s", cause, host, port);
	return s;
}

static void
escape(FILE *fp, const uint8_t *s)
{
	uint32_t codepoint, state;
	const uint8_t *start = s;

	state = 0;
	for (; *s; ++s) {
		switch (decode(&state, &codepoint, *s)) {
		case UTF8_ACCEPT:
			switch (codepoint) {
			case '"':
			case '\\':
				fprintf(fp, "\\%c", *s);
				break;
			case '\b':
				fprintf(fp, "\\b");
				break;
			case '\f':
				fprintf(fp, "\\f");
				break;
			case '\n':
				fprintf(fp, "\\n");
				break;
			case '\r':
				fprintf(fp, "\\r");
				break;
			case '\t':
				fprintf(fp, "\\t");
				break;
			default:
				/* other control characters */
				if (codepoint < ' ' || codepoint == 0x7F) {
					fprintf(fp, "\\u%04x", codepoint);
					break;
				}
				fwrite(start, 1, s - start + 1, fp);
				break;
			}
			start = s + 1;
			break;

		case UTF8_REJECT:
			/* bad UTF-8 sequence; try to recover */
			fputs("\\uFFFD", fp);
			state = UTF8_ACCEPT;
			start = s + 1;
			break;
		}
        }
}

static void
json_field(FILE *fp, const char *key, const char *val, int comma)
{
	fprintf(fp, "\"%s\":\"", key);
	escape(fp, val);
	fprintf(fp, "\"%s", comma ? "," : "");
}

static void
json_date(FILE *fp, const char *key, const char *date, int comma)
{
	fprintf(fp, "\"%s\":%s%s", key, date, comma ? "," : "");
}

static void
json_author(FILE *fp, const char *type, char *address, int comma)
{
	char	*gt, *lt, *at, *email, *endname;

	fprintf(fp, "\"%s\":{", type);

	gt = strchr(address, '<');
	if (gt != NULL) {
		/* long format, e.g. "Omar Polo <op@openbsd.org>" */

		json_field(fp, "full", address, 1);

		endname = gt;
		while (endname > address && endname[-1] == ' ')
			endname--;

		*endname = '\0';
		json_field(fp, "name", address, 1);

		email = gt + 1;
		lt = strchr(email, '>');
		if (lt)
			*lt = '\0';

		json_field(fp, "mail", email, 1);

		at = strchr(email, '@');
		if (at)
			*at = '\0';

		json_field(fp, "user", email, 0);
	} else {
		/* short format only shows the username */
		json_field(fp, "user", address, 0);
	}

	fprintf(fp, "}%s", comma ? "," : "");
}

static int
jsonify_branch_rm(FILE *fp, char *line, const char *repo, const char *user)
{
	char	*ref, *id;

	line = strchr(line, ' ');
	if (line == NULL)
		errx(1, "invalid branch rm line");
	line += strspn(line, " ");

	ref = line;

	line = strchr(line, ':');
	if (line == NULL)
		errx(1, "invalid branch rm line");
	*line++ = '\0';
	id = line + strspn(line, " ");

	fputc('{', fp);
	json_field(fp, "type", "branch-deleted", 1);
	json_field(fp, "repo", repo, 1);
	json_field(fp, "authenticated_user", user, 1);
	json_field(fp, "ref", ref, 1);
	json_field(fp, "id", id, 0);
	fputc('}', fp);

	return 0;
}

static int
jsonify_commit_short(FILE *fp, char *line, const char *repo, const char *user)
{
	char	*t, *date, *id, *author, *message;

	t = line;
	date = t;
	if ((t = strchr(t, ' ')) == NULL)
      			errx(1, "malformed line");
	*t++ = '\0';

	id = t;
	if ((t = strchr(t, ' ')) == NULL)
      			errx(1, "malformed line");
	*t++ = '\0';

	author = t;
	if ((t = strchr(t, ' ')) == NULL)
      			errx(1, "malformed line");
	*t++ = '\0';

	message = t;

	fprintf(fp, "{\"type\":\"commit\",\"short\":true,");
	json_field(fp, "repo", repo, 1);
	json_field(fp, "authenticated_user", user, 1);
	json_field(fp, "id", id, 1);
	json_author(fp, "committer", author, 1);
	json_date(fp, "date", date, 1);
	json_field(fp, "short_message", message, 0);
	fprintf(fp, "}");

	return 0;
}

static int
jsonify_commit(FILE *fp, const char *repo, const char *user,
    char **line, ssize_t *linesize)
{
	const char	*errstr;
	char		*author = NULL;
	char		*filename, *t;
	char		*l;
	ssize_t		 linelen;
	int		 parent = 0;
	int		 msglen = 0, msgwrote = 0;
	int		 n, files = 0;
	int		 done = 0;
	enum {
		P_FROM,
		P_VIA,
		P_DATE,
		P_PARENT,
		P_MSGLEN,
		P_MSG,
		P_DST,
		P_SUM,
	} phase = P_FROM;

	l = *line;
	if (strncmp(l, "commit ", 7) != 0)
		errx(1, "%s: unexpected line: %s", __func__, l);
	l += 7;

	fprintf(fp, "{\"type\":\"commit\",\"short\":false,");
	json_field(fp, "repo", repo, 1);
	json_field(fp, "authenticated_user", user, 1);
	json_field(fp, "id", l, 1);

	while (!done) {
		if ((linelen = getline(line, linesize, stdin)) == -1)
			break;

		if ((*line)[linelen - 1] == '\n')
			(*line)[--linelen] = '\0';

		l = *line;
		switch (phase) {
		case P_FROM:
			if (strncmp(l, "from: ", 6) != 0)
				errx(1, "unexpected from line");
			l += 6;

			author = strdup(l);
			if (author == NULL)
				fatal("strdup");

			json_author(fp, "author", l, 1);

			phase = P_VIA;
			break;

		case P_VIA:
			/* optional */
			if (!strncmp(l, "via: ", 5)) {
				l += 5;
				json_author(fp, "committer", l, 1);
				phase = P_DATE;
				break;
			}

			if (author == NULL) /* impossible */
				fatalx("from not specified");
			json_author(fp, "committer", author, 1);
			free(author);
			author = NULL;

			phase = P_DATE;
			/* fallthrough */

		case P_DATE:
			/* optional */
			if (!strncmp(l, "date: ", 6)) {
				l += 6;
				json_date(fp, "date", l, 1);
				phase = P_PARENT;
				break;
			}
			phase = P_PARENT;
			/* fallthrough */

		case P_PARENT:
			/* optional - more than one */
			if (!strncmp(l, "parent ", 7)) {
				l += 7;
				l += strcspn(l, ":");
				l += strspn(l, " ");

				if (parent == 0) {
					parent = 1;
					fprintf(fp, "\"parents\":[");
				}

				fputc('"', fp);
				escape(fp, l);
				fputc('"', fp);

				break;
			}
			if (parent != 0) {
				fprintf(fp, "],");
				parent = 0;
			}
			phase = P_MSGLEN;
			/* fallthrough */

		case P_MSGLEN:
			if (strncmp(l, "messagelen: ", 12) != 0)
				errx(1, "unexpected messagelen line");
			l += 12;
			msglen = strtonum(l, 1, INT_MAX, &errstr);
			if (errstr)
				errx(1, "message len is %s: %s", errstr, l);

			msglen++;

			phase = P_MSG;
			break;

		case P_MSG:
			/*
			 * The commit message is indented with one extra
			 * space which is not accounted for in messagelen,
			 * but we also strip the trailing \n so that
			 * accounts for it.
			 *
			 * Since we read line-by-line and there is always
			 * a \n added at the end of the message,
			 * tolerate one byte less than advertised.
			 */
			if (*l != ' ')
				errx(1, "unexpected line in commit message");

			l++; /* skip leading space */
			linelen--;

			if (msgwrote == 0 && linelen != 0) {
				json_field(fp, "short_message", l, 1);
				fprintf(fp, "\"message\":\"");
				escape(fp, l);
				escape(fp, "\n");
				msgwrote += linelen;
			} else if (msgwrote != 0) {
				escape(fp, l);
				escape(fp, "\n");
			}

			msglen -= linelen + 1;
			if (msglen <= 1) {
				fprintf(fp, "\",");
				phase = P_DST;
				break;
			}
			break;

		case P_DST:
			if (files == 0 && !strcmp(l, " "))
				break;

			if (files == 0)
				fputs("\"diffstat\":{\"files\":[", fp);

			if (*l == '\0') {
				fputs("],", fp);
				phase = P_SUM;
				break;
			}

			if (*l != ' ')
				errx(1, "bad diffstat line");
			l++;

			if (files != 0)
				fputc(',', fp);
			fputc('{', fp);

			switch (*l) {
			case 'A':
				json_field(fp, "action", "added", 1);
				break;
			case 'D':
				json_field(fp, "action", "deleted", 1);
				break;
			case 'M':
				json_field(fp, "action", "modified", 1);
				break;
			case 'm':
				json_field(fp, "action", "mode changed", 1);
				break;
			default:
				json_field(fp, "action", "unknown", 1);
				break;
			}

			l++;
			while (*l == ' ')
				*l++ = '\0';
			if (*l == '\0')
				errx(1, "invalid diffstat: no filename");

			filename = l;
			l = strrchr(l, '|');
			if (l == NULL)
				errx(1, "invalid diffstat: no separator");
			t = l - 1;
			while (t > filename && *t == ' ')
				*t-- = '\0';
			json_field(fp, "file", filename, 1);

			l++;
			while (*l == ' ')
				l++;

			t = strchr(l, '+');
			if (t == NULL)
				errx(1, "invalid diffstat: no added counter");
			*t++ = '\0';

			n = strtonum(l, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "added counter is %s: %s", errstr, l);
			fprintf(fp, "\"added\":%d,", n);

			l = ++t;
			while (*l == ' ')
				l++;

			t = strchr(l, '-');
			if (t == NULL)
				errx(1, "invalid diffstat: no del counter");
			*t = '\0';

			n = strtonum(l, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "del counter is %s: %s", errstr, l);
			fprintf(fp, "\"removed\":%d", n);

			fputc('}', fp);

			files++;

			break;

		case P_SUM:
			fputs("\"total\":{", fp);

			t = l;
			l = strchr(l, ' ');
			if (l == NULL)
				errx(1, "missing number of additions");
			*l++ = '\0';

			n = strtonum(t, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "add counter is %s: %s", errstr, t);
			fprintf(fp, "\"added\":%d,", n);

			l = strchr(l, ',');
			if (l == NULL)
				errx(1, "missing number of deletions");
			l++;
			while (*l == ' ')
				l++;

			t = strchr(l, ' ');
			if (t == NULL)
				errx(1, "malformed diffstat sum line");
			*t = '\0';

			n = strtonum(l, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "del counter is %s: %s", errstr, l);
			fprintf(fp, "\"removed\":%d", n);

			fputs("}}", fp);
			done = 1;
			break;

		default:
			/* unreachable */
			errx(1, "unexpected line: %s", *line);
		}
	}
	if (ferror(stdin))
		fatalx("getline");
	if (!done)
		fatalx("%s: unexpected EOF", __func__);
	fputc('}', fp);

	return 0;
}

static int
jsonify_tag(FILE *fp, const char *repo, const char *user,
    char **line, ssize_t *linesize)
{
	const char	*errstr;
	char		*l;
	ssize_t		 linelen;
	int		 msglen = 0, msgwrote = 0;
	int		 done = 0;
	enum {
		P_FROM,
		P_DATE,
		P_OBJECT,
		P_MSGLEN,
		P_MSG,
	} phase = P_FROM;

	l = *line;
	if (strncmp(l, "tag ", 4) != 0)
		errx(1, "%s: unexpected line: %s", __func__, l);
	l += 4;

	fputc('{', fp);
	json_field(fp, "type", "tag", 1);
	json_field(fp, "repo", repo, 1);
	json_field(fp, "authenticated_user", user, 1);
	json_field(fp, "tag", l, 1);

	while (!done) {
		if ((linelen = getline(line, linesize, stdin)) == -1)
			break;

		if ((*line)[linelen - 1] == '\n')
			(*line)[--linelen] = '\0';

		l = *line;
		switch (phase) {
		case P_FROM:
			if (strncmp(l, "from: ", 6) != 0)
				errx(1, "unexpected from line");
			l += 6;

			json_author(fp, "tagger", l, 1);

			phase = P_DATE;
			break;

		case P_DATE:
			/* optional */
			if (!strncmp(l, "date: ", 6)) {
				l += 6;
				json_date(fp, "date", l, 1);
				phase = P_OBJECT;
				break;
			}
			phase = P_OBJECT;
			/* fallthrough */

		case P_OBJECT:
			/* optional */
			if (!strncmp(l, "object: ", 8)) {
				char *type, *id;

				l += 8;
				type = l;
				id = strchr(l, ' ');
				if (id == NULL)
					errx(1, "malformed tag object line");
				*id++ = '\0';

				fputs("\"object\":{", fp);
				json_field(fp, "type", type, 1);
				json_field(fp, "id", id, 0);
				fputs("},", fp);

				phase = P_MSGLEN;
				break;
			}
			phase = P_MSGLEN;
			/* fallthrough */

		case P_MSGLEN:
			if (strncmp(l, "messagelen: ", 12) != 0)
				errx(1, "unexpected messagelen line");
			l += 12;
			msglen = strtonum(l, 1, INT_MAX, &errstr);
			if (errstr)
				errx(1, "message len is %s: %s", errstr, l);

			msglen++;

			phase = P_MSG;
			break;

		case P_MSG:
			if (*l != ' ')
				errx(1, "unexpected line in tag message");

			l++; /* skip leading space */
			linelen--;

			if (msgwrote == 0 && linelen != 0) {
				fprintf(fp, "\"message\":\"");
				escape(fp, l);
				escape(fp, "\n");
				msgwrote += linelen;
			} else if (msgwrote != 0) {
				escape(fp, l);
				escape(fp, "\n");
			}

			msglen -= linelen + 1;
			if (msglen <= 0) {
				fprintf(fp, "\"");
				done = 1;
				break;
			}
			break;

		default:
			/* unreachable */
			errx(1, "unexpected line: %s", *line);
		}
	}
	if (ferror(stdin))
		fatal("getline");
	if (!done)
		fatalx("%s: unexpected EOF", __func__);
	fputc('}', fp);

	return 0;
}

static int
jsonify(FILE *fp, const char *repo, const char *user)
{
	char		*line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;
	int		 needcomma = 0;

	fprintf(fp, "{\"notifications\":[");
	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';

		if (*line == '\0')
			continue;

		if (needcomma)
			fputc(',', fp);
		needcomma = 1;

		if (strncmp(line, "Removed refs/heads/", 19) == 0) {
			if (jsonify_branch_rm(fp, line, repo, user) == -1)
				fatal("jsonify_branch_rm");
			continue;
		}

		if (strncmp(line, "commit ", 7) == 0) {
			if (jsonify_commit(fp, repo, user,
			    &line, &linesize) == -1)
				fatal("jsonify_commit");
			continue;
		}

		if (*line >= '0' && *line <= '9') {
			if (jsonify_commit_short(fp, line, repo, user) == -1)
				fatal("jsonify_commit_short");
			continue;
		}

		if (strncmp(line, "tag ", 4) == 0) {
			if (jsonify_tag(fp, repo, user, &line, &linesize) == -1)
				fatal("jsonify_tag");
			continue;
		}

		errx(1, "unexpected line: %s", line);
	}
	if (ferror(stdin))
		fatal("getline");
	fprintf(fp, "]}");

	return 0;
}

static char
sixet2ch(int c)
{
	c &= 0x3F;

	if (c < 26)
		return 'A' + c;
	c -= 26;
	if (c < 26)
		return 'a' + c;
	c -= 26;
	if (c < 10)
		return '0' + c;
	c -= 10;
	if (c == 0)
		return '+';
	if (c == 1)
		return '/';

	errx(1, "invalid sixet 0x%x", c);
}

static char *
basic_auth(const char *username, const char *password)
{
	char	*str, *tmp, *end, *s, *p;
	char	 buf[3];
	int	 len, i, r;

	r = asprintf(&str, "%s:%s", username, password);
	if (r == -1)
		fatal("asprintf");

	/*
	 * Will need 4 * r/3 bytes to encode the string, plus a
	 * rounding to the next multiple of 4 for padding, plus NUL.
	 */
	len = 4 * r / 3;
	len = (len + 3) & ~3;
	len++;

	tmp = calloc(1, len);
	if (tmp == NULL)
		fatal("calloc");

	s = str;
	p = tmp;
	while (*s != '\0') {
		memset(buf, 0, sizeof(buf));
		for (i = 0; i < 3 && *s != '\0'; ++i, ++s)
			buf[i] = *s;

		*p++ = sixet2ch(buf[0] >> 2);
		*p++ = sixet2ch((buf[1] >> 4) | (buf[0] << 4));
		if (i > 1)
			*p++ = sixet2ch((buf[1] << 2) | (buf[2] >> 6));
		if (i > 2)
			*p++ = sixet2ch(buf[2]);
	}

	for (end = tmp + len - 1; p < end; ++p)
		*p = '=';

	free(str);
	return tmp;
}

static inline int
bufio2poll(struct bufio *bio)
{
	int f, ret = 0;

	/*
	 * If we have data queued up, retry for both POLLIN and POLLOUT
	 * since we want to push this data to the server while still
	 * processing an eventual reply.  Otherwise, we could wait
	 * indefinitely for the server to reply without us having
	 * sent the HTTP request completely.
	 */
	if (bio->wbuf.len)
		return POLLIN|POLLOUT;

	f = bufio_ev(bio);
	if (f & BUFIO_WANT_READ)
		ret |= POLLIN;
	if (f & BUFIO_WANT_WRITE)
		ret |= POLLOUT;
	return ret;
}

static unsigned char *
compute_hmac_sha256(FILE *payload, off_t paylen, const char *hmac_secret,
    size_t secret_len, unsigned char *hmac_sig_buf, unsigned int *hmac_siglen)
{
	HMAC_CTX *ctx;
	char buf[4096];
	off_t n;
	ssize_t r;

	*hmac_siglen = 0;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
		log_warnx("HMAC_CTX_new failed");
		return NULL;
	}

	if (!HMAC_Init_ex(ctx, hmac_secret, secret_len, EVP_sha256(), NULL)) {
		log_warnx("HMAC_Init_ex failed");
		goto fail;
	}

	n = paylen;
	while (n > 0) {
		r = fread(buf, 1, n > sizeof(buf) ? sizeof(buf) : n, payload);
		if (r == 0) {
			if (feof(payload)) {
				log_warnx("HMAC payload truncated");
				goto fail;
			}
			log_warn("failed to read HMAC payload");
			goto fail;
		}
		if (!HMAC_Update(ctx, buf, r)) {
			log_warn("HMAC_Update");
			goto fail;
		}
		n -= r;
	}

	if (!HMAC_Final(ctx, hmac_sig_buf, hmac_siglen)) {
		log_warnx("HMAC_Final failed");
		goto fail;
	}

	*hmac_siglen = HMAC_size(ctx);

	HMAC_CTX_free(ctx);
	return hmac_sig_buf;
fail:
	HMAC_CTX_free(ctx);
	return NULL;
}

int
main(int argc, char **argv)
{
	FILE		*tmpfp;
	struct bufio	 bio;
	struct pollfd	 pfd;
	struct timespec	 timeout;
	const char	*username;
	const char	*password;
	const char	*timeoutstr;
	const char	*hmac_secret;
	const char	*errstr;
	const char	*repo = NULL;
	const char	*host = NULL, *port = NULL, *path = NULL;
	const char	*gotd_auth_user = NULL;
	char		*auth, *line, *spc;
	unsigned char	*hmac_sig = NULL;
	unsigned char	 hmac_sig_buf[EVP_MAX_MD_SIZE];
	unsigned int	 hmac_siglen;
	char		 hex[SHA256_DIGEST_STRING_LENGTH];
	size_t		 len;
	ssize_t		 r;
	off_t		 paylen;
	int		 tls = 0;
	int		 response_code = 0, done = 0;
	int		 ch, flags, ret, nonstd = 0;

#ifndef PROFILE
	const char *root_ca;
	root_ca = tls_default_ca_cert_file();

	if (unveil(root_ca, "r") == -1)
		err(1, "unveil %s", root_ca);
	if (unveil("/tmp/", "rwc") == -1)
		err(1, "unveil /tmp");
	if (pledge("stdio rpath wpath cpath dns inet", NULL) == -1)
		err(1, "pledge");
#endif

	log_init(0, LOG_DAEMON);

	while ((ch = getopt(argc, argv, "ch:p:r:u:")) != -1) {
		switch (ch) {
		case 'c':
			tls = 1;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			repo = optarg;
			break;
		case 'u':
			gotd_auth_user = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (host == NULL || repo == NULL || gotd_auth_user == NULL || argc != 1)
		usage();
	if (tls && port == NULL)
		port = "443";
	path = argv[0];

	username = getenv("GOT_NOTIFY_HTTP_USER");
	password = getenv("GOT_NOTIFY_HTTP_PASS");
	if ((username != NULL && password == NULL) ||
	    (username == NULL && password != NULL))
		fatalx("username or password are not specified");
	if (username && *password == '\0')
		fatalx("password can't be empty");

	/* used by the regression test suite */
	timeoutstr = getenv("GOT_NOTIFY_TIMEOUT");
	if (timeoutstr) {
		http_timeout = strtonum(timeoutstr, 0, 600, &errstr);
		if (errstr != NULL)
			fatalx("timeout in seconds is %s: %s",
			    errstr, timeoutstr);
	}

	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = http_timeout;

	tmpfp = got_opentemp();
	if (tmpfp == NULL)
		fatal("opentemp");

	jsonify(tmpfp, repo, gotd_auth_user);

	paylen = ftello(tmpfp);
	if (paylen == -1)
		fatal("ftello");
	if (fseeko(tmpfp, 0, SEEK_SET) == -1)
		fatal("fseeko");

#ifndef PROFILE
	/* drop wpath cpath */
	if (pledge("stdio rpath dns inet", NULL) == -1)
		err(1, "pledge");
#endif
	hmac_secret = getenv("GOT_NOTIFY_HTTP_HMAC_SECRET");
	if (hmac_secret) {
		hmac_sig = compute_hmac_sha256(tmpfp, paylen, hmac_secret,
		    strlen(hmac_secret), hmac_sig_buf, &hmac_siglen);
		if (hmac_sig == NULL || hmac_siglen != SHA256_DIGEST_LENGTH)
			fatalx("HMAC computation failed");
		if (got_sha256_digest_to_str(hmac_sig, hex, sizeof(hex))
		    == NULL)
			fatalx("HMAC conversion to hex string failed");

		if (fseeko(tmpfp, 0, SEEK_SET) == -1)
			fatal("fseeko");
	}

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = dial(host, port);

	if ((flags = fcntl(pfd.fd, F_GETFL)) == -1)
		fatal("fcntl(F_GETFL)");
	if (fcntl(pfd.fd, F_SETFL, flags | O_NONBLOCK) == -1)
		fatal("fcntl(F_SETFL)");

	if (bufio_init(&bio) == -1)
		fatal("bufio_init");
	bufio_set_fd(&bio, pfd.fd);
	if (tls && bufio_starttls(&bio, host, 0, NULL, 0, NULL, 0) == -1)
		fatal("bufio_starttls");

#ifndef PROFILE
	/* drop rpath dns inet */
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	if ((!tls && strcmp(port, "80") != 0) ||
	    (tls && strcmp(port, "443")) != 0)
		nonstd = 1;

	ret = bufio_compose_fmt(&bio,
	    "POST %s HTTP/1.1\r\n"
	    "Host: %s%s%s\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: %lld\r\n"
	    "User-Agent: %s\r\n"
	    "Connection: close\r\n"
	    "%s%s%s%s",
	    path, host,
	    nonstd ? ":" : "", nonstd ? port : "",
	    (long long)paylen, USERAGENT,
	    hmac_sig ? "X-Gotd-Signature: " : "",
	    hmac_sig ? "sha256=" : "",
	    hmac_sig ? hex : "",
	    hmac_sig ? "\r\n" : "");
	if (ret == -1)
		fatal("bufio_compose_fmt");

	if (username) {
		auth = basic_auth(username, password);
		ret = bufio_compose_fmt(&bio, "Authorization: basic %s\r\n",
		    auth);
		if (ret == -1)
			fatal("bufio_compose_fmt");
		free(auth);
	}

	if (bufio_compose(&bio, "\r\n", 2) == -1)
		fatal("bufio_compose");

	while (!done) {
		struct timespec	 elapsed, start, stop;
		char		 buf[BUFSIZ];

		pfd.events = bufio2poll(&bio);
		clock_gettime(CLOCK_MONOTONIC, &start);
		ret = ppoll(&pfd, 1, &timeout, NULL);
		if (ret == -1)
			fatal("poll");
		clock_gettime(CLOCK_MONOTONIC, &stop);
		timespecsub(&stop, &start, &elapsed);
		timespecsub(&timeout, &elapsed, &timeout);
		if (ret == 0 || timeout.tv_sec <= 0)
			fatalx("timeout");

		if (bio.wbuf.len > 0) {
			if (bufio_write(&bio) == -1 && errno != EAGAIN)
				fatalx("bufio_write: %s", bufio_io_err(&bio));
		}

		r = bufio_read(&bio);
		if (r == -1 && errno != EAGAIN)
			fatalx("bufio_read: %s", bufio_io_err(&bio));
		if (r == 0)
			fatalx("unexpected EOF from upstream HTTP server");

		for (;;) {
			line = buf_getdelim(&bio.rbuf, "\r\n", &len);
			if (line == NULL)
				break;
			if (response_code && *line == '\0') {
				/*
				 * end of headers, don't bother
				 * reading the body, if there is.
				 */
				done = 1;
				break;
			}
			if (response_code) {
				buf_drain(&bio.rbuf, len);
				continue;
			}
			spc = strchr(line, ' ');
			if (spc == NULL)
				fatalx("bad HTTP response from server");
			*spc++ = '\0';
			if (strcasecmp(line, "HTTP/1.1") != 0)
				log_warnx("warning: unexpected protocol: %s",
				    line);
			line = spc;

			spc = strchr(line, ' ');
			if (spc == NULL)
				fatalx("bad HTTP response from server");
			*spc++ = '\0';

			response_code = strtonum(line, 100, 599,
			    &errstr);
			if (errstr != NULL)
				log_warnx("warning: response code is %s: %s",
				    errstr, line);

			buf_drain(&bio.rbuf, len);
		}
		if (done)
			break;

		if (!feof(tmpfp) && bio.wbuf.len < sizeof(buf)) {
			len = fread(buf, 1, sizeof(buf), tmpfp);
			if (len == 0) {
				if (ferror(tmpfp))
					fatal("fread");
				continue;
			}

			if (bufio_compose(&bio, buf, len) == -1)
				fatal("buf_compose");
		}
	}

	if (response_code >= 200 && response_code < 300)
		return 0;
	fatalx("request failed with code %d", response_code);
}
