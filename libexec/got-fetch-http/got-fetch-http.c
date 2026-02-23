/*
 * Copyright (c) 2024 Tobias Heider <me@tobhe.de>
 * Copyright (c) 2022, 2025 Omar Polo <op@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_version.h"

#include "got_lib_pkt.h"

#include "bufio.h"

#define UPLOAD_PACK_ADV "application/x-git-upload-pack-advertisement"
#define UPLOAD_PACK_REQ "application/x-git-upload-pack-request"
#define UPLOAD_PACK_RES "application/x-git-upload-pack-result"

#define	GOT_USERAGENT	"got/" GOT_VERSION_STR
#define MINIMUM(a, b)	((a) < (b) ? (a) : (b))
#define hasprfx(str, p)	(strncasecmp(str, p, strlen(p)) == 0)

static int	verbose;

static char *
bufio_getdelim_sync(struct bufio *bio, const char *nl, size_t *len)
{
	int	r;

	do {
		r = bufio_read(bio);
		if (r == -1 && errno != EAGAIN)
			errx(1, "bufio_read: %s", bufio_io_err(bio));
	} while (r == -1 && errno == EAGAIN);
	return buf_getdelim(&bio->rbuf, nl, len);
}

static void
bufio_close_sync(struct bufio *bio)
{
	int	 r;

	do {
		r = bufio_close(bio);
		if (r == -1 && errno != EAGAIN)
			errx(1, "bufio_close: %s", bufio_io_err(bio));
	} while (r == -1 && errno == EAGAIN);
}

static long long
hexstrtonum(const char *str, long long min, long long max, const char **errstr)
{
	long long	 lval;
	char		*cp;

	errno = 0;
	lval = strtoll(str, &cp, 16);
	if (*str == '\0' || *cp != '\0') {
		*errstr = "not a number";
		return 0;
	}
	if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
	    lval < min || lval > max) {
		*errstr = "out of range";
		return 0;
	}

	*errstr = NULL;
	return lval;
}

static int
dial(int https, const char *host, const char *port)
{
	struct addrinfo		 hints, *res, *res0;
	int			 error, saved_errno, fd = -1;
	const char		*cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		warnx("%s", gai_strerror(error));
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (fd == -1) {
			cause = "socket";
			continue;
		}

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		cause = "connect";
		saved_errno = errno;
		close(fd);
		fd = -1;
		errno = saved_errno;
	}
	freeaddrinfo(res0);

	if (fd == -1) {
		warn("%s", cause);
		return -1;
	}

	return fd;
}

static int
http_open(struct bufio *bio, int https, const char *method, const char *host, const char *port,
    const char *path, const char *path_sufx, const char *query, const char *ctype)
{
	const char	*chdr = NULL, *te = "";
	char		*p, *req;
	int		 r;

	if (strcmp(method, "POST") == 0)
		te = "\r\nTransfer-Encoding: chunked\r\n";

	if (ctype)
		chdr = "Content-Type: ";

	r = asprintf(&p, "%s%s/%s%s%s", got_path_is_absolute(path) ? "" :"/",
	    path, path_sufx, query ? "?" : "", query ? query : "");
	if (r == -1)
		err(1, "asprintf");

	r = asprintf(&req, "%s %s HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "Connection: close\r\n"
	    "User-agent: %s\r\n"
	    "%s%s%s\r\n",
	    method, p, host, GOT_USERAGENT,
	    chdr ? chdr : "", ctype ? ctype : "", te);
	if (r == -1)
		err(1, "asprintf");
	free(p);

	if (verbose > 0)
		fprintf(stderr, "%s: request: %s\n", getprogname(), req);

	r = bufio_compose(bio, req, r);
	if (r == -1)
		err(1, "bufio_compose_fmt");
	free(req);

	do {
		r = bufio_write(bio);
		if (r == -1 && errno != EAGAIN)
			errx(1, "bufio_write: %s", bufio_io_err(bio));
	} while (bio->wbuf.len != 0);

	return 0;
}

static int
http_parse_reply(struct bufio *bio, int *chunked, const char *expected_ctype)
{
	char		*cp, *line;
	size_t		 linelen;

	*chunked = 0;

	line = bufio_getdelim_sync(bio, "\r\n", &linelen);
	if (line == NULL) {
		warnx("%s: bufio_getdelim_sync()", __func__);
		return -1;
	}

	if (verbose > 0)
		fprintf(stderr, "%s: response: %s\n", getprogname(), line);

	if ((cp = strchr(line, ' ')) == NULL) {
		warnx("malformed HTTP response");
		return -1;
	}
	cp++;

	if (strncmp(cp, "200 ", 4) != 0) {
		warnx("malformed HTTP response");
		return -1;
	}
	buf_drain(&bio->rbuf, linelen);

	while(1) {
		line = bufio_getdelim_sync(bio, "\r\n", &linelen);
		if (line == NULL) {
			warnx("%s: bufio_getdelim_sync()", __func__);
			return -1;
		}
		if (*line == '\0') {
			buf_drain(&bio->rbuf, linelen);
			break;
		}

		if (hasprfx(line, "content-type:")) {
			cp = strchr(line, ':') + 1;
			cp += strspn(cp, " \t");
			cp[strcspn(cp, " \t")] = '\0';
			if (strcmp(cp, expected_ctype) != 0) {
				warnx("server not using the \"smart\" "
				    "HTTP protocol.");
				return -1;
			}
		}
		if (hasprfx(line, "transfer-encoding:")) {
			cp = strchr(line, ':') + 1;
			cp += strspn(cp, " \t");
			cp[strcspn(cp, " \t")] = '\0';
			if (strcmp(cp, "chunked") != 0) {
				warnx("unknown transfer-encoding");
				return -1;
			}
			*chunked = 1;
		}
		buf_drain(&bio->rbuf, linelen);
	}

	return 0;
}

static ssize_t
http_read(struct bufio *bio, int chunked, size_t *chunksz, char *buf, size_t bufsz,
    FILE *out)
{
	struct buf	*rbuf = &bio->rbuf;
	const char	*errstr;
	char		*chunk, *endln;
	size_t		 avail, w;
	ssize_t		 r, ret = 0;

	while (out != NULL || bufsz > 0) {
		if (rbuf->cur == rbuf->len) {
			rbuf->cur = 0;
			rbuf->len = 0;
			r = bufio_read(bio);
			if (r == -1) {
				warnx("bufio_read: %s", bufio_io_err(bio));
				return (-1);
			}
			if (r == 0)
				return ret;
		}

		if (chunked && *chunksz == 0) {
			for (;;) {
				chunk = rbuf->buf + rbuf->cur;
				avail = rbuf->len - rbuf->cur;
				endln = memmem(chunk, avail, "\r\n", 2);
				if (endln == NULL) {
					r = bufio_read(bio);
					if (r == -1) {
						warnx("bufio_read: %s",
						    bufio_io_err(bio));
						return (-1);
					}
					if (r == 0)
						return ret;
					continue;
				}
				rbuf->cur += (endln - chunk) + 2;
				*endln = '\0';
				/* was the CRLF after the chunk? */
				if (chunk == endln)
					continue;
				break;
			}

			*chunksz = hexstrtonum(chunk, 0, INT_MAX, &errstr);
			if (errstr != NULL) {
				warnx("invalid HTTP chunk: size is %s (%s)",
				    errstr, chunk);
				return (-1);
			}

			if (*chunksz == 0)
				break;
		}

		avail = rbuf->len - rbuf->cur;
		if (chunked && avail > *chunksz)
			avail = *chunksz;

		if (out != NULL) {
			w = fwrite(rbuf->buf + rbuf->cur, 1, avail, out);
			if (w != avail)
				return (-1);
		} else {
			avail = MINIMUM(avail, bufsz);
			memcpy(buf, rbuf->buf + rbuf->cur, avail);
		}

		rbuf->cur += avail;
		ret += avail;
		buf += avail;
		bufsz -= avail;
		*chunksz -= avail;
	}

	return ret;
}

static int
http_chunk(struct bufio *bio, const void *buf, size_t len)
{
	int r;

	if (bufio_compose_fmt(bio, "%zx\r\n", len) == -1 ||
	    bufio_compose(bio, buf, len) == -1 ||
	    bufio_compose(bio, "\r\n", 2) == -1)
		return 1;

	do {
		r = bufio_write(bio);
		if (r == -1 && errno != EAGAIN)
			errx(1, "bufio_read: %s", bufio_io_err(bio));
	} while (bio->wbuf.len != 0);

	return 0;
}

static int
get_refs(int https, const char *host, const char *port, const char *path)
{
	struct bufio		 bio;
	char			 buf[GOT_PKT_MAX];
	const struct got_error	*e;
	size_t			 chunksz = 0;
	ssize_t			 r;
	int			 skip;
	int			 chunked;
	int			 sock;
	int			 ret = -1;

	if ((sock = dial(https, host, port)) == -1)
		return -1;

	if (bufio_init(&bio)) {
		warnx("bufio_init");
		goto err;
	}
	bufio_set_fd(&bio, sock);
	if (https && bufio_starttls(&bio, host, 0, NULL, 0, NULL, 0) == -1) {
		warnx("bufio_starttls");
		goto err;
	}

	if (http_open(&bio, https, "GET", host, port, path, "info/refs",
	    "service=git-upload-pack", NULL) == -1)
		goto err;

	/* Fetch the initial reference announcement from the server. */
	if (http_parse_reply(&bio, &chunked, UPLOAD_PACK_ADV) == -1)
		goto err;

	/* skip first pack; why git over http is like this? */
	r = http_read(&bio, chunked, &chunksz, buf, 4, NULL);
	if (r <= 0)
		goto err;

	e = got_pkt_readlen(&skip, buf, verbose);
	if (e) {
		warnx("%s", e->msg);
		goto err;
	}

	/* TODO: validate it's # service=git-upload-pack\n */
	while (skip > 0) {
		r = http_read(&bio, chunked, &chunksz, buf,
		    MINIMUM(skip, sizeof(buf)), NULL);
		if (r <= 0)
			goto err;
		skip -= r;
	}

	http_read(&bio, chunked, &chunksz, NULL, 0, stdout);
	fflush(stdout);
	ret = 0;
err:
	bufio_close_sync(&bio);
	bufio_free(&bio);
	return ret;
}

static int
upload_request(int https, const char *host, const char *port, const char *path,
    FILE *in)
{
	struct bufio		 bio;
	char			 buf[GOT_PKT_MAX];
	const struct got_error	*e;
	ssize_t			 r;
	size_t			 chunksz = 0;
	int			 t;
	int			 chunked;
	int			 sock;
	int			 ret = -1;

	if ((sock = dial(https, host, port)) == -1)
		return -1;

	if (bufio_init(&bio)) {
		warnx("bufio_init");
		goto err;
	}
	bufio_set_fd(&bio, sock);
	if (https && bufio_starttls(&bio, host, 0, NULL, 0, NULL, 0) == -1) {
		warnx("bufio_starttls");
		goto err;
	}
#ifndef PROFILE
	/* TODO: can we push this upwards such that get_refs() is covered? */
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif
	if (http_open(&bio, https, "POST", host, port, path, "git-upload-pack",
	    NULL, UPLOAD_PACK_REQ) == -1)
		goto err;

	/*
	 * Read have/want lines generated by got-fetch-pack and forward
	 * them to the server in the POST request body.
	 */
	for (;;) {
		r = fread(buf, 1, 4, in);
		if (r != 4)
			goto err;

		e = got_pkt_readlen(&t, buf, verbose);
		if (e) {
			warnx("%s", e->msg);
			goto err;
		}

		if (t == 0) {
			const char *flushpkt = "0000";
			if (http_chunk(&bio, flushpkt, strlen(flushpkt)))
				goto err;
			continue; /* got-fetch-pack will send "done" */
		}

		if (t < 6) {
			warnx("pktline len is too small");
			goto err;
		}

		r = fread(buf + 4, 1, t - 4, in);
		if (r != t - 4)
			goto err;

		if (http_chunk(&bio, buf, t))
			goto err;

		/*
		 * Once got-fetch-pack is done the server will
		 * send pack file data.
		 */
		if (t == 9 && strncmp(buf + 4, "done\n", 5) == 0) {
			if (http_chunk(&bio, NULL, 0))
				goto err;
			break;
		}
	}

	if (http_parse_reply(&bio, &chunked, UPLOAD_PACK_RES) == -1)
		goto err;

	/* Fetch pack file data from server. */
	http_read(&bio, chunked, &chunksz, NULL, 0, stdout);

	ret = 0;
err:
	bufio_close_sync(&bio);
	bufio_free(&bio);
	return ret;
}

static __dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-qv] proto host port path\n",
	     getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct pollfd	 pfd;
	const char	*host, *port;
	char		*path;
	int		 https = 0;
	int		 ch;

#ifndef PROFILE
	if (pledge("stdio rpath inet dns unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "qv")) != -1) {
		switch (ch) {
		case 'q':
			verbose = -1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 4)
		usage();

	https = strcmp(argv[0], "https") == 0;
#ifndef PROFILE
	if (https) {
		if (unveil("/etc/ssl/cert.pem", "r") == -1)
			err(1, "unveil /etc/ssl/cert.pem");
	} else {
		/* drop "rpath" */
		if (pledge("stdio inet dns unveil", NULL) == -1)
			err(1, "pledge");
	}
#else
	if (unveil("gmon.out", "rwc") != 0)
		err(1, "unveil gmon.out");
#endif
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil NULL");

	host = argv[1];
	port = argv[2];
	path = argv[3];
	got_path_strip_trailing_slashes(path);

	if (get_refs(https, host, port, path) == -1)
		errx(1, "failed to get refs");

	pfd.fd = 0;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, INFTIM) == -1)
		err(1, "poll");

	if ((ch = fgetc(stdin)) == EOF)
		return 0;

	ungetc(ch, stdin);
	if (upload_request(https, host, port, path, stdin) == -1) {
		errx(1, "failed to upload request");
	}

	return 0;
}
