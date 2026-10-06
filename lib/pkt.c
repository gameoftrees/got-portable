/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "got_error.h"
#include "got_lib_pkt.h"
#include "got_lib_poll.h"

const struct got_error *
got_pkt_readn(ssize_t *off, int fd, void *buf, size_t n,
    int timeout)
{
	const struct got_error *err;
	size_t len;

	err = got_poll_read_full_timeout(fd, &len, buf, n, n,
	    timeout);
	if (err)
		return err;

	/* XXX size_t -> ssize_t */
	if (len > SSIZE_MAX)
		return got_error(GOT_ERR_RANGE);
	*off = len;
	return NULL;
}

const struct got_error *
got_pkt_flushpkt(int fd, int chattygot)
{
	ssize_t w;

	if (chattygot > 1)
		fprintf(stderr, "%s: writepkt: 0000\n", getprogname());

	w = write(fd, "0000", 4);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != 4)
		return got_error(GOT_ERR_IO);
	return NULL;
}

const struct got_error *
got_pkt_readlen(int *len, const char *str, int chattygot)
{
	int	 i;

	*len = 0;
	for (i = 0; i < 4; i++) {
		if ('0' <= str[i] && str[i] <= '9') {
			*len *= 16;
			*len += str[i] - '0';
		} else if ('a' <= str[i] && str[i] <= 'f') {
			*len *= 16;
			*len += str[i] - 'a' + 10;
		} else {
			if (chattygot)
				fprintf(stderr, "%s: bad length: '.4%s'\n",
				    getprogname(), str);
			return got_error_msg(GOT_ERR_BAD_PACKET,
			    "packet length has invalid format");
		}
	}
	return NULL;
}

/*
 * Packet header contains a 4-byte hexstring which specifies the length
 * of data which follows.
 */
const struct got_error *
got_pkt_readhdr(int *datalen, int fd, int chattygot, int timeout)
{
	static const struct got_error *err;
	char lenstr[4];
	ssize_t r;
	int n;

	*datalen = 0;

	err = got_pkt_readn(&r, fd, lenstr, 4, timeout);
	if (err)
		return err;
	if (r == 0) {
		/* implicit "0000" */
		if (chattygot > 1)
			fprintf(stderr, "%s: readpkt: 0000\n", getprogname());
		return NULL;
	}
	if (r != 4)
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "wrong packet header length");

	err = got_pkt_readlen(&n, lenstr, chattygot);
	if (n == 0)
		return err;
	if (n <= 4)
		return got_error_msg(GOT_ERR_BAD_PACKET, "packet too short");
	n -= 4;

	*datalen = n;
	return NULL;
}

const struct got_error *
got_pkt_readpkt(int *outlen, int fd, char *buf, int buflen, int chattygot,
    int timeout)
{
	const struct got_error *err = NULL;
	int datalen, i;
	ssize_t n;

	memset(buf, '\0', buflen);
	*outlen = 0;

	err = got_pkt_readhdr(&datalen, fd, chattygot, timeout);
	if (err)
		return err;

	if (datalen > buflen)
		return got_error(GOT_ERR_NO_SPACE);

	err = got_pkt_readn(&n, fd, buf, datalen, timeout);
	if (err)
		return err;
	if (n != datalen)
		return got_error_msg(GOT_ERR_BAD_PACKET, "short packet");

	if (chattygot > 1) {
		fprintf(stderr, "%s: readpkt: %zd:\t", getprogname(), n);
		for (i = 0; i < n; i++) {
			if (isprint((unsigned char)buf[i]))
				fputc(buf[i], stderr);
			else
				fprintf(stderr, "[0x%.2x]", buf[i]);
		}
		fputc('\n', stderr);
	}

	*outlen = n;
	return NULL;
}

const struct got_error *
got_pkt_writepkt(int fd, char *buf, int nbuf, int chattygot)
{
	char len[5];
	int i, ret;
	ssize_t w;

	ret = snprintf(len, sizeof(len), "%04x", nbuf + 4);
	if (ret < 0 || (size_t)ret >= sizeof(len))
		return got_error(GOT_ERR_NO_SPACE);
	w = write(fd, len, 4);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != 4)
		return got_error(GOT_ERR_IO);
	w = write(fd, buf, nbuf);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != nbuf)
		return got_error(GOT_ERR_IO);
	if (chattygot > 1) {
		fprintf(stderr, "%s: writepkt: %s:\t", getprogname(), len);
		for (i = 0; i < nbuf; i++) {
			if (isprint((unsigned char)buf[i]))
				fputc(buf[i], stderr);
			else
				fprintf(stderr, "[0x%.2x]", buf[i]);
		}
		fputc('\n', stderr);
	}
	return NULL;
}
