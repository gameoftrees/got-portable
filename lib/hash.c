/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "got_object.h"
#include "got_error.h"

#include "got_lib_hash.h"

struct got_object_id *
got_object_id_dup(struct got_object_id *id1)
{
	struct got_object_id *id2;

	id2 = malloc(sizeof(*id2));
	if (id2 == NULL)
		return NULL;
	memcpy(id2, id1, sizeof(*id2));
	return id2;
}

int
got_object_id_cmp(const struct got_object_id *id1,
    const struct got_object_id *id2)
{
	if (id1->algo != id2->algo)
		abort();
	return memcmp(id1->hash, id2->hash, got_hash_digest_length(id1->algo));
}

const struct got_error *
got_object_id_str(char **outbuf, struct got_object_id *id)
{
	static const size_t len = GOT_OBJECT_ID_HEX_MAXLEN;

	*outbuf = malloc(len);
	if (*outbuf == NULL)
		return got_error_from_errno("malloc");

	if (got_object_id_hex(id, *outbuf, len) == NULL) {
		free(*outbuf);
		*outbuf = NULL;
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);
	}

	return NULL;
}

int
got_parse_xdigit(uint8_t *val, const char *hex)
{
	char *ep;
	long lval;

	errno = 0;
	lval = strtol(hex, &ep, 16);
	if (hex[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN))
		return 0;

	*val = (uint8_t)lval;
	return 1;
}

static int
parse_digest(uint8_t *digest, int len, const char *line)
{
	uint8_t b = 0;
	char hex[3] = {'\0', '\0', '\0'};
	int i, j;

	for (i = 0; i < len; i++) {
		if (line[0] == '\0' || line[1] == '\0')
			return 0;
		for (j = 0; j < 2; j++) {
			hex[j] = *line;
			line++;
		}
		if (!got_parse_xdigit(&b, hex))
			return 0;
		digest[i] = b;
	}

	return 1;
}

static char *
digest_to_str(const uint8_t *digest, int len, char *buf)
{
	const char hex[] = "0123456789abcdef";
	char *p = buf;
	int i;

	for (i = 0; i < len; i++) {
		*p++ = hex[digest[i] >> 4];
		*p++ = hex[digest[i] & 0xf];
	}
	*p = '\0';

	return buf;
}

char *
got_sha1_digest_to_str(const uint8_t *digest, char *buf, size_t size)
{
	if (size < SHA1_DIGEST_STRING_LENGTH)
		return NULL;
	return digest_to_str(digest, SHA1_DIGEST_LENGTH, buf);
}

char *
got_sha256_digest_to_str(const uint8_t *digest, char *buf, size_t size)
{
	if (size < SHA256_DIGEST_STRING_LENGTH)
		return NULL;
	return digest_to_str(digest, SHA256_DIGEST_LENGTH, buf);
}

char *
got_hash_digest_to_str(const uint8_t *digest, char *buf, size_t size,
    enum got_hash_algorithm algo)
{
	switch (algo) {
	case GOT_HASH_SHA1:
		return got_sha1_digest_to_str(digest, buf, size);
	case GOT_HASH_SHA256:
		return got_sha256_digest_to_str(digest, buf, size);
	default:
		abort();
		return NULL;
	}
}

int
got_parse_hash_digest(uint8_t *digest, const char *line,
    enum got_hash_algorithm algo)
{
	switch (algo) {
	case GOT_HASH_SHA1:
		return parse_digest(digest, SHA1_DIGEST_LENGTH, line);
	case GOT_HASH_SHA256:
		return parse_digest(digest, SHA256_DIGEST_LENGTH, line);
	default:
		return 0;
	}
}

char *
got_object_id_hex(struct got_object_id *id, char *buf, size_t len)
{
	if (id->algo == GOT_HASH_SHA1)
		return got_sha1_digest_to_str(id->hash, buf, len);
	if (id->algo == GOT_HASH_SHA256)
		return got_sha256_digest_to_str(id->hash, buf, len);
	abort();
}

int
got_parse_object_id(struct got_object_id *id, const char *line,
    enum got_hash_algorithm algo)
{
	memset(id, 0, sizeof(*id));
	id->algo = algo;
	return got_parse_hash_digest(id->hash, line, algo);
}

void
got_hash_init(struct got_hash *hash, enum got_hash_algorithm algo)
{
	memset(hash, 0, sizeof(*hash));
	hash->algo = algo;

	if (algo == GOT_HASH_SHA1)
		SHA1Init(&hash->sha1_ctx);
	else if (algo == GOT_HASH_SHA256)
		SHA256Init(&hash->sha256_ctx);
	else
		abort();
}

void
got_hash_update(struct got_hash *hash, const void *data, size_t len)
{
	if (hash->algo == GOT_HASH_SHA1)
		SHA1Update(&hash->sha1_ctx, data, len);
	else if (hash->algo == GOT_HASH_SHA256)
		SHA256Update(&hash->sha256_ctx, data, len);
	else
		abort();
}

void
got_hash_final(struct got_hash *hash, uint8_t *out)
{
	if (hash->algo == GOT_HASH_SHA1)
		SHA1Final(out, &hash->sha1_ctx);
	else if (hash->algo == GOT_HASH_SHA256)
		SHA256Final(out, &hash->sha256_ctx);
	else
		abort();
}

void
got_hash_final_object_id(struct got_hash *hash, struct got_object_id *id)
{
	memset(id, 0, sizeof(*id));
	id->algo = hash->algo;
	if (hash->algo == GOT_HASH_SHA1)
		SHA1Final(id->hash, &hash->sha1_ctx);
	else if (hash->algo == GOT_HASH_SHA256)
		SHA256Final(id->hash, &hash->sha256_ctx);
	else
		abort();
}

int
got_hash_cmp(enum got_hash_algorithm algo, uint8_t *b1, uint8_t *b2)
{
	if (algo == GOT_HASH_SHA1)
		return memcmp(b1, b2, SHA1_DIGEST_LENGTH);
	else if (algo == GOT_HASH_SHA256)
		return memcmp(b1, b2, SHA256_DIGEST_LENGTH);
	else
		abort();
	return -1;
}

const char *
got_hash_algo_name(enum got_hash_algorithm algo)
{
	switch (algo) {
	case GOT_HASH_SHA1:
		return "sha1";
	case GOT_HASH_SHA256:
		return "sha256";
	default:
		return "unknown";
	}
}
