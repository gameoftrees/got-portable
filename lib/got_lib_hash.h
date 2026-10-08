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

#define GOT_SHA1_STRING_ZERO "0000000000000000000000000000000000000000"
#define GOT_SHA256_STRING_ZERO "0000000000000000000000000000000000000000000000000000000000000000"

int got_parse_xdigit(uint8_t *, const char *);

char *got_sha1_digest_to_str(const uint8_t *, char *, size_t);
char *got_sha256_digest_to_str(const uint8_t *, char *, size_t);
char *got_hash_digest_to_str(const uint8_t *, char *, size_t,
    enum got_hash_algorithm);

int got_parse_hash_digest(uint8_t *, const char *, enum got_hash_algorithm);

/*
 * Write the string representation fo an object ID in the given buffer.
 * This buffer must be at least GOT_OBJECT_ID_HEX_MAXLEN bytes in size.
 * The output depends on the hash function used by the repository format.
 */
char *got_object_id_hex(struct got_object_id *, char *, size_t);

int got_parse_object_id(struct got_object_id *, const char *,
    enum got_hash_algorithm);

static inline int
got_hash_digest_length(enum got_hash_algorithm algo)
{
	switch (algo) {
	case GOT_HASH_SHA1:
		return SHA1_DIGEST_LENGTH;
	case GOT_HASH_SHA256:
		return SHA256_DIGEST_LENGTH;
	default:
		return 0;
	}
}

static inline int
got_hash_digest_string_length(enum got_hash_algorithm algo)
{
	switch (algo) {
	case GOT_HASH_SHA1:
		return SHA1_DIGEST_STRING_LENGTH;
	case GOT_HASH_SHA256:
		return SHA256_DIGEST_STRING_LENGTH;
	default:
		return 0;
	}
}

struct got_hash {
	SHA1_CTX		 sha1_ctx;
	SHA2_CTX		 sha256_ctx;
	enum got_hash_algorithm	 algo;
};

/*
 * These functions allow to compute and check hashes.
 * The hash function used is specified during got_hash_init.
 * Data can be added with got_hash_update and, once done, the checksum
 * saved in a buffer long at least GOT_HASH_DIGEST_MAXLEN bytes with
 * got_hash_final or in an got_object_id with got_hash_final_object_id.
 */
void	got_hash_init(struct got_hash *, enum got_hash_algorithm);
void	got_hash_update(struct got_hash *, const void *, size_t);
void	got_hash_final(struct got_hash *, uint8_t *);
void	got_hash_final_object_id(struct got_hash *, struct got_object_id *);

/*
 * Compare two hash digest; similar to memcmp().
 */
int	got_hash_cmp(enum got_hash_algorithm, uint8_t *, uint8_t *);

/* Return a human-readable name of the hash algorithm. */
const char *got_hash_algo_name(enum got_hash_algorithm);
