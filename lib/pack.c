/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <endian.h>
#include <unistd.h>
#include <zlib.h>
#include <imsg.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_delta_cache.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_qid.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

static const struct got_error *
verify_fanout_table(uint32_t *fanout_table)
{
	int i;

	for (i = 0; i < 0xff - 1; i++) {
		if (be32toh(fanout_table[i]) > be32toh(fanout_table[i + 1]))
			return got_error(GOT_ERR_BAD_PACKIDX);
	}

	return NULL;
}

const struct got_error *
got_packidx_init_hdr(struct got_packidx *p, int verify, off_t packfile_size)
{
	const struct got_error *err = NULL;
	struct got_packidx_v2_hdr *h;
	struct got_hash ctx;
	uint8_t hash[GOT_HASH_DIGEST_MAXLEN];
	size_t nobj, len_fanout, len_ids, offset, remain, digest_string_len;
	ssize_t n;
	int i;

	got_hash_init(&ctx, p->algo);
	digest_string_len = got_hash_digest_length(p->algo);

	h = &p->hdr;
	offset = 0;
	remain = p->len;

	if (remain < sizeof(*h->magic)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->magic = (uint32_t *)(p->map + offset);
	else {
		h->magic = malloc(sizeof(*h->magic));
		if (h->magic == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->magic, sizeof(*h->magic));
		if (n < 0) {
			err = got_error_from_errno("read");
			goto done;
		} else if (n != sizeof(*h->magic)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (*h->magic != htobe32(GOT_PACKIDX_V2_MAGIC)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	offset += sizeof(*h->magic);
	remain -= sizeof(*h->magic);

	if (verify)
		got_hash_update(&ctx, h->magic, sizeof(*h->magic));

	if (remain < sizeof(*h->version)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->version = (uint32_t *)(p->map + offset);
	else {
		h->version = malloc(sizeof(*h->version));
		if (h->version == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->version, sizeof(*h->version));
		if (n < 0) {
			err = got_error_from_errno("read");
			goto done;
		} else if (n != sizeof(*h->version)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (*h->version != htobe32(GOT_PACKIDX_VERSION)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	offset += sizeof(*h->version);
	remain -= sizeof(*h->version);

	if (verify)
		got_hash_update(&ctx, h->version, sizeof(*h->version));

	len_fanout =
	    sizeof(*h->fanout_table) * GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS;
	if (remain < len_fanout) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->fanout_table = (uint32_t *)(p->map + offset);
	else {
		h->fanout_table = malloc(len_fanout);
		if (h->fanout_table == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->fanout_table, len_fanout);
		if (n < 0) {
			err = got_error_from_errno("read");
			goto done;
		} else if (n != len_fanout) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	err = verify_fanout_table(h->fanout_table);
	if (err)
		goto done;
	if (verify)
		got_hash_update(&ctx, h->fanout_table, len_fanout);
	offset += len_fanout;
	remain -= len_fanout;

	nobj = be32toh(h->fanout_table[0xff]);
	len_ids = nobj * got_hash_digest_length(p->algo);
	if (len_ids <= nobj || len_ids > remain) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->sorted_ids = p->map + offset;
	else {
		h->sorted_ids = malloc(len_ids);
		if (h->sorted_ids == NULL) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
		n = read(p->fd, h->sorted_ids, len_ids);
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != len_ids) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		got_hash_update(&ctx, h->sorted_ids, len_ids);
	offset += len_ids;
	remain -= len_ids;

	if (remain < nobj * sizeof(*h->crc32)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->crc32 = (uint32_t *)((uint8_t*)(p->map + offset));
	else {
		h->crc32 = malloc(nobj * sizeof(*h->crc32));
		if (h->crc32 == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->crc32, nobj * sizeof(*h->crc32));
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != nobj * sizeof(*h->crc32)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		got_hash_update(&ctx, h->crc32, nobj * sizeof(*h->crc32));
	remain -= nobj * sizeof(*h->crc32);
	offset += nobj * sizeof(*h->crc32);

	if (remain < nobj * sizeof(*h->offsets)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->offsets = (uint32_t *)((uint8_t*)(p->map + offset));
	else {
		h->offsets = malloc(nobj * sizeof(*h->offsets));
		if (h->offsets == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->offsets, nobj * sizeof(*h->offsets));
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != nobj * sizeof(*h->offsets)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		got_hash_update(&ctx, h->offsets, nobj * sizeof(*h->offsets));
	remain -= nobj * sizeof(*h->offsets);
	offset += nobj * sizeof(*h->offsets);

	/* Large file offsets are contained only in files > 2GB. */
	if (verify || packfile_size > 0x7fffffff) {
		for (i = 0; i < nobj; i++) {
			uint32_t o = h->offsets[i];
			if (o & htobe32(GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX))
				p->nlargeobj++;
		}
	}
	if (p->nlargeobj == 0)
		goto checksum;
	else if (packfile_size <= 0x7fffffff) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (remain < p->nlargeobj * sizeof(*h->large_offsets)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->large_offsets = (uint64_t *)((uint8_t*)(p->map + offset));
	else {
		h->large_offsets = malloc(p->nlargeobj *
		    sizeof(*h->large_offsets));
		if (h->large_offsets == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		n = read(p->fd, h->large_offsets,
		    p->nlargeobj * sizeof(*h->large_offsets));
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != p->nlargeobj * sizeof(*h->large_offsets)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		got_hash_update(&ctx, h->large_offsets,
		    p->nlargeobj * sizeof(*h->large_offsets));
	remain -= p->nlargeobj * sizeof(*h->large_offsets);
	offset += p->nlargeobj * sizeof(*h->large_offsets);

checksum:
	if (remain < digest_string_len * 2) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map) {
		memcpy(h->trailer.packfile_hash, p->map + offset,
		    digest_string_len);
		memcpy(h->trailer.packidx_hash,
		    p->map + offset + digest_string_len, digest_string_len);
	} else {
		n = read(p->fd, h->trailer.packfile_hash, digest_string_len);
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != digest_string_len) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
		n = read(p->fd, h->trailer.packidx_hash, digest_string_len);
		if (n < 0)
			err = got_error_from_errno("read");
		else if (n != digest_string_len) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify) {
		got_hash_update(&ctx, h->trailer.packfile_hash,
		    digest_string_len);
		got_hash_final(&ctx, hash);
		if (got_hash_cmp(ctx.algo, hash, h->trailer.packidx_hash) != 0)
			err = got_error(GOT_ERR_PACKIDX_CSUM);
	}
done:
	return err;
}

const struct got_error *
got_packidx_open(struct got_packidx **packidx,
    int dir_fd, const char *relpath, int verify,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	struct got_packidx *p = NULL;
	char *pack_relpath;
	struct stat idx_sb, pack_sb;

	*packidx = NULL;

	err = got_packidx_get_packfile_path(&pack_relpath, relpath);
	if (err)
		return err;

	/*
	 * Ensure that a corresponding pack file exists.
	 * Some Git repositories have this problem. Git seems to ignore
	 * the existence of lonely pack index files but we do not.
	 */
	if (fstatat(dir_fd, pack_relpath, &pack_sb, 0) == -1) {
		if (errno == ENOENT)
			err = got_error_path(relpath, GOT_ERR_LONELY_PACKIDX);
		else
			err = got_error_from_errno2("fstatat", pack_relpath);
		goto done;
	}

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	p->algo = algo;

	p->fd = openat(dir_fd, relpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (p->fd == -1) {
		err = got_error_from_errno2("openat", relpath);
		goto done;
	}

	if (fstat(p->fd, &idx_sb) != 0) {
		err = got_error_from_errno2("fstat", relpath);
		goto done;
	}
	p->len = idx_sb.st_size;
	if (p->len < sizeof(p->hdr)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	p->path_packidx = strdup(relpath);
	if (p->path_packidx == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	if (p->len > 0 && p->len <= SIZE_MAX) {
		p->map = mmap(NULL, p->len, PROT_READ, MAP_PRIVATE, p->fd, 0);
		if (p->map == MAP_FAILED) {
			if (errno != ENOMEM) {
				err = got_error_from_errno("mmap");
				goto done;
			}
			p->map = NULL; /* fall back to read(2) */
		}
	}
#endif

	err = got_packidx_init_hdr(p, verify, pack_sb.st_size);
done:
	if (err) {
		if (p)
			got_packidx_close(p);
	} else
		*packidx = p;
	free(pack_relpath);
	return err;
}

const struct got_error *
got_packidx_close(struct got_packidx *packidx)
{
	const struct got_error *err = NULL;

	free(packidx->path_packidx);
	if (packidx->map) {
		if (munmap(packidx->map, packidx->len) == -1)
			err = got_error_from_errno("munmap");
	} else {
		free(packidx->hdr.magic);
		free(packidx->hdr.version);
		free(packidx->hdr.fanout_table);
		free(packidx->hdr.sorted_ids);
		free(packidx->hdr.crc32);
		free(packidx->hdr.offsets);
		free(packidx->hdr.large_offsets);
	}
	if (close(packidx->fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(packidx->sorted_offsets);
	free(packidx->sorted_large_offsets);
	free(packidx);

	return err;
}

const struct got_error *
got_packidx_get_packfile_path(char **path_packfile, const char *path_packidx)
{
	size_t size;

	/* Packfile path contains ".pack" instead of ".idx", so add one byte. */
	size = strlen(path_packidx) + 2;
	if (size < GOT_PACKFILE_NAMELEN + 1)
		return got_error_path(path_packidx, GOT_ERR_BAD_PATH);

	*path_packfile = malloc(size);
	if (*path_packfile == NULL)
		return got_error_from_errno("malloc");

	/* Copy up to and excluding ".idx". */
	if (strlcpy(*path_packfile, path_packidx,
	    size - strlen(GOT_PACKIDX_SUFFIX) - 1) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	if (strlcat(*path_packfile, GOT_PACKFILE_SUFFIX, size) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	return NULL;
}

off_t
got_packidx_get_object_offset(struct got_packidx *packidx, int idx)
{
	uint32_t offset = be32toh(packidx->hdr.offsets[idx]);
	if (offset & GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
		uint64_t loffset;
		idx = offset & GOT_PACKIDX_OFFSET_VAL_MASK;
		if (idx < 0 || idx >= packidx->nlargeobj ||
		    packidx->hdr.large_offsets == NULL)
			return -1;
		loffset = be64toh(packidx->hdr.large_offsets[idx]);
		return (loffset > INT64_MAX ? -1 : (off_t)loffset);
	}
	return (off_t)(offset & GOT_PACKIDX_OFFSET_VAL_MASK);
}

int
got_packidx_get_object_idx(struct got_packidx *packidx,
    struct got_object_id *id)
{
	u_int8_t id0 = id->hash[0];
	uint32_t totobj = be32toh(packidx->hdr.fanout_table[0xff]);
	int left = 0, right = totobj - 1;
	size_t digest_len = got_hash_digest_length(packidx->algo);

	if (id0 > 0)
		left = be32toh(packidx->hdr.fanout_table[id0 - 1]);

	while (left <= right) {
		uint8_t *oid;
		int i, cmp;

		i = ((left + right) / 2);
		oid = packidx->hdr.sorted_ids + i * digest_len;
		cmp = memcmp(id->hash, oid, digest_len);
		if (cmp == 0)
			return i;
		else if (cmp > 0)
			left = i + 1;
		else if (cmp < 0)
			right = i - 1;
	}

	return -1;
}

static int
offset_cmp(const void *pa, const void *pb)
{
	const struct got_pack_offset_index *a, *b;

	a = (const struct got_pack_offset_index *)pa;
	b = (const struct got_pack_offset_index *)pb;

	if (a->offset < b->offset)
		return -1;
	else if (a->offset > b->offset)
		return 1;

	return 0;
}

static int
large_offset_cmp(const void *pa, const void *pb)
{
	const struct got_pack_large_offset_index *a, *b;

	a = (const struct got_pack_large_offset_index *)pa;
	b = (const struct got_pack_large_offset_index *)pb;

	if (a->offset < b->offset)
		return -1;
	else if (a->offset > b->offset)
		return 1;

	return 0;
}

static const struct got_error *
build_offset_index(struct got_packidx *p)
{
	uint32_t nobj = be32toh(p->hdr.fanout_table[0xff]);
	unsigned int i, j, k;

	p->sorted_offsets = calloc(nobj - p->nlargeobj,
	    sizeof(p->sorted_offsets[0]));
	if (p->sorted_offsets == NULL)
		return got_error_from_errno("calloc");

	if (p->nlargeobj > 0) {
		p->sorted_large_offsets = calloc(p->nlargeobj,
		    sizeof(p->sorted_large_offsets[0]));
		if (p->sorted_large_offsets == NULL)
			return got_error_from_errno("calloc");
	}

	j = 0;
	k = 0;
	for (i = 0; i < nobj; i++) {
		uint32_t offset = be32toh(p->hdr.offsets[i]);
		if (offset & GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
			uint64_t loffset;
			uint32_t idx;
			idx = offset & GOT_PACKIDX_OFFSET_VAL_MASK;
			if (idx >= p->nlargeobj ||
			    p->nlargeobj == 0 ||
			    p->hdr.large_offsets == NULL)
				return got_error(GOT_ERR_BAD_PACKIDX);
			loffset = be64toh(p->hdr.large_offsets[idx]);
			p->sorted_large_offsets[j].offset = loffset;
			p->sorted_large_offsets[j].idx = i;
			j++;
		} else {
			p->sorted_offsets[k].offset = offset;
			p->sorted_offsets[k].idx = i;
			k++;
		}
	}
	if (j != p->nlargeobj || k != nobj - p->nlargeobj)
		return got_error(GOT_ERR_BAD_PACKIDX);

	qsort(p->sorted_offsets, nobj - p->nlargeobj,
	    sizeof(p->sorted_offsets[0]), offset_cmp);

	if (p->sorted_large_offsets)
		qsort(p->sorted_large_offsets, p->nlargeobj,
		    sizeof(p->sorted_large_offsets[0]), large_offset_cmp);

	return NULL;
}

const struct got_error *
got_packidx_get_offset_idx(int *idx, struct got_packidx *packidx, off_t offset)
{
	const struct got_error *err;
	uint32_t totobj = be32toh(packidx->hdr.fanout_table[0xff]);
	int i, left, right;

	*idx = -1;

	if (packidx->sorted_offsets == NULL) {
		err = build_offset_index(packidx);
		if (err)
			return err;
	}

	if (offset >= 0x7fffffff) {
		uint64_t lo;
		left = 0, right = packidx->nlargeobj - 1;
		while (left <= right) {
			i = ((left + right) / 2);
			lo = packidx->sorted_large_offsets[i].offset;
			if (lo == offset) {
				*idx = packidx->sorted_large_offsets[i].idx;
				break;
			} else if (offset > lo)
				left = i + 1;
			else if (offset < lo)
				right = i - 1;
		}
	} else {
		uint32_t o;
		left = 0, right = totobj - packidx->nlargeobj - 1;
		while (left <= right) {
			i = ((left + right) / 2);
			o = packidx->sorted_offsets[i].offset;
			if (o == offset) {
				*idx = packidx->sorted_offsets[i].idx;
				break;
			} else if (offset > o)
				left = i + 1;
			else if (offset < o)
				right = i - 1;
		}
	}

	return NULL;
}

const struct got_error *
got_packidx_get_object_id(struct got_object_id *id,
    struct got_packidx *packidx, int idx)
{
	uint32_t totobj = be32toh(packidx->hdr.fanout_table[0xff]);
	uint8_t *oid;
	size_t digest_len = got_hash_digest_length(packidx->algo);

	if (idx < 0 || idx >= totobj)
		return got_error(GOT_ERR_NO_OBJ);

	oid = packidx->hdr.sorted_ids + idx * digest_len;
	memcpy(id->hash, oid, digest_len);
	id->algo = packidx->algo;
	return NULL;
}

const struct got_error *
got_packidx_match_id_str_prefix(struct got_object_id_queue *matched_ids,
    struct got_packidx *packidx, const char *id_str_prefix)
{
	const struct got_error *err = NULL;
	u_int8_t id0;
	uint32_t totobj = be32toh(packidx->hdr.fanout_table[0xff]);
	char hex[3];
	size_t prefix_len = strlen(id_str_prefix);
	uint8_t *oid;
	uint32_t i = 0;
	size_t digest_len = got_hash_digest_length(packidx->algo);

	if (prefix_len < 2)
		return got_error_path(id_str_prefix, GOT_ERR_BAD_OBJ_ID_STR);

	hex[0] = id_str_prefix[0];
	hex[1] = id_str_prefix[1];
	hex[2] = '\0';
	if (!got_parse_xdigit(&id0, hex))
		return got_error_path(id_str_prefix, GOT_ERR_BAD_OBJ_ID_STR);

	if (id0 > 0)
		i = be32toh(packidx->hdr.fanout_table[id0 - 1]);
	oid = packidx->hdr.sorted_ids + i * digest_len;
	while (i < totobj && oid[0] == id0) {
		char id_str[GOT_HASH_DIGEST_STRING_MAXLEN];
		struct got_object_qid *qid;
		int cmp;

		if (!got_hash_digest_to_str(oid, id_str, sizeof(id_str),
		    packidx->algo))
			return got_error(GOT_ERR_NO_SPACE);

		cmp = strncmp(id_str, id_str_prefix, prefix_len);
		if (cmp < 0) {
			oid = packidx->hdr.sorted_ids + (++i) * digest_len;
			continue;
		} else if (cmp > 0)
			break;

		err = got_object_qid_alloc_partial(&qid);
		if (err)
			return err;
		memcpy(qid->id.hash, oid, digest_len);
		qid->id.algo = packidx->algo;
		STAILQ_INSERT_TAIL(matched_ids, qid, entry);

		oid = packidx->hdr.sorted_ids + (++i) * digest_len;
	}

	return NULL;
}

static void
set_max_datasize(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_DATA, &rl) != 0)
		return;

	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_DATA, &rl);
}

const struct got_error *
got_pack_start_privsep_child(struct got_pack *pack, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno("calloc");

	pack->privsep_child = calloc(1, sizeof(*pack->privsep_child));
	if (pack->privsep_child == NULL) {
		err = got_error_from_errno("calloc");
		free(ibuf);
		return err;
	}
	pack->child_has_tempfiles = 0;
	pack->child_has_delta_outfd = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		close(imsg_fds[0]);
		close(imsg_fds[1]);
		goto done;
	} else if (pid == 0) {
		set_max_datasize();
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_READ_PACK,
		    pack->path_packfile);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		close(imsg_fds[0]);
		goto done;
	}
	pack->privsep_child->imsg_fd = imsg_fds[0];
	pack->privsep_child->pid = pid;
	if (imsgbuf_init(ibuf, imsg_fds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		close(imsg_fds[0]);
		goto done;
	}
	imsgbuf_allow_fdpass(ibuf);

	pack->privsep_child->ibuf = ibuf;

	err = got_privsep_init_pack_child(ibuf, pack, packidx);
	if (err) {
		const struct got_error *child_err;
		err = got_privsep_send_stop(pack->privsep_child->imsg_fd);
		child_err = got_privsep_wait_for_child(
		    pack->privsep_child->pid);
		if (child_err && err == NULL)
			err = child_err;
	}
done:
	if (err) {
		imsgbuf_clear(ibuf);
		free(ibuf);
		free(pack->privsep_child);
		pack->privsep_child = NULL;
	}
	return err;
}

static const struct got_error *
pack_stop_privsep_child(struct got_pack *pack)
{
	const struct got_error *err = NULL;
	const struct got_error *close_err = NULL, *child_err = NULL;

	if (pack->privsep_child == NULL)
		return NULL;

	err = got_privsep_send_stop(pack->privsep_child->imsg_fd);
	if (close(pack->privsep_child->imsg_fd) == -1)
		close_err = got_error_from_errno("close");
	if (close_err && err == NULL)
		err = close_err;
	child_err = got_privsep_wait_for_child(pack->privsep_child->pid);
	if (child_err && err == NULL)
		err = child_err;
	imsgbuf_clear(pack->privsep_child->ibuf);
	free(pack->privsep_child->ibuf);
	free(pack->privsep_child);
	pack->privsep_child = NULL;
	return err;
}

const struct got_error *
got_pack_close(struct got_pack *pack)
{
	const struct got_error *err = NULL;

	err = pack_stop_privsep_child(pack);
	if (pack->map && munmap(pack->map, pack->filesize) == -1 && !err)
		err = got_error_from_errno("munmap");
	if (pack->fd != -1 && close(pack->fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	pack->fd = -1;
	free(pack->path_packfile);
	pack->path_packfile = NULL;
	pack->filesize = 0;
	if (pack->delta_cache) {
		got_delta_cache_free(pack->delta_cache);
		pack->delta_cache = NULL;
	}

	/*
	 * Leave accumfd and basefd alone. They are managed by the
	 * repository layer and can be reused.
	 */

	return err;
}

const struct got_error *
got_pack_parse_object_type_and_size(uint8_t *type, uint64_t *size, size_t *len,
    struct got_pack *pack, off_t offset)
{
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizeN;
	size_t mapoff = 0;
	int i = 0;

	*len = 0;

	if (offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	if (pack->map) {
		if (offset > SIZE_MAX) {
			return got_error_fmt(GOT_ERR_PACK_OFFSET,
			    "offset %lld overflows size_t",
			    (long long)offset);
		}

		mapoff = (size_t)offset;
	} else {
		if (lseek(pack->fd, offset, SEEK_SET) == -1)
			return got_error_from_errno("lseek");
	}

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error_fmt(GOT_ERR_OBJ_TOO_LARGE,
			    "packfile offset %lld", (long long)offset);

		if (pack->map) {
			if (mapoff + sizeof(sizeN) >= pack->filesize)
				return got_error(GOT_ERR_BAD_PACKFILE);
			sizeN = *(pack->map + mapoff);
			mapoff += sizeof(sizeN);
		} else {
			ssize_t n = read(pack->fd, &sizeN, sizeof(sizeN));
			if (n < 0)
				return got_error_from_errno("read");
			if (n != sizeof(sizeN))
				return got_error(GOT_ERR_BAD_PACKFILE);
		}
		*len += sizeof(sizeN);

		if (i == 0) {
			t = (sizeN & GOT_PACK_OBJ_SIZE0_TYPE_MASK) >>
			    GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT;
			s = (sizeN & GOT_PACK_OBJ_SIZE0_VAL_MASK);
		} else {
			size_t shift = 4 + 7 * (i - 1);
			s |= ((sizeN & GOT_PACK_OBJ_SIZE_VAL_MASK) << shift);
		}
		i++;
	} while (sizeN & GOT_PACK_OBJ_SIZE_MORE);

	*type = t;
	*size = s;
	return NULL;
}

static const struct got_error *
open_plain_object(struct got_object **obj, struct got_object_id *id,
    uint8_t type, off_t offset, size_t size, int idx)
{
	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno("calloc");

	(*obj)->type = type;
	(*obj)->flags = GOT_OBJ_FLAG_PACKED;
	(*obj)->pack_idx = idx;
	(*obj)->hdrlen = 0;
	(*obj)->size = size;
	memcpy(&(*obj)->id, id, sizeof((*obj)->id));
	(*obj)->pack_offset = offset;

	return NULL;
}

static const struct got_error *
parse_negative_offset(int64_t *offset, size_t *len, struct got_pack *pack,
    off_t delta_offset)
{
	int64_t o = 0;
	uint8_t offN;
	int i = 0;

	*offset = 0;
	*len = 0;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error(GOT_ERR_NO_SPACE);

		if (pack->map) {
			size_t mapoff;

			if (delta_offset > SIZE_MAX - *len) {
				return got_error_fmt(GOT_ERR_PACK_OFFSET,
				    "mapoff %lld would overflow size_t",
				    (long long)delta_offset + *len);
			}

			mapoff = (size_t)delta_offset + *len;
			if (mapoff + sizeof(offN) >= pack->filesize)
				return got_error(GOT_ERR_PACK_OFFSET);
			offN = *(pack->map + mapoff);
		} else {
			ssize_t n;
			n = read(pack->fd, &offN, sizeof(offN));
			if (n < 0)
				return got_error_from_errno("read");
			if (n != sizeof(offN))
				return got_error(GOT_ERR_BAD_PACKFILE);
		}
		*len += sizeof(offN);

		if (i == 0)
			o = (offN & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		else {
			o++;
			o <<= 7;
			o += (offN & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		}
		i++;
	} while (offN & GOT_PACK_OBJ_DELTA_OFF_MORE);

	*offset = o;
	return NULL;
}

const struct got_error *
got_pack_parse_offset_delta(off_t *base_offset, size_t *len,
    struct got_pack *pack, off_t offset, size_t tslen)
{
	const struct got_error *err;
	int64_t negoffset;
	size_t negofflen;

	*len = 0;

	err = parse_negative_offset(&negoffset, &negofflen, pack,
	    offset + tslen);
	if (err)
		return err;

	/* Compute the base object's offset (must be in the same pack file). */
	*base_offset = (offset - negoffset);
	if (*base_offset <= 0)
		return got_error(GOT_ERR_BAD_PACKFILE);

	*len = negofflen;
	return NULL;
}

static const struct got_error *
read_delta_data(uint8_t **delta_buf, size_t *delta_len,
    size_t *delta_compressed_len, size_t delta_data_offset,
    struct got_pack *pack)
{
	const struct got_error *err = NULL;
	size_t consumed = 0;

	if (pack->map) {
		if (delta_data_offset >= pack->filesize)
			return got_error(GOT_ERR_PACK_OFFSET);
		err = got_inflate_to_mem_mmap(delta_buf, delta_len,
		    &consumed, NULL, pack->map, delta_data_offset,
		    pack->filesize - delta_data_offset);
		if (err)
			return err;
	} else {
		if (lseek(pack->fd, delta_data_offset, SEEK_SET) == -1)
			return got_error_from_errno("lseek");
		err = got_inflate_to_mem_fd(delta_buf, delta_len,
		    &consumed, NULL, 0, pack->fd);
		if (err)
			return err;
	}

	if (delta_compressed_len)
		*delta_compressed_len = consumed;

	return NULL;
}

static const struct got_error *
add_delta(struct got_delta_chain *deltas, off_t delta_offset, size_t tslen,
    int delta_type, size_t delta_size, off_t delta_data_offset)
{
	struct got_delta *delta;

	delta = got_delta_open(delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset);
	if (delta == NULL)
		return got_error_from_errno("got_delta_open");
	/* delta is freed in got_object_close() */
	deltas->nentries++;
	STAILQ_INSERT_HEAD(&deltas->entries, delta, entry);
	return NULL;
}

static const struct got_error *
resolve_offset_delta(struct got_delta_chain *deltas,
    struct got_packidx *packidx, struct got_pack *pack, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size, unsigned int recursion)
{
	const struct got_error *err;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;
	size_t consumed;

	err = got_pack_parse_offset_delta(&base_offset, &consumed, pack,
	    delta_offset, tslen);
	if (err)
		return err;

	delta_data_offset = delta_offset + tslen + consumed;
	if (delta_data_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	if (pack->map == NULL) {
		delta_data_offset = lseek(pack->fd, 0, SEEK_CUR);
		if (delta_data_offset == -1)
			return got_error_from_errno("lseek");
	}

	err = add_delta(deltas, delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset);
	if (err)
		return err;

	/* An offset delta must be in the same packfile. */
	if (base_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_parse_object_type_and_size(&base_type, &base_size,
	    &base_tslen, pack, base_offset);
	if (err)
		return err;

	return got_pack_resolve_delta_chain(deltas, packidx, pack, base_offset,
	    base_tslen, base_type, base_size, recursion - 1);
}

const struct got_error *
got_pack_parse_ref_delta(struct got_object_id *id,
    struct got_pack *pack, off_t delta_offset, int tslen)
{
	size_t digest_len = got_hash_digest_length(pack->algo);

	memset(id, 0, sizeof(*id));
	id->algo = pack->algo;

	if (pack->map) {
		size_t mapoff;

		if (delta_offset > SIZE_MAX - tslen) {
			return got_error_fmt(GOT_ERR_PACK_OFFSET,
			    "mapoff %lld would overflow size_t",
			    (long long)delta_offset + tslen);
		}

		mapoff = delta_offset + tslen;
		if (mapoff + sizeof(*id) >= pack->filesize)
			return got_error(GOT_ERR_PACK_OFFSET);
		memcpy(id->hash, pack->map + mapoff, digest_len);
	} else {
		ssize_t n;
		n = read(pack->fd, id->hash, digest_len);
		if (n < 0)
			return got_error_from_errno("read");
		if (n != digest_len)
			return got_error(GOT_ERR_BAD_PACKFILE);
	}

	return NULL;
}

static const struct got_error *
resolve_ref_delta(struct got_delta_chain *deltas, struct got_packidx *packidx,
    struct got_pack *pack, off_t delta_offset, size_t tslen, int delta_type,
    size_t delta_size, unsigned int recursion)
{
	const struct got_error *err;
	struct got_object_id id;
	int idx;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;

	if (delta_offset + tslen >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_parse_ref_delta(&id, pack, delta_offset, tslen);
	if (err)
		return err;
	if (pack->map) {
		delta_data_offset = delta_offset + tslen +
		    got_hash_digest_length(packidx->algo);
	} else {
		delta_data_offset = lseek(pack->fd, 0, SEEK_CUR);
		if (delta_data_offset == -1)
			return got_error_from_errno("lseek");
	}

	err = add_delta(deltas, delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset);
	if (err)
		return err;

	/* Delta base must be in the same pack file. */
	idx = got_packidx_get_object_idx(packidx, &id);
	if (idx == -1)
		return got_error(GOT_ERR_NO_OBJ);

	base_offset = got_packidx_get_object_offset(packidx, idx);
	if (base_offset == -1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	if (base_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_parse_object_type_and_size(&base_type, &base_size,
	    &base_tslen, pack, base_offset);
	if (err)
		return err;

	return got_pack_resolve_delta_chain(deltas, packidx, pack, base_offset,
	    base_tslen, base_type, base_size, recursion - 1);
}

const struct got_error *
got_pack_resolve_delta_chain(struct got_delta_chain *deltas,
    struct got_packidx *packidx, struct got_pack *pack, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size, unsigned int recursion)
{
	const struct got_error *err = NULL;

	if (--recursion == 0)
		return got_error(GOT_ERR_RECURSION);

	switch (delta_type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		/* Plain types are the final delta base. Recursion ends. */
		err = add_delta(deltas, delta_offset, tslen, delta_type,
		    delta_size, 0);
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		err = resolve_offset_delta(deltas, packidx, pack,
		    delta_offset, tslen, delta_type, delta_size, recursion - 1);
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		err = resolve_ref_delta(deltas, packidx, pack,
		    delta_offset, tslen, delta_type, delta_size, recursion - 1);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	return err;
}

static const struct got_error *
open_delta_object(struct got_object **obj, struct got_packidx *packidx,
    struct got_pack *pack, struct got_object_id *id, off_t offset,
    size_t tslen, int delta_type, size_t delta_size, int idx)
{
	const struct got_error *err = NULL;
	int resolved_type;

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno("calloc");

	(*obj)->flags = 0;
	(*obj)->hdrlen = 0;
	(*obj)->size = 0; /* Not known because deltas aren't applied yet. */
	memcpy(&(*obj)->id, id, sizeof((*obj)->id));
	(*obj)->pack_offset = offset + tslen;

	STAILQ_INIT(&(*obj)->deltas.entries);
	(*obj)->flags |= GOT_OBJ_FLAG_DELTIFIED;
	(*obj)->flags |= GOT_OBJ_FLAG_PACKED;
	(*obj)->pack_idx = idx;

	err = got_pack_resolve_delta_chain(&(*obj)->deltas, packidx, pack,
	    offset, tslen, delta_type, delta_size,
	    GOT_DELTA_CHAIN_RECURSION_MAX);
	if (err)
		goto done;

	err = got_delta_chain_get_base_type(&resolved_type, &(*obj)->deltas);
	if (err)
		goto done;
	(*obj)->type = resolved_type;
done:
	if (err) {
		got_object_close(*obj);
		*obj = NULL;
	}
	return err;
}

const struct got_error *
got_packfile_open_object(struct got_object **obj, struct got_pack *pack,
    struct got_packidx *packidx, int idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	off_t offset;
	uint8_t type;
	uint64_t size;
	size_t tslen;

	*obj = NULL;

	offset = got_packidx_get_object_offset(packidx, idx);
	if (offset == -1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	err = got_pack_parse_object_type_and_size(&type, &size, &tslen,
	    pack, offset);
	if (err)
		return err;

	switch (type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		err = open_plain_object(obj, id, type, offset + tslen,
		    size, idx);
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
	case GOT_OBJ_TYPE_REF_DELTA:
		err = open_delta_object(obj, packidx, pack, id, offset,
		    tslen, type, size, idx);
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

	return err;
}

const struct got_error *
got_pack_get_delta_chain_max_size(uint64_t *max_size,
    struct got_delta_chain *deltas, struct got_pack *pack)
{
	struct got_delta *delta;
	uint64_t base_size = 0, result_size = 0;

	*max_size = 0;
	STAILQ_FOREACH(delta, &deltas->entries, entry) {
		/* Plain object types are the delta base. */
		if (delta->type != GOT_OBJ_TYPE_COMMIT &&
		    delta->type != GOT_OBJ_TYPE_TREE &&
		    delta->type != GOT_OBJ_TYPE_BLOB &&
		    delta->type != GOT_OBJ_TYPE_TAG) {
			const struct got_error *err;
			uint8_t *delta_buf = NULL;
			size_t delta_len;
			int cached = 1;

			if (pack->delta_cache) {
				got_delta_cache_get(&delta_buf, &delta_len,
				    NULL, NULL, pack->delta_cache,
				    delta->data_offset);
			}
			if (delta_buf == NULL) {
				cached = 0;
				err = read_delta_data(&delta_buf, &delta_len,
				    NULL, delta->data_offset, pack);
				if (err)
					return err;
			}
			if (pack->delta_cache && !cached) {
				err = got_delta_cache_add(pack->delta_cache,
				    delta->data_offset, delta_buf, delta_len);
				if (err == NULL)
					cached = 1;
				else if (err->code != GOT_ERR_NO_SPACE) {
					free(delta_buf);
					return err;
				}
			}
			err = got_delta_get_sizes(&base_size, &result_size,
			    delta_buf, delta_len);
			if (!cached)
				free(delta_buf);
			if (err)
				return err;
		} else
			base_size = delta->size;
		if (base_size > *max_size)
			*max_size = base_size;
		if (result_size > *max_size)
			*max_size = result_size;
	}

	return NULL;
}

const struct got_error *
got_pack_get_max_delta_object_size(uint64_t *size, struct got_object *obj,
    struct got_pack *pack)
{
	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0)
		return got_error(GOT_ERR_OBJ_TYPE);

	return got_pack_get_delta_chain_max_size(size, &obj->deltas, pack);
}

const struct got_error *
got_pack_dump_delta_chain_to_file(size_t *result_size,
    struct got_delta_chain *deltas, struct got_pack *pack, FILE *outfile,
    FILE *base_file, FILE *accum_file)
{
	const struct got_error *err = NULL;
	struct got_delta *delta;
	uint8_t *base_buf = NULL, *accum_buf = NULL;
	size_t base_bufsz = 0, accum_bufsz = 0, accum_size = 0;
	/* We process small enough files entirely in memory for speed. */
	const size_t max_bufsize = GOT_DELTA_RESULT_SIZE_CACHED_MAX;
	uint64_t max_size = 0;
	int n = 0;

	*result_size = 0;

	if (STAILQ_EMPTY(&deltas->entries))
		return got_error(GOT_ERR_BAD_DELTA_CHAIN);

	if (pack->delta_cache) {
		uint8_t *delta_buf = NULL, *fulltext = NULL;
		size_t delta_len, fulltext_len;

		delta = STAILQ_LAST(&deltas->entries, got_delta, entry);
		got_delta_cache_get(&delta_buf, &delta_len,
		    &fulltext, &fulltext_len,
		    pack->delta_cache, delta->data_offset);
		if (fulltext) {
			size_t w;

			w = fwrite(fulltext, 1, fulltext_len, outfile);
			if (w != fulltext_len)
				return got_ferror(outfile, GOT_ERR_IO);
			if (fflush(outfile) != 0)
				return got_error_from_errno("fflush");
			*result_size = fulltext_len;
			return NULL;
		}
	}

	if (fseeko(base_file, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");
	if (fseeko(accum_file, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	/* Deltas are ordered in ascending order. */
	STAILQ_FOREACH(delta, &deltas->entries, entry) {
		uint8_t *delta_buf = NULL, *fulltext = NULL;
		size_t delta_len, fulltext_len;
		uint64_t base_size, result_size = 0;
		int cached = 1;
		if (n == 0) {
			size_t mapoff;
			off_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}
			if (pack->map == NULL) {
				if (lseek(pack->fd, delta_data_offset, SEEK_SET)
				    == -1) {
					err = got_error_from_errno("lseek");
					goto done;
				}
			}
			if (delta->size > max_size)
				max_size = delta->size;
			if (max_size > max_bufsize) {
				if (pack->map) {
					if (delta_data_offset > SIZE_MAX) {
						return got_error_fmt(
						    GOT_ERR_RANGE,
						    "delta offset %lld "
						    "overflows size_t",
						    (long long)
						    delta_data_offset);
					}

					mapoff = delta_data_offset;
					err = got_inflate_to_file_mmap(
					    &base_bufsz, NULL, NULL, pack->map,
					    mapoff, pack->filesize - mapoff,
					    base_file);
				} else
					err = got_inflate_to_file_fd(
					    &base_bufsz, NULL, NULL, pack->fd,
					    base_file);
			} else {
				accum_buf = malloc(max_size);
				if (accum_buf == NULL) {
					err = got_error_from_errno("malloc");
					goto done;
				}
				accum_bufsz = max_size;
				if (pack->map) {
					if (delta_data_offset > SIZE_MAX) {
						err = got_error_fmt(
						    GOT_ERR_RANGE,
						    "delta offset %lld "
						    "overflows size_t",
						    (long long)
						    delta_data_offset);
						goto done;
					}

					mapoff = delta_data_offset;
					err = got_inflate_to_mem_mmap(&base_buf,
					    &base_bufsz, NULL, NULL,
					    pack->map, mapoff,
					    pack->filesize - mapoff);
				} else
					err = got_inflate_to_mem_fd(&base_buf,
					    &base_bufsz, NULL, NULL, max_size,
					    pack->fd);
			}
			if (err)
				goto done;
			n++;
			if (base_buf == NULL)
				rewind(base_file);
			else if (pack->delta_cache && fulltext == NULL) {
				err = got_delta_cache_add(pack->delta_cache,
				    delta_data_offset, NULL, 0);
				if (err) {
					if (err->code != GOT_ERR_NO_SPACE)
						goto done;
					err = NULL;
				} else {
					err = got_delta_cache_add_fulltext(
					    pack->delta_cache,
					    delta_data_offset,
					    base_buf, base_bufsz);
					if (err &&
					    err->code != GOT_ERR_NO_SPACE)
						goto done;
					err = NULL;
				}
			}
			continue;
		}

		if (pack->delta_cache) {
			got_delta_cache_get(&delta_buf, &delta_len,
			    &fulltext, &fulltext_len,
			    pack->delta_cache, delta->data_offset);
		}
		if (delta_buf == NULL) {
			cached = 0;
			err = read_delta_data(&delta_buf, &delta_len, NULL,
			    delta->data_offset, pack);
			if (err)
				goto done;
		}
		if (pack->delta_cache && !cached) {
			err = got_delta_cache_add(pack->delta_cache,
			    delta->data_offset, delta_buf, delta_len);
			if (err == NULL)
				cached = 1;
			else if (err->code != GOT_ERR_NO_SPACE) {
				free(delta_buf);
				goto done;
			}
		}

		err = got_delta_get_sizes(&base_size, &result_size,
		    delta_buf, delta_len);
		if (err) {
			if (!cached)
				free(delta_buf);
			goto done;
		}
		if (base_size > max_size)
			max_size = base_size;
		if (result_size > max_size)
			max_size = result_size;
		if (fulltext_len > max_size)
			max_size = fulltext_len;

		if (base_buf && max_size > max_bufsize) {
			/* Switch from buffers to temporary files. */
			size_t w = fwrite(base_buf, 1, base_bufsz,
			    base_file);
			if (w != base_bufsz) {
				err = got_ferror(outfile, GOT_ERR_IO);
				if (!cached)
					free(delta_buf);
				goto done;
			}
			free(base_buf);
			base_buf = NULL;
			free(accum_buf);
			accum_buf = NULL;
		}

		if (base_buf && max_size > base_bufsz) {
			uint8_t *p = realloc(base_buf, max_size);
			if (p == NULL) {
				err = got_error_from_errno("realloc");
				if (!cached)
					free(delta_buf);
				goto done;
			}
			base_buf = p;
			base_bufsz = max_size;
		}

		if (accum_buf && max_size > accum_bufsz) {
			uint8_t *p = realloc(accum_buf, max_size);
			if (p == NULL) {
				err = got_error_from_errno("realloc");
				if (!cached)
					free(delta_buf);
				goto done;
			}
			accum_buf = p;
			accum_bufsz = max_size;
		}

		if (base_buf) {
			if (fulltext) {
				memcpy(accum_buf, fulltext, fulltext_len);
				accum_size = fulltext_len;
				err = NULL;
			} else {
				err = got_delta_apply_in_mem(base_buf,
				    base_bufsz, delta_buf, delta_len,
				    accum_buf, &accum_size, max_size);
			}
			n++;
			if (!cached)
				free(delta_buf);
			if (err)
				goto done;
			if (pack->delta_cache && fulltext == NULL) {
				err = got_delta_cache_add_fulltext(
				    pack->delta_cache, delta->data_offset,
				    accum_buf, accum_size);
				if (err) {
					if (err->code != GOT_ERR_NO_SPACE)
						goto done;
					err = NULL;
				}
			}
		} else {
			err = got_delta_apply(base_file, delta_buf,
			    delta_len,
			    /* Final delta application writes to output file. */
			    ++n < deltas->nentries ? accum_file : outfile,
			    &accum_size);
			if (!cached)
				free(delta_buf);
			if (err)
				goto done;
		}

		if (n < deltas->nentries) {
			/* Accumulated delta becomes the new base. */
			if (base_buf) {
				uint8_t *tmp = accum_buf;
				size_t tmp_size = accum_bufsz;
				accum_buf = base_buf;
				accum_bufsz = base_bufsz;
				base_buf = tmp;
				base_bufsz = tmp_size;
			} else {
				FILE *tmp = accum_file;
				accum_file = base_file;
				base_file = tmp;
				rewind(base_file);
				rewind(accum_file);
			}
		}
	}

done:
	free(base_buf);
	if (err) {
		free(accum_buf);
		accum_buf = NULL;
	}
	if (accum_buf) {
		size_t len = fwrite(accum_buf, 1, accum_size, outfile);
		free(accum_buf);
		if (len != accum_size)
			err = got_ferror(outfile, GOT_ERR_IO);
	}
	rewind(outfile);
	if (err == NULL)
		*result_size = accum_size;
	return err;
}

const struct got_error *
got_pack_dump_delta_chain_to_mem(uint8_t **outbuf, size_t *outlen,
    struct got_delta_chain *deltas, struct got_pack *pack)
{
	const struct got_error *err = NULL;
	struct got_delta *delta;
	uint8_t *base_buf = NULL, *accum_buf = NULL;
	size_t base_bufsz = 0, accum_bufsz = 0, accum_size = 0;
	uint64_t max_size = 0;
	int n = 0;

	*outbuf = NULL;
	*outlen = 0;

	if (STAILQ_EMPTY(&deltas->entries))
		return got_error(GOT_ERR_BAD_DELTA_CHAIN);

	if (pack->delta_cache) {
		uint8_t *delta_buf = NULL, *fulltext = NULL;
		size_t delta_len, fulltext_len;

		delta = STAILQ_LAST(&deltas->entries, got_delta, entry);
		got_delta_cache_get(&delta_buf, &delta_len,
		    &fulltext, &fulltext_len,
		    pack->delta_cache, delta->data_offset);
		if (fulltext) {
			*outbuf = malloc(fulltext_len);
			if (*outbuf == NULL)
				return got_error_from_errno("malloc");
			memcpy(*outbuf, fulltext, fulltext_len);
			*outlen = fulltext_len;
			return NULL;
		}
	}

	/* Deltas are ordered in ascending order. */
	STAILQ_FOREACH(delta, &deltas->entries, entry) {
		uint8_t *delta_buf = NULL, *fulltext = NULL;
		size_t delta_len, fulltext_len = 0;
		uint64_t base_size, result_size = 0;
		int cached = 1;
		if (n == 0) {
			off_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}

			if (pack->delta_cache) {
				got_delta_cache_get(&delta_buf, &delta_len,
				    &fulltext, &fulltext_len,
				    pack->delta_cache, delta_data_offset);
			}

			if (delta->size > max_size)
				max_size = delta->size;
			if (delta->size > fulltext_len)
				max_size = fulltext_len;

			if (fulltext) {
				base_buf = malloc(fulltext_len);
				if (base_buf == NULL) {
					err = got_error_from_errno("malloc");
					goto done;
				}
				memcpy(base_buf, fulltext, fulltext_len);
				base_bufsz = fulltext_len;
			} else if (pack->map) {
				size_t mapoff;

				if (delta_data_offset > SIZE_MAX) {
					return got_error_fmt(GOT_ERR_RANGE,
					    "delta %lld offset would "
					    "overflow size_t",
					    (long long)delta_data_offset);
				}

				mapoff = delta_data_offset;
				err = got_inflate_to_mem_mmap(&base_buf,
				    &base_bufsz, NULL, NULL, pack->map,
				    mapoff, pack->filesize - mapoff);
			} else {
				if (lseek(pack->fd, delta_data_offset, SEEK_SET)
				    == -1) {
					err = got_error_from_errno("lseek");
					goto done;
				}
				err = got_inflate_to_mem_fd(&base_buf,
				    &base_bufsz, NULL, NULL, max_size,
				    pack->fd);
			}
			if (err)
				goto done;
			n++;

			if (pack->delta_cache && fulltext == NULL) {
				err = got_delta_cache_add(pack->delta_cache,
				    delta_data_offset, NULL, 0);
				if (err) {
					if (err->code != GOT_ERR_NO_SPACE)
						goto done;
					err = NULL;
				} else {
					err = got_delta_cache_add_fulltext(
					    pack->delta_cache,
					    delta_data_offset,
					    base_buf, base_bufsz);
					if (err &&
					    err->code != GOT_ERR_NO_SPACE)
						goto done;
					err = NULL;
				}
			}
			continue;
		}

		if (pack->delta_cache) {
			got_delta_cache_get(&delta_buf, &delta_len,
			    &fulltext, &fulltext_len,
			    pack->delta_cache, delta->data_offset);
		}
		if (delta_buf == NULL) {
			cached = 0;
			err = read_delta_data(&delta_buf, &delta_len, NULL,
			    delta->data_offset, pack);
			if (err)
				goto done;
		}
		if (pack->delta_cache && !cached) {
			err = got_delta_cache_add(pack->delta_cache,
			    delta->data_offset, delta_buf, delta_len);
			if (err == NULL)
				cached = 1;
			else if (err->code != GOT_ERR_NO_SPACE) {
				free(delta_buf);
				goto done;
			}
		}

		err = got_delta_get_sizes(&base_size, &result_size,
		    delta_buf, delta_len);
		if (err) {
			if (!cached)
				free(delta_buf);
			goto done;
		}
		if (base_size > max_size)
			max_size = base_size;
		if (result_size > max_size)
			max_size = result_size;
		if (fulltext_len > max_size)
			max_size = fulltext_len;

		if (max_size > base_bufsz) {
			uint8_t *p = realloc(base_buf, max_size);
			if (p == NULL) {
				err = got_error_from_errno("realloc");
				if (!cached)
					free(delta_buf);
				goto done;
			}
			base_buf = p;
			base_bufsz = max_size;
		}

		if (max_size > accum_bufsz) {
			uint8_t *p = realloc(accum_buf, max_size);
			if (p == NULL) {
				err = got_error_from_errno("realloc");
				if (!cached)
					free(delta_buf);
				goto done;
			}
			accum_buf = p;
			accum_bufsz = max_size;
		}

		if (fulltext) {
			memcpy(accum_buf, fulltext, fulltext_len);
			accum_size = fulltext_len;
			err = NULL;
		} else {
			err = got_delta_apply_in_mem(base_buf, base_bufsz,
			    delta_buf, delta_len, accum_buf,
			    &accum_size, max_size);
		}
		if (!cached)
			free(delta_buf);
		n++;
		if (err)
			goto done;

		if (pack->delta_cache && fulltext == NULL) {
			err = got_delta_cache_add_fulltext(pack->delta_cache,
			    delta->data_offset, accum_buf, accum_size);
			if (err) {
				if (err->code != GOT_ERR_NO_SPACE)
					goto done;
				err = NULL;
			}
		}

		if (n < deltas->nentries) {
			/* Accumulated delta becomes the new base. */
			uint8_t *tmp = accum_buf;
			size_t tmp_size = accum_bufsz;
			accum_buf = base_buf;
			accum_bufsz = base_bufsz;
			base_buf = tmp;
			base_bufsz = tmp_size;
		}
	}

done:
	free(base_buf);
	if (err) {
		free(accum_buf);
		*outbuf = NULL;
		*outlen = 0;
	} else {
		*outbuf = accum_buf;
		*outlen = accum_size;
	}
	return err;
}

const struct got_error *
got_packfile_extract_object(struct got_pack *pack, struct got_object *obj,
    FILE *outfile, FILE *base_file, FILE *accum_file)
{
	const struct got_error *err = NULL;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		if (obj->pack_offset >= pack->filesize)
			return got_error(GOT_ERR_PACK_OFFSET);

		if (pack->map) {
			size_t mapoff;

			if (obj->pack_offset > SIZE_MAX) {
				return got_error_fmt(GOT_ERR_RANGE,
				    "pack offset %lld would overflow size_t",
				    (long long)obj->pack_offset);
			}

			mapoff = obj->pack_offset;
			err = got_inflate_to_file_mmap(&obj->size, NULL, NULL,
			    pack->map, mapoff, pack->filesize - mapoff,
			    outfile);
		} else {
			if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1)
				return got_error_from_errno("lseek");
			err = got_inflate_to_file_fd(&obj->size, NULL, NULL,
			    pack->fd, outfile);
		}
	} else
		err = got_pack_dump_delta_chain_to_file(&obj->size,
		    &obj->deltas, pack, outfile, base_file, accum_file);

	return err;
}

const struct got_error *
got_packfile_extract_object_to_mem(uint8_t **buf, size_t *len,
    struct got_object *obj, struct got_pack *pack)
{
	const struct got_error *err = NULL;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		if (obj->pack_offset >= pack->filesize)
			return got_error(GOT_ERR_PACK_OFFSET);
		if (pack->map) {
			size_t mapoff;

			if (obj->pack_offset > SIZE_MAX) {
				return got_error_fmt(GOT_ERR_RANGE,
				    "pack offset %lld would overflow size_t",
				    (long long)obj->pack_offset);
			}

			mapoff = obj->pack_offset;
			err = got_inflate_to_mem_mmap(buf, len, NULL, NULL,
			    pack->map, mapoff, pack->filesize - mapoff);
		} else {
			if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1)
				return got_error_from_errno("lseek");
			err = got_inflate_to_mem_fd(buf, len, NULL, NULL,
			    obj->size, pack->fd);
		}
	} else
		err = got_pack_dump_delta_chain_to_mem(buf, len, &obj->deltas,
		    pack);

	return err;
}

static const struct got_error *
read_raw_delta_data(uint8_t **delta_buf, size_t *delta_len,
    size_t *delta_len_compressed, uint64_t *base_size, uint64_t *result_size,
    off_t delta_data_offset, struct got_pack *pack, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;

	/* Validate decompression and obtain the decompressed size. */
	err = read_delta_data(delta_buf, delta_len, delta_len_compressed,
	    delta_data_offset, pack);
	if (err)
		return err;

	/* Read delta base/result sizes from head of delta stream. */
	err = got_delta_get_sizes(base_size, result_size,
	    *delta_buf, *delta_len);
	if (err)
		goto done;

	/* Discard decompressed delta and read it again in compressed form. */
	free(*delta_buf);
	*delta_buf = malloc(*delta_len_compressed);
	if (*delta_buf == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	if (pack->map) {
		if (delta_data_offset >= pack->filesize) {
			err = got_error(GOT_ERR_PACK_OFFSET);
			goto done;
		}
		memcpy(*delta_buf, pack->map + delta_data_offset,
		    *delta_len_compressed);
	} else {
		ssize_t n;
		if (lseek(pack->fd, delta_data_offset, SEEK_SET) == -1) {
			err = got_error_from_errno("lseek");
			goto done;
		}
		n = read(pack->fd, *delta_buf, *delta_len_compressed);
		if (n < 0) {
			err = got_error_from_errno("read");
			goto done;
		} else if (n != *delta_len_compressed) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
	}
done:
	if (err) {
		free(*delta_buf);
		*delta_buf = NULL;
		*delta_len = 0;
		*delta_len_compressed = 0;
		*base_size = 0;
		*result_size = 0;
	}
	return err;
}

const struct got_error *
got_packfile_extract_raw_delta(uint8_t **delta_buf, size_t *delta_size,
    size_t *delta_compressed_size, off_t *delta_offset,
    off_t *delta_data_offset, off_t *base_offset,
    struct got_object_id *base_id, uint64_t *base_size, uint64_t *result_size,
    struct got_pack *pack, struct got_packidx *packidx, int idx)
{
	const struct got_error *err = NULL;
	off_t offset;
	uint8_t type;
	uint64_t size;
	size_t tslen, delta_hdrlen;

	*delta_buf = NULL;
	*delta_size = 0;
	*delta_compressed_size = 0;
	*delta_offset = 0;
	*delta_data_offset = 0;
	*base_offset = 0;
	*base_size = 0;
	*result_size = 0;

	offset = got_packidx_get_object_offset(packidx, idx);
	if (offset == -1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	if (offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_parse_object_type_and_size(&type, &size, &tslen,
	    pack, offset);
	if (err)
		return err;

	if (tslen + size < tslen || offset + size < size ||
	    tslen + offset < tslen)
		return got_error(GOT_ERR_PACK_OFFSET);

	switch (type) {
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		err = got_pack_parse_offset_delta(base_offset, &delta_hdrlen,
		    pack, offset, tslen);
		if (err)
			return err;
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		err = got_pack_parse_ref_delta(base_id, pack, offset, tslen);
		if (err)
			return err;
		delta_hdrlen = got_hash_digest_length(pack->algo);
		break;
	default:
		return got_error_fmt(GOT_ERR_OBJ_TYPE,
		    "non-delta object type %d found at offset %lld",
		    type, (long long)offset);
	}

	if (tslen + delta_hdrlen < delta_hdrlen ||
	    offset + delta_hdrlen < delta_hdrlen)
		return got_error(GOT_ERR_BAD_DELTA);

	*delta_data_offset = offset + tslen + delta_hdrlen;
	err = read_raw_delta_data(delta_buf, delta_size, delta_compressed_size,
	    base_size, result_size, *delta_data_offset, pack, packidx);
	if (err)
		return err;

	if (*delta_size != size) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

	*delta_offset = offset;
done:
	if (err) {
		free(*delta_buf);
		*delta_buf = NULL;
		*delta_size = 0;
		*delta_compressed_size = 0;
		*delta_offset = 0;
		*base_offset = 0;
		*base_size = 0;
		*result_size = 0;
	}
	return err;
}
