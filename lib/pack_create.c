/*
 * Copyright (c) 2020 Ori Bernstein
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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <zlib.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_repository_admin.h"

#include "got_lib_deltify.h"
#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_cache.h"
#include "got_lib_deflate.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_create.h"
#include "got_lib_repository.h"
#include "got_lib_inflate.h"
#include "got_lib_poll.h"

#include "murmurhash2.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef MAX
#define	MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
alloc_meta(struct got_pack_meta **new, struct got_object_id *id,
    const char *path, int obj_type, time_t mtime, uint32_t seed)
{
	struct got_pack_meta *m;

	*new = NULL;

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return got_error_from_errno("calloc");

	memcpy(&m->id, id, sizeof(m->id));

	m->path_hash = murmurhash2(path, strlen(path), seed);
	m->obj_type = obj_type;
	m->mtime = mtime;
	*new = m;
	return NULL;
}

static void
clear_meta(struct got_pack_meta *meta)
{
	if (meta == NULL)
		return;
	meta->path_hash = 0;
	free(meta->delta_buf);
	meta->delta_buf = NULL;
	free(meta->base_obj_id);
	meta->base_obj_id = NULL;
	meta->reused_delta_offset = 0;
	got_deltify_free(meta->dtab);
	meta->dtab = NULL;
}

static void
free_nmeta(struct got_pack_meta **meta, int nmeta)
{
	int i;

	for (i = 0; i < nmeta; i++)
		clear_meta(meta[i]);

	free(meta);
}

static int
delta_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;

	if (a->obj_type != b->obj_type)
		return a->obj_type - b->obj_type;
	if (a->path_hash < b->path_hash)
		return -1;
	if (a->path_hash > b->path_hash)
		return 1;
	if (a->mtime < b->mtime)
		return -1;
	if (a->mtime > b->mtime)
		return 1;
	return got_object_id_cmp(&a->id, &b->id);
}

static off_t
delta_size(struct got_delta_instruction *deltas, int ndeltas)
{
	int i;
	off_t size = 32;
	for (i = 0; i < ndeltas; i++) {
		if (deltas[i].copy)
			size += GOT_DELTA_SIZE_SHIFT;
		else
			size += deltas[i].len + 1;
	}
	return size;
}

static const struct got_error *
append(unsigned char **p, size_t *len, off_t *sz, void *seg, int nseg)
{
	char *n;

	if (*len + nseg >= *sz) {
		while (*len + nseg >= *sz)
			*sz += *sz / 2;
		n = realloc(*p, *sz);
		if (n == NULL)
			return got_error_from_errno("realloc");
		*p = n;
	}
	memcpy(*p + *len, seg, nseg);
	*len += nseg;
	return NULL;
}

static const struct got_error *
encode_delta_in_mem(struct got_pack_meta *m, struct got_raw_object *o,
    struct got_delta_instruction *deltas, int ndeltas,
    off_t delta_size, off_t base_size)
{
	const struct got_error *err;
	unsigned char buf[16], *bp;
	int i, j;
	size_t len = 0, compressed_len;
	off_t bufsize = delta_size;
	off_t n;
	struct got_delta_instruction *d;
	uint8_t *delta_buf;

	delta_buf = malloc(bufsize);
	if (delta_buf == NULL)
		return got_error_from_errno("malloc");

	/* base object size */
	buf[0] = base_size & GOT_DELTA_SIZE_VAL_MASK;
	n = base_size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	err = append(&delta_buf, &len, &bufsize, buf, i);
	if (err)
		goto done;

	/* target object size */
	buf[0] = o->size & GOT_DELTA_SIZE_VAL_MASK;
	n = o->size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	err = append(&delta_buf, &len, &bufsize, buf, i);
	if (err)
		goto done;

	for (j = 0; j < ndeltas; j++) {
		d = &deltas[j];
		if (d->copy) {
			n = d->offset;
			bp = &buf[1];
			buf[0] = GOT_DELTA_BASE_COPY;
			for (i = 0; i < 4; i++) {
				/* DELTA_COPY_OFF1 ... DELTA_COPY_OFF4 */
				buf[0] |= 1 << i;
				*bp++ = n & 0xff;
				n >>= 8;
				if (n == 0)
					break;
			}

			n = d->len;
			if (n != GOT_DELTA_COPY_DEFAULT_LEN) {
				/* DELTA_COPY_LEN1 ... DELTA_COPY_LEN3 */
				for (i = 0; i < 3 && n > 0; i++) {
					buf[0] |= 1 << (i + 4);
					*bp++ = n & 0xff;
					n >>= 8;
				}
			}
			err = append(&delta_buf, &len, &bufsize,
			    buf, bp - buf);
			if (err)
				goto done;
		} else if (o->f == NULL) {
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = append(&delta_buf, &len, &bufsize,
				    buf, 1);
				if (err)
					goto done;
				err = append(&delta_buf, &len, &bufsize,
				    o->data + o->hdrlen + d->offset + n,
				    buf[0]);
				if (err)
					goto done;
				n += buf[0];
			}
		} else {
			char content[128];
			size_t r;
			if (fseeko(o->f, o->hdrlen + d->offset, SEEK_SET) == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = append(&delta_buf, &len, &bufsize,
				    buf, 1);
				if (err)
					goto done;
				r = fread(content, 1, buf[0], o->f);
				if (r != buf[0]) {
					err = got_ferror(o->f, GOT_ERR_IO);
					goto done;
				}
				err = append(&delta_buf, &len, &bufsize,
				    content, buf[0]);
				if (err)
					goto done;
				n += buf[0];
			}
		}
	}

	err = got_deflate_to_mem_mmap(&m->delta_buf, &compressed_len,
	    NULL, NULL, delta_buf, 0, len);
	if (err)
		goto done;

	m->delta_len = len;
	m->delta_compressed_len = compressed_len;
done:
	free(delta_buf);
	return err;
}

static const struct got_error *
encode_delta(struct got_pack_meta *m, struct got_raw_object *o,
    struct got_delta_instruction *deltas, int ndeltas,
    off_t base_size, FILE *f)
{
	const struct got_error *err;
	unsigned char buf[16], *bp;
	int i, j;
	off_t n;
	struct got_deflate_buf zb;
	struct got_delta_instruction *d;
	off_t delta_len = 0, compressed_len = 0;

	err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
	if (err)
		return err;

	/* base object size */
	buf[0] = base_size & GOT_DELTA_SIZE_VAL_MASK;
	n = base_size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}

	err = got_deflate_append_to_file_mmap(&zb, &compressed_len,
	    buf, 0, i, f, NULL);
	if (err)
		goto done;
	delta_len += i;

	/* target object size */
	buf[0] = o->size & GOT_DELTA_SIZE_VAL_MASK;
	n = o->size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}

	err = got_deflate_append_to_file_mmap(&zb, &compressed_len,
	    buf, 0, i, f, NULL);
	if (err)
		goto done;
	delta_len += i;

	for (j = 0; j < ndeltas; j++) {
		d = &deltas[j];
		if (d->copy) {
			n = d->offset;
			bp = &buf[1];
			buf[0] = GOT_DELTA_BASE_COPY;
			for (i = 0; i < 4; i++) {
				/* DELTA_COPY_OFF1 ... DELTA_COPY_OFF4 */
				buf[0] |= 1 << i;
				*bp++ = n & 0xff;
				n >>= 8;
				if (n == 0)
					break;
			}
			n = d->len;
			if (n != GOT_DELTA_COPY_DEFAULT_LEN) {
				/* DELTA_COPY_LEN1 ... DELTA_COPY_LEN3 */
				for (i = 0; i < 3 && n > 0; i++) {
					buf[0] |= 1 << (i + 4);
					*bp++ = n & 0xff;
					n >>= 8;
				}
			}
			err = got_deflate_append_to_file_mmap(&zb,
			    &compressed_len, buf, 0, bp - buf, f, NULL);
			if (err)
				goto done;
			delta_len += (bp - buf);
		} else if (o->f == NULL) {
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = got_deflate_append_to_file_mmap(&zb,
				    &compressed_len, buf, 0, 1, f, NULL);
				if (err)
					goto done;
				delta_len++;
				err = got_deflate_append_to_file_mmap(&zb,
				    &compressed_len,
				    o->data + o->hdrlen + d->offset + n, 0,
				    buf[0], f, NULL);
				if (err)
					goto done;
				delta_len += buf[0];
				n += buf[0];
			}
		} else {
			char content[128];
			size_t r;
			if (fseeko(o->f, o->hdrlen + d->offset, SEEK_SET) == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = got_deflate_append_to_file_mmap(&zb,
				    &compressed_len, buf, 0, 1, f, NULL);
				if (err)
					goto done;
				delta_len++;
				r = fread(content, 1, buf[0], o->f);
				if (r != buf[0]) {
					err = got_ferror(o->f, GOT_ERR_IO);
					goto done;
				}
				err = got_deflate_append_to_file_mmap(&zb,
				    &compressed_len, content, 0, buf[0], f,
				    NULL);
				if (err)
					goto done;
				delta_len += buf[0];
				n += buf[0];
			}
		}
	}

	err = got_deflate_flush(&zb, f, NULL, &compressed_len);
	if (err)
		goto done;

	/* sanity check */
	if (compressed_len != ftello(f) - m->delta_offset) {
		err = got_error(GOT_ERR_COMPRESSION);
		goto done;
	}

	m->delta_len = delta_len;
	m->delta_compressed_len = compressed_len;
done:
	got_deflate_end(&zb);
	return err;
}

const struct got_error *
got_pack_report_progress(got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int obj_deltify,
    int nobj_written, int pack_done)
{
	const struct got_error *err;
	int elapsed;

	if (progress_cb == NULL)
		return NULL;

	err = got_ratelimit_check(&elapsed, rl);
	if (err || !elapsed)
		return err;

	return progress_cb(progress_arg, ncolored, nfound, ntrees,
	    packfile_size, ncommits, nobj_total, obj_deltify, nobj_written,
	    pack_done);
}

const struct got_error *
got_pack_add_meta(struct got_pack_meta *m, struct got_pack_metavec *v)
{
	if (v->nmeta == v->metasz){
		size_t newsize = 2 * v->metasz;
		struct got_pack_meta **new;
		new = reallocarray(v->meta, newsize, sizeof(*new));
		if (new == NULL)
			return got_error_from_errno("reallocarray");
		v->meta = new;
		v->metasz = newsize;
	}

	v->meta[v->nmeta++] = m;
	return NULL;
}

const struct got_error *
got_pack_find_pack_for_reuse(struct got_packidx **best_packidx,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	const char *best_packidx_path = NULL;
	int nobj_max = 0;

	*best_packidx = NULL;

	RB_FOREACH(pe, got_pathlist_head, &repo->packidx_paths) {
		const char *path_packidx = pe->path;
		struct got_packidx *packidx;
		int nobj;

		err = got_repo_get_packidx(&packidx, path_packidx, repo);
		if (err)
			break;

		nobj = be32toh(packidx->hdr.fanout_table[0xff]);
		if (nobj > nobj_max) {
			best_packidx_path = path_packidx;
			nobj_max = nobj;
		}
	}

	if (best_packidx_path) {
		err = got_repo_get_packidx(best_packidx, best_packidx_path,
		    repo);
	}

	return err;
}

const struct got_error *
got_pack_cache_pack_for_packidx(struct got_pack **pack,
    struct got_packidx *packidx, struct got_repository *repo)
{
	const struct got_error *err;
	char *path_packfile = NULL;

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	*pack = got_repo_get_cached_pack(repo, path_packfile);
	if (*pack == NULL) {
		err = got_repo_cache_pack(pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}
done:
	free(path_packfile);
	return err;
}

static const struct got_error *
pick_deltas(struct got_pack_meta **meta, int nmeta, int ncolored,
    int nfound, int ntrees, int ncommits, int nreused, FILE *delta_cache,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_pack_meta *m = NULL, *base = NULL;
	struct got_raw_object *raw = NULL, *base_raw = NULL;
	struct got_delta_instruction *deltas = NULL, *best_deltas = NULL;
	int i, j, ndeltas, best_ndeltas;
	off_t size, best_size;
	const int max_base_candidates = 3;
	size_t delta_memsize = 0;
	const size_t max_delta_memsize = 4 * GOT_DELTA_RESULT_SIZE_CACHED_MAX;
	int outfd = -1;
	uint32_t delta_seed;

	delta_seed = arc4random();

	qsort(meta, nmeta, sizeof(struct got_pack_meta *), delta_order_cmp);
	for (i = 0; i < nmeta; i++) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}
		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, 0L, ncommits, nreused + nmeta,
		    nreused + i, 0, 0);
		if (err)
			goto done;
		m = meta[i];

		if (m->obj_type == GOT_OBJ_TYPE_COMMIT ||
		    m->obj_type == GOT_OBJ_TYPE_TAG)
			continue;

		err = got_object_raw_open(&raw, &outfd, repo, &m->id);
		if (err)
			goto done;
		m->size = raw->size;

		if (raw->f == NULL) {
			err = got_deltify_init_mem(&m->dtab, raw->data,
			    raw->hdrlen, raw->size + raw->hdrlen, delta_seed);
		} else {
			err = got_deltify_init(&m->dtab, raw->f, raw->hdrlen,
			    raw->size + raw->hdrlen, delta_seed);
		}
		if (err)
			goto done;

		if (i > max_base_candidates) {
			struct got_pack_meta *n = NULL;
			n = meta[i - (max_base_candidates + 1)];
			got_deltify_free(n->dtab);
			n->dtab = NULL;
		}

		best_size = raw->size;
		best_ndeltas = 0;
		for (j = MAX(0, i - max_base_candidates); j < i; j++) {
			if (cancel_cb) {
				err = (*cancel_cb)(cancel_arg);
				if (err)
					goto done;
			}
			base = meta[j];
			/* long chains make unpacking slow, avoid such bases */
			if (base->nchain >= 128 ||
			    base->obj_type != m->obj_type)
				continue;

			err = got_object_raw_open(&base_raw, &outfd, repo,
			    &base->id);
			if (err)
				goto done;

			if (raw->f == NULL && base_raw->f == NULL) {
				err = got_deltify_mem_mem(&deltas, &ndeltas,
				    raw->data, raw->hdrlen,
				    raw->size + raw->hdrlen, delta_seed,
				    base->dtab, base_raw->data,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else if (raw->f == NULL) {
				err = got_deltify_mem_file(&deltas, &ndeltas,
				    raw->data, raw->hdrlen,
				    raw->size + raw->hdrlen, delta_seed,
				    base->dtab, base_raw->f,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else if (base_raw->f == NULL) {
				err = got_deltify_file_mem(&deltas, &ndeltas,
				    raw->f, raw->hdrlen,
				    raw->size + raw->hdrlen, delta_seed,
				    base->dtab, base_raw->data,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else {
				err = got_deltify(&deltas, &ndeltas,
				    raw->f, raw->hdrlen,
				    raw->size + raw->hdrlen, delta_seed,
				    base->dtab, base_raw->f, base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			}
			got_object_raw_close(base_raw);
			base_raw = NULL;
			if (err)
				goto done;

			size = delta_size(deltas, ndeltas);
			if (size + 32 < best_size){
				/*
				 * if we already picked a best delta,
				 * replace it.
				 */
				best_size = size;
				free(best_deltas);
				best_deltas = deltas;
				best_ndeltas = ndeltas;
				deltas = NULL;
				m->nchain = base->nchain + 1;
				m->prev = base;
				m->head = base->head;
				if (m->head == NULL)
					m->head = base;
			} else {
				free(deltas);
				deltas = NULL;
				ndeltas = 0;
			}
		}

		if (best_ndeltas > 0) {
			if (best_size <= GOT_DELTA_RESULT_SIZE_CACHED_MAX &&
			    delta_memsize + best_size <= max_delta_memsize) {
				delta_memsize += best_size;
				err = encode_delta_in_mem(m, raw, best_deltas,
				    best_ndeltas, best_size, m->prev->size);
			} else {
				m->delta_offset = ftello(delta_cache);
				err = encode_delta(m, raw, best_deltas,
				    best_ndeltas, m->prev->size, delta_cache);
			}
			free(best_deltas);
			best_deltas = NULL;
			best_ndeltas = 0;
			if (err)
				goto done;
		}

		got_object_raw_close(raw);
		raw = NULL;
	}
done:
	if (raw)
		got_object_raw_close(raw);
	if (base_raw)
		got_object_raw_close(base_raw);
	if (outfd != -1 && close(outfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(deltas);
	free(best_deltas);
	return err;
}

static const struct got_error *
search_packidx(int *found, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;

	*found = 0;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL)
		*found = 1; /* object is already packed */
	else if (err->code == GOT_ERR_NO_OBJ)
		err = NULL;
	return err;
}

const struct got_error *
got_pack_add_object(int want_meta, struct got_object_idset *idset,
    struct got_object_id *id, const char *path, int obj_type,
    time_t mtime, uint32_t seed, int loose_obj_only,
    struct got_repository *repo, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl)
{
	const struct got_error *err;
	struct got_pack_meta *m = NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed && want_meta)
			return NULL;
	}

	if (want_meta) {
		err = alloc_meta(&m, id, path, obj_type, mtime, seed);
		if (err)
			return err;

		(*nfound)++;
		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    *ncolored, *nfound, *ntrees, 0L, 0, 0, 0, 0, 0);
		if (err) {
			clear_meta(m);
			free(m);
			return err;
		}
	}

	err = got_object_idset_add(idset, id, m);
	if (err) {
		clear_meta(m);
		free(m);
	}
	return err;
}

const struct got_error *
got_pack_load_tree_entries(struct got_object_id_queue *ids, int want_meta,
    struct got_object_idset *idset, struct got_object_idset *idset_exclude,
    struct got_tree_object *tree,
    const char *dpath, time_t mtime, uint32_t seed, struct got_repository *repo,
    int loose_obj_only, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	char *p = NULL;
	int i;

	(*ntrees)++;
	err = got_pack_report_progress(progress_cb, progress_arg, rl,
	    *ncolored, *nfound, *ntrees, 0L, 0, 0, 0, 0, 0);
	if (err)
		return err;

	for (i = 0; i < got_object_tree_get_nentries(tree); i++) {
		struct got_tree_entry *e = got_object_tree_get_entry(tree, i);
		struct got_object_id *id = got_tree_entry_get_id(e);
		mode_t mode = got_tree_entry_get_mode(e);

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		if (got_object_tree_entry_is_submodule(e) ||
		    got_object_idset_contains(idset, id) ||
		    got_object_idset_contains(idset_exclude, id))
			continue;

		/*
		 * If got-read-pack is crawling trees for us then
		 * we are only here to collect blob IDs.
		 */
		if (ids == NULL && S_ISDIR(mode))
			continue;

		if (asprintf(&p, "%s%s%s", dpath,
		    got_path_is_root_dir(dpath) ? "" : "/",
		    got_tree_entry_get_name(e)) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		if (S_ISDIR(mode)) {
			struct got_object_qid *qid;
			err = got_object_qid_alloc(&qid, id);
			if (err)
				break;
			qid->data = p;
			p = NULL;
			STAILQ_INSERT_TAIL(ids, qid, entry);
		} else if (S_ISREG(mode) || S_ISLNK(mode)) {
			err = got_pack_add_object(want_meta,
			    want_meta ? idset : idset_exclude, id, p,
			    GOT_OBJ_TYPE_BLOB, mtime, seed, loose_obj_only,
			    repo, ncolored, nfound, ntrees,
			    progress_cb, progress_arg, rl);
			if (err)
				break;
			free(p);
			p = NULL;
		} else {
			free(p);
			p = NULL;
		}
	}

	free(p);
	return err;
}

const struct got_error *
got_pack_load_tree(int want_meta, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude,
    struct got_object_id *tree_id, const char *dpath, time_t mtime,
    uint32_t seed, struct got_repository *repo, int loose_obj_only,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue tree_ids;
	struct got_object_qid *qid;
	struct got_tree_object *tree = NULL;

	if (got_object_idset_contains(idset, tree_id) ||
	    got_object_idset_contains(idset_exclude, tree_id))
		return NULL;

	err = got_object_qid_alloc(&qid, tree_id);
	if (err)
		return err;
	qid->data = strdup(dpath);
	if (qid->data == NULL) {
		err = got_error_from_errno("strdup");
		got_object_qid_free(qid);
		return err;
	}

	STAILQ_INIT(&tree_ids);
	STAILQ_INSERT_TAIL(&tree_ids, qid, entry);

	while (!STAILQ_EMPTY(&tree_ids)) {
		const char *path;
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&tree_ids);
		STAILQ_REMOVE_HEAD(&tree_ids, entry);
		path = qid->data;

		if (got_object_idset_contains(idset, &qid->id) ||
		    got_object_idset_contains(idset_exclude, &qid->id)) {
			free(qid->data);
			got_object_qid_free(qid);
			continue;
		}

		err = got_pack_add_object(want_meta,
		    want_meta ? idset : idset_exclude,
		    &qid->id, path, GOT_OBJ_TYPE_TREE,
		    mtime, seed, loose_obj_only, repo,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
		if (err) {
			free(qid->data);
			got_object_qid_free(qid);
			break;
		}

		err = got_object_open_as_tree(&tree, repo, &qid->id);
		if (err) {
			free(qid->data);
			got_object_qid_free(qid);
			break;
		}

		err = got_pack_load_tree_entries(&tree_ids, want_meta, idset,
		    idset_exclude, tree, path, mtime, seed, repo,
		    loose_obj_only, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
		free(qid->data);
		got_object_qid_free(qid);
		if (err)
			break;

		got_object_tree_close(tree);
		tree = NULL;
	}

	STAILQ_FOREACH(qid, &tree_ids, entry)
		free(qid->data);
	got_object_id_queue_free(&tree_ids);
	if (tree)
		got_object_tree_close(tree);
	return err;
}

static const struct got_error *
load_commit(int want_meta, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude,
    struct got_object_id *id, struct got_repository *repo, uint32_t seed,
    int loose_obj_only, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_commit_object *commit;

	if (got_object_idset_contains(idset, id) ||
	    got_object_idset_contains(idset_exclude, id))
		return NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed && want_meta)
			return NULL;
	}

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = got_pack_add_object(want_meta,
	    want_meta ? idset : idset_exclude, id, "", GOT_OBJ_TYPE_COMMIT,
	    got_object_commit_get_committer_time(commit), seed,
	    loose_obj_only, repo,
	    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
	if (err)
		goto done;

	err = got_pack_load_tree(want_meta, idset, idset_exclude,
	    got_object_commit_get_tree_id(commit),
	    "", got_object_commit_get_committer_time(commit), seed,
	    repo, loose_obj_only, ncolored, nfound, ntrees,
	    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
done:
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
load_tag(int want_meta, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude,
    struct got_object_id *id, struct got_repository *repo, uint32_t seed,
    int loose_obj_only, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tag_object *tag = NULL;

	if (got_object_idset_contains(idset, id) ||
	    got_object_idset_contains(idset_exclude, id))
		return NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed && want_meta)
			return NULL;
	}

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	err = got_pack_add_object(want_meta,
	    want_meta ? idset : idset_exclude, id, "", GOT_OBJ_TYPE_TAG,
	    got_object_tag_get_tagger_time(tag), seed, loose_obj_only, repo,
	    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
	if (err)
		goto done;

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_COMMIT:
		err = load_commit(want_meta, idset, idset_exclude,
		    got_object_tag_get_object_id(tag), repo, seed,
		    loose_obj_only, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = got_pack_load_tree(want_meta, idset, idset_exclude,
		    got_object_tag_get_object_id(tag), "",
		    got_object_tag_get_tagger_time(tag), seed, repo,
		    loose_obj_only, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
		break;
	default:
		break;
	}

done:
	got_object_tag_close(tag);
	return err;
}

const struct got_error *
got_pack_paint_commit(struct got_object_qid *qid, intptr_t color)
{
	if (color < 0 || color >= COLOR_MAX)
		return got_error(GOT_ERR_RANGE);

	qid->data = (void *)color;
	return NULL;
}

const struct got_error *
got_pack_queue_commit_id(struct got_object_id_queue *ids,
    struct got_object_id *id, intptr_t color, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	err = got_object_qid_alloc(&qid, id);
	if (err)
		return err;

	if (color == COLOR_KEEP)
		STAILQ_INSERT_TAIL(ids, qid, entry);
	else	
		STAILQ_INSERT_HEAD(ids, qid, entry);
	return got_pack_paint_commit(qid, color);
}

struct append_id_arg {
	struct got_object_id **array;
	int idx;
	struct got_object_idset *drop;
	struct got_object_idset *skip;
};

static const struct got_error *
append_id(struct got_object_id *id, void *data, void *arg)
{
	struct append_id_arg *a = arg;

	if (got_object_idset_contains(a->skip, id) ||
	    got_object_idset_contains(a->drop, id))
		return NULL;

	a->array[++a->idx] = got_object_id_dup(id);
	if (a->array[a->idx] == NULL)
		return got_error_from_errno("got_object_id_dup");

	return NULL;
}

static const struct got_error *
free_meta(struct got_object_id *id, void *data, void *arg)
{
	struct got_pack_meta *meta = data;

	clear_meta(meta);
	free(meta);
	return NULL;
}

static const struct got_error *
queue_commit_or_tag_id(struct got_object_id *id, intptr_t color,
    struct got_object_id_queue *ids, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_tag_object *tag = NULL;
	int obj_type;

	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		return err;

	if (obj_type == GOT_OBJ_TYPE_TAG) {
		err = got_object_open_as_tag(&tag, repo, id);
		if (err)
			return err;
		obj_type = got_object_tag_get_object_type(tag);
		id = got_object_tag_get_object_id(tag);
	}

	if (obj_type == GOT_OBJ_TYPE_COMMIT) {
		err = got_pack_queue_commit_id(ids, id, color, repo);
		if (err)
			goto done;
	}
done:
	if (tag)
		got_object_tag_close(tag);
	return err;
}

const struct got_error *
got_pack_find_pack_for_commit_painting(struct got_packidx **best_packidx,
    struct got_object_id_queue *ids, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	const char *best_packidx_path = NULL;
	int nobj_max = 0;
	int ncommits_max = 0;

	*best_packidx = NULL;

	/*
	 * Find the largest pack which contains the commit at the head
	 * of the queue and some other commits we are interested in.
	 */
	RB_FOREACH(pe, got_pathlist_head, &repo->packidx_paths) {
		const char *path_packidx = pe->path;
		struct got_packidx *packidx;
		int nobj, idx, ncommits = 0;
		struct got_object_qid *qid;

		err = got_repo_get_packidx(&packidx, path_packidx, repo);
		if (err)
			break;

		nobj = be32toh(packidx->hdr.fanout_table[0xff]);
		if (nobj < nobj_max)
			continue;

		qid = STAILQ_FIRST(ids);
		idx = got_packidx_get_object_idx(packidx, &qid->id);
		if (idx == -1)
			continue;
		ncommits++;

		qid = STAILQ_NEXT(qid, entry);
		while (qid) {
			idx = got_packidx_get_object_idx(packidx, &qid->id);
			if (idx != -1)
				ncommits++;
			qid = STAILQ_NEXT(qid, entry);
		}

		if (ncommits >= ncommits_max) {
			best_packidx_path = path_packidx;
			nobj_max = nobj;
			ncommits_max = ncommits;
		}
	}

	if (best_packidx_path && err == NULL) {
		err = got_repo_get_packidx(best_packidx, best_packidx_path,
		    repo);
	}

	return err;
}

static const struct got_error *
findtwixt(struct got_object_id ***res, int *nres, int *ncolored,
    struct got_object_id **head, int nhead,
    struct got_object_id **tail, int ntail,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue ids;
	struct got_object_idset *keep, *drop, *skip = NULL;
	int i, nkeep, nqueued = 0;

	STAILQ_INIT(&ids);
	*res = NULL;
	*nres = 0;
	*ncolored = 0;

	keep = got_object_idset_alloc();
	if (keep == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	drop = got_object_idset_alloc();
	if (drop == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	skip = got_object_idset_alloc();
	if (skip == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	for (i = 0; i < ntail; i++) {
		struct got_object_id *id = tail[i];
		if (id == NULL)
			continue;
		err = queue_commit_or_tag_id(id, COLOR_DROP, &ids, repo);
		if (err)
			goto done;
		nqueued++;
	}

	for (i = 0; i < nhead; i++) {
		struct got_object_id *id = head[i];
		if (id == NULL)
			continue;
		err = queue_commit_or_tag_id(id, COLOR_KEEP, &ids, repo);
		if (err)
			goto done;
		nqueued++;
	}

	err = got_pack_paint_commits(ncolored, &ids, nqueued,
	    keep, drop, skip, repo, progress_cb, progress_arg, rl,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	nkeep = got_object_idset_num_elements(keep);
	if (nkeep > 0) {
		struct append_id_arg arg;
		arg.array = calloc(nkeep, sizeof(struct got_object_id *));
		if (arg.array == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		arg.idx = -1;
		arg.skip = skip;
		arg.drop = drop;
		err = got_object_idset_for_each(keep, append_id, &arg);
		if (err) {
			free(arg.array);
			goto done;
		}
		*res = arg.array;
		*nres = arg.idx + 1;
	}
done:
	got_object_idset_free(keep);
	got_object_idset_free(drop);
	if (skip)
		got_object_idset_free(skip);
	got_object_id_queue_free(&ids);
	return err;
}

static const struct got_error *
find_pack_for_enumeration(struct got_packidx **best_packidx,
    struct got_object_id **ids, int nids, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	const char *best_packidx_path = NULL;
	int nobj_max = 0;
	int ncommits_max = 0;

	*best_packidx = NULL;

	if (nids == 0)
		return NULL;

	/*
	 * Find the largest pack which contains the commit at the head
	 * of the queue and some other commits we are interested in.
	 */
	RB_FOREACH(pe, got_pathlist_head, &repo->packidx_paths) {
		const char *path_packidx = pe->path;
		struct got_packidx *packidx;
		int nobj, i, idx, ncommits = 0;

		err = got_repo_get_packidx(&packidx, path_packidx, repo);
		if (err)
			break;

		nobj = be32toh(packidx->hdr.fanout_table[0xff]);
		if (nobj < nobj_max)
			continue;

		idx = got_packidx_get_object_idx(packidx, ids[0]);
		if (idx == -1)
			continue;
		ncommits++;

		for (i = 1; i < nids; i++) {
			idx = got_packidx_get_object_idx(packidx, ids[i]);
			if (idx != -1)
				ncommits++;
		}
		if (ncommits >= ncommits_max) {
			best_packidx_path = path_packidx;
			nobj_max = nobj;
			ncommits_max = ncommits;
		}
	}

	if (best_packidx_path && err == NULL) {
		err = got_repo_get_packidx(best_packidx, best_packidx_path,
		    repo);
	}

	return err;
}

static const struct got_error *
load_object_ids(int *ncolored, int *nfound, int *ntrees,
    struct got_object_idset *idset, struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours, struct got_repository *repo,
    uint32_t seed, int loose_obj_only, got_pack_progress_cb progress_cb,
    void *progress_arg, struct got_ratelimit *rl, got_cancel_cb cancel_cb,
    void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ids = NULL;
	struct got_packidx *packidx = NULL;
	int i, nobj = 0, obj_type, found_all_objects = 0;
	struct got_object_idset *idset_exclude;

	idset_exclude = got_object_idset_alloc();
	if (idset_exclude == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	*ncolored = 0;
	*nfound = 0;
	*ntrees = 0;

	err = findtwixt(&ids, &nobj, ncolored, ours, nours, theirs, ntheirs,
	    repo, progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = find_pack_for_enumeration(&packidx, theirs, ntheirs, repo);
	if (err)
		goto done;
	if (packidx) {
		err = got_pack_load_packed_object_ids(&found_all_objects,
		    theirs, ntheirs, NULL, 0, 0, seed, idset, idset_exclude,
		    loose_obj_only, repo, packidx, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	for (i = 0; i < ntheirs; i++) {
		struct got_object_id *id = theirs[i];
		if (id == NULL)
			continue;
		err = got_object_get_type(&obj_type, repo, id);
		if (err)
			return err;
		if (obj_type == GOT_OBJ_TYPE_COMMIT) {
			if (!found_all_objects) {
				err = load_commit(0, idset, idset_exclude,
				    id, repo, seed, loose_obj_only,
				    ncolored, nfound, ntrees,
				    progress_cb, progress_arg, rl,
				    cancel_cb, cancel_arg);
				if (err)
					goto done;
			}
		} else if (obj_type == GOT_OBJ_TYPE_TAG) {
			err = load_tag(0, idset, idset_exclude, id, repo,
			    seed, loose_obj_only, ncolored, nfound, ntrees,
			    progress_cb, progress_arg, rl,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		}
	}

	found_all_objects = 0;
	err = find_pack_for_enumeration(&packidx, ids, nobj, repo);
	if (err)
		goto done;
	if (packidx) {
		err = got_pack_load_packed_object_ids(&found_all_objects, ids,
		    nobj, theirs, ntheirs, 1, seed, idset, idset_exclude,
		    loose_obj_only, repo, packidx, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	if (!found_all_objects) {
		for (i = 0; i < nobj; i++) {
			err = load_commit(1, idset, idset_exclude, ids[i],
			    repo, seed, loose_obj_only, ncolored, nfound,
			    ntrees, progress_cb, progress_arg, rl,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		}
	}

	for (i = 0; i < nours; i++) {
		struct got_object_id *id = ours[i];
		struct got_pack_meta *m;
		if (id == NULL)
			continue;
		m = got_object_idset_get(idset, id);
		if (m == NULL) {
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
		} else
			obj_type = m->obj_type;
		if (obj_type != GOT_OBJ_TYPE_TAG)
			continue;
		err = load_tag(1, idset, idset_exclude, id, repo,
		    seed, loose_obj_only, ncolored, nfound, ntrees,
		    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
		if (err)
			goto done;
	}
done:
	for (i = 0; i < nobj; i++) {
		free(ids[i]);
	}
	free(ids);
	got_object_idset_free(idset_exclude);
	return err;
}

static const struct got_error *
hwrite(int fd, const void *buf, off_t len, struct got_hash *ctx)
{
	got_hash_update(ctx, buf, len);
	return got_poll_write_full(fd, buf, len);
}

static const struct got_error *
hcopy(FILE *fsrc, int fd_dst, off_t len, struct got_hash *ctx)
{
	const struct got_error *err;
	unsigned char buf[65536];
	off_t remain = len;
	size_t n;

	while (remain > 0) {
		size_t copylen = MIN(sizeof(buf), remain);
		n = fread(buf, 1, copylen, fsrc);
		if (n != copylen)
			return got_ferror(fsrc, GOT_ERR_IO);
		got_hash_update(ctx, buf, copylen);
		err = got_poll_write_full(fd_dst, buf, copylen);
		if (err)
			return err;
		remain -= copylen;
	}

	return NULL;
}

static const struct got_error *
hcopy_mmap(uint8_t *src, off_t src_offset, size_t src_size,
    int fd, off_t len, struct got_hash *ctx)
{
	if (src_offset + len > src_size)
		return got_error(GOT_ERR_RANGE);

	got_hash_update(ctx, src + src_offset, len);
	return got_poll_write_full(fd, src + src_offset, len);
}

static void
putbe32(char *b, uint32_t n)
{
	b[0] = n >> 24;
	b[1] = n >> 16;
	b[2] = n >> 8;
	b[3] = n >> 0;
}

static int
write_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b, *ahd, *bhd;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;
	ahd = (a->head == NULL) ? a : a->head;
	bhd = (b->head == NULL) ? b : b->head;
	if (bhd->mtime < ahd->mtime)
		return -1;
	if (bhd->mtime > ahd->mtime)
		return 1;
	if (bhd < ahd)
		return -1;
	if (bhd > ahd)
		return 1;
	if (a->nchain != b->nchain)
		return a->nchain - b->nchain;
	if (a->mtime < b->mtime)
		return -1;
	if (a->mtime > b->mtime)
		return 1;
	return got_object_id_cmp(&a->id, &b->id);
}

static int
reuse_write_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;

	if (a->reused_delta_offset < b->reused_delta_offset)
		return -1;
	if (a->reused_delta_offset > b->reused_delta_offset)
		return 1;
	return 0;
}

static const struct got_error *
packhdr(int *hdrlen, char *hdr, size_t bufsize, int obj_type, size_t len)
{
	size_t i;

	*hdrlen = 0;

	hdr[0] = obj_type << 4;
	hdr[0] |= len & 0xf;
	len >>= 4;
	for (i = 1; len != 0; i++){
		if (i >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
		hdr[i - 1] |= GOT_DELTA_SIZE_MORE;
		hdr[i] = len & GOT_DELTA_SIZE_VAL_MASK;
		len >>= GOT_DELTA_SIZE_SHIFT;
	}

	*hdrlen = i;
	return NULL;
}

static int
packoff(char *hdr, off_t off)
{
	int i, j;
	char rbuf[8];

	rbuf[0] = off & GOT_DELTA_SIZE_VAL_MASK;
	for (i = 1; (off >>= GOT_DELTA_SIZE_SHIFT) != 0; i++) {
		rbuf[i] = (--off & GOT_DELTA_SIZE_VAL_MASK) |
		    GOT_DELTA_SIZE_MORE;
	}

	j = 0;
	while (i > 0)
		hdr[j++] = rbuf[--i];
	return j;
}

static const struct got_error *
deltahdr(off_t *packfile_size, struct got_hash *ctx, int packfd,
    int force_refdelta, struct got_pack_meta *m)
{
	const struct got_error *err;
	char buf[32];
	int nh;
	size_t digest_len = got_hash_digest_length(m->prev->id.algo);

	if (m->prev->off != 0 && !force_refdelta) {
		err = packhdr(&nh, buf, sizeof(buf),
		    GOT_OBJ_TYPE_OFFSET_DELTA, m->delta_len);
		if (err)
			return err;
		nh += packoff(buf + nh, m->off - m->prev->off);
		err = hwrite(packfd, buf, nh, ctx);
		if (err)
			return err;
		*packfile_size += nh;
	} else {
		err = packhdr(&nh, buf, sizeof(buf),
		    GOT_OBJ_TYPE_REF_DELTA, m->delta_len);
		if (err)
			return err;
		err = hwrite(packfd, buf, nh, ctx);
		if (err)
			return err;
		*packfile_size += nh;
		err = hwrite(packfd, m->prev->id.hash, digest_len, ctx);
		if (err)
			return err;
		*packfile_size += digest_len;
	}

	return NULL;
}

static const struct got_error *
write_packed_object(off_t *packfile_size, int packfd,
    FILE *delta_cache, uint8_t *delta_cache_map, size_t delta_cache_size,
    struct got_pack_meta *m, int *outfd, struct got_hash *ctx,
    struct got_repository *repo, int force_refdelta)
{
	const struct got_error *err = NULL;
	struct got_deflate_checksum csum;
	char buf[32];
	int nh;
	struct got_raw_object *raw = NULL;
	off_t outlen, delta_offset;

	memset(&csum, 0, sizeof(csum));
	csum.output_ctx = ctx;

	if (m->reused_delta_offset)
		delta_offset = m->reused_delta_offset;
	else
		delta_offset = m->delta_offset;

	m->off = *packfile_size;
	if (m->delta_len == 0) {
		err = got_object_raw_open(&raw, outfd, repo, &m->id);
		if (err)
			goto done;
		err = packhdr(&nh, buf, sizeof(buf),
		    m->obj_type, raw->size);
		if (err)
			goto done;
		err = hwrite(packfd, buf, nh, ctx);
		if (err)
			goto done;
		*packfile_size += nh;
		if (raw->f == NULL) {
			err = got_deflate_to_fd_mmap(&outlen,
			    raw->data + raw->hdrlen, 0, raw->size,
			    packfd, &csum);
			if (err)
				goto done;
		} else {
			if (fseeko(raw->f, raw->hdrlen, SEEK_SET)
			    == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			err = got_deflate_to_fd(&outlen, raw->f,
			    raw->size, packfd, &csum);
			if (err)
				goto done;
		}
		*packfile_size += outlen;
		got_object_raw_close(raw);
		raw = NULL;
	} else if (m->delta_buf) {
		err = deltahdr(packfile_size, ctx, packfd, force_refdelta, m);
		if (err)
			goto done;
		err = hwrite(packfd, m->delta_buf,
		    m->delta_compressed_len, ctx);
		if (err)
			goto done;
		*packfile_size += m->delta_compressed_len;
		free(m->delta_buf);
		m->delta_buf = NULL;
	} else if (delta_cache_map) {
		err = deltahdr(packfile_size, ctx, packfd, force_refdelta, m);
		if (err)
			goto done;
		err = hcopy_mmap(delta_cache_map, delta_offset,
		    delta_cache_size, packfd, m->delta_compressed_len,
		    ctx);
		if (err)
			goto done;
		*packfile_size += m->delta_compressed_len;
	} else {
		if (fseeko(delta_cache, delta_offset, SEEK_SET) == -1) {
			err = got_error_from_errno("fseeko");
			goto done;
		}
		err = deltahdr(packfile_size, ctx, packfd, force_refdelta, m);
		if (err)
			goto done;
		err = hcopy(delta_cache, packfd,
		    m->delta_compressed_len, ctx);
		if (err)
			goto done;
		*packfile_size += m->delta_compressed_len;
	}
done:
	if (raw)
		got_object_raw_close(raw);
	return err;
}

static const struct got_error *
genpack(struct got_object_id *pack_hash, int packfd,
    struct got_pack *reuse_pack, FILE *delta_cache,
    struct got_pack_meta **deltify, int ndeltify,
    struct got_pack_meta **reuse, int nreuse,
    int ncolored, int nfound, int ntrees, int nours,
    struct got_repository *repo, int force_refdelta,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	int i;
	struct got_hash ctx;
	struct got_pack_meta *m;
	char buf[32];
	off_t packfile_size = 0;
	int outfd = -1;
	int delta_cache_fd = -1;
	uint8_t *delta_cache_map = NULL;
	size_t delta_cache_size = 0;
	FILE *packfile = NULL;
	enum got_hash_algorithm algo;
	size_t digest_len;

	algo = got_repo_get_object_format(repo);
	digest_len = got_hash_digest_length(algo);
	got_hash_init(&ctx, algo);

	memset(pack_hash, 0, sizeof(*pack_hash));
	pack_hash->algo = algo;

#ifndef GOT_PACK_NO_MMAP
	delta_cache_fd = dup(fileno(delta_cache));
	if (delta_cache_fd != -1) {
		struct stat sb;
		if (fstat(delta_cache_fd, &sb) == -1) {
			err = got_error_from_errno("fstat");
			goto done;
		}
		if (sb.st_size > 0 && sb.st_size <= SIZE_MAX) {
			delta_cache_map = mmap(NULL, sb.st_size,
			    PROT_READ, MAP_PRIVATE, delta_cache_fd, 0);
			if (delta_cache_map == MAP_FAILED) {
				if (errno != ENOMEM) {
					err = got_error_from_errno("mmap");
					goto done;
				}
				delta_cache_map = NULL; /* fallback on stdio */
			} else
				delta_cache_size = (size_t)sb.st_size;
		}
	}
#endif
	err = hwrite(packfd, "PACK", 4, &ctx);
	if (err)
		goto done;
	putbe32(buf, GOT_PACKFILE_VERSION);
	err = hwrite(packfd, buf, 4, &ctx);
	if (err)
		goto done;
	putbe32(buf, ndeltify + nreuse);
	err = hwrite(packfd, buf, 4, &ctx);
	if (err)
		goto done;

	qsort(deltify, ndeltify, sizeof(struct got_pack_meta *),
	    write_order_cmp);
	for (i = 0; i < ndeltify; i++) {
		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, packfile_size, nours,
		    ndeltify + nreuse, ndeltify + nreuse, i, 0);
		if (err)
			goto done;
		m = deltify[i];
		err = write_packed_object(&packfile_size, packfd,
		    delta_cache, delta_cache_map, delta_cache_size,
		    m, &outfd, &ctx, repo, force_refdelta);
		if (err)
			goto done;
	}

	qsort(reuse, nreuse, sizeof(struct got_pack_meta *),
	    reuse_write_order_cmp);
	if (nreuse > 0 && reuse_pack->map == NULL) {
		int fd = dup(reuse_pack->fd);
		if (fd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}
		packfile = fdopen(fd, "r");
		if (packfile == NULL) {
			err = got_error_from_errno("fdopen");
			close(fd);
			goto done;
		}
	}
	for (i = 0; i < nreuse; i++) {
		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, packfile_size, nours,
		    ndeltify + nreuse, ndeltify + nreuse, ndeltify + i, 0);
		if (err)
			goto done;
		m = reuse[i];
		err = write_packed_object(&packfile_size, packfd,
		    packfile, reuse_pack->map, reuse_pack->filesize,
		    m, &outfd, &ctx, repo, force_refdelta);
		if (err)
			goto done;
	}

	got_hash_final_object_id(&ctx, pack_hash);
	err = got_poll_write_full(packfd, pack_hash->hash, digest_len);
	if (err)
		goto done;
	packfile_size += digest_len;
	packfile_size += sizeof(struct got_packfile_hdr);
	if (progress_cb) {
		err = progress_cb(progress_arg, ncolored, nfound, ntrees,
		    packfile_size, nours, ndeltify + nreuse,
		    ndeltify + nreuse, ndeltify + nreuse, 1);
		if (err)
			goto done;
	}
done:
	if (outfd != -1 && close(outfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (delta_cache_map && munmap(delta_cache_map, delta_cache_size) == -1)
		err = got_error_from_errno("munmap");
	if (delta_cache_fd != -1 && close(delta_cache_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfile && fclose(packfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
add_meta_idset_cb(struct got_object_id *id, void *data, void *arg)
{
	struct got_pack_meta *m = data;
	struct got_pack_metavec *v = arg;

	if (m->reused_delta_offset != 0)
		return NULL;

	return got_pack_add_meta(m, v);
}

const struct got_error *
got_pack_create(struct got_object_id *packhash, int packfd, FILE *delta_cache,
    struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours,
    struct got_repository *repo, int loose_obj_only, int allow_empty,
    int force_refdelta, got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_object_idset *idset;
	struct got_packidx *reuse_packidx = NULL;
	struct got_pack *reuse_pack = NULL;
	struct got_pack_metavec deltify, reuse;
	int ncolored = 0, nfound = 0, ntrees = 0;
	size_t ndeltify;
	uint32_t seed;

	seed = arc4random();

	memset(&deltify, 0, sizeof(deltify));
	memset(&reuse, 0, sizeof(reuse));

	idset = got_object_idset_alloc();
	if (idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	err = load_object_ids(&ncolored, &nfound, &ntrees, idset, theirs,
	    ntheirs, ours, nours, repo, seed, loose_obj_only,
	    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (progress_cb) {
		err = progress_cb(progress_arg, ncolored, nfound, ntrees,
		    0L, nours, got_object_idset_num_elements(idset), 0, 0, 0);
		if (err)
			goto done;
	}

	if (got_object_idset_num_elements(idset) == 0 && !allow_empty) {
		err = got_error(GOT_ERR_CANNOT_PACK);
		goto done;
	}

	reuse.metasz = 64;
	reuse.meta = calloc(reuse.metasz,
	    sizeof(struct got_pack_meta *));
	if (reuse.meta == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = got_pack_search_deltas(&reuse_packidx, &reuse_pack,
	    &reuse, idset, ncolored, nfound, ntrees, nours,
	    repo, progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (reuse_packidx && reuse_pack) {
		err = got_repo_pin_pack(repo, reuse_packidx, reuse_pack);
		if (err)
			goto done;
	}

	if (fseeko(delta_cache, 0L, SEEK_END) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	ndeltify = got_object_idset_num_elements(idset) - reuse.nmeta;
	if (ndeltify > 0) {
		deltify.meta = calloc(ndeltify, sizeof(struct got_pack_meta *));
		if (deltify.meta == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		deltify.metasz = ndeltify;

		err = got_object_idset_for_each(idset, add_meta_idset_cb,
		    &deltify);
		if (err)
			goto done;
		if (deltify.nmeta > 0) {
			err = pick_deltas(deltify.meta, deltify.nmeta,
			    ncolored, nfound, ntrees, nours, reuse.nmeta,
			    delta_cache, repo, progress_cb, progress_arg, rl,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		}
	}

	if (fflush(delta_cache) == EOF) {
		err = got_error_from_errno("fflush");
		goto done;
	}

	if (progress_cb) {
		/*
		 * Report a 1-byte packfile write to indicate we are about
		 * to start sending packfile data. gotd(8) needs this.
		 */
		err = progress_cb(progress_arg, ncolored, nfound, ntrees,
		    1 /* packfile_size */, nours,
		    got_object_idset_num_elements(idset),
		    deltify.nmeta + reuse.nmeta, 0, 0);
		if (err)
			goto done;
	}

	/* Pinned pack may have moved to different cache slot. */
	reuse_pack = got_repo_get_pinned_pack(repo);

	err = genpack(packhash, packfd, reuse_pack, delta_cache, deltify.meta,
	    deltify.nmeta, reuse.meta, reuse.nmeta, ncolored, nfound, ntrees,
	    nours, repo, force_refdelta, progress_cb, progress_arg, rl,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
done:
	free_nmeta(deltify.meta, deltify.nmeta);
	free_nmeta(reuse.meta, reuse.nmeta);
	got_object_idset_for_each(idset, free_meta, NULL);
	got_object_idset_free(idset);
	got_repo_unpin_pack(repo);
	return err;
}
