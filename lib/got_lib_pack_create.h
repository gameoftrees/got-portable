/*
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

/*
 * Write pack file data into the provided open packfile handle, for all
 * objects reachable via the commits listed in 'ours'.
 * Exclude any objects for commits listed in 'theirs' if 'theirs' is not NULL.
 * Return the hash digest of the resulting pack file in pack_hash which must
 * be pre-allocated by the caller with at least GOT_HASH_DIGEST_MAXLEN bytes.
 */
const struct got_error *got_pack_create(struct got_object_id *pack_hash,
    int packfd, FILE *delta_cache, struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours,
    struct got_repository *repo, int loose_obj_only, int allow_empty,
    int force_refdelta, got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *, got_cancel_cb cancel_cb, void *cancel_arg);

const struct got_error *
got_pack_cache_pack_for_packidx(struct got_pack **pack,
    struct got_packidx *packidx, struct got_repository *repo);

const struct got_error *
got_pack_find_pack_for_commit_painting(struct got_packidx **best_packidx,
    struct got_object_id_queue *ids, struct got_repository *repo);
const struct got_error *got_pack_find_pack_for_reuse(
    struct got_packidx **best_packidx, struct got_repository *repo);

struct got_ratelimit;
const struct got_error *got_pack_paint_commits(int *ncolored,
    struct got_object_id_queue *ids, int nids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_idset *skip, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg);

enum got_pack_findtwixt_color {
	COLOR_KEEP = 0,
	COLOR_DROP,
	COLOR_SKIP,
	COLOR_MAX,
};

const struct got_error *got_pack_paint_commit(struct got_object_qid *qid,
    intptr_t color);
const struct got_error *got_pack_queue_commit_id(
    struct got_object_id_queue *ids, struct got_object_id *id, intptr_t color,
    struct got_repository *repo);

struct got_pack_metavec {
	struct got_pack_meta **meta;
	int nmeta;
	int metasz;
};

struct got_pack_meta {
	struct got_object_id id;
	uint32_t path_hash;
	int	obj_type;
	off_t	size;
	time_t	mtime;

	/* The best delta we picked */
	struct got_pack_meta *head;
	struct got_pack_meta *prev;
	unsigned char *delta_buf; /* if encoded in memory (compressed) */
	off_t	delta_offset;	/* offset in delta cache file (compressed) */
	off_t	delta_len;	/* encoded delta length */
	off_t	delta_compressed_len; /* encoded+compressed delta length */
	int	nchain;

	off_t   reused_delta_offset; /* offset of delta in reused pack file */
	struct got_object_id *base_obj_id;

	/* Only used for delta window */
	struct got_delta_table *dtab;

	/* Only used for writing offset deltas */
	off_t	off;
};

const struct got_error *got_pack_add_meta(struct got_pack_meta *m,
    struct got_pack_metavec *v);

const struct got_error *
got_pack_search_deltas(struct got_packidx **packidx, struct got_pack **pack,
    struct got_pack_metavec *v, struct got_object_idset *idset,
    int ncolored, int nfound, int ntrees, int ncommits,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg);

const struct got_error *
got_pack_report_progress(got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int obj_deltify,
    int nobj_written, int pack_done);

const struct got_error *
got_pack_load_packed_object_ids(int *found_all_objects,
    struct got_object_id **ours, int nours,
    struct got_object_id **theirs, int ntheirs,
    int want_meta, uint32_t seed, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude, int loose_obj_only,
    struct got_repository *repo, struct got_packidx *packidx,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg);

const struct got_error *
got_pack_load_tree_entries(struct got_object_id_queue *ids, int want_meta,
    struct got_object_idset *idset, struct got_object_idset *idset_exclude,
    struct got_tree_object *tree, const struct got_object_id *tree_id,
    const char *dpath, time_t mtime, uint32_t seed, struct got_repository *repo,
    int loose_obj_only, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg);

const struct got_error *
got_pack_load_tree(int want_meta, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude,
    struct got_object_id *tree_id, const char *dpath, time_t mtime,
    uint32_t seed, struct got_repository *repo, int loose_obj_only,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg);

const struct got_error *
got_pack_add_object(int want_meta, struct got_object_idset *idset,
    struct got_object_id *id, const char *path, int obj_type,
    time_t mtime, uint32_t seed, int loose_obj_only,
    struct got_repository *repo, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl);
