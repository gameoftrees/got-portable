/*
 * Copyright (c) 2020 Ori Bernstein
 * Copyright (c) 2021, 2022 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <sha1.h>
#include <sha2.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <imsg.h>
#include <inttypes.h>
#include <unistd.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository_admin.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_idset.h"
#include "got_lib_privsep.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_create.h"
#include "got_lib_repository.h"

struct send_id_arg {
	struct imsgbuf *ibuf;
	struct got_object_id *ids[GOT_IMSG_OBJ_ID_LIST_MAX_NIDS];
	size_t nids;
};

static const struct got_error *
send_id(struct got_object_id *id, void *data, void *arg)
{
	const struct got_error *err = NULL;
	struct send_id_arg *a = arg;

	a->ids[a->nids++] = id;

	if (a->nids >= GOT_IMSG_OBJ_ID_LIST_MAX_NIDS) {
		err = got_privsep_send_object_idlist(a->ibuf, a->ids, a->nids);
		if (err)
			return err;
		a->nids = 0;
	}

	return NULL;
}

static const struct got_error *
send_idset(struct imsgbuf *ibuf, struct got_object_idset *idset)
{
	const struct got_error *err;
	struct send_id_arg sia;

	memset(&sia, 0, sizeof(sia));
	sia.ibuf = ibuf;
	err = got_object_idset_for_each(idset, send_id, &sia);
	if (err)
		return err;

	if (sia.nids > 0) {
		err = got_privsep_send_object_idlist(ibuf, sia.ids, sia.nids);
		if (err)
			return err;
	}

	return got_privsep_send_object_idlist_done(ibuf);
}

static const struct got_error *
recv_reused_delta(struct got_imsg_reused_delta *delta,
    struct got_object_idset *idset, struct got_pack_metavec *v)
{
	struct got_pack_meta *m, *base;

	if (delta->delta_offset + delta->delta_size < delta->delta_offset ||
	    delta->delta_offset +
	    delta->delta_compressed_size < delta->delta_offset)
		return got_error(GOT_ERR_BAD_PACKFILE);

	m = got_object_idset_get(idset, &delta->id);
	if (m == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	base = got_object_idset_get(idset, &delta->base_id);
	if (base == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	m->delta_len = delta->delta_size;
	m->delta_compressed_len = delta->delta_compressed_size;
	m->delta_offset = 0;
	m->prev = base;
	m->size = delta->result_size;
	m->reused_delta_offset = delta->delta_offset;
	m->base_obj_id = got_object_id_dup(&delta->base_id);
	if (m->base_obj_id == NULL)
		return got_error_from_errno("got_object_id_dup");

	return got_pack_add_meta(m, v);
}

const struct got_error *
got_pack_search_deltas(struct got_packidx **packidx, struct got_pack **pack,
    struct got_pack_metavec *v, struct got_object_idset *idset,
    int ncolored, int nfound, int ntrees, int ncommits,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_imsg_reused_delta deltas[GOT_IMSG_REUSED_DELTAS_MAX_NDELTAS];
	size_t ndeltas, i;

	*packidx = NULL;
	*pack = NULL;

	err = got_pack_find_pack_for_reuse(packidx, repo);
	if (err)
		return err;

	if (*packidx == NULL)
		return NULL;

	err = got_pack_cache_pack_for_packidx(pack, *packidx, repo);
	if (err)
		goto done;

	if ((*pack)->privsep_child == NULL) {
		err = got_pack_start_privsep_child(*pack, *packidx);
		if (err)
			goto done;
	}

	err = got_privsep_send_delta_reuse_req((*pack)->privsep_child->ibuf);
	if (err)
		goto done;

	err = send_idset((*pack)->privsep_child->ibuf, idset);
	if (err)
		goto done;

	for (;;) {
		int done = 0;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		err = got_privsep_recv_reused_deltas(&done, deltas, &ndeltas,
		    (*pack)->privsep_child->ibuf);
		if (err || done)
			break;

		for (i = 0; i < ndeltas; i++) {
			struct got_imsg_reused_delta *delta = &deltas[i];
			err = recv_reused_delta(delta, idset, v);
			if (err)
				goto done;
		}

		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, 0L, ncommits,
		    got_object_idset_num_elements(idset), v->nmeta, 0, 0);
		if (err)
			break;
	}
done:
	return err;
}

struct recv_painted_commit_arg {
	int *ncolored;
	int *nqueued;
	int *nskip;
	struct got_object_id_queue *ids;
	struct got_object_idset *keep;
	struct got_object_idset *drop;
	struct got_object_idset *skip;
	got_pack_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
	struct got_object_qid **qid0;
};

static const struct got_error *
recv_painted_commit(void *arg, struct got_object_id *id, intptr_t color)
{
	const struct got_error *err = NULL;
	struct recv_painted_commit_arg *a = arg;
	struct got_object_qid *qid, *tmp;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}
	switch (color) {
	case COLOR_KEEP:
		if (!got_object_idset_contains(a->keep, id)) {
			err = got_object_idset_add(a->keep, id, NULL);
			if (err)
				return err;
			(*a->ncolored)++;
		}
		break;
	case COLOR_DROP:
		if (!got_object_idset_contains(a->drop, id)) {
			err = got_object_idset_add(a->drop, id, NULL);
			if (err)
				return err;
			(*a->ncolored)++;
		}
		break;
	case COLOR_SKIP:
		if (!got_object_idset_contains(a->skip, id)) {
			err = got_object_idset_add(a->skip, id, NULL);
			if (err)
				return err;
		}
		break;
	default:
		/* should not happen */
		return got_error_fmt(GOT_ERR_NOT_IMPL,
		    "%s invalid commit color %"PRIdPTR, __func__, color);
	}

	STAILQ_FOREACH_SAFE(qid, a->ids, entry, tmp) {
		if (got_object_id_cmp(&qid->id, id) != 0)
			continue;
		STAILQ_REMOVE(a->ids, qid, got_object_qid, entry);
		color = (intptr_t)qid->data;
		if (*(a->qid0) == qid)
			*(a->qid0) = NULL;
		got_object_qid_free(qid);
		(*a->nqueued)--;
		if (color == COLOR_SKIP)
			(*a->nskip)--;
		break;
	}

	return got_pack_report_progress(a->progress_cb, a->progress_arg, a->rl,
	    *a->ncolored, 0, 0, 0L, 0, 0, 0, 0, 0);
}

static const struct got_error *
paint_packed_commits(struct got_object_qid **qid0,
    struct got_pack *pack, intptr_t color,
    int *ncolored, int *nqueued, int *nskip, struct got_object_id_queue *ids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_idset *skip, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue next_ids;
	struct got_object_qid *qid, *tmp;
	struct recv_painted_commit_arg arg;

	STAILQ_INIT(&next_ids);

	err = got_privsep_send_painting_request(pack->privsep_child->ibuf);
	if (err)
		return err;

	err = got_privsep_send_object_id_queue(pack->privsep_child->ibuf,
	    ids, *nqueued);
	if (err)
		return err;

	arg.ncolored = ncolored;
	arg.nqueued = nqueued;
	arg.nskip = nskip;
	arg.ids = ids;
	arg.keep = keep;
	arg.drop = drop;
	arg.skip = skip;
	arg.progress_cb = progress_cb;
	arg.progress_arg = progress_arg;
	arg.rl = rl;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	arg.qid0 = qid0;
	err = got_privsep_recv_painted_commits(&next_ids,
	    recv_painted_commit, &arg, pack->privsep_child->ibuf);
	if (err)
		return err;

	STAILQ_FOREACH_SAFE(qid, &next_ids, entry, tmp) {
		struct got_object_qid *old_id;
		intptr_t qcolor, ocolor;
		STAILQ_FOREACH(old_id, ids, entry) {
			if (got_object_id_cmp(&qid->id, &old_id->id))
				continue;
			qcolor = (intptr_t)qid->data;
			ocolor = (intptr_t)old_id->data;
			STAILQ_REMOVE(&next_ids, qid, got_object_qid, entry);
			got_object_qid_free(qid);
			qid = NULL;
			if (qcolor != ocolor) {
				got_pack_paint_commit(old_id, qcolor);
				if (ocolor == COLOR_SKIP)
					(*nskip)--;
				else if (qcolor == COLOR_SKIP)
					(*nskip)++;
			}
			break;
		}
	}
	while (!STAILQ_EMPTY(&next_ids)) {
		qid = STAILQ_FIRST(&next_ids);
		STAILQ_REMOVE_HEAD(&next_ids, entry);
		got_pack_paint_commit(qid, color);
		if (color == COLOR_KEEP)
			STAILQ_INSERT_TAIL(ids, qid, entry);
		else
			STAILQ_INSERT_HEAD(ids, qid, entry);
		(*nqueued)++;
		if (color == COLOR_SKIP)
			(*nskip)++;
	}

	return err;
}

static const struct got_error *
pin_pack_for_commit_painting(struct got_pack **pack,
    struct got_packidx **packidx, struct got_object_id_queue *ids,
    struct got_repository *repo)
{
	const struct got_error *err;

	err = got_pack_find_pack_for_commit_painting(packidx, ids, repo);
	if (err || *packidx == NULL) {
		*pack = NULL;
		return err;
	}

	err = got_pack_cache_pack_for_packidx(pack, *packidx, repo);
	if (err)
		return err;

	if ((*pack)->privsep_child == NULL) {
		err = got_pack_start_privsep_child(*pack, *packidx);
		if (err)
			return err;
	}

	return got_repo_pin_pack(repo, *packidx, *pack);
}

const struct got_error *
got_pack_paint_commits(int *ncolored, struct got_object_id_queue *ids, int nids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_idset *skip, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	const struct got_object_id_queue *parents;
	struct got_object_qid *qid = NULL;
	int nqueued = nids, nskip = 0;
	int idx;

	err = pin_pack_for_commit_painting(&pack, &packidx, ids, repo);
	if (err)
		return err;

	while (!STAILQ_EMPTY(ids) && nskip != nqueued) {
		intptr_t color;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}

		/* Pinned pack may have moved to different cache slot. */
		pack = got_repo_get_pinned_pack(repo);
		if (pack == NULL) {
			err = pin_pack_for_commit_painting(&pack, &packidx,
			    ids, repo);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(ids);
		color = (intptr_t)qid->data;

		/* Use the fast path if we have a suitable pack file. */
		if (packidx && pack) {
			idx = got_packidx_get_object_idx(packidx, &qid->id);
			if (idx != -1) {
				err = got_privsep_init_commit_painting(
				    pack->privsep_child->ibuf);
				if (err)
					goto done;
				err = send_idset(pack->privsep_child->ibuf,
				    keep);
				if (err)
					goto done;
				err = send_idset(pack->privsep_child->ibuf,
				    drop);
				if (err)
					goto done;
				err = send_idset(pack->privsep_child->ibuf,
				    skip);
				if (err)
					goto done;
				err = paint_packed_commits(&qid, pack,
				    color, ncolored, &nqueued, &nskip,
				    ids, keep, drop, skip, repo,
				    progress_cb, progress_arg, rl,
				    cancel_cb, cancel_arg);
				if (err && qid == NULL)
					goto done;
				if (qid) {
					STAILQ_REMOVE(ids, qid,
					    got_object_qid, entry);
					nqueued--;
					got_object_qid_free(qid);
					qid = NULL;
					if (err)
						goto done;
				}
				continue;
			}
		}

		STAILQ_REMOVE_HEAD(ids, entry);
		nqueued--;

		got_repo_unpin_pack(repo);
		pack = NULL;
		packidx = NULL;

		if (color == COLOR_SKIP)
			nskip--;

		if (got_object_idset_contains(skip, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}
		if (color == COLOR_KEEP &&
		    got_object_idset_contains(keep, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}
		if (color == COLOR_DROP &&
		    got_object_idset_contains(drop, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}

		switch (color) {
		case COLOR_KEEP:
			if (got_object_idset_contains(drop, &qid->id)) {
				err = got_pack_paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			} else
				(*ncolored)++;
			err = got_object_idset_add(keep, &qid->id, NULL);
			if (err)
				goto done;
			break;
		case COLOR_DROP:
			if (got_object_idset_contains(keep, &qid->id)) {
				err = got_pack_paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			} else
				(*ncolored)++;
			err = got_object_idset_add(drop, &qid->id, NULL);
			if (err)
				goto done;
			break;
		case COLOR_SKIP:
			if (!got_object_idset_contains(skip, &qid->id)) {
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			}
			break;
		default:
			/* should not happen */
			err = got_error_fmt(GOT_ERR_NOT_IMPL,
			    "%s invalid commit color %"PRIdPTR, __func__,
			    color);
			goto done;
		}

		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    *ncolored, 0, 0, 0L, 0, 0, 0, 0, 0);
		if (err)
			break;

		err = got_object_open_as_commit(&commit, repo, &qid->id);
		if (err)
			break;

		parents = got_object_commit_get_parent_ids(commit);
		if (parents) {
			struct got_object_qid *pid;
			color = (intptr_t)qid->data;
			STAILQ_FOREACH(pid, parents, entry) {
				err = got_pack_queue_commit_id(ids, &pid->id,
				    color, repo);
				if (err)
					goto done;
				nqueued++;
				if (color == COLOR_SKIP)
					nskip++;
			}
		}

		got_object_commit_close(commit);
		commit = NULL;

		got_object_qid_free(qid);
		qid = NULL;
	}
done:
	if (pack) {
		const struct got_error *pack_err;
		pack_err = got_privsep_send_painting_commits_done(
		    pack->privsep_child->ibuf);
		if (err == NULL)
			err = pack_err;
	}
	if (commit)
		got_object_commit_close(commit);
	got_object_qid_free(qid);
	got_repo_unpin_pack(repo);
	return err;
}

struct load_packed_obj_arg {
	/* output parameters: */
	struct got_object_id *id;
	char *dpath;
	time_t mtime;

	/* input parameters: */
	uint32_t seed;
	int want_meta;
	struct got_object_idset *idset;
	struct got_object_idset *idset_exclude;
	int loose_obj_only;
	int *ncolored;
	int *nfound;
	int *ntrees;
	got_pack_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
};

static const struct got_error *
load_packed_commit_id(void *arg, time_t mtime, struct got_object_id *id,
    struct got_repository *repo)
{
	struct load_packed_obj_arg *a = arg;

	if (got_object_idset_contains(a->idset, id) ||
	    got_object_idset_contains(a->idset_exclude, id))
		return NULL;

	return got_pack_add_object(a->want_meta,
	    a->want_meta ? a->idset : a->idset_exclude,
	    id, "", GOT_OBJ_TYPE_COMMIT, mtime, a->seed, a->loose_obj_only,
	    repo, a->ncolored, a->nfound, a->ntrees,
	    a->progress_cb, a->progress_arg, a->rl);
}

static const struct got_error *
load_packed_tree_ids(void *arg, struct got_tree_object *tree, time_t mtime,
    struct got_object_id *id, const char *dpath, struct got_repository *repo)
{
	const struct got_error *err;
	struct load_packed_obj_arg *a = arg;
	const char *relpath;

	/*
	 * When we receive a tree's ID and path but not the tree itself,
	 * this tree object was not found in the pack file. This is the
	 * last time we are being called for this optimized traversal.
	 * Return from here and switch to loading objects the slow way.
	 */
	if (tree == NULL) {
		free(a->id);
		a->id = got_object_id_dup(id);
		if (a->id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			free(a->dpath);
			a->dpath = NULL;
			return err;
		}

		free(a->dpath);
		a->dpath = strdup(dpath);
		if (a->dpath == NULL) {
			err = got_error_from_errno("strdup");
			free(a->id);
			a->id = NULL;
			return err;
		}

		a->mtime = mtime;
		return NULL;
	}

	if (got_object_idset_contains(a->idset, id) ||
	    got_object_idset_contains(a->idset_exclude, id))
		return NULL;

	relpath = dpath;
	while (relpath[0] == '/')
		relpath++;

	err = got_pack_add_object(a->want_meta,
	    a->want_meta ? a->idset : a->idset_exclude,
	    id, relpath, GOT_OBJ_TYPE_TREE, mtime, a->seed,
	    a->loose_obj_only, repo, a->ncolored, a->nfound, a->ntrees,
	    a->progress_cb, a->progress_arg, a->rl);
	if (err)
		return err;

	return got_pack_load_tree_entries(NULL, a->want_meta, a->idset,
	    a->idset_exclude, tree, dpath, mtime, a->seed, repo,
	    a->loose_obj_only, a->ncolored, a->nfound, a->ntrees,
	    a->progress_cb, a->progress_arg, a->rl,
	    a->cancel_cb, a->cancel_arg);
}

const struct got_error *
got_pack_load_packed_object_ids(int *found_all_objects,
    struct got_object_id **ours, int nours,
    struct got_object_id **theirs, int ntheirs,
    int want_meta, uint32_t seed, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude, int loose_obj_only,
    struct got_repository *repo, struct got_packidx *packidx,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct load_packed_obj_arg lpa;

	memset(&lpa, 0, sizeof(lpa));
	lpa.seed = seed;
	lpa.want_meta = want_meta;
	lpa.idset = idset;
	lpa.idset_exclude = idset_exclude;
	lpa.loose_obj_only = loose_obj_only;
	lpa.ncolored = ncolored;
	lpa.nfound = nfound;
	lpa.ntrees = ntrees;
	lpa.progress_cb = progress_cb;
	lpa.progress_arg = progress_arg;
	lpa.rl = rl;
	lpa.cancel_cb = cancel_cb;
	lpa.cancel_arg = cancel_arg;

	/* Attempt to load objects via got-read-pack, as far as possible. */
	err = got_object_enumerate(found_all_objects, load_packed_commit_id,
	   load_packed_tree_ids, &lpa, ours, nours, theirs, ntheirs,
	   packidx, repo);
	if (err)
		return err;

	if (lpa.id == NULL)
		return NULL;

	/*
	 * An incomplete tree hierarchy was present in the pack file
	 * and caused loading to be aborted.
	 * Continue loading trees the slow way.
	 */
	err = got_pack_load_tree(want_meta, idset, idset_exclude,
	    lpa.id, lpa.dpath, lpa.mtime, seed, repo, loose_obj_only,
	    ncolored, nfound, ntrees, progress_cb, progress_arg, rl,
	    cancel_cb, cancel_arg);
	free(lpa.id);
	free(lpa.dpath);
	return err;
}
