/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <event.h>
#include <errno.h>
#include <imsg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <poll.h>
#include <unistd.h>
#include <zlib.h>

#include "buf.h"

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_path.h"
#include "got_diff.h"
#include "got_cancel.h"
#include "got_commit_graph.h"
#include "got_opentemp.h"

#include "got_lib_delta.h"
#include "got_lib_delta_cache.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_parse.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_index.h"
#include "got_lib_repository.h"
#include "got_lib_poll.h"

#include "log.h"
#include "gotd.h"
#include "repo_write.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct repo_write {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
	FILE *base_file;
	FILE *accum_file;
	int session_fd;
	struct gotd_imsgev session_iev;
	struct got_pathlist_head protected_tag_namespaces;
	struct got_pathlist_head protected_branch_namespaces;
	struct got_pathlist_head protected_branches;
	struct {
		FILE *f1;
		FILE *f2;
		int fd1;
		int fd2;
	} diff;
	int refs_listed;
	int have_packfile;
	struct got_pathlist_head *protected_refs_cur;
	size_t nprotected_refs_needed;
	size_t nprotected_refs_received;
} repo_write;

struct gotd_ref_update {
	STAILQ_ENTRY(gotd_ref_update) entry;
	struct got_reference *ref;
	int ref_is_new;
	int delete_ref;
	struct got_object_id old_id;
	struct got_object_id new_id;
};
STAILQ_HEAD(gotd_ref_updates, gotd_ref_update);

static struct repo_write_client {
	uint32_t			 id;
	int				 fd;
	int				 pack_pipe;
	struct got_pack			 pack;
	struct got_packidx		 *packidx;
	uint8_t				 pack_sha1[SHA1_DIGEST_LENGTH];
	int				 packidx_fd;
	struct gotd_ref_updates		 ref_updates;
	int				 nref_updates;
	int				 nref_del;
	int				 nref_new;
	int				 nref_move;
} repo_write_client;

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigterm_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigterm(int signo)
{
	sigterm_received = 1;
}

static const struct got_error *
check_cancelled(void *arg)
{
	if (sigint_received || sigterm_received)
		return got_error(GOT_ERR_CANCELLED);

	return NULL;
}

static const struct got_error *
send_peeled_tag_ref(struct got_reference *ref, struct got_object *obj,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_tag_object *tag;
	size_t namelen, len;
	char *peeled_refname = NULL;
	struct got_object_id *id;
	struct ibuf *wbuf;

	err = got_object_tag_open(&tag, repo_write.repo, obj);
	if (err)
		return err;

	if (asprintf(&peeled_refname, "%s^{}", got_ref_get_name(ref)) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	id = got_object_tag_get_object_id(tag);
	namelen = strlen(peeled_refname);

	len = sizeof(struct gotd_imsg_ref) + namelen;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, GOTD_PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF");
		goto done;
	}

	/* Keep in sync with struct gotd_imsg_ref definition. */
	if (imsg_add(wbuf, id->hash, SHA1_DIGEST_LENGTH) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}
	if (imsg_add(wbuf, &namelen, sizeof(namelen)) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}
	if (imsg_add(wbuf, peeled_refname, namelen) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}

	imsg_close(ibuf, wbuf);
done:
	got_object_tag_close(tag);
	return err;
}

static const struct got_error *
send_ref(struct got_reference *ref, struct imsgbuf *ibuf)
{
	const struct got_error *err;
	const char *refname = got_ref_get_name(ref);
	size_t namelen;
	struct got_object_id *id = NULL;
	struct got_object *obj = NULL;
	size_t len;
	struct ibuf *wbuf;

	namelen = strlen(refname);

	len = sizeof(struct gotd_imsg_ref) + namelen;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	err = got_ref_resolve(&id, repo_write.repo, ref);
	if (err)
		return err;

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, GOTD_PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF");
		goto done;
	}

	/* Keep in sync with struct gotd_imsg_ref definition. */
	if (imsg_add(wbuf, id->hash, SHA1_DIGEST_LENGTH) == -1)
		return got_error_from_errno("imsg_add REF");
	if (imsg_add(wbuf, &namelen, sizeof(namelen)) == -1)
		return got_error_from_errno("imsg_add REF");
	if (imsg_add(wbuf, refname, namelen) == -1)
		return got_error_from_errno("imsg_add REF");

	imsg_close(ibuf, wbuf);

	err = got_object_open(&obj, repo_write.repo, id);
	if (err)
		goto done;
	if (obj->type == GOT_OBJ_TYPE_TAG)
		err = send_peeled_tag_ref(ref, obj, ibuf);
done:
	if (obj)
		got_object_close(obj);
	free(id);
	return err;
}

static const struct got_error *
list_refs(struct imsg *imsg)
{
	const struct got_error *err;
	struct repo_write_client *client = &repo_write_client;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	size_t datalen;
	struct gotd_imsg_reflist irefs;
	struct imsgbuf ibuf;

	TAILQ_INIT(&refs);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (repo_write.refs_listed) {
		return got_error_msg(GOT_ERR_CLIENT_ID,
		    "duplicate list-refs request");
	}
	repo_write.refs_listed = 1;

	client->fd = imsg_get_fd(imsg);
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	client->nref_updates = 0;
	client->nref_del = 0;
	client->nref_new = 0;
	client->nref_move = 0;

	if (imsgbuf_init(&ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	err = got_ref_list(&refs, repo_write.repo, "",
	    got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	memset(&irefs, 0, sizeof(irefs));
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		int obj_type;

		if (got_ref_is_symbolic(re->ref))
			continue;

		irefs.nrefs++;

		/* Account for a peeled tag refs. */
		err = got_ref_resolve(&id, repo_write.repo, re->ref);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo_write.repo, id);
		free(id);
		if (err)
			goto done;
		if (obj_type == GOT_OBJ_TYPE_TAG)
			irefs.nrefs++;
	}

	if (imsg_compose(&ibuf, GOTD_IMSG_REFLIST, GOTD_PROC_REPO_WRITE,
	    repo_write.pid, -1, &irefs, sizeof(irefs)) == -1) {
		err = got_error_from_errno("imsg_compose REFLIST");
		goto done;
	}

	TAILQ_FOREACH(re, &refs, entry) {
		if (got_ref_is_symbolic(re->ref))
			continue;
		err = send_ref(re->ref, &ibuf);
		if (err)
			goto done;
	}

	err = gotd_imsg_flush(&ibuf);
done:
	got_ref_list_free(&refs);
	imsgbuf_clear(&ibuf);
	return err;
}

static const struct got_error *
validate_namespace(const char *namespace)
{
	size_t len = strlen(namespace);

	if (len < 5 || strncmp("refs/", namespace, 5) != 0 ||
	    namespace[len -1] != '/') {
		return got_error_fmt(GOT_ERR_BAD_REF_NAME,
		    "reference namespace '%s'", namespace);
	}

	return NULL;
}

static const struct got_error *
protect_ref_namespace(const char *refname, const char *namespace)
{
	const struct got_error *err;

	err = validate_namespace(namespace);
	if (err)
		return err;

	if (strncmp(namespace, refname, strlen(namespace)) == 0)
		return got_error_fmt(GOT_ERR_REFS_PROTECTED, "%s", namespace);

	return NULL;
}

static const struct got_error *
verify_object_type(struct got_object_id *id, int expected_obj_type,
    struct got_pack *pack, struct got_packidx *packidx)
{
	const struct got_error *err;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	struct got_object *obj;
	int idx;
	const char *typestr;

	idx = got_packidx_get_object_idx(packidx, id);
	if (idx == -1) {
		got_object_id_hex(id, hex, sizeof(hex));
		return got_error_fmt(GOT_ERR_BAD_PACKFILE,
		    "object %s is missing from pack file", hex);
	}

	err = got_object_open_from_packfile(&obj, id, pack, packidx,
	    idx, repo_write.repo);
	if (err)
		return err;

	if (obj->type != expected_obj_type) {
		got_object_id_hex(id, hex, sizeof(hex));
		got_object_type_label(&typestr, expected_obj_type);
		err = got_error_fmt(GOT_ERR_OBJ_TYPE,
		    "%s is not pointing at a %s object", hex, typestr);
	}
	got_object_close(obj);
	return err;
}

static const struct got_error *
protect_tag_namespace(const char *namespace, struct got_pack *pack,
    struct got_packidx *packidx, struct gotd_ref_update *ref_update)
{
	const struct got_error *err;

	err = validate_namespace(namespace);
	if (err)
		return err;

	if (strncmp(namespace, got_ref_get_name(ref_update->ref),
	    strlen(namespace)) != 0)
		return NULL;

	if (!ref_update->ref_is_new)
		return got_error_fmt(GOT_ERR_REFS_PROTECTED, "%s", namespace);

	return verify_object_type(&ref_update->new_id, GOT_OBJ_TYPE_TAG,
	    pack, packidx);
}

static const struct got_error *
protect_require_yca(struct got_object_id *tip_id,
    size_t max_commits_to_traverse, struct got_pack *pack,
    struct got_packidx *packidx, struct got_reference *ref)
{
	const struct got_error *err;
	uint8_t *buf = NULL;
	size_t len;
	struct got_object_id *expected_yca_id = NULL;
	struct got_object *obj = NULL;
	struct got_commit_object *commit = NULL;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	const struct got_object_id_queue *parent_ids;
	struct got_object_id_queue ids;
	struct got_object_qid *pid, *qid;
	struct got_object_idset *traversed_set = NULL;
	int found_yca = 0, obj_type;

	STAILQ_INIT(&ids);

	err = got_ref_resolve(&expected_yca_id, repo_write.repo, ref);
	if (err)
		return err;

	err = got_object_get_type(&obj_type, repo_write.repo, expected_yca_id);
	if (err)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_COMMIT) {
		got_object_id_hex(expected_yca_id, hex, sizeof(hex));
		err = got_error_fmt(GOT_ERR_OBJ_TYPE,
		    "%s is not pointing at a commit object", hex);
		goto done;
	}

	traversed_set = got_object_idset_alloc();
	if (traversed_set == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	err = got_object_qid_alloc(&qid, tip_id);
	if (err)
		goto done;
	STAILQ_INSERT_TAIL(&ids, qid, entry);
	while (!STAILQ_EMPTY(&ids)) {
		err = check_cancelled(NULL);
		if (err)
			break;

		qid = STAILQ_FIRST(&ids);
		if (got_object_id_cmp(&qid->id, expected_yca_id) == 0) {
			found_yca = 1;
			break;
		}

		if (max_commits_to_traverse > 0 &&
		    got_object_idset_num_elements(traversed_set) >=
		    max_commits_to_traverse)
			break;

		if (got_object_idset_contains(traversed_set, &qid->id)) {
			STAILQ_REMOVE_HEAD(&ids, entry);
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}
		err = got_object_idset_add(traversed_set, &qid->id, NULL);
		if (err)
			goto done;

		err = got_object_open(&obj, repo_write.repo, &qid->id);
		if (err && err->code != GOT_ERR_NO_OBJ)
			goto done;
		err = NULL;
		if (obj) {
			err = got_object_commit_open(&commit, repo_write.repo,
			    obj);
			if (err)
				goto done;
		} else {
			int idx;

			idx = got_packidx_get_object_idx(packidx, &qid->id);
			if (idx == -1) {
				got_object_id_hex(&qid->id, hex, sizeof(hex));
				err = got_error_fmt(GOT_ERR_BAD_PACKFILE,
				    "object %s is missing from pack file", hex);
				goto done;
			}

			err = got_object_open_from_packfile(&obj, &qid->id,
				pack, packidx, idx, repo_write.repo);
			if (err)
				goto done;

			if (obj->type != GOT_OBJ_TYPE_COMMIT) {
				got_object_id_hex(&qid->id, hex, sizeof(hex));
				err = got_error_fmt(GOT_ERR_OBJ_TYPE,
				    "%s is not pointing at a commit object",
				    hex);
				goto done;
			}

			err = got_packfile_extract_object_to_mem(&buf, &len,
			    obj, pack);
			if (err)
				goto done;

			err = got_object_parse_commit(&commit, buf, len,
			    GOT_HASH_SHA1);
			if (err)
				goto done;

			free(buf);
			buf = NULL;
		}

		got_object_close(obj);
		obj = NULL;

		STAILQ_REMOVE_HEAD(&ids, entry);
		got_object_qid_free(qid);
		qid = NULL;

		if (got_object_commit_get_nparents(commit) == 0)
			break;

		parent_ids = got_object_commit_get_parent_ids(commit);
		STAILQ_FOREACH(pid, parent_ids, entry) {
			err = check_cancelled(NULL);
			if (err)
				goto done;
			err = got_object_qid_alloc(&qid, &pid->id);
			if (err)
				goto done;
			STAILQ_INSERT_TAIL(&ids, qid, entry);
			qid = NULL;
		}
		got_object_commit_close(commit);
		commit = NULL;
	}

	if (!found_yca) {
		err = got_error_fmt(GOT_ERR_REF_PROTECTED, "%s",
		    got_ref_get_name(ref));
	}
done:
	got_object_idset_free(traversed_set);
	got_object_id_queue_free(&ids);
	free(buf);
	if (obj)
		got_object_close(obj);
	if (commit)
		got_object_commit_close(commit);
	free(expected_yca_id);
	return err;
}

static const struct got_error *
protect_branch_namespace(const char *namespace, struct got_pack *pack,
    struct got_packidx *packidx, struct gotd_ref_update *ref_update)
{
	const struct got_error *err;

	err = validate_namespace(namespace);
	if (err)
		return err;

	if (strncmp(namespace, got_ref_get_name(ref_update->ref),
	    strlen(namespace)) != 0)
		return NULL;

	if (ref_update->ref_is_new) {
		return verify_object_type(&ref_update->new_id,
		    GOT_OBJ_TYPE_COMMIT, pack, packidx);
	}

	return protect_require_yca(&ref_update->new_id,
	    be32toh(packidx->hdr.fanout_table[0xff]), pack, packidx,
	    ref_update->ref);
}

static const struct got_error *
protect_branch(const char *refname, struct got_pack *pack,
    struct got_packidx *packidx, struct gotd_ref_update *ref_update)
{
	if (strcmp(refname, got_ref_get_name(ref_update->ref)) != 0)
		return NULL;

	/* Always allow new branches to be created. */
	if (ref_update->ref_is_new) {
		return verify_object_type(&ref_update->new_id,
		    GOT_OBJ_TYPE_COMMIT, pack, packidx);
	}

	return protect_require_yca(&ref_update->new_id,
	    be32toh(packidx->hdr.fanout_table[0xff]), pack, packidx,
	    ref_update->ref);
}

static const struct got_error *
recv_ref_update(struct imsg *imsg)
{
	static const char zero_id[SHA1_DIGEST_LENGTH];
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_ref_update iref;
	size_t datalen;
	char *refname = NULL;
	struct got_reference *ref = NULL;
	struct got_object_id *id = NULL;
	struct imsgbuf ibuf;
	struct gotd_ref_update *ref_update = NULL;

	log_debug("ref-update received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));
	if (datalen != sizeof(iref) + iref.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (imsgbuf_init(&ibuf, client->fd))
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	refname = strndup(imsg->data + sizeof(iref), iref.name_len);
	if (refname == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

	ref_update = calloc(1, sizeof(*ref_update));
	if (ref_update == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}

	memcpy(ref_update->old_id.hash, iref.old_id, SHA1_DIGEST_LENGTH);
	memcpy(ref_update->new_id.hash, iref.new_id, SHA1_DIGEST_LENGTH);

	err = got_ref_open(&ref, repo_write.repo, refname, 0);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		if (memcmp(ref_update->new_id.hash,
		    zero_id, sizeof(zero_id)) == 0) {
			err = got_error_fmt(GOT_ERR_BAD_OBJ_ID,
			    "%s", refname);
			goto done;
		}
		err = got_ref_alloc(&ref, refname, &ref_update->new_id);
		if (err)
			goto done;
		ref_update->ref_is_new = 1;
		client->nref_new++;
	}
	if (got_ref_is_symbolic(ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "'%s' is a symbolic reference and cannot "
		    "be updated", got_ref_get_name(ref));
		goto done;
	}
	if (strncmp("refs/", got_ref_get_name(ref), 5) != 0) {
		err = got_error_fmt(GOT_ERR_BAD_REF_NAME,
		    "%s: does not begin with 'refs/'",
		    got_ref_get_name(ref));
		goto done;
	}

	err = protect_ref_namespace(got_ref_get_name(ref), "refs/got/");
	if (err)
		goto done;
	err = protect_ref_namespace(got_ref_get_name(ref), "refs/remotes/");
	if (err)
		goto done;

	if (!ref_update->ref_is_new) {
		/*
		 * Ensure the client's idea of this update is still valid.
		 * At this point we can only return an error, to prevent
		 * the client from uploading a pack file which will likely
		 * have to be discarded.
		 */
		err = got_ref_resolve(&id, repo_write.repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &ref_update->old_id) != 0) {
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "%s has been modified by someone else "
			    "while transaction was in progress",
			    got_ref_get_name(ref));
			goto done;
		}
	}

	gotd_imsg_send_ack(&ref_update->new_id, &ibuf, GOTD_PROC_REPO_WRITE,
	    repo_write.pid);

	ref_update->ref = ref;
	if (memcmp(ref_update->new_id.hash, zero_id, sizeof(zero_id)) == 0) {
		ref_update->delete_ref = 1;
		client->nref_del++;
	}
	STAILQ_INSERT_HEAD(&client->ref_updates, ref_update, entry);
	client->nref_updates++;
	ref = NULL;
	ref_update = NULL;
done:
	if (ref)
		got_ref_close(ref);
	free(ref_update);
	free(refname);
	free(id);
	return err;
}

static const struct got_error *
pack_index_progress(void *arg, uint32_t nobj_total, uint32_t nobj_indexed,
    uint32_t nobj_loose, uint32_t nobj_resolved)
{
	int p_indexed = 0, p_resolved = 0;
	int nobj_delta = nobj_total - nobj_loose;

	if (nobj_total > 0)
		p_indexed = (nobj_indexed * 100) / nobj_total;

	if (nobj_delta > 0)
		p_resolved = (nobj_resolved * 100) / nobj_delta;

	if (p_resolved > 0) {
		log_debug("indexing %d objects %d%%; resolving %d deltas %d%%",
		    nobj_total, p_indexed, nobj_delta, p_resolved);
	} else
		log_debug("indexing %d objects %d%%", nobj_total, p_indexed);

	return NULL;
}

static const struct got_error *
read_more_pack_stream(int infd, BUF *buf, size_t minsize)
{
	const struct got_error *err = NULL;
	uint8_t readahead[65536];
	size_t have, newlen;

	err = got_poll_read_full(infd, &have,
	    readahead, sizeof(readahead), minsize);
	if (err)
		return err;

	err = buf_append(&newlen, buf, readahead, have);
	if (err)
		return err;
	return NULL;
}

static const struct got_error *
copy_object_type_and_size(uint8_t *type, uint64_t *size, int infd, int outfd,
    off_t *outsize, BUF *buf, size_t *buf_pos, struct got_hash *ctx)
{
	const struct got_error *err = NULL;
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizebuf[8];
	size_t i = 0;
	off_t obj_offset = *outsize;

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error_fmt(GOT_ERR_OBJ_TOO_LARGE,
			    "packfile offset %lld", (long long)obj_offset);

		if (buf_len(buf) - *buf_pos < sizeof(sizebuf[0])) {
			err = read_more_pack_stream(infd, buf,
			    sizeof(sizebuf[0]));
			if (err)
				return err;
		}

		sizebuf[i] = buf_getc(buf, *buf_pos);
		*buf_pos += sizeof(sizebuf[i]);

		if (i == 0) {
			t = (sizebuf[i] & GOT_PACK_OBJ_SIZE0_TYPE_MASK) >>
			    GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT;
			s = (sizebuf[i] & GOT_PACK_OBJ_SIZE0_VAL_MASK);
		} else {
			size_t shift = 4 + 7 * (i - 1);
			s |= ((sizebuf[i] & GOT_PACK_OBJ_SIZE_VAL_MASK) <<
			    shift);
		}
		i++;
	} while (sizebuf[i - 1] & GOT_PACK_OBJ_SIZE_MORE);

	err = got_pack_hwrite(outfd, sizebuf, i, ctx);
	if (err)
		return err;
	*outsize += i;

	*type = t;
	*size = s;
	return NULL;
}

static const struct got_error *
copy_ref_delta(int infd, int outfd, off_t *outsize, BUF *buf, size_t *buf_pos,
    struct got_hash *ctx)
{
	const struct got_error *err = NULL;
	size_t remain = buf_len(buf) - *buf_pos;

	if (remain < SHA1_DIGEST_LENGTH) {
		err = read_more_pack_stream(infd, buf,
		    SHA1_DIGEST_LENGTH - remain);
		if (err)
			return err;
	}

	err = got_pack_hwrite(outfd, buf_get(buf) + *buf_pos,
	    SHA1_DIGEST_LENGTH, ctx);
	if (err)
		return err;

	*buf_pos += SHA1_DIGEST_LENGTH;
	*outsize += SHA1_DIGEST_LENGTH;
	return NULL;
}

static const struct got_error *
copy_offset_delta(int infd, int outfd, off_t *outsize, BUF *buf,
    size_t *buf_pos, struct got_hash *ctx)
{
	const struct got_error *err = NULL;
	uint64_t o = 0;
	uint8_t offbuf[8];
	size_t i = 0;
	off_t obj_offset = *outsize;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error_fmt(GOT_ERR_OBJ_TOO_LARGE,
			    "packfile offset %lld", (long long)obj_offset);

		if (buf_len(buf) - *buf_pos < sizeof(offbuf[0])) {
			err = read_more_pack_stream(infd, buf,
			    sizeof(offbuf[0]));
			if (err)
				return err;
		}

		offbuf[i] = buf_getc(buf, *buf_pos);
		*buf_pos += sizeof(offbuf[i]);

		if (i == 0)
			o = (offbuf[i] & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		else {
			o++;
			o <<= 7;
			o += (offbuf[i] & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		}
		i++;
	} while (offbuf[i - 1] & GOT_PACK_OBJ_DELTA_OFF_MORE);

	if (o < sizeof(struct got_packfile_hdr) || o > *outsize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_hwrite(outfd, offbuf, i, ctx);
	if (err)
		return err;

	*outsize += i;
	return NULL;
}

static const struct got_error *
copy_zstream(int infd, int outfd, off_t *outsize, BUF *buf, size_t *buf_pos,
    struct got_hash *ctx)
{
	const struct got_error *err = NULL;
	z_stream z;
	int zret;
	char voidbuf[1024];
	size_t consumed_total = 0;
	off_t zstream_offset = *outsize;

	memset(&z, 0, sizeof(z));

	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	zret = inflateInit(&z);
	if (zret != Z_OK) {
		if  (zret == Z_ERRNO)
			return got_error_from_errno("inflateInit");
		if  (zret == Z_MEM_ERROR) {
			errno = ENOMEM;
			return got_error_from_errno("inflateInit");
		}
		return got_error_msg(GOT_ERR_DECOMPRESSION,
		    "inflateInit failed");
	}

	while (zret != Z_STREAM_END) {
		size_t last_total_in, consumed;

		/*
		 * Decompress into the void. Object data will be parsed
		 * later, when the pack file is indexed. For now, we just
		 * want to locate the end of the compressed stream.
		 */
		while (zret != Z_STREAM_END && buf_len(buf) - *buf_pos > 0) {
			last_total_in = z.total_in;
			z.next_in = buf_get(buf) + *buf_pos;
			z.avail_in = buf_len(buf) - *buf_pos;
			z.next_out = voidbuf;
			z.avail_out = sizeof(voidbuf);

			zret = inflate(&z, Z_SYNC_FLUSH);
			if (zret != Z_OK && zret != Z_BUF_ERROR &&
			    zret != Z_STREAM_END) {
				err = got_error_fmt(GOT_ERR_DECOMPRESSION,
				    "packfile offset %lld",
				    (long long)zstream_offset);
				goto done;
			}
			consumed = z.total_in - last_total_in;

			err = got_pack_hwrite(outfd, buf_get(buf) + *buf_pos,
			    consumed, ctx);
			if (err)
				goto done;

			err = buf_discard(buf, *buf_pos + consumed);
			if (err)
				goto done;
			*buf_pos = 0;

			consumed_total += consumed;
		}

		if (zret != Z_STREAM_END) {
			err = read_more_pack_stream(infd, buf, 1);
			if (err)
				goto done;
		}
	}

	if (err == NULL)
		*outsize += consumed_total;
done:
	inflateEnd(&z);
	return err;
}

static const struct got_error *
validate_object_type(int obj_type)
{
	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_TAG:
	case GOT_OBJ_TYPE_REF_DELTA:
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		return NULL;
	default:
		break;
	}

	return got_error(GOT_ERR_OBJ_TYPE);
}

static const struct got_error *
ensure_all_objects_exist_locally(struct gotd_ref_updates *ref_updates)
{
	const struct got_error *err = NULL;
	struct gotd_ref_update *ref_update;
	struct got_object *obj;

	STAILQ_FOREACH(ref_update, ref_updates, entry) {
		err = got_object_open(&obj, repo_write.repo,
		    &ref_update->new_id);
		if (err)
			return err;
		got_object_close(obj);
	}

	return NULL;
}

static const struct got_error *
recv_packdata(off_t *outsize, uint32_t *nobj, uint8_t *sha1,
    int infd, int outfd)
{
	const struct got_error *err;
	struct repo_write_client *client = &repo_write_client;
	struct got_packfile_hdr hdr;
	size_t have;
	uint32_t nhave = 0;
	struct got_hash ctx;
	uint8_t expected_sha1[SHA1_DIGEST_LENGTH];
	char hex[SHA1_DIGEST_STRING_LENGTH];
	BUF *buf = NULL;
	size_t buf_pos = 0, remain;
	ssize_t w;

	*outsize = 0;
	*nobj = 0;

	/* if only deleting references there's nothing to read */
	if (client->nref_updates == client->nref_del)
		return NULL;

	got_hash_init(&ctx, GOT_HASH_SHA1);

	err = got_poll_read_full(infd, &have, &hdr, sizeof(hdr), sizeof(hdr));
	if (err)
		return err;
	if (have != sizeof(hdr))
		return got_error_msg(GOT_ERR_BAD_PACKFILE, "short pack file");
	*outsize += have;

	if (hdr.signature != htobe32(GOT_PACKFILE_SIGNATURE))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile signature");
	if (hdr.version != htobe32(GOT_PACKFILE_VERSION))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile version");

	*nobj = be32toh(hdr.nobjects);
	if (*nobj == 0) {
		/*
		 * Clients which are creating new references only
		 * will send us an empty pack file.
		 */
		if (client->nref_updates > 0 &&
		    client->nref_updates == client->nref_new)
			return NULL;

		/*
		 * Clients which only move existing refs will send us an empty
		 * pack file. All referenced objects must exist locally.
		 */
		err = ensure_all_objects_exist_locally(&client->ref_updates);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				return err;
			return got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "bad packfile with zero objects");
		}

		client->nref_move = client->nref_updates;
		return NULL;
	}

	log_debug("expecting %d objects", *nobj);

	err = got_pack_hwrite(outfd, &hdr, sizeof(hdr), &ctx);
	if (err)
		return err;

	err = buf_alloc(&buf, 65536);
	if (err)
		return err;

	while (nhave != *nobj) {
		uint8_t obj_type;
		uint64_t obj_size;

		err = copy_object_type_and_size(&obj_type, &obj_size,
		    infd, outfd, outsize, buf, &buf_pos, &ctx);
		if (err)
			goto done;

		err = validate_object_type(obj_type);
		if (err)
			goto done;

		if (obj_type == GOT_OBJ_TYPE_REF_DELTA) {
			err = copy_ref_delta(infd, outfd, outsize,
			    buf, &buf_pos, &ctx);
			if (err)
				goto done;
		} else if (obj_type == GOT_OBJ_TYPE_OFFSET_DELTA) {
			err = copy_offset_delta(infd, outfd, outsize,
			    buf, &buf_pos, &ctx);
			if (err)
				goto done;
		}

		err = copy_zstream(infd, outfd, outsize, buf, &buf_pos, &ctx);
		if (err)
			goto done;

		nhave++;
	}

	log_debug("received %u objects", *nobj);

	got_hash_final(&ctx, expected_sha1);

	remain = buf_len(buf) - buf_pos;
	if (remain < SHA1_DIGEST_LENGTH) {
		err = read_more_pack_stream(infd, buf,
		    SHA1_DIGEST_LENGTH - remain);
		if (err)
			return err;
	}

	got_sha1_digest_to_str(expected_sha1, hex, sizeof(hex));
	log_debug("expect SHA1: %s", hex);
	got_sha1_digest_to_str(buf_get(buf) + buf_pos, hex, sizeof(hex));
	log_debug("actual SHA1: %s", hex);

	if (memcmp(buf_get(buf) + buf_pos, expected_sha1,
	    SHA1_DIGEST_LENGTH) != 0) {
		err = got_error(GOT_ERR_PACKFILE_CSUM);
		goto done;
	}

	memcpy(sha1, expected_sha1, SHA1_DIGEST_LENGTH);

	w = write(outfd, expected_sha1, SHA1_DIGEST_LENGTH);
	if (w == -1) {
		err = got_error_from_errno("write");
		goto done;
	}
	if (w != SHA1_DIGEST_LENGTH) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}

	*outsize += SHA1_DIGEST_LENGTH;

	if (fsync(outfd) == -1) {
		err = got_error_from_errno("fsync");
		goto done;
	}
	if (lseek(outfd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
done:
	buf_free(buf);
	return err;
}

static const struct got_error *
report_pack_status(const struct got_error *unpack_err)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_status istatus;
	struct ibuf *wbuf;
	struct imsgbuf ibuf;
	const char *unpack_ok = "unpack ok\n";
	size_t len;

	if (imsgbuf_init(&ibuf, client->fd))
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	if (unpack_err)
		istatus.reason_len = strlen(unpack_err->msg);
	else
		istatus.reason_len = strlen(unpack_ok);

	len = sizeof(istatus) + istatus.reason_len;
	wbuf = imsg_create(&ibuf, GOTD_IMSG_PACKFILE_STATUS,
	    GOTD_PROC_REPO_WRITE, repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create PACKFILE_STATUS");
		goto done;
	}

	if (imsg_add(wbuf, &istatus, sizeof(istatus)) == -1) {
		err = got_error_from_errno("imsg_add PACKFILE_STATUS");
		goto done;
	}

	if (imsg_add(wbuf, err ? err->msg : unpack_ok,
	    istatus.reason_len) == -1) {
		err = got_error_from_errno("imsg_add PACKFILE_STATUS");
		goto done;
	}

	imsg_close(&ibuf, wbuf);

	err = gotd_imsg_flush(&ibuf);
done:
	imsgbuf_clear(&ibuf);
	return err;
}

static const struct got_error *
recv_packfile(int *have_packfile, struct imsg *imsg)
{
	const struct got_error *err = NULL, *unpack_err;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_recv_packfile ireq;
	struct got_object_id id;
	FILE *tempfiles[3] = { NULL, NULL, NULL };
	struct repo_tempfile {
		int fd;
		int idx;
	} repo_tempfiles[3] = { { - 1, - 1 }, { - 1, - 1 }, { - 1, - 1 }, };
	int i;
	size_t datalen;
	struct got_ratelimit rl;
	struct got_pack *pack = NULL;
	off_t pack_filesize = 0;
	uint32_t nobj = 0;

	log_debug("packfile request received");

	*have_packfile = 0;
	got_ratelimit_init(&rl, 2, 0);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (client->pack_pipe == -1 || client->packidx_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	pack = &client->pack;
	memset(pack, 0, sizeof(*pack));
	pack->fd = imsg_get_fd(imsg);
	if (pack->fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	err = got_delta_cache_alloc(&pack->delta_cache);
	if (err)
		goto done;

	for (i = 0; i < nitems(repo_tempfiles); i++) {
		struct repo_tempfile *t = &repo_tempfiles[i];
		err = got_repo_temp_fds_get(&t->fd, &t->idx, repo_write.repo);
		if (err)
			goto done;
	}

	for (i = 0; i < nitems(tempfiles); i++) {
		int fd;
		FILE *f;

		fd = dup(repo_tempfiles[i].fd);
		if (fd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}
		f = fdopen(fd, "w+");
		if (f == NULL) {
			err = got_error_from_errno("fdopen");
			close(fd);
			goto done;
		}
		tempfiles[i] = f;
	}

	log_debug("receiving pack data");
	unpack_err = recv_packdata(&pack_filesize, &nobj,
	    client->pack_sha1, client->pack_pipe, pack->fd);
	if (ireq.report_status) {
		err = report_pack_status(unpack_err);
		if (err) {
			/* Git clients hang up after sending the pack file. */
			if (err->code == GOT_ERR_EOF)
				err = NULL;
		}
	}
	if (unpack_err)
		err = unpack_err;
	if (err)
		goto done;

	log_debug("pack data received");

	/*
	 * Clients which are creating new references only will
	 * send us an empty pack file.
	 */
	if (nobj == 0 &&
	    pack_filesize == sizeof(struct got_packfile_hdr) &&
	    client->nref_updates > 0 &&
	    client->nref_updates == client->nref_new)
		goto done;

	/*
	 * Clients which are deleting references only will send
	 * no pack file.
	 */
	if (nobj == 0 &&
	    client->nref_del > 0 &&
	    client->nref_updates == client->nref_del)
		goto done;

	/*
	 * Clients which only move existing refs will send us an empty
	 * pack file. All referenced objects must exist locally.
	 */
	if (nobj == 0 &&
	    pack_filesize == sizeof(struct got_packfile_hdr) &&
	    client->nref_move > 0 &&
	    client->nref_updates == client->nref_move)
		goto done;

	pack->filesize = pack_filesize;
	*have_packfile = 1;

	memset(&id, 0, sizeof(id));
	memcpy(&id.hash, client->pack_sha1, SHA1_DIGEST_LENGTH);
	id.algo = GOT_HASH_SHA1;

	log_debug("begin indexing pack (%lld bytes in size)",
	    (long long)pack->filesize);
	err = got_pack_index(pack, client->packidx_fd,
	    tempfiles[0], tempfiles[1], tempfiles[2], &id,
	    pack_index_progress, NULL, &rl);
	if (err)
		goto done;
	log_debug("done indexing pack");

	if (fsync(client->packidx_fd) == -1) {
		err = got_error_from_errno("fsync");
		goto done;
	}
	if (lseek(client->packidx_fd, 0L, SEEK_SET) == -1)
		err = got_error_from_errno("lseek");
done:
	if (close(client->pack_pipe) == -1 && err == NULL)
		err = got_error_from_errno("close");
	client->pack_pipe = -1;
	for (i = 0; i < nitems(repo_tempfiles); i++) {
		struct repo_tempfile *t = &repo_tempfiles[i];
		if (t->idx != -1)
			got_repo_temp_fds_put(t->idx, repo_write.repo);
	}
	for (i = 0; i < nitems(tempfiles); i++) {
		if (tempfiles[i] && fclose(tempfiles[i]) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
	if (err)
		got_pack_close(pack);
	return err;
}

static const struct got_error *
verify_packfile(void)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;
	struct stat sb;
	char *id_str = NULL;
	struct got_object *obj = NULL;
	struct got_pathlist_entry *pe;
	char hex[SHA1_DIGEST_STRING_LENGTH];

	if (STAILQ_EMPTY(&client->ref_updates)) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "cannot verify pack file without any ref-updates");
	}

	if (client->pack.fd == -1) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "invalid pack file handle during pack verification");
	}
	if (client->packidx_fd == -1) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "invalid pack index handle during pack verification");
	}

	if (fstat(client->packidx_fd, &sb) == -1)
		return got_error_from_errno("pack index fstat");

	if (client->packidx != NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->packidx = calloc(1, sizeof(*client->packidx));
	if (client->packidx == NULL)
		return got_error_from_errno("calloc");

	client->packidx->fd = client->packidx_fd;
	client->packidx_fd = -1;
	client->packidx->len = sb.st_size;

	err = got_packidx_init_hdr(client->packidx, 1, client->pack.filesize);
	if (err)
		return err;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		if (ref_update->delete_ref)
			continue;

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_tag_namespaces) {
			err = protect_tag_namespace(pe->path, &client->pack,
			    client->packidx, ref_update);
			if (err)
				goto done;
		}

		/*
		 * Objects which already exist in our repository need
		 * not be present in the pack file.
		 */
		err = got_object_open(&obj, repo_write.repo,
		    &ref_update->new_id);
		if (err && err->code != GOT_ERR_NO_OBJ)
			goto done;
		err = NULL;
		if (obj) {
			got_object_close(obj);
			obj = NULL;
		} else {
			int idx = got_packidx_get_object_idx(client->packidx,
			    &ref_update->new_id);
			if (idx == -1) {
				got_object_id_hex(&ref_update->new_id,
				    hex, sizeof(hex));
				err = got_error_fmt(GOT_ERR_BAD_PACKFILE,
				    "object %s is missing from pack file",
				    hex);
				goto done;
			}
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branch_namespaces) {
			err = protect_branch_namespace(pe->path,
			    &client->pack, client->packidx, ref_update);
			if (err)
				goto done;
		}
		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branches) {
			err = protect_branch(pe->path, &client->pack,
			    client->packidx, ref_update);
			if (err)
				goto done;
		}
	}

done:
	free(id_str);
	if (obj)
		got_object_close(obj);
	return err;
}

static const struct got_error *
protect_refs_from_deletion(void)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;
	struct got_pathlist_entry *pe;
	const char *refname;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		if (!ref_update->delete_ref)
			continue;

		refname = got_ref_get_name(ref_update->ref);

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_tag_namespaces) {
			err = protect_ref_namespace(refname, pe->path);
			if (err)
				return err;
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branch_namespaces) {
			err = protect_ref_namespace(refname, pe->path);
			if (err)
				return err;
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branches) {
			if (strcmp(refname, pe->path) == 0) {
				return got_error_fmt(GOT_ERR_REF_PROTECTED,
				    "%s", refname);
			}
		}
	}

	return NULL;
}

static const struct got_error *
protect_refs_from_moving(void)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;
	struct got_pathlist_entry *pe;
	const char *refname;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		if (ref_update->delete_ref)
			continue;

		if (got_object_id_cmp(&ref_update->old_id,
		    &ref_update->new_id) == 0)
			continue;

		refname = got_ref_get_name(ref_update->ref);

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_tag_namespaces) {
			err = protect_ref_namespace(refname, pe->path);
			if (err)
				return err;
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branch_namespaces) {
			if (strcmp(pe->path, refname) != 0)
				continue;

			err = protect_require_yca(&ref_update->new_id, 0,
			    NULL, NULL, ref_update->ref);
			if (err)
				return err;
			break;
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo_write.protected_branches) {
			if (strcmp(pe->path, refname) != 0)
				continue;

			err = protect_require_yca(&ref_update->new_id, 0,
			    NULL, NULL, ref_update->ref);
			if (err)
				return err;
			break;
		}
	}

	return NULL;
}

static const struct got_error *
install_packfile(struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_install inst;
	int ret;

	memset(&inst, 0, sizeof(inst));
	memcpy(inst.pack_sha1, client->pack_sha1, SHA1_DIGEST_LENGTH);

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_INSTALL,
	    GOTD_PROC_REPO_WRITE, -1, &inst, sizeof(inst));
	if (ret == -1)
		return got_error_from_errno("imsg_compose PACKFILE_INSTALL");

	return NULL;
}

static const struct got_error *
send_ref_updates_start(int nref_updates, struct gotd_imsgev *iev)
{
	struct gotd_imsg_ref_updates_start istart;
	int ret;

	memset(&istart, 0, sizeof(istart));
	istart.nref_updates = nref_updates;

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_REF_UPDATES_START,
	    GOTD_PROC_REPO_WRITE, -1, &istart, sizeof(istart));
	if (ret == -1)
		return got_error_from_errno("imsg_compose REF_UPDATES_START");

	return NULL;
}


static const struct got_error *
send_ref_update(struct gotd_ref_update *ref_update, struct gotd_imsgev *iev)
{
	struct gotd_imsg_ref_update iref;
	const char *refname = got_ref_get_name(ref_update->ref);
	struct ibuf *wbuf;
	size_t len;

	memset(&iref, 0, sizeof(iref));
	memcpy(iref.old_id, ref_update->old_id.hash, SHA1_DIGEST_LENGTH);
	memcpy(iref.new_id, ref_update->new_id.hash, SHA1_DIGEST_LENGTH);
	iref.ref_is_new = ref_update->ref_is_new;
	iref.delete_ref = ref_update->delete_ref;
	iref.name_len = strlen(refname);

	len = sizeof(iref) + iref.name_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE,
	    GOTD_PROC_REPO_WRITE, repo_write.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE");

	if (imsg_add(wbuf, &iref, sizeof(iref)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");
	if (imsg_add(wbuf, refname, iref.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");

	imsg_close(&iev->ibuf, wbuf);

	gotd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
update_refs(struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;

	err = send_ref_updates_start(client->nref_updates, iev);
	if (err)
		return err;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		err = send_ref_update(ref_update, iev);
		if (err)
			goto done;
	}
done:
	return err;
}

static const struct got_error *
receive_pack_pipe(struct imsg *imsg, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	size_t datalen;

	log_debug("receiving pack pipe descriptor");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (client->pack_pipe != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->pack_pipe = imsg_get_fd(imsg);
	if (client->pack_pipe == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	return NULL;
}

static const struct got_error *
receive_pack_idx(struct imsg *imsg, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	size_t datalen;

	log_debug("receiving pack index output file");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (client->packidx_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->packidx_fd = imsg_get_fd(imsg);
	if (client->packidx_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	return NULL;
}

static const struct got_error *
notify_removed_ref(const char *refname, struct got_object_id *id,
    struct gotd_imsgev *iev, int fd)
{
	const struct got_error *err;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	dprintf(fd, "Removed %s: %s\n", refname, id_str);
	free(id_str);
	return err;
}

static const char *
format_author(char *author)
{
	char *smallerthan;

	smallerthan = strchr(author, '<');
	if (smallerthan && smallerthan[1] != '\0')
		author = smallerthan + 1;
	author[strcspn(author, "@>")] = '\0';

	return author;
}

static const struct got_error *
print_commit_oneline(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, int fd)
{
	const struct got_error *err = NULL;
	char *id_str = NULL, *logmsg0 = NULL;
	char *s, *nl;
	char *committer = NULL, *author = NULL;
	time_t committer_time;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	committer_time = got_object_commit_get_committer_time(commit);

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;

	s = logmsg0;
	while (isspace((unsigned char)s[0]))
		s++;

	nl = strchr(s, '\n');
	if (nl) {
		*nl = '\0';
	}

	if (strcmp(got_object_commit_get_author(commit),
	    got_object_commit_get_committer(commit)) != 0) {
		author = strdup(got_object_commit_get_author(commit));
		if (author == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		dprintf(fd, "%lld %.7s %.8s %s\n", (long long)committer_time,
		    id_str, format_author(author), s);
	} else {
		committer = strdup(got_object_commit_get_committer(commit));
		dprintf(fd, "%lld %.7s %.8s %s\n", (long long)committer_time,
		    id_str, format_author(committer), s);
	}

	if (fsync(fd) == -1 && err == NULL)
		err = got_error_from_errno("fsync");
done:
	free(id_str);
	free(logmsg0);
	free(committer);
	free(author);
	return err;
}

static const struct got_error *
print_diffstat(struct got_diffstat_cb_arg *dsa, int fd)
{
	struct got_pathlist_entry *pe;

	RB_FOREACH(pe, got_pathlist_head, dsa->paths) {
		struct got_diff_changed_path *cp = pe->data;
		int pad = dsa->max_path_len - pe->path_len + 1;

		dprintf(fd, " %c  %s%*c | %*d+ %*d-\n", cp->status,
		    pe->path, pad, ' ', dsa->add_cols + 1, cp->add,
		    dsa->rm_cols + 1, cp->rm);
	}
	dprintf(fd,
	    "\n%d file%s changed, %d insertion%s(+), %d deletion%s(-)\n\n",
	    dsa->nfiles, dsa->nfiles > 1 ? "s" : "", dsa->ins,
	    dsa->ins != 1 ? "s" : "", dsa->del, dsa->del != 1 ? "s" : "");

	return NULL;
}

static const struct got_error *
print_commit(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, struct got_pathlist_head *changed_paths,
    struct got_diffstat_cb_arg *diffstat, int fd)
{
	const struct got_error *err = NULL;
	char *id_str, *logmsg0, *logmsg, *line;
	time_t committer_time;
	const char *author, *committer;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	dprintf(fd, "commit %s\n", id_str);
	free(id_str);
	id_str = NULL;
	dprintf(fd, "from: %s\n", got_object_commit_get_author(commit));
	author = got_object_commit_get_author(commit);
	committer = got_object_commit_get_committer(commit);
	if (strcmp(author, committer) != 0)
		dprintf(fd, "via: %s\n", committer);
	committer_time = got_object_commit_get_committer_time(commit);
	dprintf(fd, "date: %lld\n", (long long)committer_time);
	if (got_object_commit_get_nparents(commit) > 1) {
		const struct got_object_id_queue *parent_ids;
		struct got_object_qid *qid;
		int n = 1;
		parent_ids = got_object_commit_get_parent_ids(commit);
		STAILQ_FOREACH(qid, parent_ids, entry) {
			err = got_object_id_str(&id_str, &qid->id);
			if (err)
				goto done;
			dprintf(fd, "parent %d: %s\n", n++, id_str);
			free(id_str);
			id_str = NULL;
		}
	}

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;

	dprintf(fd, "messagelen: %zu\n", strlen(logmsg0));

	logmsg = logmsg0;
	do {
		line = strsep(&logmsg, "\n");
		if (line)
			dprintf(fd, " %s\n", line);
	} while (line);
	free(logmsg0);

	err = print_diffstat(diffstat, fd);
	if (err)
		goto done;

	if (fsync(fd) == -1 && err == NULL)
		err = got_error_from_errno("fsync");
done:
	free(id_str);
	return err;
}

static const struct got_error *
get_changed_paths(struct got_pathlist_head *paths,
    struct got_commit_object *commit, struct got_repository *repo,
    struct got_diffstat_cb_arg *dsa)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id1 = NULL, *tree_id2 = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_object_qid *qid;
	got_diff_blob_cb cb = got_diff_tree_collect_changed_paths;
	FILE *f1 = repo_write.diff.f1, *f2 = repo_write.diff.f2;
	int fd1 = repo_write.diff.fd1, fd2 = repo_write.diff.fd2;

	if (dsa)
		cb = got_diff_tree_compute_diffstat;

	err = got_opentemp_truncate(f1);
	if (err)
		return err;
	err = got_opentemp_truncate(f2);
	if (err)
		return err;
	err = got_opentemp_truncatefd(fd1);
	if (err)
		return err;
	err = got_opentemp_truncatefd(fd2);
	if (err)
		return err;

	qid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		struct got_commit_object *pcommit;
		err = got_object_open_as_commit(&pcommit, repo,
		    &qid->id);
		if (err)
			return err;

		tree_id1 = got_object_id_dup(
		    got_object_commit_get_tree_id(pcommit));
		if (tree_id1 == NULL) {
			got_object_commit_close(pcommit);
			return got_error_from_errno("got_object_id_dup");
		}
		got_object_commit_close(pcommit);

	}

	if (tree_id1) {
		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;
	}

	tree_id2 = got_object_commit_get_tree_id(commit);
	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, f1, f2, fd1, fd2, "", "", repo,
	    cb, dsa ? (void *)dsa : paths, dsa ? 1 : 0);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	free(tree_id1);
	return err;
}

static const struct got_error *
print_commits(struct got_object_id *root_id, struct got_object_id *end_id,
    struct got_repository *repo, int fd)
{
	const struct got_error *err;
	struct got_commit_graph *graph = NULL;
	struct got_object_id_queue reversed_commits;
	struct got_object_qid *qid;
	struct got_commit_object *commit = NULL;
	struct got_pathlist_head changed_paths;
	int ncommits = 0;
	const int shortlog_threshold = 50;
	struct got_object_id *yca_id = NULL;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_id = NULL;

	STAILQ_INIT(&reversed_commits);
	RB_INIT(&changed_paths);

	if (end_id && got_object_id_cmp(root_id, end_id) != 0) {
		err = got_commit_graph_find_youngest_common_ancestor(
		    &yca_id, root_id, end_id, 1, 0, repo_write.repo,
		    check_cancelled, NULL);
		if (err)
			return err;
		if (yca_id)
			end_id = yca_id;
	}

	if (end_id == NULL) {
		err = got_ref_open(&head_ref, repo_write.repo, GOT_REF_HEAD, 0);
		if (err) {
			if (err->code != GOT_ERR_NOT_REF)
				goto done;
		} else {
			err = got_ref_resolve(&head_id, repo_write.repo,
			    head_ref);
			if (err)
				goto done;
			if (got_object_id_cmp(root_id, head_id) != 0) {
				err =
				got_commit_graph_find_youngest_common_ancestor(
				    &yca_id, root_id, head_id, 1, 0,
				    repo_write.repo, check_cancelled, NULL);
				if (err)
					goto done;
				if (yca_id)
					end_id = yca_id;
			}
		}
	}

	/* XXX first-parent only for now */
	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		return err;
	err = got_commit_graph_bfsort(graph, root_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;
	for (;;) {
		struct got_object_id id;

		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		err = got_object_open_as_commit(&commit, repo, &id);
		if (err)
			break;

		if (end_id && got_object_id_cmp(&id, end_id) == 0)
			break;

		err = got_object_qid_alloc(&qid, &id);
		if (err)
			break;

		STAILQ_INSERT_HEAD(&reversed_commits, qid, entry);
		ncommits++;
		got_object_commit_close(commit);

		if (end_id == NULL)
			break;
	}

	STAILQ_FOREACH(qid, &reversed_commits, entry) {
		struct got_diffstat_cb_arg dsa = { 0, 0, 0, 0, 0, 0,
		    &changed_paths, 0, 0, GOT_DIFF_ALGORITHM_PATIENCE };

		err = got_object_open_as_commit(&commit, repo, &qid->id);
		if (err)
			break;

		if (ncommits > shortlog_threshold) {
			err = print_commit_oneline(commit, &qid->id,
			    repo, fd);
			if (err)
				break;
		} else {
			err = get_changed_paths(&changed_paths, commit,
			    repo, &dsa);
			if (err)
				break;
			err = print_commit(commit, &qid->id, repo,
			    &changed_paths, &dsa, fd);
		}
		got_object_commit_close(commit);
		commit = NULL;
		got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
	}
done:
	free(yca_id);
	free(head_id);
	if (head_ref)
		got_ref_close(head_ref);
	if (commit)
		got_object_commit_close(commit);
	got_object_id_queue_free(&reversed_commits);
	got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
	if (graph)
		got_commit_graph_close(graph);
	return err;
}

static const struct got_error *
print_tag(struct got_object_id *id,
    const char *refname, struct got_repository *repo, int fd)
{
	const struct got_error *err = NULL;
	struct got_tag_object *tag = NULL;
	const char *tagger = NULL;
	char *id_str = NULL, *tagmsg0 = NULL, *tagmsg, *line;
	time_t tagger_time;

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	tagger = got_object_tag_get_tagger(tag);
	tagger_time = got_object_tag_get_tagger_time(tag);
	err = got_object_id_str(&id_str,
	    got_object_tag_get_object_id(tag));
	if (err)
		goto done;

	dprintf(fd, "tag %s\n", refname);
	dprintf(fd, "from: %s\n", tagger);
	dprintf(fd, "date: %lld\n", (long long)tagger_time);

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_BLOB:
		dprintf(fd, "object: %s %s\n", GOT_OBJ_LABEL_BLOB, id_str);
		break;
	case GOT_OBJ_TYPE_TREE:
		dprintf(fd, "object: %s %s\n", GOT_OBJ_LABEL_TREE, id_str);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		dprintf(fd, "object: %s %s\n", GOT_OBJ_LABEL_COMMIT, id_str);
		break;
	case GOT_OBJ_TYPE_TAG:
		dprintf(fd, "object: %s %s\n", GOT_OBJ_LABEL_TAG, id_str);
		break;
	default:
		break;
	}

	tagmsg0 = strdup(got_object_tag_get_message(tag));
	if (tagmsg0 == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	dprintf(fd, "messagelen: %zu\n", strlen(tagmsg0));

	tagmsg = tagmsg0;
	do {
		line = strsep(&tagmsg, "\n");
		if (line)
			dprintf(fd, " %s\n", line);
	} while (line);
	free(tagmsg0);
done:
	if (tag)
		got_object_tag_close(tag);
	free(id_str);
	return err;
}

static const struct got_error *
notify_changed_ref(const char *refname, struct got_object_id *old_id,
    struct got_object_id *new_id, struct gotd_imsgev *iev, int fd)
{
	const struct got_error *err;
	int old_obj_type, new_obj_type;
	const char *label;
	char *new_id_str = NULL;

	err = got_object_get_type(&old_obj_type, repo_write.repo, old_id);
	if (err)
		return err;

	err = got_object_get_type(&new_obj_type, repo_write.repo, new_id);
	if (err)
		return err;

	switch (new_obj_type) {
	case GOT_OBJ_TYPE_COMMIT:
		err = print_commits(new_id,
		    old_obj_type == GOT_OBJ_TYPE_COMMIT ? old_id : NULL,
		    repo_write.repo, fd);
		break;
	case GOT_OBJ_TYPE_TAG:
		err = print_tag(new_id, refname, repo_write.repo, fd);
		break;
	default:
		err = got_object_type_label(&label, new_obj_type);
		if (err)
			goto done;
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
		dprintf(fd, "%s: %s object %s\n", refname, label, new_id_str);
		break;
	}
done:
	free(new_id_str);
	return err;
}

static const struct got_error *
notify_created_ref(const char *refname, struct got_object_id *id,
    struct gotd_imsgev *iev, int fd)
{
	const struct got_error *err = NULL;
	int obj_type;

	err = got_object_get_type(&obj_type, repo_write.repo, id);
	if (err)
		return err;

	if (obj_type == GOT_OBJ_TYPE_TAG)
		return print_tag(id, refname, repo_write.repo, fd);

	return print_commits(id, NULL, repo_write.repo, fd);
}

static const struct got_error *
render_notification(struct imsg *imsg, struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_notification_content ireq;
	size_t datalen, len;
	char *refname = NULL;
	struct ibuf *wbuf;
	int fd = -1;

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ireq)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (datalen != sizeof(ireq) +  ireq.refname_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	refname = strndup(imsg->data + sizeof(ireq), ireq.refname_len);
	if (refname == NULL) {
		err =  got_error_from_errno("strndup");
		goto done;
	}

	switch (ireq.action) {
	case GOTD_NOTIF_ACTION_CREATED:
		err = notify_created_ref(refname, &ireq.new_id, iev, fd);
		break;
	case GOTD_NOTIF_ACTION_REMOVED:
		err = notify_removed_ref(refname, &ireq.old_id, iev, fd);
		break;
	case GOTD_NOTIF_ACTION_CHANGED:
		err = notify_changed_ref(refname, &ireq.old_id, &ireq.new_id,
		    iev, fd);
		break;
	}
	if (err != NULL)
		goto done;

	if (fsync(fd) == -1) {
		err = got_error_from_errno("fsync");
		goto done;
	}

	len = sizeof(ireq) + ireq.refname_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_NOTIFY, GOTD_PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF");
		goto done;
	}
	if (imsg_add(wbuf, &ireq, sizeof(ireq)) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}
	if (imsg_add(wbuf, refname, ireq.refname_len) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}

	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
done:
	free(refname);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
send_packfile_received(struct gotd_imsgev *iev, int have_packfile)
{
	struct gotd_imsg_packfile_received recvd;
	int ret;

	if (have_packfile)
		recvd.pack_empty = 0;
	else
		recvd.pack_empty = 1;

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_RECEIVED,
	    GOTD_PROC_REPO_WRITE, -1, &recvd, sizeof(recvd));
	if (ret == -1)
		return got_error_from_errno("imsg_compose PACKFILE_RECEIVED");

	return NULL;
}

static const struct got_error *
open_tree(struct got_tree_object **tree, struct got_pack *pack,
    struct got_packidx *packidx, int idx, struct got_object_id *tree_id)
{
	const struct got_error *err;
	struct got_parsed_tree_entry *entries = NULL;
	size_t nentries = 0, nentries_alloc = 0, i;
	struct got_object *obj = NULL;
	uint8_t *buf = NULL;
	size_t len;

	*tree = NULL;

	err = got_packfile_open_object(&obj, pack, packidx, idx, tree_id);
	if (err)
		return err;

	if (obj->type != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		goto done;
	
	err = got_object_parse_tree(&entries, &nentries, &nentries_alloc,
	    buf, len, GOT_HASH_SHA1);
	if (err)
		goto done;

	*tree = malloc(sizeof(**tree));
	if (*tree == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	(*tree)->entries = calloc(nentries, sizeof(struct got_tree_entry));
	if ((*tree)->entries == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	(*tree)->nentries = nentries;
	(*tree)->refcnt = 0;

	for (i = 0; i < nentries; i++) {
		struct got_parsed_tree_entry *pe = &entries[i];
		struct got_tree_entry *te = &(*tree)->entries[i];

		if (strlcpy(te->name, pe->name,
		    sizeof(te->name)) >= sizeof(te->name)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		memcpy(te->id.hash, pe->id, pe->digest_len);
		te->id.algo = GOT_HASH_SHA1;
		te->mode = pe->mode;
		te->idx = i;
	}
done:
	if (err && *tree) {
		got_object_tree_close(*tree);
		*tree = NULL;
	}
	got_object_close(obj);
	free(buf);
	return err;
}

static struct got_tree_entry *
find_entry_by_name(struct got_tree_object *tree, const char *name, size_t len)
{
	int i;

	/* Note that tree entries are sorted in strncmp() order. */
	for (i = 0; i < tree->nentries; i++) {
		struct got_tree_entry *te = &tree->entries[i];
		int cmp = strncmp(te->name, name, len);
		if (cmp < 0)
			continue;
		if (cmp > 0)
			break;
		if (te->name[len] == '\0')
			return te;
	}
	return NULL;
}

static const struct got_error *
find_id_by_path(struct got_object_id **id,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_tree_object *tree, const char *path)
{
	const struct got_error *err = NULL;
	struct got_tree_object *subtree = NULL;
	struct got_tree_entry *te = NULL;
	const char *seg, *s;
	size_t seglen;

	*id = NULL;

	s = path;
	while (s[0] == '/')
		s++;
	seg = s;
	seglen = 0;
	subtree = tree;
	while (*s) {
		struct got_tree_object *next_tree;

		if (*s != '/') {
			s++;
			seglen++;
			if (*s)
				continue;
		}

		te = find_entry_by_name(subtree, seg, seglen);
		if (te == NULL)
			break;

		if (*s == '\0')
			break;

		seg = s + 1;
		seglen = 0;
		s++;
		if (*s) {
			int idx;

			idx = got_packidx_get_object_idx(packidx, &te->id);
			if (idx == -1)  {
				te = NULL;
				break;
			}
			err = open_tree(&next_tree, pack, packidx, idx,
			    &te->id);
			te = NULL;
			if (err)
				goto done;
			if (subtree != tree)
				got_object_tree_close(subtree);
			subtree = next_tree;
		}
	}

	if (te) {
		*id = got_object_id_dup(&te->id);
		if (*id == NULL)
			return got_error_from_errno("got_object_id_dup");
	} else
		err = got_error_path(path, GOT_ERR_NO_TREE_ENTRY);
done:
	if (subtree && subtree != tree)
		got_object_tree_close(subtree);
	return err;
}

static const struct got_error *
get_content_from_packfile(struct gotd_imsgev *iev, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_get_content content_req;
	struct gotd_imsg_packfile_content_written written_resp;
	size_t datalen;
	char *refname = NULL;
	char *path = NULL;
	int fd = -1, idx;
	struct gotd_ref_update *ref_update;
	struct got_object_id *tree_id = NULL, *content_id = NULL;
	struct got_object *obj = NULL;
	uint8_t *buf = NULL;
	size_t len;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	FILE *outfile = NULL;

	memset(&written_resp, 0, sizeof(written_resp));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(content_req))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&content_req, imsg->data, sizeof(content_req)); 

	if (content_req.path_len == 0 ||
	    content_req.refname_len == 0 ||
	    datalen != sizeof(content_req) + content_req.refname_len +
	    content_req.path_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	
	refname = strndup(imsg->data + sizeof(content_req),
	    content_req.refname_len);
	if (strlen(refname) != content_req.refname_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	path = strndup(imsg->data + sizeof(content_req) +
	    content_req.refname_len, content_req.path_len);
	if (strlen(path) != content_req.path_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	if (got_path_is_root_dir(path)) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	outfile = fdopen(fd, "w");
	if (outfile == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	fd = -1;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		if (strcmp(got_ref_get_name(ref_update->ref), refname) == 0)
			break;
	}
	if (ref_update == NULL)
		goto send_response;

	written_resp.ref_found = 1;	

	idx = got_packidx_get_object_idx(client->packidx, &ref_update->new_id);
	if (idx == -1) 
		goto send_response;

	err = got_packfile_open_object(&obj, &client->pack, client->packidx,
	   idx, &ref_update->new_id);
	if (err)
		goto done;

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		goto send_response;

	err = got_packfile_extract_object_to_mem(&buf, &len, obj,
	    &client->pack);
	if (err)
		goto done;
	got_object_close(obj);
	obj = NULL;
	
	err = got_object_parse_commit(&commit, buf, len, GOT_HASH_SHA1);
	if (err)
		goto done;

	tree_id = got_object_id_dup(commit->tree_id);
	if (tree_id == NULL)
		err = got_error_from_errno("got_object_id_dup");

	got_object_commit_close(commit);
	commit = NULL;
	free(buf);
	buf = NULL;
	len = 0;

	idx = got_packidx_get_object_idx(client->packidx, tree_id);
	if (idx == -1) 
		goto send_response;

	err = open_tree(&tree, &client->pack, client->packidx, idx, tree_id);
	if (err)
		goto done;

	err = find_id_by_path(&content_id, &client->pack, client->packidx,
	    tree, path);
	if (err)
		goto done;

	idx = got_packidx_get_object_idx(client->packidx, content_id);
	if (idx == -1) 
		goto send_response;

	err = got_packfile_open_object(&obj, &client->pack, client->packidx,
	   idx, content_id);
	if (err)
		goto done;

	if (obj->type != GOT_OBJ_TYPE_BLOB)
		goto send_response;

	err = got_packfile_extract_object(&client->pack, obj, outfile,
	    repo_write.base_file, repo_write.accum_file);
	if (err)
		goto done;
	
	written_resp.wrote_content = 1;	
send_response:
	if (imsg_compose(&iev->ibuf, GOTD_IMSG_PACKFILE_CONTENT_WRITTEN,
	    GOTD_PROC_REPO_WRITE, repo_write.pid, -1, &written_resp,
	    sizeof(written_resp)) == -1) {
		err = got_error_from_errno("imsg_compose "
		    "PACKFILE_CONTENT_WRITTEn");
		goto done;
	}
	err = gotd_imsg_flush(&iev->ibuf);
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(refname);
	free(path);
	free(tree_id);
	free(buf);
	if (obj)
		got_object_close(obj);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static void
repo_write_dispatch_session(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	struct repo_write_client *client = &repo_write_client;
	ssize_t n;
	int shut = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	while (err == NULL) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		if (imsg.hdr.type != GOTD_IMSG_LIST_REFS_INTERNAL &&
		    !repo_write.refs_listed) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_LIST_REFS_INTERNAL:
			err = list_refs(&imsg);
			if (err)
				log_warnx("ls-refs: %s", err->msg);
			break;
		case GOTD_IMSG_REF_UPDATE:
			err = recv_ref_update(&imsg);
			if (err)
				log_warnx("ref-update: %s", err->msg);
			break;
		case GOTD_IMSG_PACKFILE_PIPE:
			err = receive_pack_pipe(&imsg, iev);
			if (err) {
				log_warnx("receiving pack pipe: %s", err->msg);
				break;
			}
			break;
		case GOTD_IMSG_PACKIDX_FILE:
			err = receive_pack_idx(&imsg, iev);
			if (err) {
				log_warnx("receiving pack index: %s",
				    err->msg);
				break;
			}
			break;
		case GOTD_IMSG_RECV_PACKFILE:
			err = protect_refs_from_deletion();
			if (err)
				break;
			err = recv_packfile(&repo_write.have_packfile, &imsg);
			if (err) {
				log_warnx("receive packfile: %s", err->msg);
				break;
			}
			if (repo_write.have_packfile) {
				err = verify_packfile();
				if (err) {
					log_warnx("verify packfile: %s",
					    err->msg);
					break;
				}
			} else {
				/*
				 * Clients sending empty pack files might be
				 * attempting to move a protected reference.
				 */
				err = protect_refs_from_moving();
				if (err)
					break;
			}
			err = send_packfile_received(iev,
			    repo_write.have_packfile);
			if (err)
				log_warnx("receive packfile: %s", err->msg);
			break;
		case GOTD_IMSG_PACKFILE_GET_CONTENT:
			if (!repo_write.have_packfile ||
			    client->packidx == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = get_content_from_packfile(iev, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_VERIFIED:
			if (repo_write.have_packfile) {
				err = install_packfile(iev);
				if (err) {
					log_warnx("install packfile: %s",
					    err->msg);
					break;
				}
				/*
				 * Ensure we re-read the pack index list
				 * upon next access.
				 */
				repo_write.repo->pack_path_mtime.tv_sec = 0;
				repo_write.repo->pack_path_mtime.tv_nsec = 0;
			}
			err = update_refs(iev);
			if (err)
				log_warnx("update refs: %s", err->msg);
			break;
		case GOTD_IMSG_NOTIFY:
			err = render_notification(&imsg, iev);
			if (err) {
				log_warnx("render notification: %s", err->msg);
				shut = 1;
			}
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err && gotd_imsg_send_error_event(iev,
		    GOTD_PROC_REPO_WRITE, client->id, err) == -1) {
			log_warnx("could not send error to parent: %s",
			    err->msg);
		}
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static const struct got_error *
recv_connect(struct imsg *imsg)
{
	struct gotd_imsgev *iev = &repo_write.session_iev;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (repo_write.session_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	repo_write.session_fd = imsg_get_fd(imsg);
	if (repo_write.session_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&iev->ibuf, repo_write.session_fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = repo_write_dispatch_session;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ,
	    repo_write_dispatch_session, iev);
	gotd_imsg_event_add(iev);

	return NULL;
}

static void
repo_write_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	struct repo_write_client *client = &repo_write_client;
	size_t npaths;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {	/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	while (err == NULL) {
		err = check_cancelled(NULL);
		if (err)
			break;
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_PROTECTED_TAG_NAMESPACES:
			if (repo_write.protected_refs_cur != NULL ||
			    repo_write.nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			repo_write.protected_refs_cur =
			    &repo_write.protected_tag_namespaces;
			repo_write.nprotected_refs_needed = npaths;
			repo_write.nprotected_refs_received = 0;
			break;
		case GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES:
			if (repo_write.protected_refs_cur != NULL ||
			    repo_write.nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			repo_write.protected_refs_cur =
			    &repo_write.protected_branch_namespaces;
			repo_write.nprotected_refs_needed = npaths;
			repo_write.nprotected_refs_received = 0;
			break;
		case GOTD_IMSG_PROTECTED_BRANCHES:
			if (repo_write.protected_refs_cur != NULL ||
			    repo_write.nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			repo_write.protected_refs_cur =
			    &repo_write.protected_branches;
			repo_write.nprotected_refs_needed = npaths;
			repo_write.nprotected_refs_received = 0;
			break;
		case GOTD_IMSG_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTD_IMSG_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTD_IMSG_PROTECTED_BRANCHES_ELEM:
			if (repo_write.protected_refs_cur == NULL ||
			    repo_write.nprotected_refs_needed == 0 ||
			    repo_write.nprotected_refs_received >=
			    repo_write.nprotected_refs_needed) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist_elem(&imsg,
			    repo_write.protected_refs_cur);
			if (err)
				break;
			if (++repo_write.nprotected_refs_received >=
			    repo_write.nprotected_refs_needed) {
				repo_write.protected_refs_cur = NULL;
				repo_write.nprotected_refs_needed = 0;
			}
			break;
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_connect(&imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err && gotd_imsg_send_error_event(iev, GOTD_PROC_REPO_WRITE,
	    client->id, err) == -1)
		log_warnx("could not send error to parent: %s", err->msg);
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
repo_write_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds, FILE *base_file, FILE *accum_file,
    FILE *diff_f1, FILE *diff_f2, int diff_fd1, int diff_fd2)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsgev iev;

	client->fd = -1;
	client->pack_pipe = -1;
	client->packidx_fd = -1;
	client->pack.fd = -1;

	repo_write.title = title;
	repo_write.pid = getpid();
	repo_write.pack_fds = pack_fds;
	repo_write.temp_fds = temp_fds;
	repo_write.base_file = base_file;
	repo_write.accum_file = accum_file;
	repo_write.session_fd = -1;
	repo_write.session_iev.ibuf.fd = -1;
	RB_INIT(&repo_write.protected_tag_namespaces);
	RB_INIT(&repo_write.protected_branch_namespaces);
	RB_INIT(&repo_write.protected_branches);
	repo_write.diff.f1 = diff_f1;
	repo_write.diff.f2 = diff_f2;
	repo_write.diff.fd1 = diff_fd1;
	repo_write.diff.fd2 = diff_fd2;

	STAILQ_INIT(&repo_write_client.ref_updates);

	err = got_repo_open(&repo_write.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(repo_write.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}
	if (got_repo_get_object_format(repo_write.repo) != GOT_HASH_SHA1) {
		err = got_error_msg(GOT_ERR_NOT_IMPL,
		    "sha256 object IDs unsupported in network protocol");
		goto done;
	}

	got_repo_temp_fds_set(repo_write.repo, temp_fds);

	signal(SIGINT, catch_sigint);
	signal(SIGTERM, catch_sigterm);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if (imsgbuf_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = repo_write_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, repo_write_dispatch, &iev);
	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_REPO_CHILD_READY,
	    GOTD_PROC_REPO_WRITE, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose REPO_CHILD_READY");
		goto done;
	}

	event_dispatch();
done:
	if (fclose(diff_f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (fclose(diff_f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (close(diff_fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (close(diff_fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err)
		log_warnx("%s: %s", title, err->msg);
	repo_write_shutdown();
}

void
repo_write_shutdown(void)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;

	log_debug("%s: shutting down", repo_write.title);

	while (!STAILQ_EMPTY(&client->ref_updates)) {
		ref_update = STAILQ_FIRST(&client->ref_updates);
		STAILQ_REMOVE_HEAD(&client->ref_updates, entry);
		got_ref_close(ref_update->ref);
		free(ref_update);
	}

	if (client->packidx)
		got_packidx_close(client->packidx);
	got_pack_close(&client->pack);
	if (client->fd != -1)
		close(client->fd);
	if (client->pack_pipe != -1)
		close(client->pack_pipe);
	if (client->packidx_fd != -1)
		close(client->packidx_fd);

	if (repo_write.repo)
		got_repo_close(repo_write.repo);
	got_repo_pack_fds_close(repo_write.pack_fds);
	got_repo_temp_fds_close(repo_write.temp_fds);
	if (repo_write.session_fd != -1)
		close(repo_write.session_fd);
	exit(0);
}
