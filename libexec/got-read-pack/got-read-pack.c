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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>
#include <unistd.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_delta_cache.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_qid.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_idset.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
open_object(struct got_object **obj, struct got_pack *pack,
    struct got_packidx *packidx, int idx, struct got_object_id *id,
    struct got_object_cache *objcache)
{
	const struct got_error *err;

	err = got_packfile_open_object(obj, pack, packidx, idx, id);
	if (err)
		return err;
	(*obj)->refcnt++;

	err = got_object_cache_add(objcache, id, *obj);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
		return err;
	}
	(*obj)->refcnt++;
	return NULL;
}

static const struct got_error *
object_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	obj = got_object_cache_get(objcache, &id);
	if (obj) {
		obj->refcnt++;
	} else {
		err = open_object(&obj, pack, packidx, iobj.idx, &id,
		    objcache);
		if (err)
			goto done;
	}

	err = got_privsep_send_obj(ibuf, obj);
done:
	got_object_close(obj);
	return err;
}

static const struct got_error *
open_commit(struct got_commit_object **commit, struct got_pack *pack,
    struct got_packidx *packidx, int obj_idx, struct got_object_id *id,
    struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	uint8_t *buf = NULL;
	size_t len;

	*commit = NULL;

	obj = got_object_cache_get(objcache, id);
	if (obj) {
		obj->refcnt++;
	} else {
		err = open_object(&obj, pack, packidx, obj_idx, id,
		    objcache);
		if (err)
			return err;
	}

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		goto done;

	obj->size = len;

	err = got_object_parse_commit(commit, buf, len, pack->algo);
done:
	got_object_close(obj);
	free(buf);
	return err;
}

static const struct got_error *
commit_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_commit_object *commit = NULL;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	err = open_commit(&commit, pack, packidx, iobj.idx, &id, objcache);
	if (err)
		goto done;

	err = got_privsep_send_commit(ibuf, commit);
done:
	if (commit)
		got_object_commit_close(commit);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}

static const struct got_error *
open_tree(uint8_t **buf, size_t *len,
    struct got_pack *pack, struct got_packidx *packidx, int obj_idx,
    struct got_object_id *id, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	int cached = 0;

	*buf = NULL;
	*len = 0;

	obj = got_object_cache_get(objcache, id);
	if (obj) {
		obj->refcnt++;
		cached = 1;
	} else {
		err = open_object(&obj, pack, packidx, obj_idx, id,
		    objcache);
		if (err)
			return err;
	}

	err = got_packfile_extract_object_to_mem(buf, len, obj, pack);
	if (err)
		goto done;

	if (!cached)
		obj->size = *len;
done:
	got_object_close(obj);
	if (err) {
		free(*buf);
		*buf = NULL;
	}
	return err;
}

static const struct got_error *
tree_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache,
    struct got_parsed_tree_entry **entries, size_t *nentries,
    size_t *nentries_alloc)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	uint8_t *buf = NULL;
	size_t len = 0;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	err = open_tree(&buf, &len, pack, packidx, iobj.idx, &id, objcache);
	if (err)
		return err;

	err = got_object_parse_tree(entries, nentries, nentries_alloc,
	    buf, len, id.algo);
	if (err)
		goto done;

	err = got_privsep_send_tree(ibuf, *entries, *nentries);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}
done:
	free(buf);
	return err;
}

static const struct got_error *
receive_file(FILE **f, struct imsgbuf *ibuf, uint32_t imsg_code)
{
	const struct got_error *err;
	struct imsg imsg;
	size_t datalen;
	int fd;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	if (imsg.hdr.type != imsg_code) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	fd = imsg_get_fd(&imsg);
	if (fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	*f = fdopen(fd, "w+");
	if (*f == NULL) {
		err = got_error_from_errno("fdopen");
		close(fd);
		goto done;
	}
done:
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
receive_tempfile(FILE **f, const char *mode, struct imsg *imsg,
    struct imsgbuf *ibuf)
{
	const struct got_error *err;
	size_t datalen;
	int fd;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	*f = fdopen(fd, mode);
	if (*f == NULL) {
		err = got_error_from_errno("fdopen");
		close(fd);
		return err;
	}

	return NULL;
}

static const struct got_error *
blob_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache,
    FILE *basefile, FILE *accumfile)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj = NULL;
	FILE *outfile = NULL;
	struct got_object_id id;
	size_t datalen;
	uint64_t blob_size;
	uint8_t *buf = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	obj = got_object_cache_get(objcache, &id);
	if (obj) {
		obj->refcnt++;
	} else {
		err = open_object(&obj, pack, packidx, iobj.idx, &id,
		    objcache);
		if (err)
			return err;
	}

	err = receive_file(&outfile, ibuf, GOT_IMSG_BLOB_OUTFD);
	if (err)
		goto done;

	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		err = got_pack_get_max_delta_object_size(&blob_size, obj, pack);
		if (err)
			goto done;
	} else
		blob_size = obj->size;

	if (blob_size <= GOT_PRIVSEP_INLINE_BLOB_DATA_MAX)
		err = got_packfile_extract_object_to_mem(&buf, &obj->size,
		    obj, pack);
	else
		err = got_packfile_extract_object(pack, obj, outfile, basefile,
		    accumfile);
	if (err)
		goto done;

	err = got_privsep_send_blob(ibuf, obj->size, obj->hdrlen, buf);
done:
	free(buf);
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	got_object_close(obj);
	if (err && err->code != GOT_ERR_PRIVSEP_PIPE)
		got_privsep_send_error(ibuf, err);

	return err;
}

static const struct got_error *
tag_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj = NULL;
	struct got_tag_object *tag = NULL;
	uint8_t *buf = NULL;
	size_t len;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	obj = got_object_cache_get(objcache, &id);
	if (obj) {
		obj->refcnt++;
	} else {
		err = open_object(&obj, pack, packidx, iobj.idx, &id,
		    objcache);
		if (err)
			return err;
	}

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		goto done;

	obj->size = len;
	err = got_object_parse_tag(&tag, buf, len, id.algo);
	if (err)
		goto done;

	err = got_privsep_send_tag(ibuf, tag);
done:
	free(buf);
	got_object_close(obj);
	if (tag)
		got_object_tag_close(tag);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}

static const struct got_error *
tree_path_changed(int *changed, uint8_t **buf1, size_t *len1,
    uint8_t **buf2, size_t *len2, const char *path,
    struct got_pack *pack, struct got_packidx *packidx,
    struct imsgbuf *ibuf, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_parsed_tree_entry pte1, pte2;
	const char *seg, *s;
	size_t seglen, digest_len;
	size_t remain1 = *len1, remain2 = *len2, elen;
	uint8_t *next_entry1 = *buf1;
	uint8_t *next_entry2 = *buf2;

	memset(&pte1, 0, sizeof(pte1));
	memset(&pte2, 0, sizeof(pte2));

	*changed = 0;

	digest_len = got_hash_digest_length(pack->algo);

	/* We not do support comparing the root path. */
	if (got_path_is_root_dir(path))
		return got_error_path(path, GOT_ERR_BAD_PATH);

	s = path;
	while (*s == '/')
		s++;
	seg = s;
	seglen = 0;
	while (*s) {
		if (*s != '/') {
			s++;
			seglen++;
			if (*s)
				continue;
		}

		/*
		 * As an optimization we compare entries in on-disk order
		 * rather than in got_path_cmp() order. We only need to
		 * find out if any entries differ. Parsing all entries and
		 * sorting them slows us down significantly when tree objects
		 * have thousands of entries. We can assume that on-disk entry
		 * ordering is stable, as per got_object_tree_create() and
		 * sort_tree_entries_the_way_git_likes_it(). Other orderings
		 * are incompatible with Git and would yield false positives
		 * here, too.
		 */
		while (remain1 > 0) {
			err = got_object_parse_tree_entry(&pte1, &elen,
			    next_entry1, remain1, digest_len, pack->algo);
			if (err)
				return err;
			next_entry1 += elen;
			remain1 -= elen;
			if (strncmp(pte1.name, seg, seglen) != 0 ||
			    pte1.name[seglen] != '\0') {
				memset(&pte1, 0, sizeof(pte1));
				continue;
			} else
				break;
		}
		if (pte1.name == NULL) {
			err = got_error(GOT_ERR_NO_OBJ);
			break;
		}

		if (remain2 == 0) {
			*changed = 1;
			break;
		}

		while (remain2 > 0) {
			err = got_object_parse_tree_entry(&pte2, &elen,
			    next_entry2, remain2, digest_len, pack->algo);
			if (err)
				return err;
			next_entry2 += elen;
			remain2 -= elen;
			if (strncmp(pte2.name, seg, seglen) != 0 ||
			    pte2.name[seglen] != '\0') {
				memset(&pte2, 0, sizeof(pte2));
				continue;
			} else
				break;
		}

		if (pte2.name == NULL) {
			*changed = 1;
			break;
		}

		if (pte1.mode != pte2.mode) {
			*changed = 1;
			break;
		}

		if (memcmp(pte1.id, pte2.id, pte1.digest_len) == 0) {
			*changed = 0;
			break;
		}

		if (*s == '\0') { /* final path element */
			*changed = 1;
			break;
		}

		seg = s + 1;
		s++;
		seglen = 0;
		if (*s) {
			struct got_object_id id1, id2;
			int idx;

			memcpy(id1.hash, pte1.id, pte1.digest_len);
			id1.algo = pack->algo;
			idx = got_packidx_get_object_idx(packidx, &id1);
			if (idx == -1) {
				err = got_error_no_obj(&id1);
				break;
			}
			free(*buf1);
			*buf1 = NULL;
			err = open_tree(buf1, len1, pack, packidx, idx, &id1,
			    objcache);
			memset(&pte1, 0, sizeof(pte1));
			if (err)
				break;
			next_entry1 = *buf1;
			remain1 = *len1;

			memcpy(id2.hash, pte2.id, pte2.digest_len);
			id2.algo = pack->algo;
			idx = got_packidx_get_object_idx(packidx, &id2);
			if (idx == -1) {
				err = got_error_no_obj(&id2);
				break;
			}
			free(*buf2);
			*buf2 = NULL;
			err = open_tree(buf2, len2, pack, packidx, idx, &id2,
			    objcache);
			memset(&pte2, 0, sizeof(pte2));
			if (err)
				break;
			next_entry2 = *buf2;
			remain2 = *len2;
		}
	}

	return err;
}

static const struct got_error *
send_traversed_commits(struct got_object_id *commit_ids, size_t ncommits,
    struct imsgbuf *ibuf)
{
	struct ibuf *wbuf;
	size_t i;

	wbuf = imsg_create(ibuf, GOT_IMSG_TRAVERSED_COMMITS, 0, 0,
	    sizeof(struct got_imsg_traversed_commits) +
	    ncommits * sizeof(commit_ids[0]));
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create TRAVERSED_COMMITS");

	if (imsg_add(wbuf, &ncommits, sizeof(ncommits)) == -1)
		return got_error_from_errno("imsg_add TRAVERSED_COMMITS");

	for (i = 0; i < ncommits; i++) {
		struct got_object_id *id = &commit_ids[i];
		if (imsg_add(wbuf, id, sizeof(*id)) == -1) {
			return got_error_from_errno(
			    "imsg_add TRAVERSED_COMMITS");
		}
	}

	imsg_close(ibuf, wbuf);

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_commit_traversal_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_COMMIT_TRAVERSAL_DONE, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose TRAVERSAL_DONE");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
commit_traversal_request(struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_commit_traversal_request ctreq;
	struct got_object_qid *pid;
	struct got_commit_object *commit = NULL, *pcommit = NULL;
	struct got_object_id id;
	size_t datalen;
	char *path = NULL;
	const int min_alloc = 64;
	int changed = 0, ncommits = 0, nallocated = 0;
	struct got_object_id *commit_ids = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ctreq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ctreq, imsg->data, sizeof(ctreq));
	memcpy(&id, &ctreq.iobj.id, sizeof(id));

	if (datalen != sizeof(ctreq) + ctreq.path_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (ctreq.path_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	path = strndup(imsg->data + sizeof(ctreq), ctreq.path_len);
	if (path == NULL)
		return got_error_from_errno("strndup");

	nallocated = min_alloc;
	commit_ids = reallocarray(NULL, nallocated, sizeof(*commit_ids));
	if (commit_ids == NULL)
		return got_error_from_errno("reallocarray");

	do {
		const size_t max_datalen = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
		int idx;

		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			goto done;
		}

		if (commit == NULL) {
			idx = got_packidx_get_object_idx(packidx, &id);
			if (idx == -1)
				break;
			err = open_commit(&commit, pack, packidx,
			    idx, &id, objcache);
			if (err) {
				if (err->code != GOT_ERR_NO_OBJ)
					goto done;
				err = NULL;
				break;
			}
		}

		if (sizeof(struct got_imsg_traversed_commits) +
		    (ncommits + 1) * sizeof(commit_ids[0]) >= max_datalen) {
			err = send_traversed_commits(commit_ids, ncommits,
			    ibuf);
			if (err)
				goto done;
			ncommits = 0;
		}
		ncommits++;
		if (ncommits > nallocated) {
			struct got_object_id *new;
			nallocated += min_alloc;
			new = reallocarray(commit_ids, nallocated,
			    sizeof(*commit_ids));
			if (new == NULL) {
				err = got_error_from_errno("reallocarray");
				goto done;
			}
			commit_ids = new;
		}
		memcpy(&commit_ids[ncommits - 1], &id, sizeof(id));

		pid = STAILQ_FIRST(&commit->parent_ids);
		if (pid == NULL)
			break;

		idx = got_packidx_get_object_idx(packidx, &pid->id);
		if (idx == -1)
			break;

		err = open_commit(&pcommit, pack, packidx, idx, &pid->id,
		    objcache);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				goto done;
			err = NULL;
			break;
		}

		if (path[0] == '/' && path[1] == '\0') {
			if (got_object_id_cmp(pcommit->tree_id,
			    commit->tree_id) != 0) {
				changed = 1;
				break;
			}
		} else {
			int pidx;
			uint8_t *buf = NULL, *pbuf = NULL;
			size_t len = 0, plen = 0;

			idx = got_packidx_get_object_idx(packidx,
			    commit->tree_id);
			if (idx == -1)
				break;
			pidx = got_packidx_get_object_idx(packidx,
			    pcommit->tree_id);
			if (pidx == -1)
				break;

			err = open_tree(&buf, &len, pack, packidx, idx,
			    commit->tree_id, objcache);
			if (err)
				goto done;

			err = open_tree(&pbuf, &plen, pack, packidx, pidx,
			    pcommit->tree_id, objcache);
			if (err) {
				free(buf);
				goto done;
			}

			err = tree_path_changed(&changed, &buf, &len,
			    &pbuf, &plen, path, pack, packidx, ibuf,
			    objcache);

			free(buf);
			free(pbuf);
			if (err) {
				if (err->code != GOT_ERR_NO_OBJ)
					goto done;
				err = NULL;
				break;
			}
		}

		if (!changed) {
			memcpy(&id, &pid->id, sizeof(id));
			got_object_commit_close(commit);
			commit = pcommit;
			pcommit = NULL;
		}
	} while (!changed);

	if (ncommits > 0) {
		err = send_traversed_commits(commit_ids, ncommits, ibuf);
		if (err)
			goto done;

		if (changed) {
			err = got_privsep_send_commit(ibuf, commit);
			if (err)
				goto done;
		}
	}
	err = send_commit_traversal_done(ibuf);
done:
	free(path);
	free(commit_ids);
	if (commit)
		got_object_commit_close(commit);
	if (pcommit)
		got_object_commit_close(pcommit);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}

static const struct got_error *
raw_object_request(struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache, FILE *basefile, FILE *accumfile)
{
	const struct got_error *err = NULL;
	uint8_t *buf = NULL;
	uint64_t size = 0;
	FILE *outfile = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(&id, &iobj.id, sizeof(id));

	obj = got_object_cache_get(objcache, &id);
	if (obj) {
		obj->refcnt++;
	} else {
		err = open_object(&obj, pack, packidx, iobj.idx, &id,
		    objcache);
		if (err)
			return err;
	}

	err = receive_file(&outfile, ibuf, GOT_IMSG_RAW_OBJECT_OUTFD);
	if (err)
		return err;

	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		err = got_pack_get_max_delta_object_size(&size, obj, pack);
		if (err)
			goto done;
	} else
		size = obj->size;

	if (size <= GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX)
		err = got_packfile_extract_object_to_mem(&buf, &obj->size,
		    obj, pack);
	else
		err = got_packfile_extract_object(pack, obj, outfile, basefile,
		    accumfile);
	if (err)
		goto done;

	err = got_privsep_send_raw_obj(ibuf, obj->size, obj->hdrlen, buf);
done:
	free(buf);
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	got_object_close(obj);
	if (err && err->code != GOT_ERR_PRIVSEP_PIPE)
		got_privsep_send_error(ibuf, err);

	return err;
}

static const struct got_error *
get_base_object_id(struct got_object_id *base_id, struct got_packidx *packidx,
    off_t base_offset)
{
	const struct got_error *err;
	int idx;

	err = got_packidx_get_offset_idx(&idx, packidx, base_offset);
	if (err)
		return err;
	if (idx == -1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	return got_packidx_get_object_id(base_id, packidx, idx);
}

static const struct got_error *
raw_delta_request(struct imsg *imsg, struct imsgbuf *ibuf,
    FILE *delta_outfile, struct got_pack *pack,
    struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_imsg_raw_delta_request req;
	size_t datalen, delta_size, delta_compressed_size;
	off_t delta_offset, delta_data_offset;
	uint8_t *delta_buf = NULL;
	struct got_object_id id, base_id;
	off_t base_offset, delta_out_offset = 0;
	uint64_t base_size = 0, result_size = 0;
	size_t w;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(req))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&req, imsg->data, sizeof(req));
	memcpy(&id, &req.id, sizeof(id));

	err = got_packfile_extract_raw_delta(&delta_buf, &delta_size,
	    &delta_compressed_size, &delta_offset, &delta_data_offset,
	    &base_offset, &base_id, &base_size, &result_size,
	    pack, packidx, req.idx);
	if (err)
		goto done;

	/*
	 * If this is an offset delta we must determine the base
	 * object ID ourselves.
	 */
	if (base_offset != 0) {
		err = get_base_object_id(&base_id, packidx, base_offset);
		if (err)
			goto done;
	}

	delta_out_offset = ftello(delta_outfile);
	w = fwrite(delta_buf, 1, delta_compressed_size, delta_outfile);
	if (w != delta_compressed_size) {
		err = got_ferror(delta_outfile, GOT_ERR_IO);
		goto done;
	}
	if (fflush(delta_outfile) == -1) {
		err = got_error_from_errno("fflush");
		goto done;
	}

	err = got_privsep_send_raw_delta(ibuf, base_size, result_size,
	    delta_size, delta_compressed_size, delta_offset, delta_out_offset,
	    &base_id);
done:
	free(delta_buf);
	return err;
}

struct search_deltas_arg {
	struct imsgbuf *ibuf;
	struct got_packidx *packidx;
	struct got_pack *pack;
	struct got_object_idset *idset;
	struct got_imsg_reused_delta deltas[GOT_IMSG_REUSED_DELTAS_MAX_NDELTAS];
	size_t ndeltas;
};

static const struct got_error *
search_delta_for_object(struct got_object_id *id, void *data, void *arg)
{
	const struct got_error *err;
	struct search_deltas_arg *a = arg;
	int obj_idx;
	uint8_t *delta_buf = NULL;
	uint64_t base_size, result_size;
	size_t delta_size, delta_compressed_size;
	off_t delta_offset, delta_data_offset, base_offset;
	struct got_object_id base_id;

	if (sigint_received)
		return got_error(GOT_ERR_CANCELLED);

	obj_idx = got_packidx_get_object_idx(a->packidx, id);
	if (obj_idx == -1)
		return NULL; /* object not present in our pack file */

	err = got_packfile_extract_raw_delta(&delta_buf, &delta_size,
	    &delta_compressed_size, &delta_offset, &delta_data_offset,
	    &base_offset, &base_id, &base_size, &result_size,
	    a->pack, a->packidx, obj_idx);
	if (err) {
		if (err->code == GOT_ERR_OBJ_TYPE)
			return NULL; /* object not stored as a delta */
		return err;
	}

	/*
	 * If this is an offset delta we must determine the base
	 * object ID ourselves.
	 */
	if (base_offset != 0) {
		err = get_base_object_id(&base_id, a->packidx, base_offset);
		if (err)
			goto done;
	}

	if (got_object_idset_contains(a->idset, &base_id)) {
		struct got_imsg_reused_delta *delta;

		delta = &a->deltas[a->ndeltas++];
		memcpy(&delta->id, id, sizeof(delta->id));
		memcpy(&delta->base_id, &base_id, sizeof(delta->base_id));
		delta->base_size = base_size;
		delta->result_size = result_size;
		delta->delta_size = delta_size;
		delta->delta_compressed_size = delta_compressed_size;
		delta->delta_offset = delta_data_offset;

		if (a->ndeltas >= GOT_IMSG_REUSED_DELTAS_MAX_NDELTAS) {
			err = got_privsep_send_reused_deltas(a->ibuf,
			    a->deltas, a->ndeltas);
			if (err)
				goto done;
			a->ndeltas = 0;
		}
	}
done:
	free(delta_buf);
	return err;
}

static const struct got_error *
recv_object_ids(struct got_object_idset *idset, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	int done = 0;
	struct got_object_id *ids;
	size_t nids, i;

	for (;;) {
		err = got_privsep_recv_object_idlist(&done, &ids, &nids, ibuf);
		if (err || done)
			break;
		for (i = 0; i < nids; i++) {
			err = got_object_idset_add(idset, &ids[i], NULL);
			if (err) {
				free(ids);
				return err;
			}
		}
		free(ids);
	}

	return err;
}

static const struct got_error *
recv_object_id_queue(size_t *nids_total, struct got_object_id_queue *queue,
    void *data, struct got_object_idset *queued_ids, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	int done = 0;
	struct got_object_qid *qid;
	struct got_object_id *ids;
	size_t nids, i;

	*nids_total = 0;
	for (;;) {
		err = got_privsep_recv_object_idlist(&done, &ids, &nids, ibuf);
		if (err || done)
			break;
		*nids_total += nids;
		for (i = 0; i < nids; i++) {
			err = got_object_qid_alloc_partial(&qid);
			if (err)
				goto done;
			memcpy(&qid->id, &ids[i], sizeof(qid->id));
			if (data)
				qid->data = data;
			STAILQ_INSERT_TAIL(queue, qid, entry);
			if (queued_ids) {
				err = got_object_idset_add(queued_ids,
				    &qid->id, NULL);
				if (err)
					goto done;
			}
		}
		free(ids);
		ids = NULL;
	}
done:
	free(ids);
	return err;
}

static const struct got_error *
delta_reuse_request(struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_object_idset *idset;
	struct search_deltas_arg sda;

	idset = got_object_idset_alloc();
	if (idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	err = recv_object_ids(idset, ibuf);
	if (err)
		return err;

	memset(&sda, 0, sizeof(sda));
	sda.ibuf = ibuf;
	sda.idset = idset;
	sda.pack = pack;
	sda.packidx = packidx;
	err = got_object_idset_for_each(idset, search_delta_for_object, &sda);
	if (err)
		goto done;

	if (sda.ndeltas > 0) {
		err = got_privsep_send_reused_deltas(ibuf, sda.deltas,
		    sda.ndeltas);
		if (err)
			goto done;
	}

	err = got_privsep_send_reused_deltas_done(ibuf);
done:
	got_object_idset_free(idset);
	return err;
}

static const struct got_error *
receive_packidx(struct got_packidx **packidx, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_packidx ipackidx;
	size_t datalen;
	struct got_packidx *p;

	*packidx = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (imsg.hdr.type != GOT_IMSG_PACKIDX) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ipackidx)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&ipackidx, imsg.data, sizeof(ipackidx));

	p->algo = ipackidx.algo;
	p->fd = imsg_get_fd(&imsg);
	p->len = ipackidx.len;
	if (p->fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}
	if (lseek(p->fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	if (p->len > 0 && p->len <= SIZE_MAX) {
		p->map = mmap(NULL, p->len, PROT_READ, MAP_PRIVATE, p->fd, 0);
		if (p->map == MAP_FAILED)
			p->map = NULL; /* fall back to read(2) */
	}
#endif
	err = got_packidx_init_hdr(p, 1, ipackidx.packfile_size);
done:
	if (err) {
		if (p != NULL)
			got_packidx_close(p);
	} else
		*packidx = p;
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
send_tree_enumeration_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_TREE_ENUMERATION_DONE, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose TREE_ENUMERATION_DONE");

	return got_privsep_flush_imsg(ibuf);
}

struct enumerated_tree {
	struct got_object_id id;
	char *path;
	uint8_t *buf;
	struct got_parsed_tree_entry *entries;
	int nentries;
};

static const struct got_error *
enumerate_tree(int *have_all_entries, struct imsgbuf *ibuf, size_t *totlen,
    struct got_object_id *tree_id,
    const char *path, struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache, struct got_object_idset *idset,
    struct enumerated_tree **trees, size_t *nalloc, size_t *ntrees)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue ids;
	struct got_object_qid *qid;
	uint8_t *buf = NULL;
	size_t len = 0;
	struct got_parsed_tree_entry *entries = NULL;
	size_t nentries = 0, nentries_alloc = 0, i;
	struct enumerated_tree *tree;

	*ntrees = 0;
	*have_all_entries = 1;
	STAILQ_INIT(&ids);

	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;
	memcpy(&qid->id, tree_id, sizeof(*tree_id));
	qid->data = strdup(path);
	if (qid->data == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	STAILQ_INSERT_TAIL(&ids, qid, entry);
	qid = NULL;

	/* Traverse the tree hierarchy, gather tree object IDs and paths. */
	do {
		const char *path;
		int idx, i;

		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			goto done;
		}

		qid = STAILQ_FIRST(&ids);
		STAILQ_REMOVE_HEAD(&ids, entry);
		path = qid->data;

		idx = got_packidx_get_object_idx(packidx, &qid->id);
		if (idx == -1) {
			*have_all_entries = 0;
			break;
		}

		err = open_tree(&buf, &len, pack, packidx, idx, &qid->id,
		    objcache);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				goto done;
		}

		err = got_object_parse_tree(&entries, &nentries,
		    &nentries_alloc, buf, len, pack->algo);
		if (err)
			goto done;

		err = got_object_idset_add(idset, &qid->id, NULL);
		if (err)
			goto done;

		for (i = 0; i < nentries; i++) {
			struct got_object_qid *eqid = NULL;
			struct got_parsed_tree_entry *pte = &entries[i];
			char *p;

			if (!S_ISDIR(pte->mode))
				continue;

			err = got_object_qid_alloc_partial(&eqid);
			if (err)
				goto done;
			eqid->id.algo = pte->algo;
			memcpy(eqid->id.hash, pte->id, pte->digest_len);

			if (got_object_idset_contains(idset, &eqid->id)) {
				got_object_qid_free(eqid);
				continue;
			}

			if (asprintf(&p, "%s%s%s", path,
			    got_path_is_root_dir(path) ? "" : "/",
			    pte->name) == -1) {
				err = got_error_from_errno("asprintf");
				got_object_qid_free(eqid);
				goto done;
			}
			eqid->data = p;
			STAILQ_INSERT_TAIL(&ids, eqid, entry);
		}

		if (*ntrees >= *nalloc) {
			struct enumerated_tree *new;
			new = recallocarray(*trees, *nalloc, *nalloc + 16,
			    sizeof(*new));
			if (new == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}
			*trees = new;
			*nalloc += 16;
		}
		tree = &(*trees)[*ntrees];
		(*ntrees)++;
		memcpy(&tree->id, &qid->id, sizeof(tree->id));
		tree->path = qid->data;
		tree->buf = buf;
		buf = NULL;
		tree->entries = entries;
		entries = NULL;
		nentries_alloc = 0;
		tree->nentries = nentries;
		nentries = 0;

		got_object_qid_free(qid);
		qid = NULL;
	} while (!STAILQ_EMPTY(&ids));

	if (*have_all_entries) {
		int i;
		/*
		 * We have managed to traverse all entries in the hierarchy.
		 * Tell the main process what we have found.
		 */
		for (i = 0; i < *ntrees; i++) {
			tree = &(*trees)[i];
			err = got_privsep_send_enumerated_tree(totlen,
			    ibuf, &tree->id, tree->path, tree->entries,
			    tree->nentries);
			if (err)
				goto done;
			free(tree->buf);
			tree->buf = NULL;
			free(tree->path);
			tree->path = NULL;
			free(tree->entries);
			tree->entries = NULL;
		}
		*ntrees = 0; /* don't loop again below to free memory */

		err = send_tree_enumeration_done(ibuf);
	} else {
		/*
		 * We can only load fully packed tree hierarchies on
		 * behalf of the main process, otherwise the main process
		 * gets a wrong idea about which tree objects have
		 * already been traversed.
		 * Indicate a missing entry for the root of this tree.
		 * The main process should continue by loading this
		 * entire tree the slow way.
		 */
		err = got_privsep_send_enumerated_tree(totlen, ibuf,
		    tree_id, "/", NULL, -1);
		if (err)
			goto done;
	}
done:
	free(buf);
	free(entries);
	for (i = 0; i < *ntrees; i++) {
		tree = &(*trees)[i];
		free(tree->buf);
		tree->buf = NULL;
		free(tree->path);
		tree->path = NULL;
		free(tree->entries);
		tree->entries = NULL;
	}
	if (qid)
		free(qid->data);
	got_object_qid_free(qid);
	got_object_id_queue_free(&ids);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}


static const struct got_error *
resolve_tag(struct got_object **obj, struct got_object_id *id,
    struct got_packidx *packidx, struct got_pack *pack,
    struct got_object_cache *objcache)
{
	const struct got_error *err;
	struct got_object *tagged_obj;
	struct got_tag_object *tag;
	uint8_t *buf;
	size_t len;
	int idx;

	err = got_packfile_extract_object_to_mem(&buf, &len, *obj, pack);
	if (err)
		return err;

	(*obj)->size = len;
	err = got_object_parse_tag(&tag, buf, len, id->algo);
	if (err)
		goto done;

	idx = got_packidx_get_object_idx(packidx, &tag->id);
	if (idx == -1) {
		got_object_close(*obj);
		*obj = NULL;
		return NULL;
	}

	tagged_obj = got_object_cache_get(objcache, &tag->id);
	if (tagged_obj) {
		tagged_obj->refcnt++;
	} else {
		err = open_object(&tagged_obj, pack, packidx,
		    idx, &tag->id, objcache);
		if (err)
			goto done;
	}

	got_object_close(*obj);
	*obj = tagged_obj;
done:
	got_object_tag_close(tag);
	free(buf);
	return err;
}

static const struct got_error *
enumeration_request(struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue commit_ids;
	const struct got_object_id_queue *parents = NULL;
	struct got_object_qid *qid = NULL;
	struct got_object *obj = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *tree_id = NULL;
	size_t totlen = 0;
	struct got_object_idset *idset, *queued_ids = NULL;
	int i, idx, have_all_entries = 1;
	struct enumerated_tree *trees = NULL;
	size_t ntrees = 0, nalloc = 16, nids = 0;

	STAILQ_INIT(&commit_ids);

	trees = calloc(nalloc, sizeof(*trees));
	if (trees == NULL)
		return got_error_from_errno("calloc");

	idset = got_object_idset_alloc();
	if (idset == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	queued_ids = got_object_idset_alloc();
	if (queued_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	err = recv_object_id_queue(&nids, &commit_ids, NULL, queued_ids, ibuf);
	if (err)
		goto done;

	if (STAILQ_EMPTY(&commit_ids)) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	err = recv_object_ids(idset, ibuf);
	if (err)
		goto done;

	while (!STAILQ_EMPTY(&commit_ids)) {
		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			goto done;
		}

		qid = STAILQ_FIRST(&commit_ids);
		STAILQ_REMOVE_HEAD(&commit_ids, entry);

		if (got_object_idset_contains(idset, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}

		idx = got_packidx_get_object_idx(packidx, &qid->id);
		if (idx == -1) {
			have_all_entries = 0;
			break;
		}

		err = open_object(&obj, pack, packidx, idx, &qid->id,
		    objcache);
		if (err)
			goto done;
		if (obj->type == GOT_OBJ_TYPE_TAG) {
			while (obj->type == GOT_OBJ_TYPE_TAG) {
				err = resolve_tag(&obj, &qid->id, packidx,
				    pack, objcache);
				if (err)
					goto done;
				if (obj == NULL)
					break;
			}
			if (obj == NULL) {
				have_all_entries = 0;
				break;
			}
			if (obj->type != GOT_OBJ_TYPE_COMMIT) {
				got_object_qid_free(qid);
				qid = NULL;
				got_object_close(obj);
				obj = NULL;
				continue;
			}
			err = open_commit(&commit, pack, packidx, idx,
			    &obj->id, objcache);
			if (err)
				goto done;
		} else if (obj->type == GOT_OBJ_TYPE_COMMIT) {
			err = open_commit(&commit, pack, packidx, idx,
			    &qid->id, objcache);
			if (err)
				goto done;
		} else {
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}
		got_object_close(obj);
		obj = NULL;

		err = got_privsep_send_enumerated_commit(ibuf, &qid->id,
		    got_object_commit_get_committer_time(commit));
		if (err)
			goto done;

		tree_id = got_object_commit_get_tree_id(commit);
		idx = got_packidx_get_object_idx(packidx, tree_id);
		if (idx == -1) {
			have_all_entries = 0;
			err = got_privsep_send_enumerated_tree(&totlen, ibuf,
			    tree_id, "/", NULL, -1);
			if (err)
				goto done;
			break;
		}

		if (got_object_idset_contains(idset, tree_id)) {
			got_object_qid_free(qid);
			qid = NULL;
			err = send_tree_enumeration_done(ibuf);
			if (err)
				goto done;
			got_object_commit_close(commit);
			commit = NULL;
			continue;
		}

		err = enumerate_tree(&have_all_entries, ibuf, &totlen,
		    tree_id, "/", pack, packidx, objcache, idset,
		    &trees, &nalloc, &ntrees);
		if (err)
			goto done;

		if (!have_all_entries)
			break;

		got_object_qid_free(qid);
		qid = NULL;

		parents = got_object_commit_get_parent_ids(commit);
		if (parents) {
			struct got_object_qid *pid;
			STAILQ_FOREACH(pid, parents, entry) {
				if (got_object_idset_contains(idset, &pid->id))
					continue;
				if (got_object_idset_contains(queued_ids, &pid->id))
					continue;
				err = got_object_qid_alloc_partial(&qid);
				if (err)
					goto done;
				memcpy(&qid->id, &pid->id, sizeof(qid->id));
				STAILQ_INSERT_TAIL(&commit_ids, qid, entry);
				qid = NULL;
			}
		}

		got_object_commit_close(commit);
		commit = NULL;
	}

	if (have_all_entries) {
		err = got_privsep_send_object_enumeration_done(ibuf);
		if (err)
			goto done;
	} else {
		err = got_privsep_send_object_enumeration_incomplete(ibuf);
		if (err)
			goto done;
	}
done:
	if (obj)
		got_object_close(obj);
	if (commit)
		got_object_commit_close(commit);
	got_object_qid_free(qid);
	got_object_id_queue_free(&commit_ids);
	if (idset)
		got_object_idset_free(idset);
	if (queued_ids)
		got_object_idset_free(queued_ids);
	for (i = 0; i < ntrees; i++) {
		struct enumerated_tree *tree = &trees[i];
		free(tree->buf);
		free(tree->path);
		free(tree->entries);
	}
	free(trees);
	return err;
}

enum findtwixt_color {
	COLOR_KEEP = 0,
	COLOR_DROP,
	COLOR_SKIP,
	COLOR_MAX,
};

static const struct got_error *
paint_commit(struct got_object_qid *qid, intptr_t color)
{
	if (color < 0 || color >= COLOR_MAX)
		return got_error(GOT_ERR_RANGE);

	qid->data = (void *)color;
	return NULL;
}

static const struct got_error *
queue_commit_id(struct got_object_id_queue *ids, struct got_object_id *id,
    intptr_t color)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;

	memcpy(&qid->id, id, sizeof(qid->id));
	if (color == COLOR_KEEP)
		STAILQ_INSERT_TAIL(ids, qid, entry);
	else
		STAILQ_INSERT_HEAD(ids, qid, entry);
	return paint_commit(qid, color);
}

static const struct got_error *
paint_commits(struct got_object_id_queue *ids, int *nids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_idset *skip, struct got_pack *pack,
    struct got_packidx *packidx, struct imsgbuf *ibuf,
    struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id_queue painted;
	const struct got_object_id_queue *parents;
	struct got_object_qid *qid = NULL;
	int nqueued = *nids, nskip = 0, npainted = 0;

	STAILQ_INIT(&painted);

	while (!STAILQ_EMPTY(ids) && nskip != nqueued) {
		int idx;
		intptr_t color;

		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			goto done;
		}

		qid = STAILQ_FIRST(ids);
		idx = got_packidx_get_object_idx(packidx, &qid->id);
		if (idx == -1) {
			qid = NULL;
			break;
		}

		STAILQ_REMOVE_HEAD(ids, entry);
		nqueued--;
		color = (intptr_t)qid->data;
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
				err = paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
				break;
			}
			if (!got_object_idset_contains(keep, &qid->id)) {
				err = got_object_idset_add(keep, &qid->id,
				    NULL);
				if (err)
					goto done;
			}
			break;
		case COLOR_DROP:
			if (got_object_idset_contains(keep, &qid->id)) {
				err = paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
				break;
			}
			if (!got_object_idset_contains(drop, &qid->id)) {
				err = got_object_idset_add(drop, &qid->id,
				    NULL);
				if (err)
					goto done;
			}
			break;
		case COLOR_SKIP:
			err = got_object_idset_add(skip, &qid->id,
			    NULL);
			if (err)
				goto done;
			break;
		default:
			/* should not happen */
			err = got_error_fmt(GOT_ERR_NOT_IMPL,
			    "%s invalid commit color %"PRIdPTR, __func__,
			    color);
			goto done;
		}

		err = open_commit(&commit, pack, packidx, idx, &qid->id,
		    objcache);
		if (err)
			goto done;

		parents = got_object_commit_get_parent_ids(commit);
		if (parents) {
			struct got_object_qid *pid;

			STAILQ_FOREACH(pid, parents, entry) {
				if (got_packidx_get_object_idx(packidx,
				    &pid->id) == -1)
					goto send;
			}

			color = (intptr_t)qid->data;
			STAILQ_FOREACH(pid, parents, entry) {
				err = queue_commit_id(ids, &pid->id, color);
				if (err)
					goto done;
				nqueued++;
				if (color == COLOR_SKIP)
					nskip++;
			}
		}

		got_object_commit_close(commit);
		commit = NULL;

		STAILQ_INSERT_TAIL(&painted, qid, entry);
		qid = NULL;
		npainted++;

		err = got_privsep_send_painted_commits(ibuf, &painted,
		    &npainted, 1, 0);
		if (err)
			goto done;
	}
send:
	err = got_privsep_send_painted_commits(ibuf, &painted, &npainted, 1, 1);
	if (err)
		goto done;

	*nids = nqueued;
done:
	if (commit)
		got_object_commit_close(commit);
	got_object_qid_free(qid);
	return err;
}

static void
commit_painting_free(struct got_object_idset **keep,
    struct got_object_idset **drop,
    struct got_object_idset **skip)
{
	if (*keep) {
		got_object_idset_free(*keep);
		*keep = NULL;
	}
	if (*drop) {
		got_object_idset_free(*drop);
		*drop = NULL;
	}
	if (*skip) {
		got_object_idset_free(*skip);
		*skip = NULL;
	}
}

static const struct got_error *
commit_painting_init(struct imsgbuf *ibuf, struct got_object_idset **keep,
    struct got_object_idset **drop, struct got_object_idset **skip)
{
	const struct got_error *err = NULL;

	*keep = got_object_idset_alloc();
	if (*keep == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}
	*drop = got_object_idset_alloc();
	if (*drop == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}
	*skip = got_object_idset_alloc();
	if (*skip == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	err = recv_object_ids(*keep, ibuf);
	if (err)
		goto done;
	err = recv_object_ids(*drop, ibuf);
	if (err)
		goto done;
	err = recv_object_ids(*skip, ibuf);
	if (err)
		goto done;

done:
	if (err)
		commit_painting_free(keep, drop, skip);

	return err;
}

static const struct got_error *
commit_painting_request(struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache, struct got_object_idset *keep,
    struct got_object_idset *drop, struct got_object_idset *skip)
{
	const struct got_error *err = NULL;
	size_t datalen;
	struct got_object_id_queue ids;
	size_t nids;
	int nqueued = 0, done = 0;

	STAILQ_INIT(&ids);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	while (!done) {
		err = got_privsep_recv_object_id_queue(&done, &ids, &nids, ibuf);
		if (err)
			goto done;
		if (nqueued + nids > INT_MAX) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		nqueued += nids;
	}

	err = paint_commits(&ids, &nqueued, keep, drop, skip,
	    pack, packidx, ibuf, objcache);
	if (err)
		goto done;

	err = got_privsep_send_painted_commits(ibuf, &ids, &nqueued, 0, 1);
	if (err)
		goto done;

	err = got_privsep_send_painting_commits_done(ibuf);
done:
	got_object_id_queue_free(&ids);
	return err;
}

static const struct got_error *
receive_pack(struct got_pack **packp, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_pack ipack;
	size_t datalen;
	struct got_pack *pack;

	*packp = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	pack = calloc(1, sizeof(*pack));
	if (pack == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (imsg.hdr.type != GOT_IMSG_PACK) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ipack)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&ipack, imsg.data, sizeof(ipack));

	pack->algo = ipack.algo;
	pack->filesize = ipack.filesize;
	pack->fd = imsg_get_fd(&imsg);
	if (pack->fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}
	if (lseek(pack->fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	pack->path_packfile = strdup(ipack.path_packfile);
	if (pack->path_packfile == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	err = got_delta_cache_alloc(&pack->delta_cache);
	if (err)
		goto done;

#ifndef GOT_PACK_NO_MMAP
	if (pack->filesize > 0 && pack->filesize <= SIZE_MAX) {
		pack->map = mmap(NULL, pack->filesize, PROT_READ, MAP_PRIVATE,
		    pack->fd, 0);
		if (pack->map == MAP_FAILED)
			pack->map = NULL; /* fall back to read(2) */
	}
#endif
done:
	if (err) {
		if (pack != NULL)
			got_pack_close(pack);
	} else
		*packp = pack;
	imsg_free(&imsg);
	return err;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	struct got_object_cache objcache;
	FILE *basefile = NULL, *accumfile = NULL, *delta_outfile = NULL;
	struct got_object_idset *keep = NULL, *drop = NULL, *skip = NULL;
	struct got_parsed_tree_entry *entries = NULL;
	size_t nentries = 0, nentries_alloc = 0;

	//static int attached;
	//while (!attached) sleep(1);

	signal(SIGINT, catch_sigint);

	if (imsgbuf_init(&ibuf, GOT_IMSG_FD_CHILD) == -1) {
		warn("imsgbuf_init");
		return 1;
	}
	imsgbuf_allow_fdpass(&ibuf);

	err = got_object_cache_init(&objcache, GOT_OBJECT_CACHE_TYPE_OBJ);
	if (err) {
		err = got_error_from_errno("got_object_cache_init");
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}
#endif

	err = receive_packidx(&packidx, &ibuf);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}

	err = receive_pack(&pack, &ibuf);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}

	for (;;) {
		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP) {
			imsg_free(&imsg);
			break;
		}

		switch (imsg.hdr.type) {
		case GOT_IMSG_TMPFD:
			if (basefile == NULL) {
				err = receive_tempfile(&basefile, "w+",
				   &imsg, &ibuf);
			} else if (accumfile == NULL) {
				err = receive_tempfile(&accumfile, "w+",
				   &imsg, &ibuf);
			} else
				err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		case GOT_IMSG_PACKED_OBJECT_REQUEST:
			err = object_request(&imsg, &ibuf, pack, packidx,
			    &objcache);
			break;
		case GOT_IMSG_PACKED_RAW_OBJECT_REQUEST:
			if (basefile == NULL || accumfile == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = raw_object_request(&imsg, &ibuf, pack, packidx,
			    &objcache, basefile, accumfile);
			break;
		case GOT_IMSG_RAW_DELTA_OUTFD:
			if (delta_outfile != NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = receive_tempfile(&delta_outfile, "w",
			    &imsg, &ibuf);
			break;
		case GOT_IMSG_RAW_DELTA_REQUEST:
			if (delta_outfile == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}
			err = raw_delta_request(&imsg, &ibuf, delta_outfile,
			    pack, packidx);
			break;
		case GOT_IMSG_DELTA_REUSE_REQUEST:
			err = delta_reuse_request(&imsg, &ibuf, pack, packidx);
			break;
		case GOT_IMSG_COMMIT_REQUEST:
			err = commit_request(&imsg, &ibuf, pack, packidx,
			    &objcache);
			break;
		case GOT_IMSG_TREE_REQUEST:
			err = tree_request(&imsg, &ibuf, pack, packidx,
			    &objcache, &entries, &nentries, &nentries_alloc);
			break;
		case GOT_IMSG_BLOB_REQUEST:
			if (basefile == NULL || accumfile == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = blob_request(&imsg, &ibuf, pack, packidx,
			    &objcache, basefile, accumfile);
			break;
		case GOT_IMSG_TAG_REQUEST:
			err = tag_request(&imsg, &ibuf, pack, packidx,
			    &objcache);
			break;
		case GOT_IMSG_COMMIT_TRAVERSAL_REQUEST:
			err = commit_traversal_request(&imsg, &ibuf, pack,
			    packidx, &objcache);
			break;
		case GOT_IMSG_OBJECT_ENUMERATION_REQUEST:
			err = enumeration_request(&imsg, &ibuf, pack,
			    packidx, &objcache);
			break;
		case GOT_IMSG_COMMIT_PAINTING_INIT:
			commit_painting_free(&keep, &drop, &skip);
			err = commit_painting_init(&ibuf, &keep, &drop, &skip);
			break;
		case GOT_IMSG_COMMIT_PAINTING_REQUEST:
			if (keep == NULL || drop == NULL || skip == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = commit_painting_request(&imsg, &ibuf, pack,
			    packidx, &objcache, keep, drop, skip);
			break;
		case GOT_IMSG_COMMIT_PAINTING_DONE:
			commit_painting_free(&keep, &drop, &skip);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	free(entries);
	commit_painting_free(&keep, &drop, &skip);
	if (packidx)
		got_packidx_close(packidx);
	if (pack) {
		got_pack_close(pack);
		free(pack);
	}
	got_object_cache_close(&objcache);
	if (basefile && fclose(basefile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (accumfile && fclose(accumfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (delta_outfile && fclose(delta_outfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		if (!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	imsgbuf_clear(&ibuf);
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
