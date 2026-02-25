/*
 * Copyright (c) 2018, 2019, 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <imsg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>
#include <limits.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_hash.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

static const struct got_error *
request_packed_object(struct got_object **obj, struct got_pack *pack, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf = pack->privsep_child->ibuf;

	err = got_privsep_send_packed_obj_req(ibuf, idx, id);
	if (err)
		return err;

	err = got_privsep_recv_obj(obj, ibuf);
	if (err)
		return err;

	memcpy(&(*obj)->id, id, sizeof((*obj)->id));

	return NULL;
}

/* Create temporary files used during delta application. */
static const struct got_error *
pack_child_send_tempfiles(struct imsgbuf *ibuf, struct got_pack *pack)
{
	const struct got_error *err;
	int basefd = -1, accumfd = -1;

	/*
	 * For performance reasons, the child will keep reusing the
	 * same temporary files during every object request.
	 * Opening and closing new files for every object request is
	 * too expensive during operations such as 'gotadmin pack'.
	 */
	if (pack->child_has_tempfiles)
		return NULL;

	basefd = dup(pack->basefd);
	if (basefd == -1)
		return got_error_from_errno("dup");

	accumfd = dup(pack->accumfd);
	if (accumfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	err = got_privsep_send_tmpfd(ibuf, basefd);
	if (err)
		goto done;

	err = got_privsep_send_tmpfd(ibuf, accumfd);
done:
	if (err) {
		if (basefd != -1)
			close(basefd);
		if (accumfd != -1)
			close(accumfd);
	} else
		pack->child_has_tempfiles = 1;
	return err;
}

static const struct got_error *
request_packed_object_raw(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    int *flags, int outfd, struct got_pack *pack, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf = pack->privsep_child->ibuf;
	int outfd_child;

	err = pack_child_send_tempfiles(ibuf, pack);
	if (err)
		return err;

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno("dup");

	err = got_privsep_send_packed_raw_obj_req(ibuf, idx, id);
	if (err) {
		close(outfd_child);
		return err;
	}

	err = got_privsep_send_raw_obj_outfd(ibuf, outfd_child);
	if (err)
		return err;

	err = got_privsep_recv_raw_obj(outbuf, size, hdrlen, flags, ibuf);
	if (err)
		return err;

	return NULL;
}

static const struct got_error *
read_packed_object_privsep(struct got_object **obj,
    struct got_repository *repo, struct got_pack *pack,
    struct got_packidx *packidx, int idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			return err;
	}

	return request_packed_object(obj, pack, idx, id);
}

static const struct got_error *
read_packed_object_raw_privsep(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    int *flags, int outfd, struct got_pack *pack, struct got_packidx *packidx,
    int idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			return err;
	}

	return request_packed_object_raw(outbuf, size, hdrlen, flags,
	    outfd, pack, idx, id);
}

const struct got_error *
got_object_open_packed(struct got_object **obj, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err)
		return err;

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	err = read_packed_object_privsep(obj, repo, pack, packidx, idx, id);
	if (err)
		goto done;
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_from_packfile(struct got_object **obj, struct got_object_id *id,
    struct got_pack *pack, struct got_packidx *packidx, int obj_idx,
    struct got_repository *repo)
{
	return read_packed_object_privsep(obj, repo, pack, packidx,
	    obj_idx, id);
}

const struct got_error *
got_object_read_raw_delta(uint64_t *base_size, uint64_t *result_size,
    off_t *delta_size, off_t *delta_compressed_size, off_t *delta_offset,
    off_t *delta_out_offset, struct got_object_id **base_id, int delta_cache_fd,
    struct got_packidx *packidx, int obj_idx, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	char *path_packfile;

	*base_size = 0;
	*result_size = 0;
	*delta_size = 0;
	*delta_compressed_size = 0;
	*delta_offset = 0;
	*delta_out_offset = 0;

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			return err;
	}

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			return err;
	}

	if (!pack->child_has_delta_outfd) {
		int outfd_child;
		outfd_child = dup(delta_cache_fd);
		if (outfd_child == -1)
			return got_error_from_errno("dup");
		err = got_privsep_send_raw_delta_outfd(
		    pack->privsep_child->ibuf, outfd_child);
		if (err)
			return err;
		pack->child_has_delta_outfd = 1;
	}

	err = got_privsep_send_raw_delta_req(pack->privsep_child->ibuf,
	    obj_idx, id);
	if (err)
		return err;

	return got_privsep_recv_raw_delta(base_size, result_size, delta_size,
	    delta_compressed_size, delta_offset, delta_out_offset, base_id,
	    pack->privsep_child->ibuf);
}

static const struct got_error *
request_object(struct got_object **obj, struct got_object_id *id,
    struct got_repository *repo, int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].ibuf;

	err = got_privsep_send_obj_req(ibuf, fd, id);
	if (err)
		return err;

	return got_privsep_recv_obj(obj, ibuf);
}

static const struct got_error *
request_raw_object(uint8_t **outbuf, off_t *size, size_t *hdrlen, int *flags,
    int outfd, struct got_object_id *id, struct got_repository *repo, int infd)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;
	int outfd_child;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].ibuf;

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno("dup");

	err = got_privsep_send_raw_obj_req(ibuf, infd, id);
	if (err)
		return err;

	err = got_privsep_send_raw_obj_outfd(ibuf, outfd_child);
	if (err)
		return err;

	return got_privsep_recv_raw_obj(outbuf, size, hdrlen, flags, ibuf);
}

static const struct got_error *
start_child(struct got_repository *repo, int type)
{
	const struct got_error *err = NULL;
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;
	const char *prog_path;

	switch (type) {
	case GOT_REPO_PRIVSEP_CHILD_OBJECT:
		prog_path = GOT_PATH_PROG_READ_OBJECT;
		break;
	case GOT_REPO_PRIVSEP_CHILD_TREE:
		prog_path = GOT_PATH_PROG_READ_TREE;
		break;
	case GOT_REPO_PRIVSEP_CHILD_COMMIT:
		prog_path = GOT_PATH_PROG_READ_COMMIT;
		break;
	case GOT_REPO_PRIVSEP_CHILD_BLOB:
		prog_path = GOT_PATH_PROG_READ_BLOB;
		break;
	case GOT_REPO_PRIVSEP_CHILD_TAG:
		prog_path = GOT_PATH_PROG_READ_TAG;
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno("calloc");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno("socketpair");
		free(ibuf);
		return err;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		close(imsg_fds[0]);
		close(imsg_fds[1]);
		free(ibuf);
		return err;
	}
	else if (pid == 0) {
		got_privsep_exec_child(imsg_fds, prog_path, repo->path);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		close(imsg_fds[0]);
		free(ibuf);
		return err;
	}

	repo->privsep_children[type].imsg_fd = imsg_fds[0];
	repo->privsep_children[type].pid = pid;
	if (imsgbuf_init(ibuf, imsg_fds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		close(imsg_fds[0]);
		free(ibuf);
		return err;
	}
	imsgbuf_allow_fdpass(ibuf);

	repo->privsep_children[type].ibuf = ibuf;

	return NULL;
}

const struct got_error *
got_object_read_header_privsep(struct got_object **obj,
    struct got_object_id *id, struct got_repository *repo, int obj_fd)
{
	const struct got_error *err;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].imsg_fd != -1)
		return request_object(obj, id, repo, obj_fd);

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_OBJECT);
	if (err)
		return err;

	return request_object(obj, id, repo, obj_fd);
}

static const struct got_error *
read_object_raw_privsep(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    int *flags, int outfd, struct got_object_id *id,
    struct got_repository *repo, int obj_fd)
{
	const struct got_error *err;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].imsg_fd != -1)
		return request_raw_object(outbuf, size, hdrlen, flags,
		    outfd, id, repo, obj_fd);

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_OBJECT);
	if (err)
		return err;

	return request_raw_object(outbuf, size, hdrlen, flags,
	    outfd, id, repo, obj_fd);
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	int fd;

	*obj = got_repo_get_cached_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	err = got_object_open_packed(obj, id, repo);
	if (err && err->code != GOT_ERR_NO_OBJ)
		return err;
	if (*obj) {
		(*obj)->refcnt++;
		return got_repo_cache_object(repo, id, *obj);
	}

	err = got_object_open_loose_fd(&fd, id, repo);
	if (err)
		return err;

	err = got_object_read_header_privsep(obj, id, repo, fd);
	if (err)
		return err;

	memcpy(&(*obj)->id, id, sizeof(*id));

	(*obj)->refcnt++;
	return got_repo_cache_object(repo, id, *obj);
}

/* *outfd must be initialized to -1 by caller */
const struct got_error *
got_object_raw_open(struct got_raw_object **obj, int *outfd,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	uint8_t *outbuf = NULL;
	off_t size = 0;
	size_t hdrlen = 0;
	char *path_packfile = NULL;
	int flags = 0;

	*obj = got_repo_get_cached_raw_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	if (*outfd == -1) {
		*outfd = got_opentempfd();
		if (*outfd == -1)
			return got_error_from_errno("got_opentempfd");
	}

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			goto done;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = read_packed_object_raw_privsep(&outbuf, &size, &hdrlen,
		    &flags, *outfd, pack, packidx, idx, id);
		if (err)
			goto done;
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			goto done;
		err = read_object_raw_privsep(&outbuf, &size, &hdrlen, &flags,
		    *outfd, id, repo, fd);
		if (err)
			goto done;
	}

	err = got_object_raw_alloc(obj, outbuf, outfd,
	    GOT_DELTA_RESULT_SIZE_CACHED_MAX, hdrlen, size);
	if (err)
		goto done;

	(*obj)->flags = flags;

	err = got_repo_cache_raw_object(repo, id, *obj);
done:
	free(path_packfile);
	if (err) {
		if (*obj) {
			got_object_raw_close(*obj);
			*obj = NULL;
		}
		free(outbuf);
	}
	return err;
}

static const struct got_error *
request_packed_commit(struct got_commit_object **commit, struct got_pack *pack,
    int pack_idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	err = got_privsep_send_commit_req(pack->privsep_child->ibuf, -1, id,
	    pack_idx);
	if (err)
		return err;

	err = got_privsep_recv_commit(commit, pack->privsep_child->ibuf);
	if (err)
		return err;

	(*commit)->flags |= GOT_COMMIT_FLAG_PACKED;
	return NULL;
}

static const struct got_error *
read_packed_commit_privsep(struct got_commit_object **commit,
    struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child)
		return request_packed_commit(commit, pack, idx, id);

	err = got_pack_start_privsep_child(pack, packidx);
	if (err)
		return err;

	return request_packed_commit(commit, pack, idx, id);
}

static const struct got_error *
request_commit(struct got_commit_object **commit, struct got_repository *repo,
    int fd, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].ibuf;

	err = got_privsep_send_commit_req(ibuf, fd, id, -1);
	if (err)
		return err;

	return got_privsep_recv_commit(commit, ibuf);
}

static const struct got_error *
read_commit_privsep(struct got_commit_object **commit, int obj_fd,
    struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].imsg_fd != -1)
		return request_commit(commit, repo, obj_fd, id);

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_COMMIT);
	if (err)
		return err;

	return request_commit(commit, repo, obj_fd, id);
}

static const struct got_error *
open_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;

	if (check_cache) {
		*commit = got_repo_get_cached_commit(repo, id);
		if (*commit != NULL) {
			(*commit)->refcnt++;
			return NULL;
		}
	} else
		*commit = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = read_packed_commit_privsep(commit, pack,
		    packidx, idx, id);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = read_commit_privsep(commit, fd, id, repo);
	}

	if (err == NULL) {
		(*commit)->refcnt++;
		err = got_repo_cache_commit(repo, id, *commit);
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_as_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id)
{
	*commit = got_repo_get_cached_commit(repo, id);
	if (*commit != NULL) {
		(*commit)->refcnt++;
		return NULL;
	}

	return open_commit(commit, repo, id, 0);
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	return open_commit(commit, repo, got_object_get_id(obj), 1);
}

static const struct got_error *
request_packed_tree(struct got_tree_object **tree, struct got_pack *pack,
    int pack_idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	err = got_privsep_send_tree_req(pack->privsep_child->ibuf, -1, id,
	    pack_idx);
	if (err)
		return err;

	return got_privsep_recv_tree(tree, pack->privsep_child->ibuf);
}

static const struct got_error *
read_packed_tree_privsep(struct got_tree_object **tree,
    struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child)
		return request_packed_tree(tree, pack, idx, id);

	err = got_pack_start_privsep_child(pack, packidx);
	if (err)
		return err;

	return request_packed_tree(tree, pack, idx, id);
}

static const struct got_error *
request_tree(struct got_tree_object **tree, struct got_repository *repo,
    int fd, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].ibuf;

	err = got_privsep_send_tree_req(ibuf, fd, id, -1);
	if (err)
		return err;

	return got_privsep_recv_tree(tree, ibuf);
}

static const struct got_error *
read_tree_privsep(struct got_tree_object **tree, int obj_fd,
    struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].imsg_fd != -1)
		return request_tree(tree, repo, obj_fd, id);

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_TREE);
	if (err)
		return err;

	return request_tree(tree, repo, obj_fd, id);
}

static const struct got_error *
open_tree(struct got_tree_object **tree, struct got_repository *repo,
    struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;

	if (check_cache) {
		*tree = got_repo_get_cached_tree(repo, id);
		if (*tree != NULL) {
			(*tree)->refcnt++;
			return NULL;
		}
	} else
		*tree = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = read_packed_tree_privsep(tree, pack,
		    packidx, idx, id);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = read_tree_privsep(tree, fd, id, repo);
	}

	if (err == NULL) {
		(*tree)->refcnt++;
		err = got_repo_cache_tree(repo, id, *tree);
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_as_tree(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object_id *id)
{
	*tree = got_repo_get_cached_tree(repo, id);
	if (*tree != NULL) {
		(*tree)->refcnt++;
		return NULL;
	}

	return open_tree(tree, repo, id, 0);
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	return open_tree(tree, repo, got_object_get_id(obj), 1);
}

static const struct got_error *
request_packed_blob(uint8_t **outbuf, size_t *size, size_t *hdrlen, int outfd,
    struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf = pack->privsep_child->ibuf;
	int outfd_child;

	err = pack_child_send_tempfiles(ibuf, pack);
	if (err)
		return err;

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno("dup");

	err = got_privsep_send_blob_req(pack->privsep_child->ibuf, -1, id, idx);
	if (err)
		return err;

	err = got_privsep_send_blob_outfd(pack->privsep_child->ibuf,
	    outfd_child);
	if (err) {
		return err;
	}

	err = got_privsep_recv_blob(outbuf, size, hdrlen,
	    pack->privsep_child->ibuf);
	if (err)
		return err;

	if (lseek(outfd, 0L, SEEK_SET) == -1)
		err = got_error_from_errno("lseek");

	return err;
}

static const struct got_error *
read_packed_blob_privsep(uint8_t **outbuf, size_t *size, size_t *hdrlen,
    int outfd, struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			return err;
	}

	return request_packed_blob(outbuf, size, hdrlen, outfd, pack, packidx,
	    idx, id);
}

static const struct got_error *
request_blob(uint8_t **outbuf, size_t *size, size_t *hdrlen, int outfd,
    int infd, struct got_object_id *id, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	int outfd_child;

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno("dup");

	err = got_privsep_send_blob_req(ibuf, infd, id, -1);
	if (err)
		return err;

	err = got_privsep_send_blob_outfd(ibuf, outfd_child);
	if (err)
		return err;

	err = got_privsep_recv_blob(outbuf, size, hdrlen, ibuf);
	if (err)
		return err;

	if (lseek(outfd, 0L, SEEK_SET) == -1)
		return got_error_from_errno("lseek");

	return err;
}

static const struct got_error *
read_blob_privsep(uint8_t **outbuf, size_t *size, size_t *hdrlen,
    int outfd, int infd, struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err;
	struct imsgbuf *ibuf;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].imsg_fd != -1) {
		ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].ibuf;
		return request_blob(outbuf, size, hdrlen, outfd, infd, id,
		    ibuf);
	}

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_BLOB);
	if (err)
		return err;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].ibuf;
	return request_blob(outbuf, size, hdrlen, outfd, infd, id, ibuf);
}

static const struct got_error *
open_blob(struct got_blob_object **blob, struct got_repository *repo,
    struct got_object_id *id, size_t blocksize, int outfd)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx, dfd = -1;
	char *path_packfile = NULL;
	uint8_t *outbuf;
	size_t size, hdrlen;
	struct stat sb;

	*blob = calloc(1, sizeof(**blob));
	if (*blob == NULL)
		return got_error_from_errno("calloc");

	(*blob)->read_buf = malloc(blocksize);
	if ((*blob)->read_buf == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}

	err = got_opentemp_truncatefd(outfd);
	if (err)
		goto done;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			goto done;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = read_packed_blob_privsep(&outbuf, &size, &hdrlen, outfd,
		    pack, packidx, idx, id);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int infd;

		err = got_object_open_loose_fd(&infd, id, repo);
		if (err)
			goto done;
		err = read_blob_privsep(&outbuf, &size, &hdrlen, outfd, infd,
		    id, repo);
	}
	if (err)
		goto done;

	if (hdrlen > size) {
		err = got_error(GOT_ERR_BAD_OBJ_HDR);
		goto done;
	}

	if (outbuf && size > 0) {
		(*blob)->f = fmemopen(outbuf, size, "rb");
		if ((*blob)->f == NULL) {
			err = got_error_from_errno("fmemopen");
			free(outbuf);
			goto done;
		}
		(*blob)->data = outbuf;
	} else {
		if (fstat(outfd, &sb) == -1) {
			err = got_error_from_errno("fstat");
			goto done;
		}

		if (sb.st_size != size) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		dfd = dup(outfd);
		if (dfd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}

		(*blob)->f = fdopen(dfd, "rb");
		if ((*blob)->f == NULL) {
			err = got_error_from_errno("fdopen");
			close(dfd);
			dfd = -1;
			goto done;
		}
	}

	(*blob)->hdrlen = hdrlen;
	(*blob)->blocksize = blocksize;
	memcpy(&(*blob)->id, id, sizeof(*id));

done:
	free(path_packfile);
	if (err) {
		if (*blob) {
			got_object_blob_close(*blob);
			*blob = NULL;
		}
	}
	return err;
}

const struct got_error *
got_object_open_as_blob(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object_id *id, size_t blocksize,
    int outfd)
{
	return open_blob(blob, repo, id, blocksize, outfd);
}

const struct got_error *
got_object_blob_open(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object *obj, size_t blocksize,
    int outfd)
{
	return open_blob(blob, repo, got_object_get_id(obj), blocksize, outfd);
}

static const struct got_error *
request_packed_tag(struct got_tag_object **tag, struct got_pack *pack,
    int pack_idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	err = got_privsep_send_tag_req(pack->privsep_child->ibuf, -1, id,
	    pack_idx);
	if (err)
		return err;

	return got_privsep_recv_tag(tag, pack->privsep_child->ibuf);
}

static const struct got_error *
read_packed_tag_privsep(struct got_tag_object **tag,
    struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (pack->privsep_child)
		return request_packed_tag(tag, pack, idx, id);

	err = got_pack_start_privsep_child(pack, packidx);
	if (err)
		return err;

	return request_packed_tag(tag, pack, idx, id);
}

static const struct got_error *
request_tag(struct got_tag_object **tag, struct got_repository *repo,
    int fd, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TAG].ibuf;

	err = got_privsep_send_tag_req(ibuf, fd, id, -1);
	if (err)
		return err;

	return got_privsep_recv_tag(tag, ibuf);
}

static const struct got_error *
read_tag_privsep(struct got_tag_object **tag, int obj_fd,
    struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TAG].imsg_fd != -1)
		return request_tag(tag, repo, obj_fd, id);

	err = start_child(repo, GOT_REPO_PRIVSEP_CHILD_TAG);
	if (err)
		return err;

	return request_tag(tag, repo, obj_fd, id);
}

static const struct got_error *
open_tag(struct got_tag_object **tag, struct got_repository *repo,
    struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;
	struct got_object *obj = NULL;
	int obj_type = GOT_OBJ_TYPE_ANY;

	if (check_cache) {
		*tag = got_repo_get_cached_tag(repo, id);
		if (*tag != NULL) {
			(*tag)->refcnt++;
			return NULL;
		}
	} else
		*tag = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}

		/* Beware of "lightweight" tags: Check object type first. */
		err = read_packed_object_privsep(&obj, repo, pack, packidx,
		    idx, id);
		if (err)
			goto done;
		obj_type = obj->type;
		got_object_close(obj);
		if (obj_type != GOT_OBJ_TYPE_TAG) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}
		err = read_packed_tag_privsep(tag, pack, packidx, idx, id);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = got_object_read_header_privsep(&obj, id, repo, fd);
		if (err)
			return err;
		obj_type = obj->type;
		got_object_close(obj);
		if (obj_type != GOT_OBJ_TYPE_TAG)
			return got_error(GOT_ERR_OBJ_TYPE);

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = read_tag_privsep(tag, fd, id, repo);
	}

	if (err == NULL) {
		(*tag)->refcnt++;
		err = got_repo_cache_tag(repo, id, *tag);
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_as_tag(struct got_tag_object **tag,
    struct got_repository *repo, struct got_object_id *id)
{
	*tag = got_repo_get_cached_tag(repo, id);
	if (*tag != NULL) {
		(*tag)->refcnt++;
		return NULL;
	}

	return open_tag(tag, repo, id, 0);
}

const struct got_error *
got_object_tag_open(struct got_tag_object **tag,
    struct got_repository *repo, struct got_object *obj)
{
	return open_tag(tag, repo, got_object_get_id(obj), 1);
}

const struct got_error *
got_traverse_packed_commits(struct got_object_id_queue *traversed_commits,
    struct got_object_id *commit_id, const char *path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	struct got_packidx *packidx = NULL;
	char *path_packfile = NULL;
	struct got_commit_object *changed_commit = NULL;
	struct got_object_qid *changed_commit_qid = NULL;
	int idx;

	err = got_repo_search_packidx(&packidx, &idx, repo, commit_id);
	if (err) {
		if (err->code != GOT_ERR_NO_OBJ)
			return err;
		return NULL;
	}

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			goto done;
	}

	err = got_privsep_send_commit_traversal_request(
	    pack->privsep_child->ibuf, commit_id, idx, path);
	if (err)
		goto done;

	err = got_privsep_recv_traversed_commits(&changed_commit,
	    traversed_commits, pack->privsep_child->ibuf);
	if (err)
		goto done;

	if (changed_commit) {
		/*
		 * Cache the commit in which the path was changed.
		 * This commit might be opened again soon.
		 */
		changed_commit->refcnt++;
		changed_commit_qid = STAILQ_LAST(traversed_commits, got_object_qid, entry);
		err = got_repo_cache_commit(repo, &changed_commit_qid->id,
		    changed_commit);
		got_object_commit_close(changed_commit);
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_enumerate(int *found_all_objects,
    got_object_enumerate_commit_cb cb_commit,
    got_object_enumerate_tree_cb cb_tree, void *cb_arg,
    struct got_object_id **ours, int nours,
    struct got_object_id **theirs, int ntheirs,
    struct got_packidx *packidx, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack;
	char *path_packfile = NULL;

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	if (pack->privsep_child == NULL) {
		err = got_pack_start_privsep_child(pack, packidx);
		if (err)
			goto done;
	}

	err = got_privsep_send_object_enumeration_request(
	    pack->privsep_child->ibuf);
	if (err)
		goto done;

	err = got_privsep_send_object_idlist(pack->privsep_child->ibuf,
	    ours, nours);
	if (err)
		goto done;
	err = got_privsep_send_object_idlist_done(pack->privsep_child->ibuf);
	if (err)
		goto done;

	err = got_privsep_send_object_idlist(pack->privsep_child->ibuf,
	    theirs, ntheirs);
	if (err)
		goto done;
	err = got_privsep_send_object_idlist_done(pack->privsep_child->ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_enumerated_objects(found_all_objects,
	    pack->privsep_child->ibuf, cb_commit, cb_tree, cb_arg, repo);
done:
	free(path_packfile);
	return err;
}
