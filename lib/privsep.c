/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2020 Ori Bernstein <ori@openbsd.org>
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
#include <sys/wait.h>

#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <poll.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
#include <unistd.h>
#include <zlib.h>

#include "got_object.h"
#include "got_error.h"
#include "got_path.h"
#include "got_repository.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_qid.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_poll.h"

#include "got_privsep.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
read_imsg(struct imsgbuf *ibuf)
{
	const struct got_error *err;
	size_t n;

	err = got_poll_fd(ibuf->fd, POLLIN, INFTIM);
	if (err) {
		if (err->code == GOT_ERR_EOF)
			return got_error(GOT_ERR_PRIVSEP_PIPE);
		return err;
	}

	n = imsgbuf_read(ibuf);
	if (n == -1)
		return got_error(GOT_ERR_PRIVSEP_READ);
	if (n == 0)
		return got_error(GOT_ERR_PRIVSEP_PIPE);

	return NULL;
}

const struct got_error *
got_privsep_wait_for_child(pid_t pid)
{
	int child_status;

	if (waitpid(pid, &child_status, 0) == -1)
		return got_error_from_errno("waitpid");

	if (!WIFEXITED(child_status))
		return got_error(GOT_ERR_PRIVSEP_DIED);

	if (WEXITSTATUS(child_status) != 0)
		return got_error(GOT_ERR_PRIVSEP_EXIT);

	return NULL;
}

static const struct got_error *
recv_imsg_error(struct imsg *imsg, size_t datalen)
{
	struct got_imsg_error *ierr;

	if (datalen != sizeof(*ierr))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	ierr = imsg->data;
	if (ierr->code == GOT_ERR_ERRNO) {
		static struct got_error serr;
		serr.code = GOT_ERR_ERRNO;
		serr.msg = strerror(ierr->errno_code);
		return &serr;
	}

	return got_error(ierr->code);
}

const struct got_error *
got_privsep_recv_imsg(struct imsg *imsg, struct imsgbuf *ibuf,
    size_t min_datalen)
{
	const struct got_error *err;
	ssize_t n;

	n = imsg_get(ibuf, imsg);
	if (n == -1)
		return got_error_from_errno("imsg_get");

	while (n == 0) {
		err = read_imsg(ibuf);
		if (err)
			return err;
		n = imsg_get(ibuf, imsg);
		if (n == -1)
			return got_error_from_errno("imsg_get");
	}

	if (imsg->hdr.type == GOT_IMSG_ERROR) {
		size_t datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
		err = recv_imsg_error(imsg, datalen);
		imsg_free(imsg);
		return err;
	}

	if (imsg->hdr.len < IMSG_HEADER_SIZE + min_datalen) {
		imsg_free(imsg);
		return got_error(GOT_ERR_PRIVSEP_LEN);
	}

	return NULL;
}

/* Attempt to send an error in an imsg. Complain on stderr as a last resort. */
void
got_privsep_send_error(struct imsgbuf *ibuf, const struct got_error *err)
{
	const struct got_error *poll_err;
	struct got_imsg_error ierr;
	int ret;

	ierr.code = err->code;
	if (err->code == GOT_ERR_ERRNO)
		ierr.errno_code = errno;
	else
		ierr.errno_code = 0;
	ret = imsg_compose(ibuf, GOT_IMSG_ERROR, 0, 0, -1, &ierr, sizeof(ierr));
	if (ret == -1) {
		fprintf(stderr, "%s: error %d \"%s\": imsg_compose: %s\n",
		    getprogname(), err->code, err->msg, strerror(errno));
		return;
	}

	poll_err = got_poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (poll_err) {
		if (poll_err->code != GOT_ERR_EOF)
			fprintf(stderr, "%s: error %d \"%s\": poll: %s\n",
			    getprogname(), err->code, err->msg, poll_err->msg);
		return;
	}

	ret = imsgbuf_flush(ibuf);
	if (ret == -1) {
		fprintf(stderr, "%s: error %d \"%s\": imsgbuf_flush: %s\n",
		    getprogname(), err->code, err->msg, strerror(errno));
		return;
	}
}

static const struct got_error *
flush_imsg(struct imsgbuf *ibuf)
{
	const struct got_error *err;

	err = got_poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (err)
		return err;

	if (imsgbuf_flush(ibuf) == -1)
		return got_error_from_errno("imsgbuf_flush");

	return NULL;
}

const struct got_error *
got_privsep_flush_imsg(struct imsgbuf *ibuf)
{
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_stop(int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;

	if (imsgbuf_init(&ibuf, fd) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOT_IMSG_STOP, 0, 0, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose STOP");
		goto done;
	}

	err = flush_imsg(&ibuf);
 done:
	imsgbuf_clear(&ibuf);
	return err;
}

const struct got_error *
got_privsep_send_obj_req(struct imsgbuf *ibuf, int fd,
    struct got_object_id *id)
{
	if (imsg_compose(ibuf, GOT_IMSG_OBJECT_REQUEST, 0, 0, fd,
	    id, sizeof(*id)) == -1)
		return got_error_from_errno("imsg_compose OBJECT_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_raw_obj_req(struct imsgbuf *ibuf, int fd,
    struct got_object_id *id)
{
	const struct got_error *err;

	if (imsg_compose(ibuf, GOT_IMSG_RAW_OBJECT_REQUEST, 0, 0, fd,
	    id, sizeof(*id)) == -1) {
		err = got_error_from_errno("imsg_compose RAW_OBJECT_REQUEST");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_raw_obj_outfd(struct imsgbuf *ibuf, int outfd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, GOT_IMSG_RAW_OBJECT_OUTFD, 0, 0, outfd, NULL, 0)
	    == -1) {
		err = got_error_from_errno("imsg_compose RAW_OBJECT_OUTFD");
		close(outfd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_raw_obj(struct imsgbuf *ibuf, off_t size, size_t hdrlen,
    uint8_t *data)
{
	struct got_imsg_raw_obj iobj;
	size_t len = sizeof(iobj);
	struct ibuf *wbuf;

	memset(&iobj, 0, sizeof(iobj));
	iobj.hdrlen = hdrlen;
	iobj.size = size;

	if (data && size + hdrlen <= GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX)
		len += (size_t)size + hdrlen;

	wbuf = imsg_create(ibuf, GOT_IMSG_RAW_OBJECT, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create RAW_OBJECT");

	if (imsg_add(wbuf, &iobj, sizeof(iobj)) == -1)
		return got_error_from_errno("imsg_add RAW_OBJECT");

	if (data && size + hdrlen <= GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX) {
		if (imsg_add(wbuf, data, size + hdrlen) == -1)
			return got_error_from_errno("imsg_add RAW_OBJECT");
	}

	imsg_close(ibuf, wbuf);
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_raw_obj(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_raw_obj *iobj;
	size_t datalen;

	*outbuf = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_RAW_OBJECT:
		if (datalen < sizeof(*iobj)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		iobj = imsg.data;
		*size = iobj->size;
		*hdrlen = iobj->hdrlen;

		if (datalen == sizeof(*iobj)) {
			/* Data has been written to file descriptor. */
			break;
		}

		if (*size < 0 ||
		    *size + *hdrlen > GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		*outbuf = malloc(*size + *hdrlen);
		if (*outbuf == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		memcpy(*outbuf, imsg.data + sizeof(*iobj), *size + *hdrlen);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_send_commit_req(struct imsgbuf *ibuf, int fd,
    struct got_object_id *id, int pack_idx)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	void *data;
	size_t len;

	memset(&iobj, 0, sizeof(iobj));
	if (pack_idx != -1) { /* commit is packed */
		iobj.idx = pack_idx;
		memcpy(&iobj.id, id, sizeof(iobj.id));
		data = &iobj;
		len = sizeof(iobj);
	} else {
		data = id;
		len = sizeof(*id);
	}

	if (imsg_compose(ibuf, GOT_IMSG_COMMIT_REQUEST, 0, 0, fd, data, len)
	    == -1) {
		err = got_error_from_errno("imsg_compose COMMIT_REQUEST");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_tree_req(struct imsgbuf *ibuf, int fd,
    struct got_object_id *id, int pack_idx)
{
	const struct got_error *err;
	struct ibuf *wbuf;
	size_t len;

	if (pack_idx != -1)
		len = sizeof(struct got_imsg_packed_object);
	else
		len = sizeof(*id);

	wbuf = imsg_create(ibuf, GOT_IMSG_TREE_REQUEST, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create TREE_REQUEST");
		if (fd != -1)
			close(fd);
		return err;
	}

	if (imsg_add(wbuf, id, sizeof(*id)) == -1) {
		err = got_error_from_errno("imsg_add TREE_REQUEST");
		if (fd != -1)
			close(fd);
		return err;
	}

	if (pack_idx != -1) { /* tree is packed */
		if (imsg_add(wbuf, &pack_idx, sizeof(pack_idx)) == -1) {
			err = got_error_from_errno("imsg_add TREE_REQUEST");
			if (fd != -1)
				close(fd);
			return err;
		}
	}

	ibuf_fd_set(wbuf, fd);
	imsg_close(ibuf, wbuf);

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_tag_req(struct imsgbuf *ibuf, int fd,
    struct got_object_id *id, int pack_idx)
{
	const struct got_error *err;
	struct got_imsg_packed_object iobj;
	void *data;
	size_t len;

	memset(&iobj, 0, sizeof(iobj));
	if (pack_idx != -1) { /* tag is packed */
		iobj.idx = pack_idx;
		memcpy(&iobj.id, id, sizeof(iobj.id));
		data = &iobj;
		len = sizeof(iobj);
	} else {
		data = id;
		len = sizeof(*id);
	}

	if (imsg_compose(ibuf, GOT_IMSG_TAG_REQUEST, 0, 0, fd, data, len)
	    == -1) {
		err = got_error_from_errno("imsg_compose TAG_REQUEST");
		if (fd != -1)
			close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_blob_req(struct imsgbuf *ibuf, int infd,
    struct got_object_id *id, int pack_idx)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	void *data;
	size_t len;

	memset(&iobj, 0, sizeof(iobj));
	if (pack_idx != -1) { /* blob is packed */
		iobj.idx = pack_idx;
		memcpy(&iobj.id, id, sizeof(iobj.id));
		data = &iobj;
		len = sizeof(iobj);
	} else {
		data = id;
		len = sizeof(*id);
	}

	if (imsg_compose(ibuf, GOT_IMSG_BLOB_REQUEST, 0, 0, infd, data, len)
	    == -1) {
		err = got_error_from_errno("imsg_compose BLOB_REQUEST");
		close(infd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_blob_outfd(struct imsgbuf *ibuf, int outfd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, GOT_IMSG_BLOB_OUTFD, 0, 0, outfd, NULL, 0)
	    == -1) {
		err = got_error_from_errno("imsg_compose BLOB_OUTFD");
		close(outfd);
		return err;
	}

	return flush_imsg(ibuf);
}

static const struct got_error *
send_fd(struct imsgbuf *ibuf, int imsg_code, int fd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, imsg_code, 0, 0, fd, NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose TMPFD");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_tmpfd(struct imsgbuf *ibuf, int fd)
{
	return send_fd(ibuf, GOT_IMSG_TMPFD, fd);
}

const struct got_error *
got_privsep_send_obj(struct imsgbuf *ibuf, struct got_object *obj)
{
	struct got_imsg_object iobj;

	memset(&iobj, 0, sizeof(iobj));

	memcpy(&iobj.id, &obj->id, sizeof(iobj.id));
	iobj.type = obj->type;
	iobj.flags = obj->flags;
	iobj.hdrlen = obj->hdrlen;
	iobj.size = obj->size;
	if (iobj.flags & GOT_OBJ_FLAG_PACKED) {
		iobj.pack_offset = obj->pack_offset;
		iobj.pack_idx = obj->pack_idx;
	}

	if (imsg_compose(ibuf, GOT_IMSG_OBJECT, 0, 0, -1, &iobj, sizeof(iobj))
	    == -1)
		return got_error_from_errno("imsg_compose OBJECT");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_fetch_req(struct imsgbuf *ibuf, int fd,
    struct got_pathlist_head *have_refs, int fetch_all_branches,
    struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, int list_refs_only,
    const char *worktree_branch, const char *remote_head,
    int no_head, int verbosity)
{
	const struct got_error *err = NULL;
	struct ibuf *wbuf;
	struct got_pathlist_entry *pe;
	struct got_imsg_fetch_request fetchreq;
	size_t remote_head_len, worktree_branch_len, len = sizeof(fetchreq);

	if (worktree_branch) {
		worktree_branch_len = strlen(worktree_branch);
		len += worktree_branch_len;
	}
	if (remote_head) {
		remote_head_len = strlen(remote_head);
		len += remote_head_len;
	}

	if (len >= MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		close(fd);
		return got_error(GOT_ERR_NO_SPACE);
	}

	wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_REQUEST, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create FETCH_HAVE_REF");
		close(fd);
		return err;
	}

	memset(&fetchreq, 0, sizeof(fetchreq));
	fetchreq.no_head = no_head;
	fetchreq.fetch_all_branches = fetch_all_branches;
	fetchreq.list_refs_only = list_refs_only;
	fetchreq.verbosity = verbosity;
	if (worktree_branch != NULL)
		fetchreq.worktree_branch_len = worktree_branch_len;
	if (remote_head != NULL)
		fetchreq.remote_head_len = remote_head_len;
	RB_FOREACH(pe, got_pathlist_head, have_refs)
		fetchreq.n_have_refs++;
	RB_FOREACH(pe, got_pathlist_head, wanted_branches)
		fetchreq.n_wanted_branches++;
	RB_FOREACH(pe, got_pathlist_head, wanted_refs)
		fetchreq.n_wanted_refs++;
	if (imsg_add(wbuf, &fetchreq, sizeof(fetchreq)) == -1)
		return got_error_from_errno("imsg_add FETCH_REQUEST");
	if (worktree_branch) {
		if (imsg_add(wbuf, worktree_branch, worktree_branch_len)
		    == -1) {
			err = got_error_from_errno("imsg_add FETCH_REQUEST");
			close(fd);
			return err;
		}
	}
	if (remote_head) {
		if (imsg_add(wbuf, remote_head, remote_head_len) == -1) {
			err = got_error_from_errno("imsg_add FETCH_REQUEST");
			close(fd);
			return err;
		}
	}
	ibuf_fd_set(wbuf, fd);
	fd = -1;
	imsg_close(ibuf, wbuf);

	err = flush_imsg(ibuf);
	if (err)
		return err;

	RB_FOREACH(pe, got_pathlist_head, have_refs) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;
		struct got_object_id *id = pe->data;

		len = sizeof(struct got_imsg_fetch_have_ref) + name_len;
		wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_HAVE_REF, 0, 0, len);
		if (wbuf == NULL)
			return got_error_from_errno("imsg_create FETCH_HAVE_REF");

		/* Keep in sync with struct got_imsg_fetch_have_ref! */
		if (imsg_add(wbuf, id, sizeof(*id)) == -1)
			return got_error_from_errno("imsg_add FETCH_HAVE_REF");
		if (imsg_add(wbuf, &name_len, sizeof(name_len)) == -1)
			return got_error_from_errno("imsg_add FETCH_HAVE_REF");
		if (imsg_add(wbuf, name, name_len) == -1)
			return got_error_from_errno("imsg_add FETCH_HAVE_REF");

		imsg_close(ibuf, wbuf);
		err = flush_imsg(ibuf);
		if (err)
			return err;
	}

	RB_FOREACH(pe, got_pathlist_head, wanted_branches) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;

		len = sizeof(struct got_imsg_fetch_wanted_branch) + name_len;
		wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_WANTED_BRANCH, 0, 0,
		    len);
		if (wbuf == NULL)
			return got_error_from_errno(
			    "imsg_create FETCH_WANTED_BRANCH");

		/* Keep in sync with struct got_imsg_fetch_wanted_branch! */
		if (imsg_add(wbuf, &name_len, sizeof(name_len)) == -1)
			return got_error_from_errno(
			    "imsg_add FETCH_WANTED_BRANCH");
		if (imsg_add(wbuf, name, name_len) == -1)
			return got_error_from_errno(
			    "imsg_add FETCH_WANTED_BRANCH");

		imsg_close(ibuf, wbuf);
		err = flush_imsg(ibuf);
		if (err)
			return err;
	}

	RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;

		len = sizeof(struct got_imsg_fetch_wanted_ref) + name_len;
		wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_WANTED_REF, 0, 0,
		    len);
		if (wbuf == NULL)
			return got_error_from_errno(
			    "imsg_create FETCH_WANTED_REF");

		/* Keep in sync with struct got_imsg_fetch_wanted_ref! */
		if (imsg_add(wbuf, &name_len, sizeof(name_len)) == -1)
			return got_error_from_errno(
			    "imsg_add FETCH_WANTED_REF");
		if (imsg_add(wbuf, name, name_len) == -1)
			return got_error_from_errno(
			    "imsg_add FETCH_WANTED_REF");

		imsg_close(ibuf, wbuf);
		err = flush_imsg(ibuf);
		if (err)
			return err;
	}

	return NULL;
}

const struct got_error *
got_privsep_send_fetch_outfd(struct imsgbuf *ibuf, int fd)
{
	return send_fd(ibuf, GOT_IMSG_FETCH_OUTFD, fd);
}

const struct got_error *
got_privsep_recv_fetch_progress(int *done, struct got_object_id **id,
    char **refname, struct got_pathlist_head *symrefs, char **server_progress,
    off_t *packfile_size, uint8_t *pack_sha1, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct got_imsg_fetch_symrefs *isymrefs = NULL;
	size_t n, remain;
	struct got_pathlist_entry *new;
	off_t off;
	int i;

	*done = 0;
	*id = NULL;
	*refname = NULL;
	*server_progress = NULL;
	*packfile_size = 0;
	memset(pack_sha1, 0, SHA1_DIGEST_LENGTH);

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_FETCH_SYMREFS:
		if (datalen < sizeof(*isymrefs)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		if (isymrefs != NULL) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		isymrefs = (struct got_imsg_fetch_symrefs *)imsg.data;
		off = sizeof(*isymrefs);
		remain = datalen - off;
		for (n = 0; n < isymrefs->nsymrefs; n++) {
			struct got_imsg_fetch_symref *s;
			char *name, *target;
			if (remain < sizeof(struct got_imsg_fetch_symref)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			s = (struct got_imsg_fetch_symref *)(imsg.data + off);
			off += sizeof(*s);
			remain -= sizeof(*s);
			if (remain < s->name_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			name = strndup(imsg.data + off, s->name_len);
			if (name == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			off += s->name_len;
			remain -= s->name_len;
			if (remain < s->target_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				free(name);
				goto done;
			}
			target = strndup(imsg.data + off, s->target_len);
			if (target == NULL) {
				err = got_error_from_errno("strndup");
				free(name);
				goto done;
			}
			off += s->target_len;
			remain -= s->target_len;
			err = got_pathlist_insert(&new, symrefs, name, target);
			if (err || new == NULL) {
				free(name);
				free(target);
				if (err->code != GOT_ERR_REF_DUP_ENTRY)
					goto done;
			}
		}
		break;
	case GOT_IMSG_FETCH_REF:
		if (datalen <= sizeof(**id)) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		*id = malloc(sizeof(**id));
		if (*id == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		memcpy(*id, imsg.data, sizeof(**id));
		*refname = strndup(imsg.data + sizeof(**id),
		    datalen - sizeof(**id));
		if (*refname == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		break;
	case GOT_IMSG_FETCH_SERVER_PROGRESS:
		if (datalen == 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		*server_progress = strndup(imsg.data, datalen);
		if (*server_progress == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		for (i = 0; i < datalen; i++) {
			if (!isprint((unsigned char)(*server_progress)[i]) &&
			    !isspace((unsigned char)(*server_progress)[i])) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				free(*server_progress);
				*server_progress = NULL;
				goto done;
			}
		}
		break;
	case GOT_IMSG_FETCH_DOWNLOAD_PROGRESS:
		if (datalen < sizeof(*packfile_size)) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		memcpy(packfile_size, imsg.data, sizeof(*packfile_size));
		break;
	case GOT_IMSG_FETCH_DONE:
		if (datalen != SHA1_DIGEST_LENGTH) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		memcpy(pack_sha1, imsg.data, SHA1_DIGEST_LENGTH);
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}
done:
	if (err) {
		free(*id);
		*id = NULL;
		free(*refname);
		*refname = NULL;
	}
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
send_send_ref(const char *name, size_t name_len, struct got_object_id *id,
    int delete, struct imsgbuf *ibuf)
{
	size_t len;
	struct ibuf *wbuf;

	len = sizeof(struct got_imsg_send_ref) + name_len;
	wbuf = imsg_create(ibuf, GOT_IMSG_SEND_REF, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SEND_REF");

	/* Keep in sync with struct got_imsg_send_ref! */
	if (imsg_add(wbuf, id, sizeof(*id)) == -1)
		return got_error_from_errno("imsg_add SEND_REF");
	if (imsg_add(wbuf, &delete, sizeof(delete)) == -1)
		return got_error_from_errno("imsg_add SEND_REF");
	if (imsg_add(wbuf, &name_len, sizeof(name_len)) == -1)
		return got_error_from_errno("imsg_add SEND_REF");
	if (imsg_add(wbuf, name, name_len) == -1)
		return got_error_from_errno("imsg_add SEND_REF");

	imsg_close(ibuf, wbuf);
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_send_req(struct imsgbuf *ibuf, int fd,
    struct got_pathlist_head *have_refs,
    struct got_pathlist_head *delete_refs,
    int verbosity)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	struct got_imsg_send_request sendreq;
	struct got_object_id zero_id;

	memset(&zero_id, 0, sizeof(zero_id));
	memset(&sendreq, 0, sizeof(sendreq));
	sendreq.verbosity = verbosity;
	RB_FOREACH(pe, got_pathlist_head, have_refs)
		sendreq.nrefs++;
	RB_FOREACH(pe, got_pathlist_head, delete_refs)
		sendreq.nrefs++;
	if (imsg_compose(ibuf, GOT_IMSG_SEND_REQUEST, 0, 0, fd,
	    &sendreq, sizeof(sendreq)) == -1) {
		err = got_error_from_errno(
		    "imsg_compose FETCH_SERVER_PROGRESS");
		goto done;
	}

	fd = -1;
	err = flush_imsg(ibuf);
	if (err)
		goto done;

	RB_FOREACH(pe, got_pathlist_head ,have_refs) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;
		struct got_object_id *id = pe->data;
		err = send_send_ref(name, name_len, id, 0, ibuf);
		if (err)
			goto done;
	}

	RB_FOREACH(pe, got_pathlist_head, delete_refs) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;
		err = send_send_ref(name, name_len, &zero_id, 1, ibuf);
		if (err)
			goto done;
	}
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

const struct got_error *
got_privsep_recv_send_remote_refs(struct got_pathlist_head *remote_refs,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct got_imsg_send_remote_ref iremote_ref;
	struct got_object_id *id = NULL;
	char *refname = NULL;
	struct got_pathlist_entry *new;

	while (1) {
		err = got_privsep_recv_imsg(&imsg, ibuf, 0);
		if (err)
			return err;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOT_IMSG_SEND_REMOTE_REF:
			if (datalen < sizeof(iremote_ref)) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			memcpy(&iremote_ref, imsg.data, sizeof(iremote_ref));
			if (datalen != sizeof(iremote_ref) +
			    iremote_ref.name_len) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			id = malloc(sizeof(*id));
			if (id == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}
			memcpy(id, &iremote_ref.id, sizeof(*id));
			refname = strndup(imsg.data + sizeof(iremote_ref),
			    datalen - sizeof(iremote_ref));
			if (refname == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			err = got_pathlist_insert(&new, remote_refs,
			    refname, id);
			if (err)
				goto done;
			if (new == NULL) { /* duplicate which wasn't inserted */
				free(id);
				free(refname);
			}
			id = NULL;
			refname = NULL;
			imsg_free(&imsg);
			break;
		case GOT_IMSG_SEND_PACK_REQUEST:
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			/* got-send-pack is now waiting for a pack file. */
			goto done;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
	}
done:
	free(id);
	free(refname);
	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_send_packfd(struct imsgbuf *ibuf, int fd)
{
	return send_fd(ibuf, GOT_IMSG_SEND_PACKFD, fd);
}

const struct got_error *
got_privsep_recv_send_progress(int *done, off_t *bytes_sent,
    int *success, char **refname, char **errmsg, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct got_imsg_send_ref_status iref_status;

	/* Do not reset the current value of 'bytes_sent', it accumulates. */
	*done = 0;
	*success = 0;
	*refname = NULL;
	*errmsg = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_SEND_UPLOAD_PROGRESS:
		if (datalen < sizeof(*bytes_sent)) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		memcpy(bytes_sent, imsg.data, sizeof(*bytes_sent));
		break;
	case GOT_IMSG_SEND_REF_STATUS:
		if (datalen < sizeof(iref_status)) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		memcpy(&iref_status, imsg.data, sizeof(iref_status));
		if (datalen != sizeof(iref_status) + iref_status.name_len +
		    iref_status.errmsg_len) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		*success = iref_status.success;
		*refname = strndup(imsg.data + sizeof(iref_status),
		    iref_status.name_len);

		if (iref_status.errmsg_len != 0)
			*errmsg = strndup(imsg.data + sizeof(iref_status) +
			    iref_status.name_len, iref_status.errmsg_len);
		break;
	case GOT_IMSG_SEND_DONE:
		if (datalen != 0) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_send_index_pack_req(struct imsgbuf *ibuf, struct got_object_id *id,
    int fd)
{
	const struct got_error *err = NULL;

	/* Keep in sync with struct got_imsg_index_pack_request */
	if (imsg_compose(ibuf, GOT_IMSG_IDXPACK_REQUEST, 0, 0, fd,
	    id, sizeof(*id)) == -1) {
		err = got_error_from_errno("imsg_compose INDEX_REQUEST");
		close(fd);
		return err;
	}
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_index_pack_outfd(struct imsgbuf *ibuf, int fd)
{
	return send_fd(ibuf, GOT_IMSG_IDXPACK_OUTFD, fd);
}

const struct got_error *
got_privsep_recv_index_progress(int *done, int *nobj_total,
    int *nobj_indexed, int *nobj_loose, int *nobj_resolved,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_index_pack_progress *iprogress;
	size_t datalen;

	*done = 0;
	*nobj_total = 0;
	*nobj_indexed = 0;
	*nobj_resolved = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_IDXPACK_PROGRESS:
		if (datalen < sizeof(*iprogress)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		iprogress = (struct got_imsg_index_pack_progress *)imsg.data;
		if (iprogress->nobj_total < 0 || iprogress->nobj_indexed < 0 ||
		    iprogress->nobj_loose < 0 || iprogress->nobj_resolved < 0) {
			err = got_error(GOT_ERR_RANGE);
			break;
		}
		*nobj_total = iprogress->nobj_total;
		*nobj_indexed = iprogress->nobj_indexed;
		*nobj_loose = iprogress->nobj_loose;
		*nobj_resolved = iprogress->nobj_resolved;
		break;
	case GOT_IMSG_IDXPACK_DONE:
		if (datalen != 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_get_imsg_obj(struct got_object **obj, struct imsg *imsg,
    struct imsgbuf *ibuf)
{
	struct got_imsg_object *iobj;
	size_t datalen = imsg->hdr.len - IMSG_HEADER_SIZE;

	if (datalen != sizeof(*iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	iobj = imsg->data;

	if (iobj->pack_offset < 0)
		return got_error(GOT_ERR_PACK_OFFSET);

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno("calloc");

	memcpy(&(*obj)->id, &iobj->id, sizeof(iobj->id));
	(*obj)->type = iobj->type;
	(*obj)->flags = iobj->flags;
	(*obj)->hdrlen = iobj->hdrlen;
	(*obj)->size = iobj->size;
	/* path_packfile is handled by caller */
	if (iobj->flags & GOT_OBJ_FLAG_PACKED) {
		(*obj)->pack_offset = iobj->pack_offset;
		(*obj)->pack_idx = iobj->pack_idx;
	}
	STAILQ_INIT(&(*obj)->deltas.entries);
	return NULL;
}

const struct got_error *
got_privsep_recv_obj(struct got_object **obj, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	const size_t min_datalen = sizeof(struct got_imsg_object);

	*obj = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	switch (imsg.hdr.type) {
	case GOT_IMSG_OBJECT:
		err = got_privsep_get_imsg_obj(obj, &imsg, ibuf);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

static const struct got_error *
send_commit_logmsg(struct imsgbuf *ibuf, struct got_commit_object *commit,
    size_t logmsg_len)
{
	const struct got_error *err = NULL;
	size_t offset, remain;

	offset = 0;
	remain = logmsg_len;
	while (remain > 0) {
		size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE, remain);

		if (imsg_compose(ibuf, GOT_IMSG_COMMIT_LOGMSG, 0, 0, -1,
		    commit->logmsg + offset, n) == -1) {
			err = got_error_from_errno("imsg_compose "
			    "COMMIT_LOGMSG");
			break;
		}

		err = flush_imsg(ibuf);
		if (err)
			break;

		offset += n;
		remain -= n;
	}

	return err;
}

const struct got_error *
got_privsep_send_commit(struct imsgbuf *ibuf, struct got_commit_object *commit)
{
	const struct got_error *err = NULL;
	struct got_imsg_commit_object *icommit;
	uint8_t *buf;
	size_t len, total;
	struct got_object_qid *qid;
	size_t author_len = strlen(commit->author);
	size_t committer_len = strlen(commit->committer);
	size_t logmsg_len = strlen(commit->logmsg);

	total = sizeof(*icommit) + author_len + committer_len +
	    commit->nparents * sizeof(struct got_object_id);

	buf = malloc(total);
	if (buf == NULL)
		return got_error_from_errno("malloc");

	icommit = (struct got_imsg_commit_object *)buf;
	memcpy(&icommit->tree_id, commit->tree_id, sizeof(icommit->tree_id));
	icommit->author_len = author_len;
	icommit->author_time = commit->author_time;
	icommit->author_gmtoff = commit->author_gmtoff;
	icommit->committer_len = committer_len;
	icommit->committer_time = commit->committer_time;
	icommit->committer_gmtoff = commit->committer_gmtoff;
	icommit->logmsg_len = logmsg_len;
	icommit->nparents = commit->nparents;

	len = sizeof(*icommit);
	memcpy(buf + len, commit->author, author_len);
	len += author_len;
	memcpy(buf + len, commit->committer, committer_len);
	len += committer_len;
	STAILQ_FOREACH(qid, &commit->parent_ids, entry) {
		memcpy(buf + len, &qid->id, sizeof(qid->id));
		len += sizeof(qid->id);
	}

	if (imsg_compose(ibuf, GOT_IMSG_COMMIT, 0, 0, -1, buf, len) == -1) {
		err = got_error_from_errno("imsg_compose COMMIT");
		goto done;
	}

	if (logmsg_len == 0 ||
	    logmsg_len + len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = flush_imsg(ibuf);
		if (err)
			goto done;
	}
	err = send_commit_logmsg(ibuf, commit, logmsg_len);
done:
	free(buf);
	return err;
}

static const struct got_error *
get_commit_from_imsg(struct got_commit_object **commit,
    struct imsg *imsg, size_t datalen, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_imsg_commit_object *icommit;
	size_t len = 0;
	int i;

	if (datalen < sizeof(*icommit))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	icommit = imsg->data;
	if (datalen != sizeof(*icommit) + icommit->author_len +
	    icommit->committer_len +
	    icommit->nparents * sizeof(struct got_object_id))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (icommit->nparents < 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	len += sizeof(*icommit);

	*commit = got_object_commit_alloc_partial();
	if (*commit == NULL)
		return got_error_from_errno(
		    "got_object_commit_alloc_partial");

	memcpy((*commit)->tree_id, &icommit->tree_id,
	    sizeof(icommit->tree_id));
	(*commit)->author_time = icommit->author_time;
	(*commit)->author_gmtoff = icommit->author_gmtoff;
	(*commit)->committer_time = icommit->committer_time;
	(*commit)->committer_gmtoff = icommit->committer_gmtoff;

	(*commit)->author = strndup(imsg->data + len, icommit->author_len);
	if ((*commit)->author == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	len += icommit->author_len;

	(*commit)->committer = strndup(imsg->data + len,
	    icommit->committer_len);
	if ((*commit)->committer == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	len += icommit->committer_len;

	if (icommit->logmsg_len == 0) {
		(*commit)->logmsg = strdup("");
		if ((*commit)->logmsg == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		size_t offset = 0, remain = icommit->logmsg_len;

		(*commit)->logmsg = malloc(icommit->logmsg_len + 1);
		if ((*commit)->logmsg == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		while (remain > 0) {
			struct imsg imsg_log;
			size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE,
			    remain);

			err = got_privsep_recv_imsg(&imsg_log, ibuf, n);
			if (err)
				goto done;

			if (imsg_log.hdr.type != GOT_IMSG_COMMIT_LOGMSG) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}

			memcpy((*commit)->logmsg + offset,
			    imsg_log.data, n);
			imsg_free(&imsg_log);
			offset += n;
			remain -= n;
		}
		(*commit)->logmsg[icommit->logmsg_len] = '\0';
	}

	for (i = 0; i < icommit->nparents; i++) {
		struct got_object_qid *qid;

		err = got_object_qid_alloc_partial(&qid);
		if (err)
			break;
		memcpy(&qid->id, imsg->data + len +
		    i * sizeof(qid->id), sizeof(qid->id));
		STAILQ_INSERT_TAIL(&(*commit)->parent_ids, qid, entry);
		(*commit)->nparents++;
	}
done:
	if (err) {
		got_object_commit_close(*commit);
		*commit = NULL;
	}
	return err;
}

const struct got_error *
got_privsep_recv_commit(struct got_commit_object **commit, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	const size_t min_datalen = sizeof(struct got_imsg_commit_object);

	*commit = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_COMMIT:
		err = get_commit_from_imsg(commit, &imsg, datalen, ibuf);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

static const struct got_error *
send_tree_entries_batch(struct imsgbuf *ibuf,
    struct got_parsed_tree_entry *entries, int idx0, int idxN, size_t len)
{
	struct ibuf *wbuf;
	struct got_imsg_tree_entries ientries;
	int i;

	memset(&ientries, 0, sizeof(ientries));

	wbuf = imsg_create(ibuf, GOT_IMSG_TREE_ENTRIES, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create TREE_ENTRY");

	ientries.nentries = idxN - idx0 + 1;
	if (imsg_add(wbuf, &ientries, sizeof(ientries)) == -1)
		return got_error_from_errno("imsg_add TREE_ENTRY");

	for (i = idx0; i <= idxN; i++) {
		static const char gap[12]; /* for sha1 inside sha256 align */
		struct got_parsed_tree_entry *pte = &entries[i];

		/* Keep in sync with struct got_imsg_tree_entry definition! */
		if (imsg_add(wbuf, pte->id, pte->digest_len) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");
		if (pte->algo == GOT_HASH_SHA1 &&
		    imsg_add(wbuf, gap, sizeof(gap)) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");
		if (imsg_add(wbuf, &pte->algo, sizeof(pte->algo)) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");
		if (imsg_add(wbuf, &pte->mode, sizeof(pte->mode)) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");
		if (imsg_add(wbuf, &pte->namelen, sizeof(pte->namelen)) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");

		/* Remaining bytes are the entry's name. */
		if (imsg_add(wbuf, pte->name, pte->namelen) == -1)
			return got_error_from_errno("imsg_add TREE_ENTRY");
	}

	imsg_close(ibuf, wbuf);
	return NULL;
}

static const struct got_error *
send_tree_entries(struct imsgbuf *ibuf, struct got_parsed_tree_entry *entries,
    int nentries)
{
	const struct got_error *err = NULL;
	int i, j;
	size_t entries_len = sizeof(struct got_imsg_tree_entries);

	i = 0;
	for (j = 0; j < nentries; j++) {
		struct got_parsed_tree_entry *pte = &entries[j];
		size_t len = sizeof(struct got_imsg_tree_entry) + pte->namelen;

		if (j > 0 &&
		    entries_len + len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
			err = send_tree_entries_batch(ibuf, entries,
			    i, j - 1, entries_len);
			if (err)
				return err;
			i = j;
			entries_len = sizeof(struct got_imsg_tree_entries);
		}

		entries_len += len;
	}

	if (j > 0) {
		err = send_tree_entries_batch(ibuf, entries, i, j - 1,
		    entries_len);
		if (err)
			return err;
	}

	return NULL;
}

const struct got_error *
got_privsep_send_tree(struct imsgbuf *ibuf,
    struct got_parsed_tree_entry *entries, int nentries)
{
	const struct got_error *err = NULL;
	struct got_imsg_tree_object itree;

	memset(&itree, 0, sizeof(itree));
	itree.nentries = nentries;
	if (imsg_compose(ibuf, GOT_IMSG_TREE, 0, 0, -1, &itree, sizeof(itree))
	    == -1)
		return got_error_from_errno("imsg_compose TREE");

	err = send_tree_entries(ibuf, entries, nentries);
	if (err)
		return err;

	return flush_imsg(ibuf);
}


static const struct got_error *
recv_tree_entries(void *data, size_t datalen, struct got_tree_object *tree,
    int *nentries)
{
	const struct got_error *err = NULL;
	struct got_imsg_tree_entries *ientries;
	struct got_tree_entry *te;
	size_t te_offset;
	size_t i;

	if (datalen <= sizeof(*ientries) ||
	    datalen > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	ientries = (struct got_imsg_tree_entries *)data;
	if (ientries->nentries > INT_MAX) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "too many tree entries");
	}

	te_offset = sizeof(*ientries);
	for (i = 0; i < ientries->nentries; i++) {
		struct got_imsg_tree_entry ite;
		const char *te_name;
		uint8_t *buf = (uint8_t *)data + te_offset;

		if (te_offset >= datalen) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		/* Might not be aligned, size is ~32 bytes. */
		memcpy(&ite, buf, sizeof(ite));

		if (ite.namelen >= sizeof(te->name)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		if (te_offset + sizeof(ite) + ite.namelen > datalen) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		if (*nentries >= tree->nentries) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		te = &tree->entries[*nentries];
		te_name = buf + sizeof(ite);
		memcpy(te->name, te_name, ite.namelen);
		te->name[ite.namelen] = '\0';
		memcpy(te->id.hash, ite.id, sizeof(te->id.hash));
		memcpy(te->id.hash, ite.id, got_hash_digest_length(ite.algo));
		te->id.algo = ite.algo;
		te->mode = ite.mode;
		te->idx = *nentries;
		(*nentries)++;

		te_offset += sizeof(ite) + ite.namelen;
	}

	return err;
}

const struct got_error *
got_privsep_recv_tree(struct got_tree_object **tree, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	const size_t min_datalen = sizeof(struct got_imsg_tree_object);
	struct got_imsg_tree_object *itree;
	int nentries = 0;

	*tree = NULL;

	while (*tree == NULL || nentries < (*tree)->nentries) {
		struct imsg imsg;
		size_t datalen;

		err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
		if (err)
			break;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case GOT_IMSG_TREE:
			/* This message should only appear once. */
			if (*tree != NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen != sizeof(*itree)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			itree = imsg.data;
			if (itree->nentries < 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			*tree = malloc(sizeof(**tree));
			if (*tree == NULL) {
				err = got_error_from_errno("malloc");
				break;
			}
			(*tree)->entries = calloc(itree->nentries,
			    sizeof(struct got_tree_entry));
			if ((*tree)->entries == NULL) {
				err = got_error_from_errno("malloc");
				free(*tree);
				*tree = NULL;
				break;
			}
			(*tree)->nentries = itree->nentries;
			(*tree)->refcnt = 0;
			break;
		case GOT_IMSG_TREE_ENTRIES:
			/* This message should be preceeded by GOT_IMSG_TREE. */
			if (*tree == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = recv_tree_entries(imsg.data, datalen,
			    *tree, &nentries);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	if (*tree && (*tree)->nentries != nentries) {
		if (err == NULL)
			err = got_error(GOT_ERR_PRIVSEP_LEN);
		got_object_tree_close(*tree);
		*tree = NULL;
	}

	return err;
}

const struct got_error *
got_privsep_send_blob(struct imsgbuf *ibuf, size_t size, size_t hdrlen,
    const uint8_t *data)
{
	struct got_imsg_blob iblob;

	memset(&iblob, 0, sizeof(iblob));
	iblob.size = size;
	iblob.hdrlen = hdrlen;

	if (data) {
		uint8_t *buf;

		if (size > GOT_PRIVSEP_INLINE_BLOB_DATA_MAX)
			return got_error(GOT_ERR_NO_SPACE);

		buf = malloc(sizeof(iblob) + size);
		if (buf == NULL)
			return got_error_from_errno("malloc");

		memcpy(buf, &iblob, sizeof(iblob));
		memcpy(buf + sizeof(iblob), data, size);
		if (imsg_compose(ibuf, GOT_IMSG_BLOB, 0, 0, -1, buf,
		    sizeof(iblob) + size) == -1) {
			free(buf);
			return got_error_from_errno("imsg_compose BLOB");
		}
		free(buf);
	} else {
		/* Data has already been written to file descriptor. */
		if (imsg_compose(ibuf, GOT_IMSG_BLOB, 0, 0, -1, &iblob,
		    sizeof(iblob)) == -1)
			return got_error_from_errno("imsg_compose BLOB");
	}


	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_blob(uint8_t **outbuf, size_t *size, size_t *hdrlen,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_blob *iblob;
	size_t datalen;

	*outbuf = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_BLOB:
		if (datalen < sizeof(*iblob)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		iblob = imsg.data;
		*size = iblob->size;
		*hdrlen = iblob->hdrlen;

		if (datalen == sizeof(*iblob)) {
			/* Data has been written to file descriptor. */
			break;
		}

		if (*size > GOT_PRIVSEP_INLINE_BLOB_DATA_MAX ||
		    *size > datalen + sizeof(*iblob)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		*outbuf = malloc(*size);
		if (*outbuf == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		memcpy(*outbuf, imsg.data + sizeof(*iblob), *size);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

static const struct got_error *
send_tagmsg(struct imsgbuf *ibuf, struct got_tag_object *tag, size_t tagmsg_len)
{
	const struct got_error *err = NULL;
	size_t offset, remain;

	offset = 0;
	remain = tagmsg_len;
	while (remain > 0) {
		size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE, remain);

		if (imsg_compose(ibuf, GOT_IMSG_TAG_TAGMSG, 0, 0, -1,
		    tag->tagmsg + offset, n) == -1) {
			err = got_error_from_errno("imsg_compose TAG_TAGMSG");
			break;
		}

		err = flush_imsg(ibuf);
		if (err)
			break;

		offset += n;
		remain -= n;
	}

	return err;
}

const struct got_error *
got_privsep_send_tag(struct imsgbuf *ibuf, struct got_tag_object *tag)
{
	const struct got_error *err = NULL;
	struct got_imsg_tag_object *itag;
	uint8_t *buf;
	size_t len, total;
	size_t tag_len = strlen(tag->tag);
	size_t tagger_len = strlen(tag->tagger);
	size_t tagmsg_len = strlen(tag->tagmsg);

	total = sizeof(*itag) + tag_len + tagger_len + tagmsg_len;

	buf = malloc(total);
	if (buf == NULL)
		return got_error_from_errno("malloc");

	itag = (struct got_imsg_tag_object *)buf;
	memcpy(&itag->id, &tag->id, sizeof(itag->id));
	itag->obj_type = tag->obj_type;
	itag->tag_len = tag_len;
	itag->tagger_len = tagger_len;
	itag->tagger_time = tag->tagger_time;
	itag->tagger_gmtoff = tag->tagger_gmtoff;
	itag->tagmsg_len = tagmsg_len;

	len = sizeof(*itag);
	memcpy(buf + len, tag->tag, tag_len);
	len += tag_len;
	memcpy(buf + len, tag->tagger, tagger_len);
	len += tagger_len;

	if (imsg_compose(ibuf, GOT_IMSG_TAG, 0, 0, -1, buf, len) == -1) {
		err = got_error_from_errno("imsg_compose TAG");
		goto done;
	}

	if (tagmsg_len == 0 ||
	    tagmsg_len + len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = flush_imsg(ibuf);
		if (err)
			goto done;
	}
	err = send_tagmsg(ibuf, tag, tagmsg_len);
done:
	free(buf);
	return err;
}

const struct got_error *
got_privsep_recv_tag(struct got_tag_object **tag, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_tag_object *itag;
	size_t len, datalen;
	const size_t min_datalen = sizeof(struct got_imsg_tag_object);

	*tag = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	len = 0;

	switch (imsg.hdr.type) {
	case GOT_IMSG_TAG:
		if (datalen < sizeof(*itag)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		itag = imsg.data;
		if (datalen != sizeof(*itag) + itag->tag_len +
		    itag->tagger_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		len += sizeof(*itag);

		*tag = calloc(1, sizeof(**tag));
		if (*tag == NULL) {
			err = got_error_from_errno("calloc");
			break;
		}

		memcpy(&(*tag)->id, &itag->id, sizeof(itag->id));

		(*tag)->tag = strndup(imsg.data + len, itag->tag_len);
		if ((*tag)->tag == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		len += itag->tag_len;

		(*tag)->obj_type = itag->obj_type;
		(*tag)->tagger_time = itag->tagger_time;
		(*tag)->tagger_gmtoff = itag->tagger_gmtoff;

		(*tag)->tagger = strndup(imsg.data + len, itag->tagger_len);
		if ((*tag)->tagger == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		len += itag->tagger_len;

		if (itag->tagmsg_len == 0) {
			(*tag)->tagmsg = strdup("");
			if ((*tag)->tagmsg == NULL) {
				err = got_error_from_errno("strdup");
				break;
			}
		} else {
			size_t offset = 0, remain = itag->tagmsg_len;

			(*tag)->tagmsg = malloc(itag->tagmsg_len + 1);
			if ((*tag)->tagmsg == NULL) {
				err = got_error_from_errno("malloc");
				break;
			}
			while (remain > 0) {
				struct imsg imsg_log;
				size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE,
				    remain);

				err = got_privsep_recv_imsg(&imsg_log, ibuf, n);
				if (err)
					return err;

				if (imsg_log.hdr.type != GOT_IMSG_TAG_TAGMSG)
					return got_error(GOT_ERR_PRIVSEP_MSG);

				memcpy((*tag)->tagmsg + offset, imsg_log.data,
				    n);
				imsg_free(&imsg_log);
				offset += n;
				remain -= n;
			}
			(*tag)->tagmsg[itag->tagmsg_len] = '\0';
		}

		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_init_pack_child(struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_imsg_packidx ipackidx;
	struct got_imsg_pack ipack;
	int fd;

	memset(&ipackidx, 0, sizeof(ipackidx));
	memset(&ipack, 0, sizeof(ipack));

	ipackidx.len = packidx->len;
	ipackidx.packfile_size = pack->filesize;
	ipackidx.algo = packidx->algo;
	fd = dup(packidx->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (imsg_compose(ibuf, GOT_IMSG_PACKIDX, 0, 0, fd, &ipackidx,
	    sizeof(ipackidx)) == -1) {
		err = got_error_from_errno("imsg_compose PACKIDX");
		close(fd);
		return err;
	}

	if (strlcpy(ipack.path_packfile, pack->path_packfile,
	    sizeof(ipack.path_packfile)) >= sizeof(ipack.path_packfile))
		return got_error(GOT_ERR_NO_SPACE);
	ipack.filesize = pack->filesize;
	ipack.algo = pack->algo;

	fd = dup(pack->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (imsg_compose(ibuf, GOT_IMSG_PACK, 0, 0, fd, &ipack, sizeof(ipack))
	    == -1) {
		err = got_error_from_errno("imsg_compose PACK");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_packed_obj_req(struct imsgbuf *ibuf, int idx,
    struct got_object_id *id)
{
	struct got_imsg_packed_object iobj;

	memset(&iobj, 0, sizeof(iobj));
	iobj.idx = idx;
	memcpy(&iobj.id, id, sizeof(iobj.id));

	if (imsg_compose(ibuf, GOT_IMSG_PACKED_OBJECT_REQUEST, 0, 0, -1,
	    &iobj, sizeof(iobj)) == -1)
		return got_error_from_errno("imsg_compose "
		    "PACKED_OBJECT_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_packed_raw_obj_req(struct imsgbuf *ibuf, int idx,
    struct got_object_id *id)
{
	struct got_imsg_packed_object iobj;

	memset(&iobj, 0, sizeof(iobj));
	iobj.idx = idx;
	memcpy(&iobj.id, id, sizeof(iobj.id));

	if (imsg_compose(ibuf, GOT_IMSG_PACKED_RAW_OBJECT_REQUEST, 0, 0, -1,
	    &iobj, sizeof(iobj)) == -1)
		return got_error_from_errno("imsg_compose "
		    "PACKED_OBJECT_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_parse_req(struct imsgbuf *ibuf, int fd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, GOT_IMSG_GITCONFIG_PARSE_REQUEST, 0, 0, fd,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose "
		    "GITCONFIG_PARSE_REQUEST");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_repository_format_version_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_repository_extensions_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_REPOSITORY_EXTENSIONS_REQUEST, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_REPOSITORY_EXTENSIONS_REQUEST");

	return flush_imsg(ibuf);
}


const struct got_error *
got_privsep_send_gitconfig_author_name_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_AUTHOR_NAME_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_AUTHOR_NAME_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_author_email_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_AUTHOR_EMAIL_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_AUTHOR_EMAIL_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_remotes_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_REMOTES_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_REMOTE_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gitconfig_owner_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GITCONFIG_OWNER_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GITCONFIG_OWNER_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_gitconfig_str(char **str, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;

	*str = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_GITCONFIG_STR_VAL:
		if (datalen == 0)
			break;
		*str = strndup(imsg.data, datalen);
		if (*str == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_recv_gitconfig_pair(char **key, char **val, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_imsg_gitconfig_pair p;
	struct imsg imsg;
	size_t datalen;
	uint8_t *data;

	*key = *val = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	data = imsg.data;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	if (imsg.hdr.type != GOT_IMSG_GITCONFIG_PAIR) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	if (datalen < sizeof(p)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	memcpy(&p, data, sizeof(p));
	data += sizeof(p);

	if (datalen != sizeof(p) + p.klen + p.vlen) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	*key = strndup(data, p.klen);
	if (*key == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	data += p.klen;

	*val = strndup(data, p.vlen);
	if (*val == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

done:
	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_recv_gitconfig_int(int *val, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	const size_t min_datalen = sizeof(int);

	*val = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_GITCONFIG_INT_VAL:
		if (datalen != sizeof(*val)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		memcpy(val, imsg.data, sizeof(*val));
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
	return err;
}

static void
free_remote_data(struct got_remote_repo *remote)
{
	int i;

	free(remote->name);
	free(remote->fetch_url);
	free(remote->send_url);
	for (i = 0; i < remote->nfetch_branches; i++)
		free(remote->fetch_branches[i]);
	free(remote->fetch_branches);
	for (i = 0; i < remote->nsend_branches; i++)
		free(remote->send_branches[i]);
	free(remote->send_branches);
	for (i = 0; i < remote->nfetch_refs; i++)
		free(remote->fetch_refs[i]);
	free(remote->fetch_refs);
}

const struct got_error *
got_privsep_recv_gitconfig_remotes(struct got_remote_repo **remotes,
    int *nremotes, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct got_imsg_remotes iremotes;
	struct got_imsg_remote iremote;

	*remotes = NULL;
	*nremotes = 0;
	iremotes.nremotes = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, sizeof(iremotes));
	if (err)
		return err;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_GITCONFIG_REMOTES:
		if (datalen != sizeof(iremotes)) {
			imsg_free(&imsg);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}
		memcpy(&iremotes, imsg.data, sizeof(iremotes));
		if (iremotes.nremotes == 0) {
			imsg_free(&imsg);
			return NULL;
		}
		break;
	default:
		imsg_free(&imsg);
		return got_error(GOT_ERR_PRIVSEP_MSG);
	}

	imsg_free(&imsg);

	*remotes = recallocarray(NULL, 0, iremotes.nremotes, sizeof(**remotes));
	if (*remotes == NULL)
		return got_error_from_errno("recallocarray");

	while (*nremotes < iremotes.nremotes) {
		struct got_remote_repo *remote;

		err = got_privsep_recv_imsg(&imsg, ibuf, sizeof(iremote));
		if (err)
			break;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case GOT_IMSG_GITCONFIG_REMOTE:
			remote = &(*remotes)[*nremotes];
			memset(remote, 0, sizeof(*remote));
			if (datalen < sizeof(iremote)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&iremote, imsg.data, sizeof(iremote));
			if (iremote.name_len == 0 ||
			    iremote.fetch_url_len == 0 ||
			    iremote.send_url_len == 0 ||
			    (sizeof(iremote) + iremote.name_len +
			    iremote.fetch_url_len + iremote.send_url_len) > datalen) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			remote->name = strndup(imsg.data + sizeof(iremote),
			    iremote.name_len);
			if (remote->name == NULL) {
				err = got_error_from_errno("strndup");
				break;
			}
			remote->fetch_url = strndup(imsg.data + sizeof(iremote) +
			    iremote.name_len, iremote.fetch_url_len);
			if (remote->fetch_url == NULL) {
				err = got_error_from_errno("strndup");
				free_remote_data(remote);
				break;
			}
			remote->send_url = strndup(imsg.data + sizeof(iremote) +
			    iremote.name_len + iremote.fetch_url_len,
			    iremote.send_url_len);
			if (remote->send_url == NULL) {
				err = got_error_from_errno("strndup");
				free_remote_data(remote);
				break;
			}
			remote->mirror_references = iremote.mirror_references;
			remote->fetch_all_branches = iremote.fetch_all_branches;
			remote->nfetch_branches = 0;
			remote->fetch_branches = NULL;
			remote->nsend_branches = 0;
			remote->send_branches = NULL;
			remote->nfetch_refs = 0;
			remote->fetch_refs = NULL;
			(*nremotes)++;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	if (err) {
		int i;
		for (i = 0; i < *nremotes; i++)
			free_remote_data(&(*remotes)[i]);
		free(*remotes);
		*remotes = NULL;
		*nremotes = 0;
	}
	return err;
}

const struct got_error *
got_privsep_send_gotconfig_parse_req(struct imsgbuf *ibuf, int fd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, GOT_IMSG_GOTCONFIG_PARSE_REQUEST, 0, 0, fd,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose "
		    "GOTCONFIG_PARSE_REQUEST");
		close(fd);
		return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gotconfig_author_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GOTCONFIG_AUTHOR_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GOTCONFIG_AUTHOR_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gotconfig_allowed_signers_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GOTCONFIG_ALLOWEDSIGNERS_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GOTCONFIG_ALLOWEDSIGNERS_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gotconfig_revoked_signers_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GOTCONFIG_REVOKEDSIGNERS_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GOTCONFIG_REVOKEDSIGNERS_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gotconfig_signer_id_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GOTCONFIG_SIGNERID_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GOTCONFIG_SIGNERID_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_gotconfig_remotes_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf,
	    GOT_IMSG_GOTCONFIG_REMOTES_REQUEST, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "GOTCONFIG_REMOTE_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_gotconfig_str(char **str, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;

	*str = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_GOTCONFIG_STR_VAL:
		if (datalen == 0)
			break;
		*str = strndup(imsg.data, datalen);
		if (*str == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
	return err;
}

const struct got_error *
got_privsep_recv_gotconfig_remotes(struct got_remote_repo **remotes,
    int *nremotes, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct got_imsg_remotes iremotes;
	struct got_imsg_remote iremote;
	const size_t min_datalen = sizeof(iremotes);

	*remotes = NULL;
	*nremotes = 0;
	iremotes.nremotes = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_GOTCONFIG_REMOTES:
		if (datalen != sizeof(iremotes)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		memcpy(&iremotes, imsg.data, sizeof(iremotes));
		if (iremotes.nremotes < 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		if (iremotes.nremotes == 0) {
			imsg_free(&imsg);
			return NULL;
		}
		break;
	default:
		imsg_free(&imsg);
		return got_error(GOT_ERR_PRIVSEP_MSG);
	}

	imsg_free(&imsg);

	*remotes = recallocarray(NULL, 0, iremotes.nremotes, sizeof(**remotes));
	if (*remotes == NULL)
		return got_error_from_errno("recallocarray");

	while (*nremotes < iremotes.nremotes) {
		struct got_remote_repo *remote;
		const size_t min_datalen = sizeof(iremote);
		int i;

		err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
		if (err)
			break;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case GOT_IMSG_GOTCONFIG_REMOTE:
			remote = &(*remotes)[*nremotes];
			memset(remote, 0, sizeof(*remote));
			if (datalen < sizeof(iremote)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&iremote, imsg.data, sizeof(iremote));
			if (iremote.name_len == 0 ||
			    (iremote.fetch_url_len == 0 &&
			    iremote.send_url_len == 0) ||
			    (sizeof(iremote) + iremote.name_len +
			    iremote.fetch_url_len + iremote.send_url_len) >
			    datalen) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			remote->name = strndup(imsg.data + sizeof(iremote),
			    iremote.name_len);
			if (remote->name == NULL) {
				err = got_error_from_errno("strndup");
				break;
			}
			remote->fetch_url = strndup(imsg.data +
			    sizeof(iremote) + iremote.name_len,
			    iremote.fetch_url_len);
			if (remote->fetch_url == NULL) {
				err = got_error_from_errno("strndup");
				free_remote_data(remote);
				break;
			}
			remote->send_url = strndup(imsg.data +
			    sizeof(iremote) + iremote.name_len +
			    iremote.fetch_url_len, iremote.send_url_len);
			if (remote->send_url == NULL) {
				err = got_error_from_errno("strndup");
				free_remote_data(remote);
				break;
			}
			remote->mirror_references = iremote.mirror_references;
			remote->fetch_all_branches = iremote.fetch_all_branches;
			if (iremote.nfetch_branches > 0) {
				remote->fetch_branches = recallocarray(NULL, 0,
				    iremote.nfetch_branches, sizeof(char *));
				if (remote->fetch_branches == NULL) {
					err = got_error_from_errno("calloc");
					free_remote_data(remote);
					break;
				}
			}
			remote->nfetch_branches = 0;
			for (i = 0; i < iremote.nfetch_branches; i++) {
				char *branch;
				err = got_privsep_recv_gotconfig_str(&branch,
				    ibuf);
				if (err) {
					free_remote_data(remote);
					goto done;
				}
				remote->fetch_branches[i] = branch;
				remote->nfetch_branches++;
			}
			if (iremote.nsend_branches > 0) {
				remote->send_branches = recallocarray(NULL, 0,
				    iremote.nsend_branches, sizeof(char *));
				if (remote->send_branches == NULL) {
					err = got_error_from_errno("calloc");
					free_remote_data(remote);
					break;
				}
			}
			remote->nsend_branches = 0;
			for (i = 0; i < iremote.nsend_branches; i++) {
				char *branch;
				err = got_privsep_recv_gotconfig_str(&branch,
				    ibuf);
				if (err) {
					free_remote_data(remote);
					goto done;
				}
				remote->send_branches[i] = branch;
				remote->nsend_branches++;
			}
			if (iremote.nfetch_refs > 0) {
				remote->fetch_refs = recallocarray(NULL, 0,
				    iremote.nfetch_refs, sizeof(char *));
				if (remote->fetch_refs == NULL) {
					err = got_error_from_errno("calloc");
					free_remote_data(remote);
					break;
				}
			}
			remote->nfetch_refs = 0;
			for (i = 0; i < iremote.nfetch_refs; i++) {
				char *ref;
				err = got_privsep_recv_gotconfig_str(&ref,
				    ibuf);
				if (err) {
					free_remote_data(remote);
					goto done;
				}
				remote->fetch_refs[i] = ref;
				remote->nfetch_refs++;
			}
			(*nremotes)++;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}
done:
	if (err) {
		int i;
		for (i = 0; i < *nremotes; i++)
			free_remote_data(&(*remotes)[i]);
		free(*remotes);
		*remotes = NULL;
		*nremotes = 0;
	}
	return err;
}

const struct got_error *
got_privsep_send_commit_traversal_request(struct imsgbuf *ibuf,
    struct got_object_id *id, int idx, const char *path)
{
	struct ibuf *wbuf;
	size_t path_len = strlen(path);

	wbuf = imsg_create(ibuf, GOT_IMSG_COMMIT_TRAVERSAL_REQUEST, 0, 0,
	    sizeof(struct got_imsg_commit_traversal_request) + path_len);
	if (wbuf == NULL)
		return got_error_from_errno(
		    "imsg_create COMMIT_TRAVERSAL_REQUEST");
	/*
	 * Keep in sync with struct got_imsg_commit_traversal_request
	 * and struct got_imsg_packed_object.
	 */
	if (imsg_add(wbuf, id, sizeof(*id)) == -1)
		return got_error_from_errno("imsg_add "
		    "COMMIT_TRAVERSAL_REQUEST");
	if (imsg_add(wbuf, &idx, sizeof(idx)) == -1)
		return got_error_from_errno("imsg_add "
		    "COMMIT_TRAVERSAL_REQUEST");
	if (imsg_add(wbuf, &path_len, sizeof(path_len)) == -1)
		return got_error_from_errno("imsg_add "
		    "COMMIT_TRAVERSAL_REQUEST");
	if (imsg_add(wbuf, path, path_len) == -1)
		return got_error_from_errno("imsg_add "
		    "COMMIT_TRAVERSAL_REQUEST");

	imsg_close(ibuf, wbuf);
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_traversed_commits(struct got_commit_object **changed_commit,
    struct got_object_id_queue *commit_ids, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_traversed_commits *icommits;
	struct got_object_id *ids;
	size_t datalen;
	int i, done = 0;

	*changed_commit = NULL;

	while (!done) {
		err = got_privsep_recv_imsg(&imsg, ibuf, 0);
		if (err)
			return err;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOT_IMSG_TRAVERSED_COMMITS:
			icommits = imsg.data;
			if (datalen != sizeof(*icommits) +
			    icommits->ncommits * sizeof(*ids)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			ids = imsg.data + sizeof(*icommits);
			for (i = 0; i < icommits->ncommits; i++) {
				struct got_object_qid *qid;

				err = got_object_qid_alloc_partial(&qid);
				if (err)
					break;
				memcpy(&qid->id, &ids[i], sizeof(ids[i]));
				STAILQ_INSERT_TAIL(commit_ids, qid, entry);

			}
			break;
		case GOT_IMSG_COMMIT:
			err = get_commit_from_imsg(changed_commit, &imsg,
			    datalen, ibuf);
			break;
		case GOT_IMSG_COMMIT_TRAVERSAL_DONE:
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	if (err)
		got_object_id_queue_free(commit_ids);
	return err;
}

const struct got_error *
got_privsep_send_enumerated_tree(size_t *totlen, struct imsgbuf *ibuf,
    struct got_object_id *tree_id, const char *path,
    struct got_parsed_tree_entry *entries, int nentries)
{
	const struct got_error *err = NULL;
	struct ibuf *wbuf;
	size_t path_len = strlen(path);
	size_t msglen;

	msglen = sizeof(struct got_imsg_enumerated_tree) + path_len;
	wbuf = imsg_create(ibuf, GOT_IMSG_ENUMERATED_TREE, 0, 0, msglen);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create ENUMERATED_TREE");

	if (imsg_add(wbuf, tree_id, sizeof(*tree_id)) == -1)
		return got_error_from_errno("imsg_add ENUMERATED_TREE");
	if (imsg_add(wbuf, &nentries, sizeof(nentries)) == -1)
		return got_error_from_errno("imsg_add ENUMERATED_TREE");
	if (imsg_add(wbuf, path, path_len) == -1)
		return got_error_from_errno("imsg_add ENUMERATED_TREE");

	imsg_close(ibuf, wbuf);

	if (entries) {
		err = send_tree_entries(ibuf, entries, nentries);
		if (err)
			return err;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_object_enumeration_request(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_OBJECT_ENUMERATION_REQUEST,
	    0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "OBJECT_ENUMERATION_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_object_enumeration_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_OBJECT_ENUMERATION_DONE,
	    0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "OBJECT_ENUMERATION_DONE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_object_enumeration_incomplete(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_OBJECT_ENUMERATION_INCOMPLETE,
	    0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "OBJECT_ENUMERATION_INCOMPLETE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_enumerated_commit(struct imsgbuf *ibuf,
    struct got_object_id *id, time_t mtime)
{
	struct ibuf *wbuf;

	wbuf = imsg_create(ibuf, GOT_IMSG_ENUMERATED_COMMIT, 0, 0,
	    sizeof(struct got_imsg_enumerated_commit));
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create ENUMERATED_COMMIT");

	/* Keep in sync with struct got_imsg_enumerated_commit! */
	if (imsg_add(wbuf, id, sizeof(*id)) == -1)
		return got_error_from_errno("imsg_add ENUMERATED_COMMIT");
	if (imsg_add(wbuf, &mtime, sizeof(mtime)) == -1)
		return got_error_from_errno("imsg_add ENUMERATED_COMMIT");

	imsg_close(ibuf, wbuf);
	/* Don't flush yet, tree entries or ENUMERATION_DONE will follow. */
	return NULL;
}

const struct got_error *
got_privsep_recv_enumerated_objects(int *found_all_objects,
    struct imsgbuf *ibuf,
    got_object_enumerate_commit_cb cb_commit,
    got_object_enumerate_tree_cb cb_tree, void *cb_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_enumerated_commit *icommit = NULL;
	struct got_object_id commit_id;
	int have_commit = 0;
	time_t mtime = 0;
	struct got_tree_object tree;
	struct got_imsg_enumerated_tree *itree;
	struct got_object_id tree_id;
	char *path = NULL, *canon_path = NULL;
	size_t datalen, path_len;
	int nentries = -1;
	int done = 0;

	*found_all_objects = 0;
	memset(&tree, 0, sizeof(tree));

	while (!done) {
		err = got_privsep_recv_imsg(&imsg, ibuf, 0);
		if (err)
			break;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOT_IMSG_ENUMERATED_COMMIT:
			if (have_commit && nentries != -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen != sizeof(*icommit)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			icommit = (struct got_imsg_enumerated_commit *)imsg.data;
			memcpy(&commit_id, &icommit->id, sizeof(commit_id));
			mtime = icommit->mtime;
			have_commit = 1;
			break;
		case GOT_IMSG_ENUMERATED_TREE:
			/* Should be preceeded by GOT_IMSG_ENUMERATED_COMMIT. */
			if (!have_commit) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen < sizeof(*itree)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			itree = imsg.data;
			path_len = datalen - sizeof(*itree);
			if (path_len == 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&tree_id, &itree->id, sizeof(tree_id));
			free(path);
			path = strndup(imsg.data + sizeof(*itree), path_len);
			if (path == NULL) {
				err = got_error_from_errno("strndup");
				break;
			}
			free(canon_path);
			canon_path = malloc(path_len + 1);
			if (canon_path == NULL) {
				err = got_error_from_errno("malloc");
				break;
			}
			if (!got_path_is_absolute(path)) {
				err = got_error(GOT_ERR_BAD_PATH);
				break;
			}
			if (got_path_is_root_dir(path)) {
				/* XXX check what got_canonpath() does wrong */
				canon_path[0] = '/';
				canon_path[1] = '\0';
			} else {
				err = got_canonpath(path, canon_path,
				    path_len + 1);
				if (err)
					break;
			}
			if (strcmp(path, canon_path) != 0) {
				err = got_error(GOT_ERR_BAD_PATH);
				break;
			}
			if (nentries != -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (itree->nentries < -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (itree->nentries == -1) {
				/* Tree was not found in pack file. */
				err = cb_tree(cb_arg, NULL, mtime, &tree_id,
				    path, repo);
				break;
			}
			if (itree->nentries > INT_MAX) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			tree.entries = calloc(itree->nentries,
			    sizeof(struct got_tree_entry));
			if (tree.entries == NULL) {
				err = got_error_from_errno("calloc");
				break;
			}
			if (itree->nentries == 0) {
				err = cb_tree(cb_arg, &tree, mtime, &tree_id,
				    path, repo);
				if (err)
					break;

				/* Prepare for next tree. */
				free(tree.entries);
				memset(&tree, 0, sizeof(tree));
				nentries = -1;
			} else {
				tree.nentries = itree->nentries;
				nentries = 0;
			}
			break;
		case GOT_IMSG_TREE_ENTRIES:
			/* Should be preceeded by GOT_IMSG_ENUMERATED_TREE. */
			if (nentries <= -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = recv_tree_entries(imsg.data, datalen,
			    &tree, &nentries);
			if (err)
				break;
			if (tree.nentries == nentries) {
				err = cb_tree(cb_arg, &tree, mtime, &tree_id,
				    path, repo);
				if (err)
					break;

				/* Prepare for next tree. */
				free(tree.entries);
				memset(&tree, 0, sizeof(tree));
				nentries = -1;
			}
			break;
		case GOT_IMSG_TREE_ENUMERATION_DONE:
			/* All trees have been found and traversed. */
			if (!have_commit || path == NULL || nentries != -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = cb_commit(cb_arg, mtime, &commit_id, repo);
			if (err)
				break;
			have_commit = 0;
			break;
		case GOT_IMSG_OBJECT_ENUMERATION_DONE:
			*found_all_objects = 1;
			done = 1;
			break;
		case GOT_IMSG_OBJECT_ENUMERATION_INCOMPLETE:
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	free(path);
	free(canon_path);
	free(tree.entries);
	return err;
}

const struct got_error *
got_privsep_send_raw_delta_req(struct imsgbuf *ibuf, int idx,
    struct got_object_id *id)
{
	struct got_imsg_raw_delta_request dreq;

	memset(&dreq, 0, sizeof(dreq));
	dreq.idx = idx;
	memcpy(&dreq.id, id, sizeof(dreq.id));

	if (imsg_compose(ibuf, GOT_IMSG_RAW_DELTA_REQUEST, 0, 0, -1,
	    &dreq, sizeof(dreq)) == -1)
		return got_error_from_errno("imsg_compose RAW_DELTA_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_raw_delta_outfd(struct imsgbuf *ibuf, int fd)
{
	return send_fd(ibuf, GOT_IMSG_RAW_DELTA_OUTFD, fd);
}

const struct got_error *
got_privsep_send_raw_delta(struct imsgbuf *ibuf, uint64_t base_size,
    uint64_t result_size,  off_t delta_size, off_t delta_compressed_size,
    off_t delta_offset, off_t delta_out_offset, struct got_object_id *base_id)
{
	struct got_imsg_raw_delta idelta;
	int ret;

	memset(&idelta, 0, sizeof(idelta));
	idelta.base_size = base_size;
	idelta.result_size = result_size;
	idelta.delta_size = delta_size;
	idelta.delta_compressed_size = delta_compressed_size;
	idelta.delta_offset = delta_offset;
	idelta.delta_out_offset = delta_out_offset;
	memcpy(&idelta.base_id, &base_id, sizeof(idelta.base_id));

	ret = imsg_compose(ibuf, GOT_IMSG_RAW_DELTA, 0, 0, -1,
	    &idelta, sizeof(idelta));
	if (ret == -1)
		return got_error_from_errno("imsg_compose RAW_DELTA");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_raw_delta(uint64_t *base_size, uint64_t *result_size,
    off_t *delta_size, off_t *delta_compressed_size, off_t *delta_offset,
    off_t *delta_out_offset, struct got_object_id **base_id,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_raw_delta *delta;
	size_t datalen;

	*base_size = 0;
	*result_size = 0;
	*delta_size = 0;
	*delta_compressed_size = 0;
	*delta_offset = 0;
	*delta_out_offset = 0;
	*base_id = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_RAW_DELTA:
		if (datalen != sizeof(*delta)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		delta = imsg.data;
		*base_size = delta->base_size;
		*result_size = delta->result_size;
		*delta_size = delta->delta_size;
		*delta_compressed_size = delta->delta_compressed_size;
		*delta_offset = delta->delta_offset;
		*delta_out_offset = delta->delta_out_offset;
		*base_id = calloc(1, sizeof(**base_id));
		if (*base_id == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		memcpy(*base_id, &delta->base_id, sizeof(**base_id));
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	if (err) {
		free(*base_id);
		*base_id = NULL;
	}
	return err;
}

static const struct got_error *
send_idlist(struct imsgbuf *ibuf, struct got_object_id **ids, size_t nids)
{
	const struct got_error *err = NULL;
	struct got_imsg_object_idlist idlist;
	struct ibuf *wbuf;
	size_t i;

	memset(&idlist, 0, sizeof(idlist));

	if (nids > GOT_IMSG_OBJ_ID_LIST_MAX_NIDS)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_OBJ_ID_LIST, 0, 0,
	    sizeof(idlist) + nids * sizeof(**ids));
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create OBJ_ID_LIST");
		return err;
	}

	idlist.nids = nids;
	if (imsg_add(wbuf, &idlist, sizeof(idlist)) == -1)
		return got_error_from_errno("imsg_add OBJ_ID_LIST");

	for (i = 0; i < nids; i++) {
		struct got_object_id *id = ids[i];
		if (imsg_add(wbuf, id, sizeof(*id)) == -1)
			return got_error_from_errno("imsg_add OBJ_ID_LIST");
	}

	imsg_close(ibuf, wbuf);

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_object_idlist(struct imsgbuf *ibuf,
    struct got_object_id **ids, size_t nids)
{
	const struct got_error *err = NULL;
	struct got_object_id *idlist[GOT_IMSG_OBJ_ID_LIST_MAX_NIDS];
	int i, queued = 0;

	for (i = 0; i < nids; i++) {
		idlist[i % nitems(idlist)] = ids[i];
		queued++;
		if (queued >= nitems(idlist)) {
			err = send_idlist(ibuf, idlist, queued);
			if (err)
				return err;
			queued = 0;
		}
	}

	if (queued > 0) {
		err = send_idlist(ibuf, idlist, queued);
		if (err)
			return err;
	}

	return NULL;
}

const struct got_error *
got_privsep_send_object_idlist_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_OBJ_ID_LIST_DONE, 0, 0, -1, NULL, 0)
	    == -1)
		return got_error_from_errno("imsg_compose OBJ_ID_LIST_DONE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_object_idlist(int *done, struct got_object_id **ids,
    size_t *nids, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_object_idlist *idlist;
	size_t datalen;

	*ids = NULL;
	*done = 0;
	*nids = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_OBJ_ID_LIST:
		if (datalen < sizeof(*idlist)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		idlist = imsg.data;
		if (idlist->nids > GOT_IMSG_OBJ_ID_LIST_MAX_NIDS ||
		    idlist->nids * sizeof(**ids) > datalen - sizeof(*idlist)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		*nids = idlist->nids;
		*ids = calloc(*nids, sizeof(**ids));
		if (*ids == NULL) {
			err = got_error_from_errno("calloc");
			break;
		}
		memcpy(*ids, (uint8_t *)imsg.data + sizeof(*idlist),
		    *nids * sizeof(**ids));
		break;
	case GOT_IMSG_OBJ_ID_LIST_DONE:
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

static const struct got_error *
send_qidlist(struct imsgbuf *ibuf, struct got_object_qid **qids, size_t nids)
{
	const struct got_error *err = NULL;
	struct got_imsg_object_id_queue idqueue;
	struct ibuf *wbuf;
	size_t i;

	memset(&idqueue, 0, sizeof(idqueue));

	if (nids > GOT_IMSG_OBJ_ID_QUEUE_MAX_NIDS)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_OBJ_ID_QUEUE, 0, 0,
	    sizeof(idqueue) + nids * sizeof(struct got_object_qid));
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create OBJ_ID_QUEUE");
		return err;
	}

	idqueue.nids = nids;
	if (imsg_add(wbuf, &idqueue, sizeof(idqueue)) == -1)
		return got_error_from_errno("imsg_add OBJ_ID_QUEUE");

	for (i = 0; i < nids; i++) {
		struct got_object_qid *qid = qids[i];
		if (imsg_add(wbuf, qid, sizeof(*qid)) == -1)
			return got_error_from_errno("imsg_add OBJ_ID_LIST");
	}

	imsg_close(ibuf, wbuf);

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_object_id_queue(struct imsgbuf *ibuf,
    struct got_object_id_queue *ids, size_t nids)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid, *qidlist[GOT_IMSG_OBJ_ID_QUEUE_MAX_NIDS];
	int i, queued = 0;

	qid = STAILQ_FIRST(ids);
	for (i = 0; qid && i < nids; i++) {
		qidlist[i % nitems(qidlist)] = qid;
		queued++;
		if (queued >= nitems(qidlist)) {
			err = send_qidlist(ibuf, qidlist, queued);
			if (err)
				return err;
			queued = 0;
		}
		qid = STAILQ_NEXT(qid, entry);
	}

	if (queued > 0) {
		err = send_qidlist(ibuf, qidlist, queued);
		if (err)
			return err;
	}

	if (imsg_compose(ibuf, GOT_IMSG_OBJ_ID_QUEUE_DONE, 0, 0, -1, NULL, 0)
	    == -1)
		return got_error_from_errno("imsg_compose OBJ_ID_QUEUE_DONE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_object_id_queue(int *done, struct got_object_id_queue *ids,
    size_t *nids, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_object_id_queue *qidlist;
	struct got_object_qid *qid, *iqid;
	size_t datalen;

	*done = 0;
	*nids = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_OBJ_ID_QUEUE:
		if (datalen < sizeof(*qidlist)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		qidlist = imsg.data;
		if (qidlist->nids > GOT_IMSG_OBJ_ID_LIST_MAX_NIDS ||
		    qidlist->nids * sizeof(struct got_object_qid) !=
		    datalen - sizeof(*qidlist)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		iqid = (struct got_object_qid *)(imsg.data + sizeof(*qidlist));
		while (*nids < qidlist->nids) {
			err = got_object_qid_alloc_partial(&qid);
			if (err)
				break;
			memcpy(qid, iqid, sizeof(*qid));
			STAILQ_INSERT_TAIL(ids, qid, entry);
			(*nids)++;
			iqid++;
		}
		break;
	case GOT_IMSG_OBJ_ID_QUEUE_DONE:
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_send_delta_reuse_req(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_DELTA_REUSE_REQUEST, 0, 0, -1, NULL, 0)
	    == -1)
		return got_error_from_errno("imsg_compose DELTA_REUSE_REQUEST");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_reused_deltas(struct imsgbuf *ibuf,
    struct got_imsg_reused_delta *deltas, size_t ndeltas)
{
	const struct got_error *err = NULL;
	struct ibuf *wbuf;
	struct got_imsg_reused_deltas ideltas;
	size_t i;

	memset(&ideltas, 0, sizeof(ideltas));

	if (ndeltas > GOT_IMSG_REUSED_DELTAS_MAX_NDELTAS)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_REUSED_DELTAS, 0, 0,
	    sizeof(ideltas) + ndeltas * sizeof(*deltas));
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REUSED_DELTAS");
		return err;
	}

	ideltas.ndeltas = ndeltas;
	if (imsg_add(wbuf, &ideltas, sizeof(ideltas)) == -1)
		return got_error_from_errno("imsg_add REUSED_DELTAS");

	for (i = 0; i < ndeltas; i++) {
		struct got_imsg_reused_delta *delta = &deltas[i];
		if (imsg_add(wbuf, delta, sizeof(*delta)) == -1)
			return got_error_from_errno("imsg_add REUSED_DELTAS");
	}

	imsg_close(ibuf, wbuf);

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_reused_deltas_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_DELTA_REUSE_DONE, 0, 0, -1, NULL, 0)
	    == -1)
		return got_error_from_errno("imsg_compose DELTA_REUSE_DONE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_reused_deltas(int *done, struct got_imsg_reused_delta *deltas,
    size_t *ndeltas, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_reused_deltas *ideltas;
	size_t datalen;

	*done = 0;
	*ndeltas = 0;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case GOT_IMSG_REUSED_DELTAS:
		if (datalen < sizeof(*ideltas)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		ideltas = imsg.data;
		if (ideltas->ndeltas > GOT_IMSG_OBJ_ID_LIST_MAX_NIDS ||
		    ideltas->ndeltas * sizeof(*deltas) >
		    datalen - sizeof(*ideltas)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		*ndeltas = ideltas->ndeltas;
		memcpy(deltas, (uint8_t *)imsg.data + sizeof(*ideltas),
		    *ndeltas * sizeof(*deltas));
		break;
	case GOT_IMSG_DELTA_REUSE_DONE:
		*done = 1;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_init_commit_painting(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_COMMIT_PAINTING_INIT,
	    0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "COMMIT_PAINTING_INIT");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_painting_request(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_COMMIT_PAINTING_REQUEST, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose "
		    "COMMIT_PAINTING_REQUEST");

	return flush_imsg(ibuf);
}

static const struct got_error *
send_painted_commits(struct got_object_id_queue *ids, int *nids,
    size_t remain, int present_in_pack, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct ibuf *wbuf = NULL;
	struct got_object_qid *qid;
	size_t msglen;
	int ncommits;
	intptr_t color;

	msglen = MIN(remain, MAX_IMSGSIZE - IMSG_HEADER_SIZE);
	ncommits = (msglen - sizeof(struct got_imsg_painted_commits)) /
	    sizeof(struct got_imsg_painted_commit);

	wbuf = imsg_create(ibuf, GOT_IMSG_PAINTED_COMMITS, 0, 0, msglen);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create PAINTED_COMMITS");
		return err;
	}

	/* Keep in sync with struct got_imsg_painted_commits! */
	if (imsg_add(wbuf, &ncommits, sizeof(ncommits)) == -1)
		return got_error_from_errno("imsg_add PAINTED_COMMITS");
	if (imsg_add(wbuf, &present_in_pack, sizeof(present_in_pack)) == -1)
		return got_error_from_errno("imsg_add PAINTED_COMMITS");

	while (ncommits > 0) {
		qid = STAILQ_FIRST(ids);
		STAILQ_REMOVE_HEAD(ids, entry);
		ncommits--;
		(*nids)--;
		color = (intptr_t)qid->data;

		/* Keep in sync with struct got_imsg_painted_commit! */
		if (imsg_add(wbuf, &qid->id, sizeof(qid->id)) == -1)
			return got_error_from_errno("imsg_add PAINTED_COMMITS");
		if (imsg_add(wbuf, &color, sizeof(color)) == -1)
			return got_error_from_errno("imsg_add PAINTED_COMMITS");

		got_object_qid_free(qid);
	}

	imsg_close(ibuf, wbuf);
	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_painted_commits(struct imsgbuf *ibuf,
    struct got_object_id_queue *ids, int *nids,
    int present_in_pack, int flush)
{
	const struct got_error *err;
	size_t remain;

	if (*nids <= 0)
		return NULL;

	do {
		remain = (sizeof(struct got_imsg_painted_commits)) +
		    *nids * sizeof(struct got_imsg_painted_commit);
		if (flush || remain >= MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
			err = send_painted_commits(ids, nids, remain,
			    present_in_pack, ibuf);
			if (err)
				return err;
		}
	} while (flush && *nids > 0);

	return NULL;
}

const struct got_error *
got_privsep_send_painting_commits_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_COMMIT_PAINTING_DONE,
	    0, 0, -1, NULL, 0)
	    == -1)
		return got_error_from_errno("imsg_compose "
		    "COMMIT_PAINTING_DONE");

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_painted_commits(struct got_object_id_queue *new_ids,
    got_privsep_recv_painted_commit_cb cb, void *cb_arg, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_painted_commits icommits;
	struct got_imsg_painted_commit icommit;
	size_t datalen;
	int i;

	for (;;) {
		err = got_privsep_recv_imsg(&imsg, ibuf, 0);
		if (err)
			return err;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (imsg.hdr.type == GOT_IMSG_COMMIT_PAINTING_DONE) {
			imsg_free(&imsg);
			return NULL;
		}
		if (imsg.hdr.type != GOT_IMSG_PAINTED_COMMITS){
			imsg_free(&imsg);
			return got_error(GOT_ERR_PRIVSEP_MSG);
		}

		if (datalen < sizeof(icommits)){
			imsg_free(&imsg);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}
		memcpy(&icommits, imsg.data, sizeof(icommits));
		if (icommits.ncommits * sizeof(icommit) < icommits.ncommits ||
		    datalen < sizeof(icommits) +
		    icommits.ncommits * sizeof(icommit)){
			imsg_free(&imsg);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}

		for (i = 0; i < icommits.ncommits; i++) {
			memcpy(&icommit,
			    (uint8_t *)imsg.data + sizeof(icommits) + i * sizeof(icommit),
			    sizeof(icommit));

			if (icommits.present_in_pack) {
				struct got_object_id id;
				memcpy(&id, &icommit.id, sizeof(id));
				err = cb(cb_arg, &id, icommit.color);
				if (err)
					break;
			} else {
				struct got_object_qid *qid;
				err = got_object_qid_alloc_partial(&qid);
				if (err)
					break;
				memcpy(&qid->id, &icommit.id,
				    sizeof(qid->id));
				qid->data = (void *)icommit.color;
				STAILQ_INSERT_TAIL(new_ids, qid, entry);
			}
		}

		imsg_free(&imsg);
		if (err)
			return err;
	}
}

const struct got_error *
got_privsep_unveil_exec_helpers(void)
{
	const char *helpers[] = {
	    GOT_PATH_PROG_READ_PACK,
	    GOT_PATH_PROG_READ_OBJECT,
	    GOT_PATH_PROG_READ_COMMIT,
	    GOT_PATH_PROG_READ_TREE,
	    GOT_PATH_PROG_READ_BLOB,
	    GOT_PATH_PROG_READ_TAG,
	    GOT_PATH_PROG_READ_GITCONFIG,
	    GOT_PATH_PROG_READ_GOTCONFIG,
	    GOT_PATH_PROG_READ_PATCH,
	    GOT_PATH_PROG_FETCH_PACK,
	    GOT_PATH_PROG_INDEX_PACK,
	    GOT_PATH_PROG_SEND_PACK,
	    /* GOT_PATH_PROG_FETCH_HTTP explicitly excluded */
	};
	size_t i;

	for (i = 0; i < nitems(helpers); i++) {
		if (unveil(helpers[i], "x") == 0)
			continue;
		return got_error_from_errno2("unveil", helpers[i]);
	}

	return NULL;
}

void
got_privsep_exec_child(int imsg_fds[2], const char *path, const char *repo_path)
{
	if (close(imsg_fds[0]) == -1) {
		fprintf(stderr, "%s: %s\n", getprogname(), strerror(errno));
		_exit(1);
	}

	if (dup2(imsg_fds[1], GOT_IMSG_FD_CHILD) == -1) {
		fprintf(stderr, "%s: %s\n", getprogname(), strerror(errno));
		_exit(1);
	}

	closefrom(GOT_IMSG_FD_CHILD + 1);

	if (execl(path, path, repo_path, (char *)NULL) == -1) {
		fprintf(stderr, "%s: %s: %s\n", getprogname(), path,
		    strerror(errno));
		_exit(1);
	}
}
