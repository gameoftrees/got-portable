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
#include <sys/types.h>

#include <event.h>
#include <errno.h>
#include <imsg.h>
#include <signal.h>
#include <stdlib.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_repository_admin.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_hash.h"
#include "got_lib_pack.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_poll.h"

#include "log.h"
#include "gotd.h"
#include "repo_read.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct repo_read {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
	int session_fd;
	struct gotd_imsgev session_iev;
	int refs_listed;
} repo_read;

static struct repo_read_client {
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	int				 report_progress;
	int				 pack_pipe;
	struct got_object_idset		*want_ids;
	struct got_object_idset		*have_ids;
} repo_read_client;

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
send_symref(struct got_reference *symref, struct got_object_id *target_id,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_symref isymref;
	const char *refname = got_ref_get_name(symref);
	const char *target = got_ref_get_symref_target(symref);
	size_t len;
	struct ibuf *wbuf;

	memset(&isymref, 0, sizeof(isymref));
	isymref.name_len = strlen(refname);
	isymref.target_len = strlen(target);
	memcpy(isymref.target_id, target_id->hash, sizeof(isymref.target_id));

	len = sizeof(isymref) + isymref.name_len + isymref.target_len;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	wbuf = imsg_create(ibuf, GOTD_IMSG_SYMREF, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create SYMREF");
		goto done;
	}

	if (imsg_add(wbuf, &isymref, sizeof(isymref)) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}
	if (imsg_add(wbuf, refname, isymref.name_len) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}
	if (imsg_add(wbuf, target, isymref.target_len) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}

	imsg_close(ibuf, wbuf);
done:
	free(target_id);
	return err;
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

	err = got_object_tag_open(&tag, repo_read.repo, obj);
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

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, GOTD_PROC_REPO_READ,
	    repo_read.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create MREF");
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

	err = got_ref_resolve(&id, repo_read.repo, ref);
	if (err)
		return err;

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, GOTD_PROC_REPO_READ,
	    repo_read.pid, len);
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

	err = got_object_open(&obj, repo_read.repo, id);
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
	struct repo_read_client *client = &repo_read_client;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	size_t datalen;
	struct gotd_imsg_reflist irefs;
	struct imsgbuf ibuf;
	struct got_object_id *head_target_id = NULL;

	TAILQ_INIT(&refs);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (repo_read.refs_listed) {
		return got_error_msg(GOT_ERR_CLIENT_ID,
		    "duplicate list-refs request");
	}
	repo_read.refs_listed = 1;

	client->fd = imsg_get_fd(imsg);
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	err = got_ref_list(&refs, repo_read.repo, "",
	    got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	memset(&irefs, 0, sizeof(irefs));
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		int obj_type;

		if (got_ref_is_symbolic(re->ref)) {
			const char *refname = got_ref_get_name(re->ref);
			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;
			err = got_ref_resolve(&head_target_id, repo_read.repo,
			    re->ref);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					return err;
				/*
				 * HEAD points to a non-existent branch.
				 * Do not advertise it.
				 * Matches git-daemon's behaviour.
				 */
				head_target_id = NULL;
				err = NULL;
			} else
				irefs.nrefs++;
			continue;
		}

		irefs.nrefs++;

		/* Account for a peeled tag refs. */
		err = got_ref_resolve(&id, repo_read.repo, re->ref);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo_read.repo, id);
		free(id);
		if (err)
			goto done;
		if (obj_type == GOT_OBJ_TYPE_TAG)
			irefs.nrefs++;
	}

	if (imsg_compose(&ibuf, GOTD_IMSG_REFLIST, GOTD_PROC_REPO_READ,
	    repo_read.pid, -1, &irefs, sizeof(irefs)) == -1) {
		err = got_error_from_errno("imsg_compose REFLIST");
		goto done;
	}

	/*
	 * Send the HEAD symref first. In Git-protocol versions < 2
	 * the HEAD symref must be announced on the initial line of
	 * the server's ref advertisement.
	 * For now, we do not advertise symrefs other than HEAD.
	 */
	TAILQ_FOREACH(re, &refs, entry) {
		if (!got_ref_is_symbolic(re->ref) ||
		    strcmp(got_ref_get_name(re->ref), GOT_REF_HEAD) != 0 ||
		    head_target_id == NULL)
			continue;
		err = send_symref(re->ref, head_target_id, &ibuf);
		if (err)
			goto done;
		break;
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
append_object_id(struct got_object_id *id, void *data, void *arg)
{
	struct gotd_object_id_array *array = arg;
	const size_t alloc_chunksz = 256;

	if (array->ids == NULL) {
		array->ids = reallocarray(NULL, alloc_chunksz,
		    sizeof(*array->ids));
		if (array->ids == NULL)
			return got_error_from_errno("reallocarray");
		array->nalloc = alloc_chunksz;
		array->nids = 0;
	} else if (array->nalloc <= array->nids) {
		struct got_object_id **new;
		new = recallocarray(array->ids, array->nalloc,
		    array->nalloc + alloc_chunksz, sizeof(*new));
		if (new == NULL)
			return got_error_from_errno("recallocarray");
		array->ids = new;
		array->nalloc += alloc_chunksz;
	}

	array->ids[array->nids] = id;
	array->nids++;
	return NULL;
}

static const struct got_error *
recv_want(struct imsg *imsg)
{
	const struct got_error *err;
	struct repo_read_client *client = &repo_read_client;
	struct gotd_imsg_want iwant;
	size_t datalen;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id id;
	int obj_type;
	struct imsgbuf ibuf;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iwant))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iwant, imsg->data, sizeof(iwant));

	memset(&id, 0, sizeof(id));
	memcpy(id.hash, iwant.object_id, SHA1_DIGEST_LENGTH);

	if (log_getverbose() > 0 &&
	    got_object_id_hex(&id, hex, sizeof(hex)))
		log_debug("client wants %s", hex);

	if (imsgbuf_init(&ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	err = got_object_get_type(&obj_type, repo_read.repo, &id);
	if (err)
		return err;

	if (obj_type != GOT_OBJ_TYPE_COMMIT &&
	    obj_type != GOT_OBJ_TYPE_TAG)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (!got_object_idset_contains(client->want_ids, &id)) {
		err = got_object_idset_add(client->want_ids, &id, NULL);
		if (err)
			return err;
	}

	gotd_imsg_send_ack(&id, &ibuf, GOTD_PROC_REPO_READ, repo_read.pid);
	imsgbuf_clear(&ibuf);
	return err;
}

static const struct got_error *
recv_have(struct imsg *imsg)
{
	const struct got_error *err;
	struct repo_read_client *client = &repo_read_client;
	struct gotd_imsg_have ihave;
	size_t datalen;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id id;
	int obj_type;
	struct imsgbuf ibuf;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ihave))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ihave, imsg->data, sizeof(ihave));

	memset(&id, 0, sizeof(id));
	memcpy(id.hash, ihave.object_id, SHA1_DIGEST_LENGTH);

	if (log_getverbose() > 0 &&
	    got_object_id_hex(&id, hex, sizeof(hex)))
		log_debug("client has %s", hex);

	if (imsgbuf_init(&ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	err = got_object_get_type(&obj_type, repo_read.repo, &id);
	if (err) {
		if (err->code == GOT_ERR_NO_OBJ) {
			gotd_imsg_send_nak(&id, &ibuf,
			    GOTD_PROC_REPO_READ, repo_read.pid);
			err = NULL;
		}
		goto done;
	}

	if (obj_type != GOT_OBJ_TYPE_COMMIT &&
	    obj_type != GOT_OBJ_TYPE_TAG) {
		gotd_imsg_send_nak(&id, &ibuf, GOTD_PROC_REPO_READ,
		    repo_read.pid);
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	if (!got_object_idset_contains(client->have_ids, &id)) {
		err = got_object_idset_add(client->have_ids, &id, NULL);
		if (err)
			goto done;
	}

	gotd_imsg_send_ack(&id, &ibuf, GOTD_PROC_REPO_READ, repo_read.pid);
done:
	imsgbuf_clear(&ibuf);
	return err;
}

struct repo_read_pack_progress_arg {
	int report_progress;
	struct imsgbuf *ibuf;
	int sent_ready;
};

static const struct got_error *
pack_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written, int pack_done)
{
	struct repo_read_pack_progress_arg *a = arg;
	struct gotd_imsg_packfile_progress iprog;
	int ret;

	if (!a->report_progress)
		return NULL;
	if (packfile_size > 0 && a->sent_ready)
		return NULL;

	memset(&iprog, 0, sizeof(iprog));
	iprog.ncolored = ncolored;
	iprog.nfound = nfound;
	iprog.ntrees = ntrees;
	iprog.packfile_size = packfile_size;
	iprog.ncommits = ncommits;
	iprog.nobj_total = nobj_total;
	iprog.nobj_deltify = nobj_deltify;
	iprog.nobj_written = nobj_written;

	/* Using synchronous writes since we are blocking the event loop. */
	if (packfile_size == 0) {
		ret = imsg_compose(a->ibuf, GOTD_IMSG_PACKFILE_PROGRESS,
		    GOTD_PROC_REPO_READ, repo_read.pid, -1,
		    &iprog, sizeof(iprog));
		if (ret == -1) {
			return got_error_from_errno("imsg compose "
			    "PACKFILE_PROGRESS");
		}
	} else {
		a->sent_ready = 1;
		ret = imsg_compose(a->ibuf, GOTD_IMSG_PACKFILE_READY,
		    GOTD_PROC_REPO_READ, repo_read.pid, -1,
		    &iprog, sizeof(iprog));
		if (ret == -1) {
			return got_error_from_errno("imsg compose "
			    "PACKFILE_READY");
		}
	}

	return gotd_imsg_flush(a->ibuf);
}

static const struct got_error *
receive_delta_cache_fd(struct imsg *imsg,
    struct gotd_imsgev *iev)
{
	struct repo_read_client *client = &repo_read_client;
	struct gotd_imsg_send_packfile ireq;
	size_t datalen;

	log_debug("receiving delta cache file");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (client->delta_cache_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->delta_cache_fd = imsg_get_fd(imsg);
	if (client->delta_cache_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	client->report_progress = ireq.report_progress;
	return NULL;
}

static const struct got_error *
receive_pack_pipe(struct imsg *imsg, struct gotd_imsgev *iev)
{
	struct repo_read_client *client = &repo_read_client;
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
send_packfile(struct imsg *imsg, struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct repo_read_client *client = &repo_read_client;
	struct got_object_id packhash;
	char hex[GOT_HASH_DIGEST_STRING_MAXLEN];
	FILE *delta_cache = NULL;
	struct imsgbuf ibuf;
	struct repo_read_pack_progress_arg pa;
	struct got_ratelimit rl;
	struct gotd_object_id_array want_ids;
	struct gotd_object_id_array have_ids;

	log_debug("packfile request received");

	memset(&want_ids, 0, sizeof(want_ids));
	memset(&have_ids, 0, sizeof(have_ids));

	got_ratelimit_init(&rl, 2, 0);

	if (client->delta_cache_fd == -1 || client->pack_pipe == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	delta_cache = fdopen(client->delta_cache_fd, "w+");
	if (delta_cache == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	client->delta_cache_fd = -1;

	memset(&pa, 0, sizeof(pa));
	pa.ibuf = &ibuf;
	pa.report_progress = client->report_progress;

	err = got_object_idset_for_each(client->want_ids,
	    append_object_id, &want_ids);
	if (err)
		goto done;
	err = got_object_idset_for_each(client->have_ids,
	   append_object_id, &have_ids);
	if (err)
		goto done;

	err = got_pack_create(&packhash, client->pack_pipe, delta_cache,
	    have_ids.ids, have_ids.nids, want_ids.ids, want_ids.nids,
	    repo_read.repo, 0, 1, 0, pack_progress, &pa, &rl,
	    check_cancelled, NULL);
	if (err)
		goto done;

	if (log_getverbose() > 0 &&
	    got_hash_digest_to_str(packhash.hash, hex, sizeof(hex),
	    packhash.algo))
		log_debug("sent pack-%s.pack", hex);

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_DONE,
	    GOTD_PROC_REPO_READ, -1, NULL, 0) == -1)
		err = got_error_from_errno("imsg compose PACKFILE_DONE");
done:
	if (client->delta_cache_fd != -1 &&
	    close(client->delta_cache_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	client->delta_cache_fd = -1;
	if (delta_cache != NULL && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	imsgbuf_clear(&ibuf);
	free(want_ids.ids);
	free(have_ids.ids);
	return err;
}

static void
repo_read_dispatch_session(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	struct repo_read_client *client = &repo_read_client;

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

	while (err == NULL && check_cancelled(NULL) == NULL) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		if (imsg.hdr.type != GOTD_IMSG_LIST_REFS_INTERNAL &&
		    !repo_read.refs_listed) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_LIST_REFS_INTERNAL:
			err = list_refs(&imsg);
			if (err)
				log_warnx("ls-refs: %s", err->msg);
			break;
		case GOTD_IMSG_WANT:
			err = recv_want(&imsg);
			if (err)
				log_warnx("want-line: %s", err->msg);
			break;
		case GOTD_IMSG_HAVE:
			err = recv_have(&imsg);
			if (err)
				log_warnx("have-line: %s", err->msg);
			break;
		case GOTD_IMSG_SEND_PACKFILE:
			err = receive_delta_cache_fd(&imsg, iev);
			if (err)
				log_warnx("receiving delta cache: %s",
				    err->msg);
			break;
		case GOTD_IMSG_PACKFILE_PIPE:
			err = receive_pack_pipe(&imsg, iev);
			if (err) {
				log_warnx("receiving pack pipe: %s", err->msg);
				break;
			}
			err = send_packfile(&imsg, iev);
			if (err)
				log_warnx("sending packfile: %s", err->msg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err &&
		    gotd_imsg_send_error_event(iev, GOTD_PROC_REPO_READ,
		        client->id, err) == -1) {
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
	struct gotd_imsgev *iev = &repo_read.session_iev;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (repo_read.session_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	repo_read.session_fd = imsg_get_fd(imsg);
	if (repo_read.session_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&iev->ibuf, repo_read.session_fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = repo_read_dispatch_session;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ,
	    repo_read_dispatch_session, iev);
	gotd_imsg_event_add(iev);

	return NULL;
}

static void
repo_read_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	struct repo_read_client *client = &repo_read_client;

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

	while (err == NULL && check_cancelled(NULL) == NULL) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_connect(&imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err &&
		    gotd_imsg_send_error_event(iev, GOTD_PROC_REPO_READ,
		        client->id, err) == -1) {
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

void
repo_read_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds)
{
	const struct got_error *err = NULL;
	struct repo_read_client *client = &repo_read_client;
	struct gotd_imsgev iev;

	client->fd = -1;
	client->delta_cache_fd = -1;
	client->pack_pipe = -1;
	client->have_ids = got_object_idset_alloc();
	if (client->have_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}
	client->want_ids = got_object_idset_alloc();
	if (client->want_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	repo_read.title = title;
	repo_read.pid = getpid();
	repo_read.pack_fds = pack_fds;
	repo_read.temp_fds = temp_fds;
	repo_read.session_fd = -1;
	repo_read.session_iev.ibuf.fd = -1;

	err = got_repo_open(&repo_read.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(repo_read.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}
	if (got_repo_get_object_format(repo_read.repo) != GOT_HASH_SHA1) {
		err = got_error_msg(GOT_ERR_NOT_IMPL,
		    "sha256 object IDs unsupported in network protocol");
		goto done;
	}

	got_repo_temp_fds_set(repo_read.repo, temp_fds);

	signal(SIGINT, catch_sigint);
	signal(SIGTERM, catch_sigterm);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if (imsgbuf_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = repo_read_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, repo_read_dispatch, &iev);

	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_REPO_CHILD_READY,
	    GOTD_PROC_REPO_READ, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose REPO_CHILD_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	repo_read_shutdown();
}

void
repo_read_shutdown(void)
{
	struct repo_read_client *client = &repo_read_client;

	log_debug("%s: shutting down", repo_read.title);

	if (client->have_ids)
		got_object_idset_free(client->have_ids);
	if (client->want_ids)
		got_object_idset_free(client->want_ids);
	if (client->fd != -1)
		close(client->fd);
	if (client->delta_cache_fd != -1)
		close(client->delta_cache_fd);
	if (client->pack_pipe != -1)
		close(client->pack_pipe);

	if (repo_read.repo)
		got_repo_close(repo_read.repo);
	got_repo_pack_fds_close(repo_read.pack_fds);
	got_repo_temp_fds_close(repo_read.temp_fds);
	if (repo_read.session_fd != -1)
		close(repo_read.session_fd);
	exit(0);
}
