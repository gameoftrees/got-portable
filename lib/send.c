/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2023 Josh Rickmar <jrick@zettaport.com>
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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"
#include "got_opentemp.h"
#include "got_send.h"
#include "got_repository_admin.h"
#include "got_commit_graph.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_dial.h"
#include "got_lib_worktree_cvg.h"
#include "got_lib_poll.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ssizeof
#define ssizeof(_x) ((ssize_t)(sizeof(_x)))
#endif

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
got_send_connect(pid_t *sendpid, int *sendfd, const char *proto,
    const char *host, const char *port, const char *server_path,
    const char *jumphost, const char *identity_file, int verbosity)
{
	const struct got_error *err = NULL;

	*sendpid = -1;
	*sendfd = -1;

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = got_dial_ssh(sendpid, sendfd, host, port, server_path,
		    jumphost, identity_file, GOT_DIAL_CMD_SEND, verbosity);
	else if (strcmp(proto, "git") == 0)
		err = got_dial_git(sendfd, host, port, server_path,
		    GOT_DIAL_CMD_SEND);
	else if (strcmp(proto, "http") == 0 || strcmp(proto, "git+http") == 0)
		err = got_error_path(proto, GOT_ERR_NOT_IMPL);
	else
		err = got_error_path(proto, GOT_ERR_BAD_PROTO);
	return err;
}

struct pack_progress_arg {
    got_send_progress_cb progress_cb;
    void *progress_arg;
    int sendfd;

    int ncolored;
    int nfound;
    int ntrees;
    off_t packfile_size;
    int ncommits;
    int nobj_total;
    int nobj_deltify;
    int nobj_written;
};

static const struct got_error *
pack_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written, int pack_done)
{
	const struct got_error *err;
	struct pack_progress_arg *a = arg;

	err = a->progress_cb(a->progress_arg, ncolored, nfound, ntrees,
	    packfile_size, ncommits, nobj_total, nobj_deltify,
	    nobj_written, 0, NULL, NULL, 0);
	if (err)
		return err;

	/*
	 * Detect the server closing our connection while we are
	 * busy creating a pack file.
	 *
	 * XXX This should be a temporary workaround. A better fix would
	 * be to avoid use of an on-disk tempfile for pack file data.
	 * Instead we could stream pack file data to got-send-pack while
	 * the pack file is being generated. Write errors in got-send-pack
	 * would then automatically abort the creation of pack file data.
	 */
	err = got_poll_fd(a->sendfd, 0, 0);
	if (err && err->code != GOT_ERR_TIMEOUT) {
		if (err->code == GOT_ERR_EOF) {
			err = got_error_msg(GOT_ERR_EOF,
			    "server unexpectedly closed the connection");
		}
		return err;
	}

	a->ncolored= ncolored;
	a->nfound = nfound;
	a->ntrees = ntrees;
	a->packfile_size = packfile_size;
	a->ncommits = ncommits;
	a->nobj_total = nobj_total;
	a->nobj_deltify = nobj_deltify;
	a->nobj_written = nobj_written;
	return NULL;
}

static const struct got_error *
insert_sendable_ref(struct got_pathlist_head *refs, const char *refname,
    const char *target_refname, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *ref;
	struct got_object_id *id = NULL;
	struct got_pathlist_entry *new = NULL;
	int obj_type;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		return err;

	if (got_ref_is_symbolic(ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "cannot send symbolic reference %s", refname);
		goto done;
	}

	err = got_ref_resolve(&id, repo, ref);
	if (err)
		goto done;
	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		goto done;
	switch (obj_type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TAG:
		break;
	default:
		err = got_error_fmt(GOT_ERR_OBJ_TYPE, "cannot send %s",
		    refname);
		goto done;
	}

	err = got_pathlist_insert(&new, refs, target_refname, id);
	if (new == NULL && err == NULL)
		err = got_error(GOT_ERR_REF_DUP_ENTRY);

done:
	if (ref)
		got_ref_close(ref);
	if (err)
		free(id);
	return err;
}

static const struct got_error *
check_common_ancestry(const char *refname, struct got_object_id *my_id,
    struct got_object_id *their_id, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id *yca_id;
	int obj_type;

	err = got_object_get_type(&obj_type, repo, their_id);
	if (err)
		return err;
	if (obj_type != GOT_OBJ_TYPE_COMMIT)
		return got_error_fmt(GOT_ERR_OBJ_TYPE,
		    "bad object type on server for %s", refname);

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    my_id, their_id, 0, 1, repo, cancel_cb, cancel_arg);
	if (err)
		return err;
	if (yca_id == NULL)
		return got_error_fmt(GOT_ERR_SEND_ANCESTRY, "%s", refname);

	if (got_object_id_cmp(their_id, yca_id) != 0)
		err = got_error_fmt(GOT_ERR_SEND_ANCESTRY, "%s", refname);

	free(yca_id);
	return err;
}

static const struct got_error *
realloc_ids(struct got_object_id ***ids, size_t *nalloc, size_t n)
{
	struct got_object_id **new;
	const size_t alloc_chunksz = 256;

	if (*nalloc >= n)
		return NULL;

	new = recallocarray(*ids, *nalloc, *nalloc + alloc_chunksz,
	    sizeof(struct got_object_id));
	if (new == NULL)
		return got_error_from_errno("recallocarray");

	*ids = new;
	*nalloc += alloc_chunksz;
	return NULL;
}

static struct got_pathlist_entry *
find_ref(struct got_pathlist_head *refs, const char *refname)
{
	struct got_pathlist_entry find;

	find.path = refname;
	find.path_len = strlen(refname);
	return RB_FIND(got_pathlist_head, refs, &find);

}

static const struct got_error *
get_remote_refname(char **remote_refname, const char *remote_name,
    const char *refname)
{
	if (strncmp(refname, "refs/", 5) == 0)
		refname += 5;
	if (strncmp(refname, "heads/", 6) == 0)
		refname += 6;

	if (asprintf(remote_refname, "refs/remotes/%s/%s",
	    remote_name, refname) == -1)
		return got_error_from_errno("asprintf");

	return NULL;
}

static const struct got_error *
update_remote_ref(struct got_pathlist_entry *my_ref, const char *remote_name,
    struct got_repository *repo)
{
	const struct got_error *err, *unlock_err;
	const char *refname = my_ref->path;
	struct got_object_id *my_id = my_ref->data;
	struct got_reference *ref = NULL;
	char *remote_refname = NULL;
	int ref_locked = 0;

	err = get_remote_refname(&remote_refname, remote_name, refname);
	if (err)
		goto done;

	err = got_ref_open(&ref, repo, remote_refname, 1 /* lock */);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = got_ref_alloc(&ref, remote_refname, my_id);
		if (err)
			goto done;
	} else {
		ref_locked = 1;
		err = got_ref_change_ref(ref, my_id);
		if (err)
			goto done;
	}

	err = got_ref_write(ref, repo);
done:
	if (ref) {
		if (ref_locked) {
			unlock_err = got_ref_unlock(ref);
			if (unlock_err && err == NULL)
				err = unlock_err;
		}
		got_ref_close(ref);
	}
	free(remote_refname);
	return err;
}

const struct got_error*
got_send_pack(const char *remote_name, struct got_pathlist_head *branch_names,
    struct got_pathlist_head *tag_names,
    struct got_pathlist_head *delete_branches,
    int verbosity, int overwrite_refs, int sendfd,
    struct got_repository *repo, got_send_progress_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	int imsg_sendfds[2] = { -1, -1 };
	int npackfd = -1, nsendfd = -1;
	int sendstatus, done = 0;
	const struct got_error *err;
	struct imsgbuf sendibuf;
	pid_t sendpid = -1;
	struct got_pathlist_head have_refs;
	struct got_pathlist_head their_refs;
	struct got_pathlist_entry *pe;
	struct got_object_id **our_ids = NULL;
	struct got_object_id **their_ids = NULL;
	int nours = 0, ntheirs = 0;
	size_t nalloc_ours = 0, nalloc_theirs = 0;
	int refs_to_send = 0, refs_to_delete = 0;
	off_t bytes_sent = 0, bytes_sent_cur = 0;
	struct pack_progress_arg ppa;
	struct got_object_id packhash;
	int packfd = -1;
	FILE *delta_cache = NULL;
	char *s = NULL;

	RB_INIT(&have_refs);
	RB_INIT(&their_refs);

	memset(&sendibuf, 0, sizeof(sendibuf));

	RB_FOREACH(pe, got_pathlist_head, branch_names) {
		const char *branchname = pe->path;
		const char *targetname = pe->data;

		if (targetname == NULL)
			targetname = branchname;

		if (strncmp(targetname, "refs/heads/", 11) != 0) {
			if (asprintf(&s, "refs/heads/%s", targetname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		} else {
			if ((s = strdup(targetname)) == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}
		err = insert_sendable_ref(&have_refs, branchname, s, repo);
		if (err) {
			if (err->code != GOT_ERR_REF_DUP_ENTRY)
				goto done;
			err = NULL;
			free(s);
		}
		s = NULL;
	}

	RB_FOREACH(pe, got_pathlist_head, delete_branches) {
		const char *branchname = pe->path;
		struct got_pathlist_entry *ref;
		if (strncmp(branchname, "refs/heads/", 11) != 0) {
			err = got_error_fmt(GOT_ERR_SEND_DELETE_REF, "%s",
			    branchname);
			goto done;
		}
		ref = find_ref(&have_refs, branchname);
		if (ref) {
			err = got_error_fmt(GOT_ERR_SEND_DELETE_REF,
			    "changes on %s will be sent to server",
			    branchname);
			goto done;
		}
	}

	RB_FOREACH(pe, got_pathlist_head, tag_names) {
		const char *tagname = pe->path;
		if (strncmp(tagname, "refs/tags/", 10) != 0) {
			if (asprintf(&s, "refs/tags/%s", tagname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		} else {
			if ((s = strdup(pe->path)) == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}
		err = insert_sendable_ref(&have_refs, s, s, repo);
		if (err) {
			if (err->code != GOT_ERR_REF_DUP_ENTRY)
				goto done;
			err = NULL;
			free(s);
		}
		s = NULL;
	}

	if (RB_EMPTY(&have_refs) && RB_EMPTY(delete_branches)) {
		err = got_error(GOT_ERR_SEND_EMPTY);
		goto done;
	}

	packfd = got_opentempfd();
	if (packfd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_sendfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	sendpid = fork();
	if (sendpid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (sendpid == 0) {
		got_privsep_exec_child(imsg_sendfds,
		    GOT_PATH_PROG_SEND_PACK, got_repo_get_path(repo));
	}

	if (close(imsg_sendfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_sendfds[1] = -1;
	if (imsgbuf_init(&sendibuf, imsg_sendfds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&sendibuf);
	nsendfd = dup(sendfd);
	if (nsendfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	/*
	 * Prepare the array of our object IDs which
	 * will be needed for generating a pack file.
	 */
	RB_FOREACH(pe, got_pathlist_head,  &have_refs) {
		struct got_object_id *id = pe->data;

		err = realloc_ids(&our_ids, &nalloc_ours, nours + 1);
		if (err)
			goto done;
		our_ids[nours] = id;
		nours++;
	}

	err = got_privsep_send_send_req(&sendibuf, nsendfd,
	    got_repo_get_object_format(repo), &have_refs,
	    delete_branches, verbosity);
	if (err)
		goto done;
	nsendfd = -1;

	err = got_privsep_recv_send_remote_refs(&their_refs, &sendibuf);
	if (err)
		goto done;
	/*
	 * Process references reported by the server.
	 * Push appropriate object IDs onto the "their IDs" array.
	 * This array will be used to exclude objects which already
	 * exist on the server from our pack file.
	 */
	RB_FOREACH(pe, got_pathlist_head, &their_refs) {
		const char *refname = pe->path;
		struct got_object_id *their_id = pe->data;
		int have_their_id;
		struct got_object *obj;
		struct got_pathlist_entry *my_ref = NULL;
		int is_tag = 0;

		/* Don't blindly trust the server to send us valid names. */
		if (!got_ref_name_is_valid(refname))
			continue;

		if (strncmp(refname, "refs/tags/", 10) == 0)
			is_tag = 1;
		/*
		 * Find out whether this is a reference we want to upload.
		 * Otherwise we can still use this reference as a hint to
		 * avoid uploading any objects the server already has.
		 */
		my_ref = find_ref(&have_refs, refname);
		if (my_ref) {
			struct got_object_id *my_id = my_ref->data;
			if (got_object_id_cmp(my_id, their_id) != 0) {
				if (!overwrite_refs && is_tag) {
					err = got_error_fmt(
					    GOT_ERR_SEND_TAG_EXISTS,
					    "%s", refname);
					goto done;
				}
				refs_to_send++;
			}
		}

		/* Check if their object exists locally. */
		err = got_object_open(&obj, repo, their_id);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				goto done;
			if (!overwrite_refs && my_ref != NULL) {
				err = got_error_fmt(GOT_ERR_SEND_ANCESTRY,
				    "%s", refname);
				goto done;
			}
			have_their_id = 0;
		} else {
			got_object_close(obj);
			have_their_id = 1;
		}

		err = realloc_ids(&their_ids, &nalloc_theirs, ntheirs + 1);
		if (err)
			goto done;

		if (have_their_id) {
			/* Enforce linear ancestry if required. */
			if (!overwrite_refs && my_ref && !is_tag) {
				struct got_object_id *my_id = my_ref->data;
				err = check_common_ancestry(refname, my_id,
				    their_id, repo, cancel_cb, cancel_arg);
				if (err)
					goto done;
			}
			/* Exclude any objects reachable via their ID. */
			their_ids[ntheirs] = their_id;
			ntheirs++;
		} else if (!is_tag) {
			char *remote_refname;
			struct got_reference *ref;
			/*
			 * Exclude any objects which exist on the server
			 * according to a locally cached remote reference.
			 */
			err = get_remote_refname(&remote_refname,
			    remote_name, refname);
			if (err)
				goto done;
			err = got_ref_open(&ref, repo, remote_refname, 0);
			free(remote_refname);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					goto done;
				err = NULL;
			} else {
				err = got_ref_resolve(&their_ids[ntheirs],
				    repo, ref);
				got_ref_close(ref);
				if (err)
					goto done;
				ntheirs++;
			}
		}
	}

	/* Account for any new references we are going to upload. */
	RB_FOREACH(pe, got_pathlist_head, &have_refs) {
		const char *refname = pe->path;
		if (find_ref(&their_refs, refname) == NULL)
			refs_to_send++;
	}

	/* Account for any existing references we are going to delete. */
	RB_FOREACH(pe, got_pathlist_head, delete_branches) {
		const char *branchname = pe->path;
		if (find_ref(&their_refs, branchname))
			refs_to_delete++;
	}

	if (refs_to_send == 0 && refs_to_delete == 0) {
		got_privsep_send_stop(imsg_sendfds[0]);
		goto done;
	}

	if (refs_to_send > 0) {
		struct got_ratelimit rl;
		got_ratelimit_init(&rl, 0, 500);
		memset(&ppa, 0, sizeof(ppa));
		ppa.progress_cb = progress_cb;
		ppa.progress_arg = progress_arg;
		ppa.sendfd = sendfd;
		err = got_pack_create(&packhash, packfd, delta_cache,
		    their_ids, ntheirs, our_ids, nours, repo, 0, 1, 0,
		    pack_progress, &ppa, &rl, cancel_cb, cancel_arg);
		if (err)
			goto done;

		npackfd = dup(packfd);
		if (npackfd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}
		err = got_privsep_send_packfd(&sendibuf, npackfd);
		if (err != NULL)
			goto done;
		npackfd = -1;
	} else {
		err = got_privsep_send_packfd(&sendibuf, -1);
		if (err != NULL)
			goto done;
	}

	while (!done) {
		int success = 0;
		char *refname = NULL;
		char *errmsg = NULL;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				goto done;
		}
		err = got_privsep_recv_send_progress(&done, &bytes_sent,
		    &success, &refname, &errmsg, &sendibuf);
		if (err)
			goto done;
		if (refname && got_ref_name_is_valid(refname) && success &&
		    strncmp(refname, "refs/tags/", 10) != 0) {
			struct got_pathlist_entry *my_ref;
			/*
			 * The server has accepted our changes.
			 * Update our reference in refs/remotes/ accordingly.
			 */
			my_ref = find_ref(&have_refs, refname);
			if (my_ref) {
				err = update_remote_ref(my_ref, remote_name,
				    repo);
				if (err)
					goto done;
			}
		}
		if (refname != NULL ||
		    bytes_sent_cur != bytes_sent) {
			err = progress_cb(progress_arg, ppa.ncolored,
			    ppa.nfound, ppa.ntrees, ppa.packfile_size,
			    ppa.ncommits, ppa.nobj_total, ppa.nobj_deltify,
			    ppa.nobj_written, bytes_sent,
			    refname, errmsg, success);
			if (err) {
				free(refname);
				free(errmsg);
				goto done;
			}
			bytes_sent_cur = bytes_sent;
		}
		free(refname);
		free(errmsg);
	}
done:
	if (sendibuf.w)
		imsgbuf_clear(&sendibuf);
	if (sendpid != -1) {
		if (err)
			got_privsep_send_stop(imsg_sendfds[0]);
		if (waitpid(sendpid, &sendstatus, 0) == -1 && err == NULL)
			err = got_error_from_errno("waitpid");
	}
	if (imsg_sendfds[0] != -1 && close(imsg_sendfds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_sendfds[1] != -1 && close(imsg_sendfds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (nsendfd != -1 && close(nsendfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");

	got_pathlist_free(&have_refs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&their_refs, GOT_PATHLIST_FREE_ALL);
	/*
	 * Object ids are owned by have_refs/their_refs and are already freed;
	 * Only the arrays must be freed.
	 */
	free(our_ids);
	free(their_ids);
	free(s);
	return err;
}
