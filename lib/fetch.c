/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <endian.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <sha2.h>
#include <unistd.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <imsg.h>
#include <time.h>
#include <uuid.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"
#include "got_opentemp.h"
#include "got_fetch.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"
#include "got_lib_dial.h"
#include "got_lib_pkt.h"

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
got_fetch_connect(pid_t *fetchpid, int *fetchfd, const char *proto,
    const char *host, const char *port, const char *server_path,
    const char *jumphost, const char *identity_file, int verbosity)
{
	const struct got_error *err = NULL;

	*fetchpid = -1;
	*fetchfd = -1;

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = got_dial_ssh(fetchpid, fetchfd, host, port,
		    server_path, jumphost, identity_file, GOT_DIAL_CMD_FETCH,
		    verbosity);
	else if (strcmp(proto, "git") == 0)
		err = got_dial_git(fetchfd, host, port, server_path,
		    GOT_DIAL_CMD_FETCH);
	else if (strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+http") == 0 ||
	    strcmp(proto, "https") == 0 ||
	    strcmp(proto, "git+https") == 0)
		err = got_dial_http(fetchpid, fetchfd, host, port,
		    server_path, verbosity, strstr(proto, "https") != NULL);
	else
		err = got_error_path(proto, GOT_ERR_BAD_PROTO);
	return err;
}

const struct got_error *
got_fetch_pack(struct got_object_id **pack_hash, struct got_pathlist_head *refs,
    struct got_pathlist_head *symrefs, const char *remote_name,
    int mirror_references, int fetch_all_branches,
    struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, int list_refs_only, int verbosity,
    int fetchfd, struct got_repository *repo, const char *worktree_refname,
    const char *remote_head, int no_head, got_fetch_progress_cb progress_cb,
    void *progress_arg)
{
	size_t i;
	int imsg_fetchfds[2], imsg_idxfds[2];
	int packfd = -1, npackfd = -1, idxfd = -1, nidxfd = -1, nfetchfd = -1;
	int tmpfds[3];
	int fetchstatus, idxstatus, done = 0;
	const struct got_error *err;
	struct imsgbuf fetchibuf, idxibuf;
	pid_t fetchpid, idxpid;
	char *tmppackpath = NULL, *tmpidxpath = NULL;
	char *packpath = NULL, *idxpath = NULL, *id_str = NULL;
	const char *repo_path = NULL;
	struct got_pathlist_head have_refs;
	struct got_pathlist_entry *pe, *new;
	struct got_reflist_head my_refs;
	struct got_reflist_entry *re;
	off_t packfile_size = 0;
	struct got_packfile_hdr pack_hdr;
	uint32_t nobj = 0;
	char *path;
	char *progress = NULL;
	enum got_hash_algorithm algo = GOT_HASH_SHA1;
	size_t idlen;

	*pack_hash = NULL;
	memset(&fetchibuf, 0, sizeof(fetchibuf));
	memset(&idxibuf, 0, sizeof(idxibuf));

	/*
	 * Prevent fetching of references that won't make any
	 * sense outside of the remote repository's context.
	 */
	RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
		const char *refname = pe->path;
		if (strncmp(refname, "refs/got/", 9) == 0 ||
		    strncmp(refname, "got/", 4) == 0 ||
		    strncmp(refname, "refs/remotes/", 13) == 0 ||
		    strncmp(refname, "remotes/", 8) == 0)
			return got_error_path(refname, GOT_ERR_FETCH_BAD_REF);
	}

	/* for listing refs we don't actually care about the algorithm */
	if (!list_refs_only)
		algo = got_repo_get_object_format(repo);

	idlen = got_hash_digest_length(algo);

	if (!list_refs_only)
		repo_path = got_repo_get_path_git_dir(repo);

	for (i = 0; i < nitems(tmpfds); i++)
		tmpfds[i] = -1;

	RB_INIT(&have_refs);
	TAILQ_INIT(&my_refs);

	if (!list_refs_only) {
		err = got_ref_list(&my_refs, repo, NULL,
		    got_ref_cmp_by_name, NULL);
		if (err)
			goto done;
	}

	TAILQ_FOREACH(re, &my_refs, entry) {
		struct got_object_id *id;
		char *refname;

		if (got_ref_is_symbolic(re->ref))
			continue;

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			goto done;
		refname = strdup(got_ref_get_name(re->ref));
		if (refname == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		err = got_pathlist_insert(&new, &have_refs, refname, id);
		if (err)
			goto done;
		if (new == NULL){
			free(refname);
			free(id);
		}
	}

	if (list_refs_only) {
		packfd = got_opentempfd();
		if (packfd == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	} else {
		if (asprintf(&path, "%s/%s/fetching.pack",
		    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = got_opentemp_named_fd(&tmppackpath, &packfd, path, "");
		free(path);
		if (err)
			goto done;
		if (fchmod(packfd, GOT_DEFAULT_FILE_MODE) != 0) {
			err = got_error_from_errno2("fchmod", tmppackpath);
			goto done;
		}
	}
	if (list_refs_only) {
		idxfd = got_opentempfd();
		if (idxfd == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	} else {
		if (asprintf(&path, "%s/%s/fetching.idx",
		    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = got_opentemp_named_fd(&tmpidxpath, &idxfd, path, "");
		free(path);
		if (err)
			goto done;
		if (fchmod(idxfd, GOT_DEFAULT_FILE_MODE) != 0) {
			err = got_error_from_errno2("fchmod", tmpidxpath);
			goto done;
		}
	}
	nidxfd = dup(idxfd);
	if (nidxfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	for (i = 0; i < nitems(tmpfds); i++) {
		tmpfds[i] = got_opentempfd();
		if (tmpfds[i] == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fetchfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	fetchpid = fork();
	if (fetchpid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (fetchpid == 0){
		got_privsep_exec_child(imsg_fetchfds,
		    GOT_PATH_PROG_FETCH_PACK, tmppackpath);
	}

	if (close(imsg_fetchfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (imsgbuf_init(&fetchibuf, imsg_fetchfds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&fetchibuf);
	nfetchfd = dup(fetchfd);
	if (nfetchfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_fetch_req(&fetchibuf, nfetchfd, algo, &have_refs,
	    fetch_all_branches, wanted_branches, wanted_refs,
	    list_refs_only, worktree_refname, remote_head, no_head, verbosity);
	if (err != NULL)
		goto done;
	nfetchfd = -1;
	npackfd = dup(packfd);
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_fetch_outfd(&fetchibuf, npackfd);
	if (err != NULL)
		goto done;
	npackfd = -1;

	packfile_size = 0;
	progress = calloc(GOT_PKT_MAX, 1);
	if (progress == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	*pack_hash = calloc(1, sizeof(**pack_hash));
	if (*pack_hash == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	while (!done) {
		struct got_object_id *id = NULL;
		char *refname = NULL;
		char *server_progress = NULL;
		off_t packfile_size_cur = 0;

		err = got_privsep_recv_fetch_progress(&done,
		    &id, &refname, symrefs, &server_progress,
		    &packfile_size_cur, *pack_hash, &fetchibuf);
		if (err != NULL)
			goto done;
		/* Don't report size progress for an empty pack file. */
		if (packfile_size_cur <= ssizeof(pack_hdr) + idlen)
			packfile_size_cur = 0;
		if (!done && refname && id) {
			err = got_pathlist_insert(&pe, refs, refname, id);
			if (err || pe == NULL) {
				free(id);
				free(refname);
				if (err != NULL)
					goto done;
			}
		} else if (!done && server_progress) {
			char *p;
			/*
			 * XXX git-daemon tends to send batched output with
			 * lines spanning separate packets. Buffer progress
			 * output until we see a CR or LF to avoid giving
			 * partial lines of progress output to the callback.
			 */
			if (strlcat(progress, server_progress,
			    GOT_PKT_MAX) >= GOT_PKT_MAX) {
				progress[0] = '\0'; /* discard */
				continue;
			}
			while ((p = strchr(progress, '\r')) != NULL ||
			    (p = strchr(progress, '\n')) != NULL) {
				char *s;
				size_t n;
				char c = *p;
				*p = '\0';
				if (asprintf(&s, "%s%s", progress,
				    c == '\n' ? "\n" : "") == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
				err = progress_cb(progress_arg, s,
				    packfile_size_cur, 0, 0, 0, 0);
				free(s);
				if (err)
					break;
				n = strlen(progress);
				if (n < GOT_PKT_MAX - 1) {
					memmove(progress, &progress[n + 1],
					    GOT_PKT_MAX - n - 1);
				} else
					progress[0] = '\0';
			}
			free(server_progress);
			if (err)
				goto done;
		} else if (!done && packfile_size_cur != packfile_size) {
			err = progress_cb(progress_arg, NULL,
			    packfile_size_cur, 0, 0, 0, 0);
			if (err)
				break;
			packfile_size = packfile_size_cur;
		}
	}
	if (close(imsg_fetchfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(fetchpid, &fetchstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	if ((*pack_hash)->algo != algo) {
		err = got_error(GOT_ERR_OBJECT_FORMAT);
		goto done;
	}

	/* If zero data was fetched without error we are already up-to-date. */
	if (packfile_size == 0) {
		free(*pack_hash);
		*pack_hash = NULL;
		goto done;
	} else if (packfile_size < ssizeof(pack_hdr) + idlen) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE, "short pack file");
		goto done;
	} else {
		ssize_t n;

		n = read(packfd, &pack_hdr, ssizeof(pack_hdr));
		if (n == -1) {
			err = got_error_from_errno("read");
			goto done;
		}
		if (n != ssizeof(pack_hdr)) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
		if (pack_hdr.signature != htobe32(GOT_PACKFILE_SIGNATURE)) {
			err = got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "bad pack file signature");
			goto done;
		}
		if (pack_hdr.version != htobe32(GOT_PACKFILE_VERSION)) {
			err = got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "bad pack file version");
			goto done;
		}
		nobj = be32toh(pack_hdr.nobjects);
		if (nobj == 0 &&
		    packfile_size > ssizeof(pack_hdr) + idlen) {
			err = got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "bad pack file with zero objects");
			goto done;
		}
		if (nobj != 0 &&
		    packfile_size <= ssizeof(pack_hdr) + idlen) {
			err = got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "empty pack file with non-zero object count");
			goto done;
		}
	}

	/*
	 * If the pack file contains no objects, we may only need to update
	 * references in our repository. The caller will take care of that.
	 */
	if (nobj == 0) {
		free(*pack_hash);
		*pack_hash = NULL;
		goto done;
	}

	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_idxfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}
	idxpid = fork();
	if (idxpid == -1) {
		err= got_error_from_errno("fork");
		goto done;
	} else if (idxpid == 0)
		got_privsep_exec_child(imsg_idxfds,
		    GOT_PATH_PROG_INDEX_PACK, tmppackpath);
	if (close(imsg_idxfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (imsgbuf_init(&idxibuf, imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&idxibuf);

	npackfd = dup(packfd);
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_index_pack_req(&idxibuf, *pack_hash, npackfd);
	if (err != NULL)
		goto done;
	npackfd = -1;
	err = got_privsep_send_index_pack_outfd(&idxibuf, nidxfd);
	if (err != NULL)
		goto done;
	nidxfd = -1;
	for (i = 0; i < nitems(tmpfds); i++) {
		err = got_privsep_send_tmpfd(&idxibuf, tmpfds[i]);
		if (err != NULL)
			goto done;
		tmpfds[i] = -1;
	}
	done = 0;
	while (!done) {
		int nobj_total, nobj_indexed, nobj_loose, nobj_resolved;

		err = got_privsep_recv_index_progress(&done, &nobj_total,
		    &nobj_indexed, &nobj_loose, &nobj_resolved,
		    &idxibuf);
		if (err != NULL)
			goto done;
		if (nobj_indexed != 0) {
			err = progress_cb(progress_arg, NULL,
			    packfile_size, nobj_total,
			    nobj_indexed, nobj_loose, nobj_resolved);
			if (err)
				break;
		}
	}
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(idxpid, &idxstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	err = got_object_id_str(&id_str, *pack_hash);
	if (err)
		goto done;
	if (asprintf(&packpath, "%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&idxpath, "%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	free(id_str);
	id_str = NULL;

	if (rename(tmppackpath, packpath) == -1) {
		err = got_error_from_errno3("rename", tmppackpath, packpath);
		goto done;
	}
	free(tmppackpath);
	tmppackpath = NULL;
	if (rename(tmpidxpath, idxpath) == -1) {
		err = got_error_from_errno3("rename", tmpidxpath, idxpath);
		goto done;
	}
	free(tmpidxpath);
	tmpidxpath = NULL;

done:
	if (fetchibuf.w)
		imsgbuf_clear(&fetchibuf);
	if (idxibuf.w)
		imsgbuf_clear(&idxibuf);
	if (tmppackpath && unlink(tmppackpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmppackpath);
	if (tmpidxpath && unlink(tmpidxpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpidxpath);
	if (nfetchfd != -1 && close(nfetchfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	for (i = 0; i < nitems(tmpfds); i++) {
		if (tmpfds[i] != -1 && close(tmpfds[i]) == -1 && err == NULL)
			err = got_error_from_errno("close");
	}
	free(tmppackpath);
	free(tmpidxpath);
	free(idxpath);
	free(id_str);
	free(packpath);
	free(progress);

	got_pathlist_free(&have_refs, GOT_PATHLIST_FREE_ALL);
	got_ref_list_free(&my_refs);
	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
		got_pathlist_free(refs, GOT_PATHLIST_FREE_ALL);
		got_pathlist_free(symrefs, GOT_PATHLIST_FREE_ALL);
	}
	return err;
}
