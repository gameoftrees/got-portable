/*
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/socket.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_repository_admin.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_repository.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
get_reflist_object_ids(struct got_object_id ***ids, int *nobjects,
    unsigned int wanted_obj_type_mask, struct got_reflist_head *refs,
    struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	const size_t alloc_chunksz = 256;
	size_t nalloc;
	struct got_reflist_entry *re;
	int i;

	*ids = NULL;
	*nobjects = 0;

	err = got_reflist_sort(refs,
	    got_ref_cmp_by_commit_timestamp_descending, repo);
	if (err)
		return err;

	*ids = reallocarray(NULL, alloc_chunksz, sizeof(struct got_object_id *));
	if (*ids == NULL)
		return got_error_from_errno("reallocarray");
	nalloc = alloc_chunksz;

	TAILQ_FOREACH(re, refs, entry) {
		struct got_object_id *id;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		err = got_ref_resolve(&id, repo, re->ref);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF &&
			    got_ref_is_symbolic(re->ref)) {
				err = NULL;
				continue;
			}
			goto done;
		}

		if (wanted_obj_type_mask != GOT_OBJ_TYPE_ANY) {
			int obj_type;
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
			if ((wanted_obj_type_mask & (1 << obj_type)) == 0) {
				free(id);
				id = NULL;
				continue;
			}
		}

		if (nalloc <= *nobjects) {
			struct got_object_id **new;
			new = recallocarray(*ids, nalloc,
			    nalloc + alloc_chunksz,
			    sizeof(struct got_object_id *));
			if (new == NULL) {
				err = got_error_from_errno(
				    "recallocarray");
				goto done;
			}
			*ids = new;
			nalloc += alloc_chunksz;
		}
		(*ids)[*nobjects] = id;
		if ((*ids)[*nobjects] == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
		(*nobjects)++;
	}
done:
	if (err) {
		for (i = 0; i < *nobjects; i++)
			free((*ids)[i]);
		free(*ids);
		*ids = NULL;
		*nobjects = 0;
	}
	return err;
}

static const struct got_error *
create_temp_packfile(int *packfd, char **tmpfile_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	*packfd = -1;

	if (asprintf(&path, "%s/%s/packing.pack",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR) == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(tmpfile_path, packfd, path, "");
	if (err)
		goto done;

	if (fchmod(*packfd, GOT_DEFAULT_PACK_MODE) == -1)
		err = got_error_from_errno2("fchmod", *tmpfile_path);
done:
	free(path);
	if (err) {
		if (*packfd != -1)
			close(*packfd);
		*packfd = -1;
		free(*tmpfile_path);
		*tmpfile_path = NULL;
	}
	return err;
}

static const struct got_error *
install_packfile(FILE **packfile, int *packfd, char **packfile_path,
    char **tmpfile_path, struct got_object_id *pack_hash,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *hash_str;

	err = got_object_id_str(&hash_str, pack_hash);
	if (err)
		return err;

	if (asprintf(packfile_path, "%s/%s/pack-%s.pack",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR,
	    hash_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (lseek(*packfd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	if (rename(*tmpfile_path, *packfile_path) == -1) {
		err = got_error_from_errno3("rename", *tmpfile_path,
		    *packfile_path);
		goto done;
	}

	free(*tmpfile_path);
	*tmpfile_path = NULL;

	*packfile = fdopen(*packfd, "w");
	if (*packfile == NULL) {
		err = got_error_from_errno2("fdopen", *packfile_path);
		goto done;
	}
	*packfd = -1;
done:
	free(hash_str);
	return err;
}

const struct got_error *
got_repo_pack_objects(FILE **packfile, struct got_object_id **pack_hash,
    struct got_reflist_head *include_refs,
    struct got_reflist_head *exclude_refs, struct got_repository *repo,
    int loose_obj_only, int force_refdelta,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ours = NULL, **theirs = NULL;
	int nours = 0, ntheirs = 0, packfd = -1, i;
	char *tmpfile_path = NULL, *packfile_path = NULL;
	FILE *delta_cache = NULL;
	struct got_ratelimit rl;

	*packfile = NULL;
	*pack_hash = NULL;

	got_ratelimit_init(&rl, 0, 500);

	err = create_temp_packfile(&packfd, &tmpfile_path, repo);
	if (err)
		return err;

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	err = get_reflist_object_ids(&ours, &nours,
	    (1 << GOT_OBJ_TYPE_COMMIT) | (1 << GOT_OBJ_TYPE_TAG),
	    include_refs, repo, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (nours == 0) {
		err = got_error(GOT_ERR_CANNOT_PACK);
		goto done;
	}

	if (!TAILQ_EMPTY(exclude_refs)) {
		err = get_reflist_object_ids(&theirs, &ntheirs,
		    (1 << GOT_OBJ_TYPE_COMMIT) | (1 << GOT_OBJ_TYPE_TAG),
		    exclude_refs, repo,
		    cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	*pack_hash = calloc(1, sizeof(**pack_hash));
	if (*pack_hash == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	err = got_pack_create(*pack_hash, packfd, delta_cache,
	    theirs, ntheirs, ours, nours, repo, loose_obj_only,
	    0, force_refdelta, progress_cb, progress_arg, &rl,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = install_packfile(packfile, &packfd, &packfile_path,
	    &tmpfile_path, *pack_hash, repo);
done:
	for (i = 0; i < nours; i++)
		free(ours[i]);
	free(ours);
	for (i = 0; i < ntheirs; i++)
		free(theirs[i]);
	free(theirs);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close",
		    packfile_path ? packfile_path : tmpfile_path);
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (tmpfile_path && unlink(tmpfile_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpfile_path);
	free(tmpfile_path);
	free(packfile_path);
	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
		if (*packfile)
			fclose(*packfile);
		*packfile = NULL;
	}
	return err;
}

const struct got_error *
got_repo_index_pack(char **idxpath, FILE *packfile,
    struct got_object_id *pack_hash, struct got_repository *repo,
    got_pack_index_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	size_t i;
	char *path;
	int imsg_idxfds[2];
	int npackfd = -1, idxfd = -1, nidxfd = -1;
	int tmpfds[3];
	int idxstatus, done = 0;
	int nobj_total = 0, nobj_indexed = 0, nobj_loose = 0, nobj_resolved = 0;
	const struct got_error *err;
	struct imsgbuf idxibuf;
	pid_t idxpid;
	char *tmpidxpath = NULL;
	char *packfile_path = NULL, *id_str = NULL;
	const char *repo_path = got_repo_get_path_git_dir(repo);
	struct stat sb;

	*idxpath = NULL;
	memset(&idxibuf, 0, sizeof(idxibuf));

	for (i = 0; i < nitems(tmpfds); i++)
		tmpfds[i] = -1;

	if (asprintf(&path, "%s/%s/indexing.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmpidxpath, &idxfd, path, "");
	free(path);
	if (err)
		goto done;
	if (fchmod(idxfd, GOT_DEFAULT_PACK_MODE) == -1) {
		err = got_error_from_errno2("fchmod", tmpidxpath);
		goto done;
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

	err = got_object_id_str(&id_str, pack_hash);
	if (err)
		goto done;

	if (asprintf(&packfile_path, "%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (fstat(fileno(packfile), &sb) == -1) {
		err = got_error_from_errno2("fstat", packfile_path);
		goto done;
	}

	if (asprintf(idxpath, "%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
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
		    GOT_PATH_PROG_INDEX_PACK, packfile_path);
	if (close(imsg_idxfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (imsgbuf_init(&idxibuf, imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&idxibuf);

	npackfd = dup(fileno(packfile));
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_index_pack_req(&idxibuf, pack_hash, npackfd);
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
		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		err = got_privsep_recv_index_progress(&done, &nobj_total,
		    &nobj_indexed, &nobj_loose, &nobj_resolved,
		    &idxibuf);
		if (err != NULL)
			goto done;
		if (nobj_indexed != 0) {
			err = progress_cb(progress_arg, sb.st_size,
			    nobj_total, nobj_indexed, nobj_loose,
			    nobj_resolved, 0);
			if (err)
				break;
		}
	}
	if (done) {
		err = progress_cb(progress_arg, sb.st_size,
		    nobj_total, nobj_indexed, nobj_loose,
		    nobj_resolved, done);
		if (err)
			goto done;
	}
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(idxpid, &idxstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (rename(tmpidxpath, *idxpath) == -1) {
		err = got_error_from_errno3("rename", tmpidxpath, *idxpath);
		goto done;
	}
	free(tmpidxpath);
	tmpidxpath = NULL;

done:
	if (idxibuf.w)
		imsgbuf_clear(&idxibuf);
	if (tmpidxpath && unlink(tmpidxpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpidxpath);
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	for (i = 0; i < nitems(tmpfds); i++) {
		if (tmpfds[i] != -1 && close(tmpfds[i]) == -1 && err == NULL)
			err = got_error_from_errno("close");
	}
	free(tmpidxpath);
	free(packfile_path);
	return err;
}

const struct got_error *
got_repo_find_pack(FILE **packfile, struct got_object_id **pack_hash,
    struct got_repository *repo, const char *packfile_path)
{
	const struct got_error *err = NULL;
	const char *packdir_path = NULL;
	char *packfile_name = NULL, *p, *dot;
	struct got_object_id id;
	int packfd = -1;

	*packfile = NULL;
	*pack_hash = NULL;

	packdir_path = got_repo_get_path_objects_pack(repo);
	if (packdir_path == NULL)
		return got_error_from_errno("got_repo_get_path_objects_pack");

	if (!got_path_is_child(packfile_path, packdir_path,
	    strlen(packdir_path))) {
		err = got_error_path(packfile_path, GOT_ERR_BAD_PATH);
		goto done;

	}

	err = got_path_basename(&packfile_name, packfile_path);
	if (err)
		goto done;
	p = packfile_name;

	if (strncmp(p, "pack-", 5) != 0) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	p += 5;
	dot = strchr(p, '.');
	if (dot == NULL) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	if (strcmp(dot + 1, "pack") != 0) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	*dot = '\0';
	if (!got_parse_object_id(&id, p, repo->algo)) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}

	*pack_hash = got_object_id_dup(&id);
	if (*pack_hash == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}

	packfd = open(packfile_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (packfd == -1) {
		err = got_error_from_errno2("open", packfile_path);
		goto done;
	}

	*packfile = fdopen(packfd, "r");
	if (*packfile == NULL) {
		err = got_error_from_errno2("fdopen", packfile_path);
		goto done;
	}
	packfd = -1;
done:
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close", packfile_path);
	free(packfile_name);
	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
	}
	return err;
}

const struct got_error *
got_repo_list_pack(FILE *packfile, struct got_object_id *pack_hash,
    struct got_repository *repo, got_pack_list_cb list_cb, void *list_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	char *id_str = NULL, *idxpath = NULL, *packpath = NULL;
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	uint32_t nobj, i;
	size_t digest_len = got_hash_digest_length(repo->algo);

	err = got_object_id_str(&id_str, pack_hash);
	if (err)
		goto done;

	if (asprintf(&packpath, "%s/pack-%s.pack",
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	if (asprintf(&idxpath, "%s/pack-%s.idx",
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_packidx_open(&packidx, got_repo_get_fd(repo), idxpath, 1,
	    repo->algo);
	if (err)
		goto done;

	err = got_repo_cache_pack(&pack, repo, packpath, packidx);
	if (err)
		goto done;

	nobj = be32toh(packidx->hdr.fanout_table[0xff]);
	for (i = 0; i < nobj; i++) {
		uint8_t *oid;
		struct got_object_id id, base_id;
		off_t offset, base_offset = 0;
		uint8_t type;
		uint64_t size;
		size_t tslen, len;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}
		oid = packidx->hdr.sorted_ids + i * digest_len;
		id.algo = repo->algo;
		memcpy(id.hash, oid, digest_len);

		offset = got_packidx_get_object_offset(packidx, i);
		if (offset == -1) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}

		err = got_pack_parse_object_type_and_size(&type, &size, &tslen,
		    pack, offset);
		if (err)
			goto done;

		switch (type) {
		case GOT_OBJ_TYPE_OFFSET_DELTA:
			err = got_pack_parse_offset_delta(&base_offset, &len,
			    pack, offset, tslen);
			if (err)
				goto done;
			break;
		case GOT_OBJ_TYPE_REF_DELTA:
			err = got_pack_parse_ref_delta(&base_id,
			    pack, offset, tslen);
			if (err)
				goto done;
			break;
		}
		err = (*list_cb)(list_arg, &id, type, offset, size,
		    base_offset, &base_id);
		if (err)
			goto done;
	}

done:
	free(id_str);
	free(idxpath);
	free(packpath);
	if (packidx)
		got_packidx_close(packidx);
	return err;
}

static const struct got_error *
repo_cleanup_lock(struct got_repository *repo, struct got_lockfile **lk)
{
	const struct got_error *err;
	char myname[_POSIX_HOST_NAME_MAX + 1];

	if (gethostname(myname, sizeof(myname)) == -1)
		return got_error_from_errno("gethostname");

	err = got_lockfile_lock(lk, "gc.pid", got_repo_get_fd(repo));
	if (err)
		return err;

	/*
	 * Git uses these info to provide some verbiage when finds a
	 * lock during `git gc --force' so don't try too hard to avoid
	 * short writes and don't care if a race happens between the
	 * lockfile creation and the write itself.
	 */
	if (dprintf((*lk)->fd, "%d %s", getpid(), myname) < 0)
		return got_error_from_errno("dprintf");

	return NULL;
}

static const struct got_error *
report_cleanup_progress(got_cleanup_progress_cb progress_cb,
    void *progress_arg, struct got_ratelimit *rl,
    int ncommits, int nloose, int npurged, int nredundant)
{
	const struct got_error *err;
	int elapsed;

	if (progress_cb == NULL)
		return NULL;

	err = got_ratelimit_check(&elapsed, rl);
	if (err || !elapsed)
		return err;

	return progress_cb(progress_arg, ncommits, nloose, npurged,
	    nredundant);
}

static const struct got_error *
get_loose_object_ids(struct got_object_idset **loose_ids,
    off_t *ondisk_size, int ncommits,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path_objects = NULL, *path = NULL;
	DIR *dir = NULL;
	struct got_object *obj = NULL;
	struct got_object_id id;
	int i, fd = -1;
	struct stat sb;

	*ondisk_size = 0;
	*loose_ids = got_object_idset_alloc();
	if (*loose_ids == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	path_objects = got_repo_get_path_objects(repo);
	if (path_objects == NULL) {
		err = got_error_from_errno("got_repo_get_path_objects");
		goto done;
	}

	for (i = 0; i <= 0xff; i++) {
		struct dirent *dent;

		if (asprintf(&path, "%s/%.2x", path_objects, i) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		dir = opendir(path);
		if (dir == NULL) {
			if (errno == ENOENT) {
				err = NULL;
				continue;
			}
			err = got_error_from_errno2("opendir", path);
			break;
		}

		while ((dent = readdir(dir)) != NULL) {
			char *id_str;

			if (strcmp(dent->d_name, ".") == 0 ||
			    strcmp(dent->d_name, "..") == 0)
				continue;

			if (asprintf(&id_str, "%.2x%s", i, dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}

			if (!got_parse_object_id(&id, id_str, repo->algo)) {
				free(id_str);
				continue;
			}
			free(id_str);

			err = got_object_open_loose_fd(&fd, &id, repo);
			if (err)
				goto done;
			if (fstat(fd, &sb) == -1) {
				err = got_error_from_errno("fstat");
				goto done;
			}
			err = got_object_read_header_privsep(&obj, &id, repo,
			    fd);
			if (err)
				goto done;
			fd = -1; /* already closed */

			switch (obj->type) {
			case GOT_OBJ_TYPE_COMMIT:
			case GOT_OBJ_TYPE_TREE:
			case GOT_OBJ_TYPE_BLOB:
			case GOT_OBJ_TYPE_TAG:
				break;
			default:
				err = got_error_fmt(GOT_ERR_OBJ_TYPE,
				    "%d", obj->type);
				goto done;
			}
			got_object_close(obj);
			obj = NULL;
			(*ondisk_size) += sb.st_size;
			err = got_object_idset_add(*loose_ids, &id, NULL);
			if (err)
				goto done;
			err = report_cleanup_progress(progress_cb,
			    progress_arg, rl, ncommits,
			    got_object_idset_num_elements(*loose_ids),
			    -1, -1);
			if (err)
				goto done;
		}

		if (closedir(dir) != 0) {
			err = got_error_from_errno("closedir");
			goto done;
		}
		dir = NULL;

		free(path);
		path = NULL;
	}
done:
	if (dir && closedir(dir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		got_object_idset_free(*loose_ids);
		*loose_ids = NULL;
	}
	if (obj)
		got_object_close(obj);
	free(path_objects);
	free(path);
	return err;
}

static const struct got_error *
load_tree_entries(struct got_object_id_queue *ids,
    struct got_object_idset *traversed_ids, struct got_object_id *tree_id,
    const char *dpath, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	char *p = NULL;
	int i;

	err = got_object_open_as_tree(&tree, repo, tree_id);
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

		if (got_object_tree_entry_is_symlink(e) ||
		    got_object_tree_entry_is_submodule(e) ||
		    got_object_idset_contains(traversed_ids, id))
			continue;

		if (asprintf(&p, "%s%s%s", dpath, dpath[0] != '\0' ? "/" : "",
		    got_tree_entry_get_name(e)) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		if (S_ISDIR(mode)) {
			struct got_object_qid *qid;
			err = got_object_qid_alloc(&qid, id);
			if (err)
				break;
			STAILQ_INSERT_TAIL(ids, qid, entry);
		} else if (S_ISREG(mode)) {
			/* This blob is referenced. */
			err = got_object_idset_add(traversed_ids, id, NULL);
			if (err)
				break;
		}
		free(p);
		p = NULL;
	}

	got_object_tree_close(tree);
	free(p);
	return err;
}

static const struct got_error *
load_tree(struct got_object_idset *traversed_ids,
    struct got_object_id *tree_id,
    const char *dpath, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue tree_ids;
	struct got_object_qid *qid;

	err = got_object_qid_alloc(&qid, tree_id);
	if (err)
		return err;

	STAILQ_INIT(&tree_ids);
	STAILQ_INSERT_TAIL(&tree_ids, qid, entry);

	while (!STAILQ_EMPTY(&tree_ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&tree_ids);
		STAILQ_REMOVE_HEAD(&tree_ids, entry);

		if (got_object_idset_contains(traversed_ids, &qid->id)) {
			got_object_qid_free(qid);
			continue;
		}

		err = got_object_idset_add(traversed_ids, &qid->id, NULL);
		if (err) {
			got_object_qid_free(qid);
			break;
		}

		err = load_tree_entries(&tree_ids, traversed_ids,
		    &qid->id, dpath, repo, cancel_cb, cancel_arg);
		got_object_qid_free(qid);
		if (err)
			break;
	}

	got_object_id_queue_free(&tree_ids);
	return err;
}

static const struct got_error *
load_commit_or_tag(int *ncommits, struct got_object_idset *traversed_ids,
    struct got_object_id *id, struct got_repository *repo,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_commit_object *commit = NULL;
	struct got_tag_object *tag = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_object_id_queue ids;
	struct got_object_qid *qid;
	int obj_type;

	err = got_object_qid_alloc(&qid, id);
	if (err)
		return err;

	STAILQ_INIT(&ids);
	STAILQ_INSERT_TAIL(&ids, qid, entry);

	while (!STAILQ_EMPTY(&ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&ids);
		STAILQ_REMOVE_HEAD(&ids, entry);

		if (got_object_idset_contains(traversed_ids, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}

		err = got_object_idset_add(traversed_ids, &qid->id, NULL);
		if (err)
			break;

		err = got_object_get_type(&obj_type, repo, &qid->id);
		if (err)
			break;
		switch (obj_type) {
		case GOT_OBJ_TYPE_COMMIT:
			err = got_object_open_as_commit(&commit, repo,
			    &qid->id);
			if (err)
				goto done;
			tree_id = got_object_commit_get_tree_id(commit);
			break;
		case GOT_OBJ_TYPE_TAG:
			err = got_object_open_as_tag(&tag, repo, &qid->id);
			if (err)
				goto done;
			/* tree_id will be set below */
			break;
		case GOT_OBJ_TYPE_TREE:
			tree_id = &qid->id;
			break;
		case GOT_OBJ_TYPE_BLOB:
			tree_id = NULL;
			break;
		default:
			/* should not happen */
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}

		if (tag) {
			struct got_object_id *id;

			obj_type = got_object_tag_get_object_type(tag);
			while (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *next_tag;

				id = got_object_tag_get_object_id(tag);
				if (!got_object_idset_contains(traversed_ids,
				    id)) {
					err = got_object_idset_add(
					    traversed_ids, id, NULL);
					if (err)
						goto done;
				}

				err = got_object_open_as_tag(&next_tag, repo,
				    id);
				if (err)
					goto done;

				got_object_tag_close(tag);
				tag = next_tag;
				obj_type = got_object_tag_get_object_type(tag);
			}
			id = got_object_tag_get_object_id(tag);
			switch (obj_type) {
			case GOT_OBJ_TYPE_COMMIT:
				if (got_object_idset_contains(traversed_ids,
				    id))
					break;
				err = got_object_idset_add(traversed_ids, id,
				    NULL);
				if (err)
					goto done;
				err = got_object_open_as_commit(&commit, repo,
				    id);
				if (err)
					goto done;
				tree_id = got_object_commit_get_tree_id(commit);
				break;
			case GOT_OBJ_TYPE_TREE:
				tree_id = id;
				break;
			case GOT_OBJ_TYPE_BLOB:
				if (got_object_idset_contains(traversed_ids,
				    id))
					break;
				err = got_object_idset_add(traversed_ids, id,
				    NULL);
				if (err)
					goto done;
				break;
			default:
				/* should not happen */
				err = got_error(GOT_ERR_OBJ_TYPE);
				goto done;
			}
		} else if (tree_id == NULL) {
			/* Blob which has already been marked as traversed. */
			continue;
		}

		if (tree_id) {
			err = load_tree(traversed_ids, tree_id, "",
			    repo, cancel_cb, cancel_arg);
			if (err)
				break;
			tree_id = NULL;
		}

		if (commit || tag)
			(*ncommits)++; /* scanned tags are counted as commits */

		err = report_cleanup_progress(progress_cb, progress_arg, rl,
		    *ncommits, -1, -1, -1);
		if (err)
			break;

		if (commit) {
			/* Find parent commits to scan. */
			const struct got_object_id_queue *parent_ids;
			parent_ids = got_object_commit_get_parent_ids(commit);
			err = got_object_id_queue_copy(parent_ids, &ids);
			if (err)
				break;
			got_object_commit_close(commit);
			commit = NULL;
		}
		if (tag) {
			got_object_tag_close(tag);
			tag = NULL;
		}
		got_object_qid_free(qid);
		qid = NULL;
	}
done:
	if (qid)
		got_object_qid_free(qid);
	if (commit)
		got_object_commit_close(commit);
	if (tag)
		got_object_tag_close(tag);
	got_object_id_queue_free(&ids);
	return err;
}

static const struct got_error *
is_object_packed(int *packed, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err;
	struct got_object *obj;

	*packed = 0;

	err = got_object_open_packed(&obj, id, repo);
	if (err) {
		if (err->code == GOT_ERR_NO_OBJ)
			err = NULL;
		return err;
	}
	got_object_close(obj);
	*packed = 1;
	return NULL;
}

struct purge_loose_object_arg {
	struct got_repository *repo;
	got_cleanup_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	struct got_object_idset *traversed_ids;
	int nloose;
	int ncommits;
	int npacked;
	int npurged;
	off_t size_purged;
	int dry_run;
	time_t max_mtime;
	int ignore_mtime;
};

static const struct got_error *
purge_loose_object(struct got_object_id *id, void *data, void *arg)
{
	struct purge_loose_object_arg *a = arg;
	const struct got_error *err, *unlock_err = NULL;
	char *path = NULL;
	int packed, fd = -1;
	struct stat sb;
	struct got_lockfile *lf = NULL;

	err = is_object_packed(&packed, a->repo, id);
	if (err)
		return err;

	if (!packed && got_object_idset_contains(a->traversed_ids, id))
		return NULL;

	if (packed)
		a->npacked++;

	err = got_object_get_path(&path, id, a->repo);
	if (err)
		return err;

	err = got_object_open_loose_fd(&fd, id, a->repo);
	if (err)
		goto done;

	if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno("fstat");
		goto done;
	}

	/*
	 * Do not delete objects which are younger than our maximum
	 * modification time threshold. This prevents a race where
	 * new objects which are being added to the repository
	 * concurrently would be deleted.
	 */
	if (a->ignore_mtime || sb.st_mtime <= a->max_mtime) {
		if (!a->dry_run) {
			err = got_lockfile_lock(&lf, path, -1);
			if (err)
				goto done;
			if (unlink(path) == -1) {
				err = got_error_from_errno2("unlink", path);
				goto done;
			}
		}

		a->npurged++;
		a->size_purged += sb.st_size;
		err = report_cleanup_progress(a->progress_cb, a->progress_arg,
		    a->rl, a->ncommits, a->nloose, a->npurged, -1);
		if (err)
			goto done;
	}
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(path);
	if (lf)
		unlock_err = got_lockfile_unlock(lf, -1);
	return err ? err : unlock_err;
}

static const struct got_error *
repo_purge_unreferenced_loose_objects(struct got_repository *repo,
    struct got_object_idset *traversed_ids,
    off_t *size_before, off_t *size_after, int ncommits, int *nloose,
    int *npacked, int *npurged, int dry_run, int ignore_mtime,
    time_t max_mtime, struct got_ratelimit *rl,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_object_idset *loose_ids;
	struct purge_loose_object_arg arg;

	err = get_loose_object_ids(&loose_ids, size_before, ncommits,
	    progress_cb, progress_arg, rl, repo);
	if (err)
		return err;
	*nloose = got_object_idset_num_elements(loose_ids);
	if (*nloose == 0) {
		got_object_idset_free(loose_ids);
		if (progress_cb) {
			err = progress_cb(progress_arg, 0, 0, 0, -1);
			if (err)
				return err;
		}
		return NULL;
	}

	memset(&arg, 0, sizeof(arg));
	arg.repo = repo;
	arg.progress_arg = progress_arg;
	arg.progress_cb = progress_cb;
	arg.rl = rl;
	arg.traversed_ids = traversed_ids;
	arg.nloose = *nloose;
	arg.npacked = 0;
	arg.npurged = 0;
	arg.size_purged = 0;
	arg.dry_run = dry_run;
	arg.max_mtime = max_mtime;
	arg.ignore_mtime = ignore_mtime;
	err = got_object_idset_for_each(loose_ids, purge_loose_object, &arg);
	if (err)
		goto done;

	*size_after = *size_before - arg.size_purged;
	*npacked = arg.npacked;
	*npurged = arg.npurged;

	/* Produce a final progress report. */
	if (progress_cb) {
		err = progress_cb(progress_arg, ncommits, *nloose,
		    arg.npurged, -1);
		if (err)
			goto done;
	}
done:
	got_object_idset_free(loose_ids);
	return err;
}

static const struct got_error *
purge_redundant_pack(struct got_repository *repo, const char *packidx_path,
    int dry_run, int ignore_mtime, time_t max_mtime, int *remove,
    int has_unref_objects, off_t *size_before, off_t *size_after)
{
	static const char *ext[] = {".idx", ".pack", ".rev", ".bitmap",
	    ".promisor", ".mtimes"};
	struct stat sb;
	char *dot, path[PATH_MAX];
	size_t i;

	if (strlcpy(path, packidx_path, sizeof(path)) >= sizeof(path))
		return got_error(GOT_ERR_NO_SPACE);

	if (*remove && !ignore_mtime && has_unref_objects) {
		/*
		 * Do not delete pack files which contain unreferenced objects
		 * and are younger than our modification time threshold.
		 * This prevents a race where a new pack file which is being
		 * added to the repository concurrently would be deleted.
		 */
		if (fstatat(got_repo_get_fd(repo), path, &sb, 0) == -1) {
			if (errno == ENOENT)
				return NULL;
			return got_error_from_errno2("fstatat", path);
		}
		if (sb.st_mtime > max_mtime)
			*remove = 0;
	}

	/*
	 * For compatibility with Git, if a matching .keep file exist
	 * don't delete the packfile.
	 */
	dot = strrchr(path, '.');
	*dot = '\0';
	if (strlcat(path, ".keep", sizeof(path)) >= sizeof(path))
		return got_error(GOT_ERR_NO_SPACE);
	if (faccessat(got_repo_get_fd(repo), path, F_OK, 0) == 0)
		*remove = 0;

	for (i = 0; i < nitems(ext); ++i) {
		*dot = '\0';

		if (strlcat(path, ext[i], sizeof(path)) >=
		    sizeof(path))
			return got_error(GOT_ERR_NO_SPACE);

		if (fstatat(got_repo_get_fd(repo), path, &sb, 0) ==
		    -1) {
			if (errno == ENOENT)
				continue;
			return got_error_from_errno2("fstatat", path);
		}

		*size_before += sb.st_size;
		if (!*remove) {
			*size_after += sb.st_size;
			continue;
		}

		if (dry_run)
			continue;

		if (unlinkat(got_repo_get_fd(repo), path, 0) == -1) {
			if (errno == ENOENT)
				continue;
			return got_error_from_errno2("unlinkat",
			    path);
		}
	}

	return NULL;
}

static const struct got_error *
pack_is_redundant(int *redundant, int *unref_objects,
    struct got_repository *repo, struct got_object_idset *traversed_ids,
    struct got_packidx *large_packidx, const char *packidx_path)
{
	const struct got_error *err;
	struct got_packidx *packidx;
	uint8_t *pid;
	struct got_object_id id;
	size_t i, nobjects;
	size_t digest_len = got_hash_digest_length(repo->algo);
	int idx;

	*redundant = 0;
	*unref_objects = 0;

	err = got_repo_get_packidx(&packidx, packidx_path, repo);
	if (err)
		return err;

	nobjects = be32toh(packidx->hdr.fanout_table[0xff]);
	for (i = 0; i < nobjects; ++i) {
		pid = packidx->hdr.sorted_ids + i * digest_len;

		memset(&id, 0, sizeof(id));
		memcpy(&id.hash, pid, digest_len);
		id.algo = repo->algo;

		/*
		 * Pack files which contain unknown objects must be kept
		 * if they meet our modification time threshold.
		 */
		if (*unref_objects == 0 &&
		    !got_object_idset_contains(traversed_ids, &id))
			*unref_objects = 1;

		/*
		 * A pack file is not redundant if any referenced object
		 * it contains has no valid index in our large pack file,
		 */
		idx = got_packidx_get_object_idx(large_packidx, &id);
		if (idx == -1 && got_object_idset_contains(traversed_ids, &id))
			return NULL;
	}

	*redundant = 1;
	return NULL;
}

struct pack_info {
	const char	*path;
	size_t		 path_len;
	size_t		 nobjects;
};

static int
pack_info_cmp(const void *a, const void *b)
{
	const struct pack_info	*pa, *pb;

	pa = a;
	pb = b;
	if (pa->nobjects == pb->nobjects)
		return got_path_cmp(pa->path, pb->path,
		    pa->path_len, pb->path_len);
	if (pa->nobjects > pb->nobjects)
		return -1;
	return 1;
}

static const struct got_error *
repo_purge_redundant_packfiles(struct got_repository *repo,
    struct got_object_idset *traversed_ids,
    off_t *size_before, off_t *size_after, int dry_run, int ignore_mtime,
    time_t max_mtime, struct got_object_id *large_pack_hash,
    int nloose, int ncommits, int npurged,
    struct got_ratelimit *rl,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct pack_info *pinfo, *sorted = NULL;
	struct got_packidx *packidx, *large_packidx = NULL;
	struct got_pathlist_entry *pe;
	size_t i, npacks;
	int redundant_packs = 0, large_idxpath_len;
	char *id_str = NULL, *large_idxpath = NULL;

	npacks = 0;
	RB_FOREACH(pe, got_pathlist_head, &repo->packidx_paths)
		npacks++;

	if (npacks == 0)
		return NULL;

	sorted = calloc(npacks, sizeof(*sorted));
	if (sorted == NULL)
		return got_error_from_errno("calloc");

	err = got_object_id_str(&id_str, large_pack_hash);
	if (err)
		goto done;
	large_idxpath_len = asprintf(&large_idxpath, "%s/pack-%s.idx",
	    GOT_OBJECTS_PACK_DIR, id_str);
	if (large_idxpath_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	i = 0;
	RB_FOREACH(pe, got_pathlist_head, &repo->packidx_paths) {
		err = got_repo_get_packidx(&packidx, pe->path, repo);
		if (err)
			goto done;

		pinfo = &sorted[i++];
		pinfo->path = pe->path;
		pinfo->path_len = pe->path_len;
		pinfo->nobjects = be32toh(packidx->hdr.fanout_table[0xff]);
	}
	qsort(sorted, npacks, sizeof(*sorted), pack_info_cmp);

	/*
	 * Open the index of the large pack file we just created.
	 * Any other pack file composed only of objects which are also
	 * contained in our large pack is now redundant and can be purged.
	 */
	err = got_packidx_open(&large_packidx, got_repo_get_fd(repo),
	    large_idxpath, 1, repo->algo);
	if (err)
		goto done;

	for (i = 0; i < npacks; ++i) {
		int is_redundant = 0, has_unref_objects = 0;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		/* Do not delete the large pack file we just created. */
		if (got_path_cmp(sorted[i].path, large_idxpath,
		    sorted[i].path_len, large_idxpath_len) != 0) {
			err = pack_is_redundant(&is_redundant,
			    &has_unref_objects, repo, traversed_ids,
			    large_packidx, sorted[i].path);
			if (err)
				goto done;
		}
		err = purge_redundant_pack(repo, sorted[i].path, dry_run,
		    ignore_mtime, max_mtime, &is_redundant, has_unref_objects,
		    size_before, size_after);
		if (err)
			goto done;
		if (!is_redundant)
			continue;
		err = report_cleanup_progress(progress_cb, progress_arg,
		    rl, ncommits, nloose, npurged, ++redundant_packs);
		if (err)
			goto done;
	}

	/* Produce a final progress report. */
	if (progress_cb) {
		err = progress_cb(progress_arg, ncommits, nloose, npurged,
		    redundant_packs);
		if (err)
			goto done;
	}
 done:
	free(sorted);
	if (large_packidx)
		got_packidx_close(large_packidx);
	free(large_idxpath);
	free(id_str);
	return err;
}

const struct got_error *
got_repo_cleanup(struct got_repository *repo,
    off_t *loose_before, off_t *loose_after,
    off_t *pack_before, off_t *pack_after,
    int *ncommits, int *nloose, int *npacked, int dry_run, int ignore_mtime,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    got_pack_progress_cb pack_progress_cb, void *pack_progress_arg,
    got_pack_index_progress_cb index_progress_cb, void *index_progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *unlock_err, *err = NULL;
	struct got_lockfile *lk = NULL;
	struct got_ratelimit rl;
	struct got_reflist_head refs;
	struct got_object_idset *traversed_ids = NULL;
	struct got_reflist_entry *re;
	struct got_object_id **referenced_ids;
	int i, nreferenced;
	int npurged = 0, packfd = -1;
	char *tmpfile_path = NULL, *packfile_path = NULL, *idxpath = NULL;
	FILE *delta_cache = NULL, *packfile = NULL;
	struct got_object_id pack_hash;
	time_t max_mtime = 0;

	TAILQ_INIT(&refs);
	got_ratelimit_init(&rl, 0, 500);
	memset(&pack_hash, 0, sizeof(pack_hash));

	*loose_before = 0;
	*loose_after = 0;
	*pack_before = 0;
	*pack_after = 0;
	*ncommits = 0;
	*nloose = 0;
	*npacked = 0;

	err = repo_cleanup_lock(repo, &lk);
	if (err)
		return err;

	err = create_temp_packfile(&packfd, &tmpfile_path, repo);
	if (err)
		goto done;

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	traversed_ids = got_object_idset_alloc();
	if (traversed_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	err = got_ref_list(&refs, repo, "", got_ref_cmp_by_name, NULL);
	if (err)
		goto done;
	if (!ignore_mtime) {
		TAILQ_FOREACH(re, &refs, entry) {
			time_t mtime = got_ref_get_mtime(re->ref);
			if (mtime > max_mtime)
				max_mtime = mtime;
		}
		/*
		 * For safety, keep objects created within 10 minutes
		 * before the youngest reference was created.
		 */
		if (max_mtime >= 600)
			max_mtime -= 600;
	}

	err = get_reflist_object_ids(&referenced_ids, &nreferenced,
	    GOT_OBJ_TYPE_ANY, &refs, repo, cancel_cb, cancel_arg);
	if (err)
		goto done;

	for (i = 0; i < nreferenced; i++) {
		struct got_object_id *id = referenced_ids[i];
		err = load_commit_or_tag(ncommits, traversed_ids,
		    id, repo, progress_cb, progress_arg, &rl,
		    cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	err = got_pack_create(&pack_hash, packfd, delta_cache,
	    NULL, 0, referenced_ids, nreferenced, repo, 0,
	    0, 0, pack_progress_cb, pack_progress_arg,
	    &rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = install_packfile(&packfile, &packfd, &packfile_path,
	    &tmpfile_path, &pack_hash, repo);
	if (err)
		goto done;

	err = got_repo_index_pack(&idxpath, packfile, &pack_hash, repo,
	    index_progress_cb, index_progress_arg,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = got_repo_list_packidx(&repo->packidx_paths, repo);
	if (err)
		goto done;

	err = repo_purge_unreferenced_loose_objects(repo, traversed_ids,
	    loose_before, loose_after, *ncommits, nloose, npacked, &npurged,
	    dry_run, ignore_mtime, max_mtime, &rl, progress_cb, progress_arg,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = repo_purge_redundant_packfiles(repo, traversed_ids,
	    pack_before, pack_after, dry_run, ignore_mtime, max_mtime,
	    &pack_hash, *nloose, *ncommits, npurged,
	    &rl, progress_cb, progress_arg, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (dry_run) {
		if (idxpath && unlink(idxpath) == -1)
			err = got_error_from_errno2("unlink", idxpath);
		if (packfile_path && unlink(packfile_path) == -1 && err == NULL)
			err = got_error_from_errno2("unlink", packfile_path);
	}
 done:
	if (lk) {
		unlock_err = got_lockfile_unlock(lk, got_repo_get_fd(repo));
		if (err == NULL)
			err = unlock_err;
	}
	if (traversed_ids)
		got_object_idset_free(traversed_ids);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close",
		    packfile_path ? packfile_path : tmpfile_path);
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (tmpfile_path && unlink(tmpfile_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpfile_path);
	free(tmpfile_path);
	free(packfile_path);
	free(idxpath);
	return err;
}

const struct got_error *
got_repo_remove_lonely_packidx(struct got_repository *repo, int dry_run,
    got_lonely_packidx_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	DIR *packdir = NULL;
	struct dirent *dent;
	char *pack_relpath = NULL;
	int packdir_fd;
	struct stat sb;

	packdir_fd = openat(got_repo_get_fd(repo),
	    GOT_OBJECTS_PACK_DIR, O_DIRECTORY | O_CLOEXEC);
	if (packdir_fd == -1) {
		if (errno == ENOENT)
			return NULL;
		return got_error_from_errno_fmt("openat: %s/%s",
		    got_repo_get_path_git_dir(repo),
		    GOT_OBJECTS_PACK_DIR);
	}

	packdir = fdopendir(packdir_fd);
	if (packdir == NULL) {
		err = got_error_from_errno("fdopendir");
		close(packdir_fd);
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		if (!got_repo_is_packidx_filename(dent->d_name,
		    strlen(dent->d_name),
		    got_repo_get_object_format(repo)))
			continue;

		err = got_packidx_get_packfile_path(&pack_relpath,
		    dent->d_name);
		if (err)
			goto done;

		if (fstatat(packdir_fd, pack_relpath, &sb, 0) != -1) {
			free(pack_relpath);
			pack_relpath = NULL;
			continue;
		}
		if (errno != ENOENT) {
			err = got_error_from_errno_fmt("fstatat: %s/%s/%s",
			    got_repo_get_path_git_dir(repo),
			    GOT_OBJECTS_PACK_DIR,
			    pack_relpath);
			goto done;
		}

		if (!dry_run) {
			if (unlinkat(packdir_fd, dent->d_name, 0) == -1) {
				err = got_error_from_errno("unlinkat");
				goto done;
			}
		}
		if (progress_cb) {
			char *path;
			if (asprintf(&path, "%s/%s/%s",
			    got_repo_get_path_git_dir(repo),
			    GOT_OBJECTS_PACK_DIR,
			    dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = progress_cb(progress_arg, path);
			free(path);
			if (err)
				goto done;
		}
		free(pack_relpath);
		pack_relpath = NULL;
	}
done:
	if (packdir && closedir(packdir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	free(pack_relpath);
	return err;
}
