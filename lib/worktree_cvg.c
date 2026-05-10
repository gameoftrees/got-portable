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
#include <sys/queue.h>
#include <sys/tree.h>

#include <dirent.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sha1.h>
#include <sha2.h>
#include <zlib.h>
#include <fnmatch.h>
#include <libgen.h>
#include <uuid.h>
#include <util.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_worktree_cvg.h"
#include "got_opentemp.h"
#include "got_diff.h"
#include "got_send.h"
#include "got_fetch.h"

#include "got_lib_worktree.h"
#include "got_lib_hash.h"
#include "got_lib_fileindex.h"
#include "got_lib_inflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_object_idset.h"
#include "got_lib_diff.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#define GOT_MERGE_LABEL_MERGED	"merged change"
#define GOT_MERGE_LABEL_BASE	"3-way merge base"

static const struct got_error *
lock_worktree(struct got_worktree *worktree, int operation)
{
	if (flock(worktree->lockfd, operation | LOCK_NB) == -1)
		return (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno2("flock",
		    got_worktree_get_root_path(worktree)));
	return NULL;
}

static const struct got_error *
is_bad_symlink_target(int *is_bad_symlink, const char *target_path,
    size_t target_len, const char *ondisk_path, const char *wtroot_path)
{
	const struct got_error *err = NULL;
	char canonpath[PATH_MAX];
	char *path_got = NULL;

	*is_bad_symlink = 0;

	if (target_len >= sizeof(canonpath)) {
		*is_bad_symlink = 1;
		return NULL;
	}

	/*
	 * We do not use realpath(3) to resolve the symlink's target
	 * path because we don't want to resolve symlinks recursively.
	 * Instead we make the path absolute and then canonicalize it.
	 * Relative symlink target lookup should begin at the directory
	 * in which the blob object is being installed.
	 */
	if (!got_path_is_absolute(target_path)) {
		char *abspath, *parent;
		err = got_path_dirname(&parent, ondisk_path);
		if (err)
			return err;
		if (asprintf(&abspath, "%s/%s",  parent, target_path) == -1) {
			free(parent);
			return got_error_from_errno("asprintf");
		}
		free(parent);
		if (strlen(abspath) >= sizeof(canonpath)) {
			err = got_error_path(abspath, GOT_ERR_BAD_PATH);
			free(abspath);
			return err;
		}
		err = got_canonpath(abspath, canonpath, sizeof(canonpath));
		free(abspath);
		if (err)
			return err;
	} else {
		err = got_canonpath(target_path, canonpath, sizeof(canonpath));
		if (err)
			return err;
	}

	/* Only allow symlinks pointing at paths within the work tree. */
	if (!got_path_is_child(canonpath, wtroot_path, strlen(wtroot_path))) {
		*is_bad_symlink = 1;
		return NULL;
	}

	/* Do not allow symlinks pointing into the .got directory. */
	if (asprintf(&path_got, "%s/%s", wtroot_path,
	    GOT_WORKTREE_GOT_DIR) == -1)
		return got_error_from_errno("asprintf");
	if (got_path_is_child(canonpath, path_got, strlen(path_got)))
		*is_bad_symlink = 1;

	free(path_got);
	return NULL;
}

/*
 * Upgrade STATUS_MODIFY to STATUS_CONFLICT if a
 * conflict marker is found in newly added lines only.
 */
static const struct got_error *
get_modified_file_content_status(unsigned char *status,
    struct got_blob_object *blob, const char *path, struct stat *sb,
    FILE *ondisk_file)
{
	const struct got_error *err, *free_err;
	const char *markers[3] = {
		GOT_DIFF_CONFLICT_MARKER_BEGIN,
		GOT_DIFF_CONFLICT_MARKER_SEP,
		GOT_DIFF_CONFLICT_MARKER_END
	};
	FILE *f1 = NULL;
	struct got_diffreg_result *diffreg_result = NULL;
	struct diff_result *r;
	int nchunks_parsed, n, i = 0, ln = 0;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	if (*status != GOT_STATUS_MODIFY)
		return NULL;

	f1 = got_opentemp();
	if (f1 == NULL)
		return got_error_from_errno("got_opentemp");

	if (blob) {
		got_object_blob_rewind(blob);
		err = got_object_blob_dump_to_file(NULL, NULL, NULL, f1, blob);
		if (err)
			goto done;
	}

	err = got_diff_files(&diffreg_result, f1, 1, NULL, ondisk_file,
	    1, NULL, 0, 0, 1, NULL, GOT_DIFF_ALGORITHM_MYERS);
	if (err)
		goto done;

	r = diffreg_result->result;

	for (n = 0; n < r->chunks.len; n += nchunks_parsed) {
		struct diff_chunk *c;
		struct diff_chunk_context cc = {};
		off_t pos;

		/*
		 * We can optimise a little by advancing straight
		 * to the next chunk if this one has no added lines.
		 */
		c = diff_chunk_get(r, n);

		if (diff_chunk_type(c) != CHUNK_PLUS) {
			nchunks_parsed = 1;
			continue;  /* removed or unchanged lines */
		}

		pos = diff_chunk_get_right_start_pos(c);
		if (fseek(ondisk_file, pos, SEEK_SET) == -1) {
			err = got_ferror(ondisk_file, GOT_ERR_IO);
			goto done;
		}

		diff_chunk_context_load_change(&cc, &nchunks_parsed, r, n, 0);
		ln = cc.right.start;

		while (ln < cc.right.end) {
			linelen = getline(&line, &linesize, ondisk_file);
			if (linelen == -1) {
				if (feof(ondisk_file))
					break;
				err = got_ferror(ondisk_file, GOT_ERR_IO);
				break;
			}

			if (line && strncmp(line, markers[i],
			    strlen(markers[i])) == 0) {
				if (strcmp(markers[i],
				    GOT_DIFF_CONFLICT_MARKER_END) == 0) {
					*status = GOT_STATUS_CONFLICT;
					goto done;
				} else
					i++;
			}
			++ln;
		}
	}

done:
	free(line);
	if (f1 != NULL && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free_err = got_diffreg_result_free(diffreg_result);
	if (err == NULL)
		err = free_err;

	return err;
}

static int
xbit_differs(struct got_fileindex_entry *ie, uint16_t st_mode)
{
	mode_t ie_mode = got_fileindex_perms_to_st(ie);
	return ((ie_mode & S_IXUSR) != (st_mode & S_IXUSR));
}

static int
stat_info_differs(struct got_fileindex_entry *ie, struct stat *sb)
{
	return !(ie->ctime_sec == sb->st_ctim.tv_sec &&
	    ie->ctime_nsec == sb->st_ctim.tv_nsec &&
	    ie->mtime_sec == sb->st_mtim.tv_sec &&
	    ie->mtime_nsec == sb->st_mtim.tv_nsec &&
	    ie->size == (sb->st_size & 0xffffffff) &&
	    !xbit_differs(ie, sb->st_mode));
}

static unsigned char
get_staged_status(struct got_fileindex_entry *ie)
{
	switch (got_fileindex_entry_stage_get(ie)) {
	case GOT_FILEIDX_STAGE_ADD:
		return GOT_STATUS_ADD;
	case GOT_FILEIDX_STAGE_DELETE:
		return GOT_STATUS_DELETE;
	case GOT_FILEIDX_STAGE_MODIFY:
		return GOT_STATUS_MODIFY;
	default:
		return GOT_STATUS_NO_CHANGE;
	}
}

static const struct got_error *
get_symlink_modification_status(unsigned char *status,
    struct got_fileindex_entry *ie, const char *abspath,
    int dirfd, const char *de_name, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	char etarget[PATH_MAX];
	ssize_t elen;
	size_t len, target_len = 0;
	const uint8_t *buf = got_object_blob_get_read_buf(blob);
	size_t hdrlen = got_object_blob_get_hdrlen(blob);

	*status = GOT_STATUS_NO_CHANGE;

	/* Blob object content specifies the target path of the link. */
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;
		if (len + target_len >= sizeof(target_path)) {
			/*
			 * Should not happen. The blob contents were OK
			 * when this symlink was installed.
			 */
			return got_error(GOT_ERR_NO_SPACE);
		}
		if (len > 0) {
			/* Skip blob object header first time around. */
			memcpy(target_path + target_len, buf + hdrlen,
			    len - hdrlen);
			target_len += len - hdrlen;
			hdrlen = 0;
		}
	} while (len != 0);
	target_path[target_len] = '\0';

	if (dirfd != -1) {
		elen = readlinkat(dirfd, de_name, etarget, sizeof(etarget));
		if (elen == -1)
			return got_error_from_errno2("readlinkat", abspath);
	} else {
		elen = readlink(abspath, etarget, sizeof(etarget));
		if (elen == -1)
			return got_error_from_errno2("readlink", abspath);
	}

	if (elen != target_len || memcmp(etarget, target_path, target_len) != 0)
		*status = GOT_STATUS_MODIFY;

	return NULL;
}

static const struct got_error *
get_file_status(unsigned char *status, struct stat *sb,
    struct got_fileindex_entry *ie, const char *abspath,
    int dirfd, const char *de_name, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id id;
	size_t hdrlen;
	int fd = -1, fd1 = -1;
	FILE *f = NULL;
	uint8_t fbuf[8192];
	struct got_blob_object *blob = NULL;
	size_t flen, blen;
	unsigned char staged_status;

	staged_status = get_staged_status(ie);
	*status = GOT_STATUS_NO_CHANGE;
	memset(sb, 0, sizeof(*sb));

	/*
	 * Whenever the caller provides a directory descriptor and a
	 * directory entry name for the file, use them! This prevents
	 * race conditions if filesystem paths change beneath our feet.
	 */
	if (dirfd != -1) {
		if (fstatat(dirfd, de_name, sb, AT_SYMLINK_NOFOLLOW) == -1) {
			if (errno == ENOENT) {
				if (got_fileindex_entry_has_file_on_disk(ie))
					*status = GOT_STATUS_MISSING;
				else
					*status = GOT_STATUS_DELETE;
				goto done;
			}
			err = got_error_from_errno2("fstatat", abspath);
			goto done;
		}
	} else {
		fd = open(abspath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd == -1 && errno != ENOENT &&
		    !got_err_open_nofollow_on_symlink())
			return got_error_from_errno2("open", abspath);
		else if (fd == -1 && got_err_open_nofollow_on_symlink()) {
			if (lstat(abspath, sb) == -1)
				return got_error_from_errno2("lstat", abspath);
		} else if (fd == -1 || fstat(fd, sb) == -1) {
			if (errno == ENOENT) {
				if (got_fileindex_entry_has_file_on_disk(ie))
					*status = GOT_STATUS_MISSING;
				else
					*status = GOT_STATUS_DELETE;
				goto done;
			}
			err = got_error_from_errno2("fstat", abspath);
			goto done;
		}
	}

	if (!S_ISREG(sb->st_mode) && !S_ISLNK(sb->st_mode)) {
		*status = GOT_STATUS_OBSTRUCTED;
		goto done;
	}

	if (!got_fileindex_entry_has_file_on_disk(ie)) {
		*status = GOT_STATUS_DELETE;
		goto done;
	} else if (!got_fileindex_entry_has_blob(ie) &&
	    staged_status != GOT_STATUS_ADD) {
		*status = GOT_STATUS_ADD;
		goto done;
	}

	if (!stat_info_differs(ie, sb))
		goto done;

	if (S_ISLNK(sb->st_mode) &&
	    got_fileindex_entry_filetype_get(ie) != GOT_FILEIDX_MODE_SYMLINK) {
		*status = GOT_STATUS_MODIFY;
		goto done;
	}

	if (staged_status == GOT_STATUS_MODIFY ||
	    staged_status == GOT_STATUS_ADD)
		got_fileindex_entry_get_staged_blob_id(&id, ie);
	else
		got_fileindex_entry_get_blob_id(&id, ie);

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}
	err = got_object_open_as_blob(&blob, repo, &id, sizeof(fbuf), fd1);
	if (err)
		goto done;

	if (S_ISLNK(sb->st_mode)) {
		err = get_symlink_modification_status(status, ie,
		    abspath, dirfd, de_name, blob);
		goto done;
	}

	if (dirfd != -1) {
		fd = openat(dirfd, de_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd == -1) {
			err = got_error_from_errno2("openat", abspath);
			goto done;
		}
	}

	f = fdopen(fd, "r");
	if (f == NULL) {
		err = got_error_from_errno2("fdopen", abspath);
		goto done;
	}
	fd = -1;
	hdrlen = got_object_blob_get_hdrlen(blob);
	for (;;) {
		const uint8_t *bbuf = got_object_blob_get_read_buf(blob);
		err = got_object_blob_read_block(&blen, blob);
		if (err)
			goto done;
		/* Skip length of blob object header first time around. */
		flen = fread(fbuf, 1, sizeof(fbuf) - hdrlen, f);
		if (flen == 0 && ferror(f)) {
			err = got_error_from_errno("fread");
			goto done;
		}
		if (blen - hdrlen == 0) {
			if (flen != 0)
				*status = GOT_STATUS_MODIFY;
			break;
		} else if (flen == 0) {
			if (blen - hdrlen != 0)
				*status = GOT_STATUS_MODIFY;
			break;
		} else if (blen - hdrlen == flen) {
			/* Skip blob object header first time around. */
			if (memcmp(bbuf + hdrlen, fbuf, flen) != 0) {
				*status = GOT_STATUS_MODIFY;
				break;
			}
		} else {
			*status = GOT_STATUS_MODIFY;
			break;
		}
		hdrlen = 0;
	}

	if (*status == GOT_STATUS_MODIFY) {
		rewind(f);
		err = get_modified_file_content_status(status, blob, ie->path,
		    sb, f);
	} else if (xbit_differs(ie, sb->st_mode))
		*status = GOT_STATUS_MODE_CHANGE;
done:
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (f != NULL && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", abspath);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", abspath);
	return err;
}

static const struct got_error *
get_ref_name(char **refname, struct got_worktree *worktree, const char *prefix)
{
	const struct got_error *err = NULL;
	char *uuidstr = NULL;

	*refname = NULL;

	err = got_worktree_get_uuid(&uuidstr, worktree);
	if (err)
		return err;

	if (asprintf(refname, "%s-%s", prefix, uuidstr) == -1) {
		err = got_error_from_errno("asprintf");
		*refname = NULL;
	}
	free(uuidstr);
	return err;
}

static const struct got_error *
get_base_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree, GOT_WORKTREE_BASE_REF_PREFIX);
}

/*
 * Prevent Git's garbage collector from deleting our base commit by
 * setting a reference to our base commit's ID.
 */
static const struct got_error *
ref_base_commit(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *refname;

	err = get_base_ref_name(&refname, worktree);
	if (err)
		return err;

	err = got_ref_alloc(&ref, refname, worktree->base_commit_id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	free(refname);
	if (ref)
		got_ref_close(ref);
	return err;
}

static const struct got_error *
get_fileindex_path(char **fileindex_path, struct got_worktree *worktree)
{
	const struct got_error *err = NULL;

	if (asprintf(fileindex_path, "%s/%s/%s", worktree->root_path,
	    GOT_WORKTREE_GOT_DIR, GOT_WORKTREE_FILE_INDEX) == -1) {
		err = got_error_from_errno("asprintf");
		*fileindex_path = NULL;
	}
	return err;
}

static const struct got_error *
open_fileindex(struct got_fileindex **fileindex, char **fileindex_path,
    struct got_worktree *worktree, enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	FILE *index = NULL;

	*fileindex_path = NULL;
	*fileindex = got_fileindex_alloc(algo);
	if (*fileindex == NULL)
		return got_error_from_errno("got_fileindex_alloc");

	err = get_fileindex_path(fileindex_path, worktree);
	if (err)
		goto done;

	index = fopen(*fileindex_path, "rbe");
	if (index == NULL) {
		if (errno != ENOENT)
			err = got_error_from_errno2("fopen", *fileindex_path);
	} else {
		err = got_fileindex_read(*fileindex, index, algo);
		if (fclose(index) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
done:
	if (err) {
		free(*fileindex_path);
		*fileindex_path = NULL;
		got_fileindex_free(*fileindex);
		*fileindex = NULL;
	}
	return err;
}

static const struct got_error *
sync_fileindex(struct got_fileindex *fileindex, const char *fileindex_path)
{
	const struct got_error *err = NULL;
	char *new_fileindex_path = NULL;
	FILE *new_index = NULL;
	struct timespec timeout;

	err = got_opentemp_named(&new_fileindex_path, &new_index,
	    fileindex_path, "");
	if (err)
		goto done;

	err = got_fileindex_write(fileindex, new_index);
	if (err)
		goto done;

	if (rename(new_fileindex_path, fileindex_path) != 0) {
		err = got_error_from_errno3("rename", new_fileindex_path,
		    fileindex_path);
		unlink(new_fileindex_path);
	}

	/*
	 * Sleep for a short amount of time to ensure that files modified after
	 * this program exits have a different time stamp from the one which
	 * was recorded in the file index.
	 */
	timeout.tv_sec = 0;
	timeout.tv_nsec = 1;
	nanosleep(&timeout, NULL);
done:
	if (new_index)
		fclose(new_index);
	free(new_fileindex_path);
	return err;
}

struct diff_dir_cb_arg {
	struct got_fileindex *fileindex;
	struct got_worktree *worktree;
	const char *status_path;
	size_t status_path_len;
	struct got_repository *repo;
	got_worktree_status_cb status_cb;
	void *status_arg;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
	/* A pathlist containing per-directory pathlists of ignore patterns. */
	struct got_pathlist_head *ignores;
	int report_unchanged;
	int no_ignores;
};

static const struct got_error *
report_file_status(struct got_fileindex_entry *ie, const char *abspath,
    int dirfd, const char *de_name,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo, int report_unchanged)
{
	const struct got_error *err = NULL;
	unsigned char status = GOT_STATUS_NO_CHANGE;
	unsigned char staged_status;
	struct stat sb;
	struct got_object_id blob_id, commit_id, staged_blob_id;
	struct got_object_id *blob_idp = NULL, *commit_idp = NULL;
	struct got_object_id *staged_blob_idp = NULL;

	staged_status = get_staged_status(ie);
	err = get_file_status(&status, &sb, ie, abspath, dirfd, de_name, repo);
	if (err)
		return err;

	if (status == GOT_STATUS_NO_CHANGE &&
	    staged_status == GOT_STATUS_NO_CHANGE && !report_unchanged)
		return NULL;

	if (got_fileindex_entry_has_blob(ie))
		blob_idp = got_fileindex_entry_get_blob_id(&blob_id, ie);
	if (got_fileindex_entry_has_commit(ie))
		commit_idp = got_fileindex_entry_get_commit_id(&commit_id, ie);
	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY) {
		staged_blob_idp = got_fileindex_entry_get_staged_blob_id(
		    &staged_blob_id, ie);
	}

	return (*status_cb)(status_arg, status, staged_status,
	    ie->path, blob_idp, staged_blob_idp, commit_idp, dirfd, de_name);
}

static const struct got_error *
status_old_new(void *arg, struct got_fileindex_entry *ie,
    struct dirent *de, const char *parent_path, int dirfd)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	char *abspath;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	if (got_path_cmp(parent_path, a->status_path,
	    strlen(parent_path), a->status_path_len) != 0 &&
	    !got_path_is_child(parent_path, a->status_path, a->status_path_len))
		return NULL;

	if (parent_path[0]) {
		if (asprintf(&abspath, "%s/%s/%s", a->worktree->root_path,
		    parent_path, de->d_name) == -1)
			return got_error_from_errno("asprintf");
	} else {
		if (asprintf(&abspath, "%s/%s", a->worktree->root_path,
		    de->d_name) == -1)
			return got_error_from_errno("asprintf");
	}

	err = report_file_status(ie, abspath, dirfd, de->d_name,
	    a->status_cb, a->status_arg, a->repo, a->report_unchanged);
	free(abspath);
	return err;
}

static const struct got_error *
status_old(void *arg, struct got_fileindex_entry *ie, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	struct got_object_id blob_id, commit_id;
	unsigned char status;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	if (!got_path_is_child(ie->path, a->status_path, a->status_path_len))
		return NULL;

	got_fileindex_entry_get_blob_id(&blob_id, ie);
	got_fileindex_entry_get_commit_id(&commit_id, ie);
	if (got_fileindex_entry_has_file_on_disk(ie))
		status = GOT_STATUS_MISSING;
	else
		status = GOT_STATUS_DELETE;
	return (*a->status_cb)(a->status_arg, status, get_staged_status(ie),
	    ie->path, &blob_id, NULL, &commit_id, -1, NULL);
}

static void
free_ignores(struct got_pathlist_head *ignores)
{
	struct got_pathlist_entry *pe;

	RB_FOREACH(pe, got_pathlist_head, ignores) {
		struct got_pathlist_head *ignorelist = pe->data;

		got_pathlist_free(ignorelist, GOT_PATHLIST_FREE_PATH);
	}
	got_pathlist_free(ignores, GOT_PATHLIST_FREE_PATH);
}

static const struct got_error *
read_ignores(struct got_pathlist_head *ignores, const char *path, FILE *f)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe = NULL;
	struct got_pathlist_head *ignorelist;
	char *line = NULL, *pattern, *dirpath = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	ignorelist = calloc(1, sizeof(*ignorelist));
	if (ignorelist == NULL)
		return got_error_from_errno("calloc");
	RB_INIT(ignorelist);

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		if (linelen > 0 && line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		/* Git's ignores may contain comments. */
		if (line[0] == '#')
			continue;

		/* Git's negated patterns are not (yet?) supported. */
		if (line[0] == '!')
			continue;

		if (asprintf(&pattern, "%s%s%s", path, path[0] ? "/" : "",
		    line) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = got_pathlist_insert(NULL, ignorelist, pattern, NULL);
		if (err)
			goto done;
	}
	if (ferror(f)) {
		err = got_error_from_errno("getline");
		goto done;
	}

	dirpath = strdup(path);
	if (dirpath == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	err = got_pathlist_insert(&pe, ignores, dirpath, ignorelist);
done:
	free(line);
	if (err || pe == NULL) {
		free(dirpath);
		got_pathlist_free(ignorelist, GOT_PATHLIST_FREE_PATH);
	}
	return err;
}

static int
match_path(const char *pattern, size_t pattern_len, const char *path,
    int flags)
{
	char buf[PATH_MAX];

	/*
	 * Trailing slashes signify directories.
	 * Append a * to make such patterns conform to fnmatch rules.
	 */
	if (pattern_len > 0 && pattern[pattern_len - 1] == '/') {
		if (snprintf(buf, sizeof(buf), "%s*", pattern) >= sizeof(buf))
			return FNM_NOMATCH; /* XXX */

		return fnmatch(buf, path, flags);
	}

	return fnmatch(pattern, path, flags);
}

static int
match_ignores(struct got_pathlist_head *ignores, const char *path)
{
	struct got_pathlist_entry *pe;

	/* Handle patterns which match in all directories. */
	RB_FOREACH(pe, got_pathlist_head, ignores) {
		struct got_pathlist_head *ignorelist = pe->data;
		struct got_pathlist_entry *pi;

		RB_FOREACH(pi, got_pathlist_head, ignorelist) {
			const char *p;

			if (pi->path_len < 3 ||
			    strncmp(pi->path, "**/", 3) != 0)
				continue;
			p = path;
			while (*p) {
				if (match_path(pi->path + 3,
				    pi->path_len - 3, p,
				    FNM_PATHNAME | FNM_LEADING_DIR)) {
					/* Retry in next directory. */
					while (*p && *p != '/')
						p++;
					while (*p == '/')
						p++;
					continue;
				}
				return 1;
			}
		}
	}

	/*
	 * The ignores pathlist contains ignore lists from children before
	 * parents, so we can find the most specific ignorelist by walking
	 * ignores backwards.
	 */
	pe = RB_MAX(got_pathlist_head, ignores);
	while (pe) {
		if (got_path_is_child(path, pe->path, pe->path_len)) {
			struct got_pathlist_head *ignorelist = pe->data;
			struct got_pathlist_entry *pi;
			RB_FOREACH(pi, got_pathlist_head, ignorelist) {
				int flags = FNM_LEADING_DIR;
				if (strstr(pi->path, "/**/") == NULL)
					flags |= FNM_PATHNAME;
				if (match_path(pi->path, pi->path_len,
				    path, flags))
					continue;
				return 1;
			}
		}
		pe = RB_PREV(got_pathlist_head, ignores,  pe);
	}

	return 0;
}

static const struct got_error *
add_ignores(struct got_pathlist_head *ignores, const char *root_path,
    const char *path, int dirfd, const char *ignores_filename)
{
	const struct got_error *err = NULL;
	char *ignorespath;
	int fd = -1;
	FILE *ignoresfile = NULL;

	if (asprintf(&ignorespath, "%s/%s%s%s", root_path, path,
	    path[0] ? "/" : "", ignores_filename) == -1)
		return got_error_from_errno("asprintf");

	if (dirfd != -1) {
		fd = openat(dirfd, ignores_filename,
		    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd == -1) {
			if (errno != ENOENT && errno != EACCES)
				err = got_error_from_errno2("openat",
				    ignorespath);
		} else {
			ignoresfile = fdopen(fd, "r");
			if (ignoresfile == NULL)
				err = got_error_from_errno2("fdopen",
				    ignorespath);
			else {
				fd = -1;
				err = read_ignores(ignores, path, ignoresfile);
			}
		}
	} else {
		ignoresfile = fopen(ignorespath, "re");
		if (ignoresfile == NULL) {
			if (errno != ENOENT && errno != EACCES)
				err = got_error_from_errno2("fopen",
				    ignorespath);
		} else
			err = read_ignores(ignores, path, ignoresfile);
	}

	if (ignoresfile && fclose(ignoresfile) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", path);
	free(ignorespath);
	return err;
}

static const struct got_error *
status_new(int *ignore, void *arg, struct dirent *de, const char *parent_path,
    int dirfd)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	char *path = NULL;

	if (ignore != NULL)
		*ignore = 0;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	if (parent_path[0]) {
		if (asprintf(&path, "%s/%s", parent_path, de->d_name) == -1)
			return got_error_from_errno("asprintf");
	} else {
		path = de->d_name;
	}

	if (de->d_type == DT_DIR) {
		if (!a->no_ignores && ignore != NULL &&
		    match_ignores(a->ignores, path))
			*ignore = 1;
	} else if (!match_ignores(a->ignores, path) &&
	    got_path_is_child(path, a->status_path, a->status_path_len))
		err = (*a->status_cb)(a->status_arg, GOT_STATUS_UNVERSIONED,
		    GOT_STATUS_NO_CHANGE, path, NULL, NULL, NULL, -1, NULL);
	if (parent_path[0])
		free(path);
	return err;
}

static const struct got_error *
status_traverse(void *arg, const char *path, int dirfd)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;

	if (a->no_ignores)
		return NULL;

	err = add_ignores(a->ignores, a->worktree->root_path,
	    path, dirfd, ".cvsignore");
	if (err)
		return err;

	err = add_ignores(a->ignores, a->worktree->root_path, path,
	    dirfd, ".gitignore");

	return err;
}

static const struct got_error *
report_single_file_status(const char *path, const char *ondisk_path,
    struct got_fileindex *fileindex, got_worktree_status_cb status_cb,
    void *status_arg, struct got_repository *repo, int report_unchanged,
    struct got_pathlist_head *ignores, int no_ignores)
{
	struct got_fileindex_entry *ie;
	struct stat sb;

	ie = got_fileindex_entry_get(fileindex, path, strlen(path));
	if (ie)
		return report_file_status(ie, ondisk_path, -1, NULL,
		    status_cb, status_arg, repo, report_unchanged);

	if (lstat(ondisk_path, &sb) == -1) {
		if (errno != ENOENT)
			return got_error_from_errno2("lstat", ondisk_path);
		return (*status_cb)(status_arg, GOT_STATUS_NONEXISTENT,
		    GOT_STATUS_NO_CHANGE, path, NULL, NULL, NULL, -1, NULL);
	}

	if (!no_ignores && match_ignores(ignores, path))
		return NULL;

	if (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode))
		return (*status_cb)(status_arg, GOT_STATUS_UNVERSIONED,
		    GOT_STATUS_NO_CHANGE, path, NULL, NULL, NULL, -1, NULL);

	return NULL;
}

static const struct got_error *
add_ignores_from_parent_paths(struct got_pathlist_head *ignores,
    const char *root_path, const char *path)
{
	const struct got_error *err;
	char *parent_path, *next_parent_path = NULL;

	err = add_ignores(ignores, root_path, "", -1,
	    ".cvsignore");
	if (err)
		return err;

	err = add_ignores(ignores, root_path, "", -1,
	    ".gitignore");
	if (err)
		return err;

	err = got_path_dirname(&parent_path, path);
	if (err) {
		if (err->code == GOT_ERR_BAD_PATH)
			return NULL; /* cannot traverse parent */
		return err;
	}
	for (;;) {
		err = add_ignores(ignores, root_path, parent_path, -1,
		    ".cvsignore");
		if (err)
			break;
		err = add_ignores(ignores, root_path, parent_path, -1,
		    ".gitignore");
		if (err)
			break;
		err = got_path_dirname(&next_parent_path, parent_path);
		if (err) {
			if (err->code == GOT_ERR_BAD_PATH)
				err = NULL; /* traversed everything */
			break;
		}
		if (got_path_is_root_dir(parent_path))
			break;
		free(parent_path);
		parent_path = next_parent_path;
		next_parent_path = NULL;
	}

	free(parent_path);
	free(next_parent_path);
	return err;
}

struct find_missing_children_args {
	const char *parent_path;
	size_t parent_len;
	struct got_pathlist_head *children;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
};

static const struct got_error *
find_missing_children(void *arg, struct got_fileindex_entry *ie)
{
	const struct got_error *err = NULL;
	struct find_missing_children_args *a = arg;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	if (got_path_is_child(ie->path, a->parent_path, a->parent_len))
		err = got_pathlist_insert(NULL, a->children, ie->path, NULL);

	return err;
}

static const struct got_error *
report_children(struct got_pathlist_head *children,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_repository *repo, int is_root_dir, int report_unchanged,
    struct got_pathlist_head *ignores, int no_ignores,
    got_worktree_status_cb status_cb, void *status_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	char *ondisk_path = NULL;

	RB_FOREACH(pe, got_pathlist_head, children) {
		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}

		if (asprintf(&ondisk_path, "%s%s%s", worktree->root_path,
		    !is_root_dir ? "/" : "", pe->path) == -1) {
			err = got_error_from_errno("asprintf");
			ondisk_path = NULL;
			break;
		}

		err = report_single_file_status(pe->path, ondisk_path,
		    fileindex, status_cb, status_arg, repo, report_unchanged,
		    ignores, no_ignores);
		if (err)
			break;

		free(ondisk_path);
		ondisk_path = NULL;
	}

	free(ondisk_path);
	return err;
}

static const struct got_error *
worktree_status(struct got_worktree *worktree, const char *path,
    struct got_fileindex *fileindex, struct got_repository *repo,
    got_worktree_status_cb status_cb, void *status_arg,
    got_cancel_cb cancel_cb, void *cancel_arg, int no_ignores,
    int report_unchanged)
{
	const struct got_error *err = NULL;
	int fd = -1;
	struct got_fileindex_diff_dir_cb fdiff_cb;
	struct diff_dir_cb_arg arg;
	char *ondisk_path = NULL;
	struct got_pathlist_head ignores, missing_children;
	struct got_fileindex_entry *ie;

	RB_INIT(&ignores);
	RB_INIT(&missing_children);

	if (asprintf(&ondisk_path, "%s%s%s",
	    worktree->root_path, path[0] ? "/" : "", path) == -1)
		return got_error_from_errno("asprintf");

	ie = got_fileindex_entry_get(fileindex, path, strlen(path));
	if (ie) {
		err = report_single_file_status(path, ondisk_path,
		    fileindex, status_cb, status_arg, repo,
		    report_unchanged, &ignores, no_ignores);
		goto done;
	} else {
		struct find_missing_children_args fmca;
		fmca.parent_path = path;
		fmca.parent_len = strlen(path);
		fmca.children = &missing_children;
		fmca.cancel_cb = cancel_cb;
		fmca.cancel_arg = cancel_arg;
		err = got_fileindex_for_each_entry_safe(fileindex,
		    find_missing_children, &fmca);
		if (err)
			goto done;
	}

	fd = open(ondisk_path, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1) {
		if (errno != ENOTDIR && errno != ENOENT && errno != EACCES &&
		    !got_err_open_nofollow_on_symlink())
			err = got_error_from_errno2("open", ondisk_path);
		else {
			if (!no_ignores) {
				err = add_ignores_from_parent_paths(&ignores,
				    worktree->root_path, ondisk_path);
				if (err)
					goto done;
			}
			if (RB_EMPTY(&missing_children)) {
				err = report_single_file_status(path,
				    ondisk_path, fileindex,
				    status_cb, status_arg, repo,
				    report_unchanged, &ignores, no_ignores);
				if (err)
					goto done;
			} else {
				err = report_children(&missing_children,
				    worktree, fileindex, repo,
				    (path[0] == '\0'), report_unchanged,
				    &ignores, no_ignores,
				    status_cb, status_arg,
				    cancel_cb, cancel_arg);
				if (err)
					goto done;
			}
		}
	} else {
		fdiff_cb.diff_old_new = status_old_new;
		fdiff_cb.diff_old = status_old;
		fdiff_cb.diff_new = status_new;
		fdiff_cb.diff_traverse = status_traverse;
		arg.fileindex = fileindex;
		arg.worktree = worktree;
		arg.status_path = path;
		arg.status_path_len = strlen(path);
		arg.repo = repo;
		arg.status_cb = status_cb;
		arg.status_arg = status_arg;
		arg.cancel_cb = cancel_cb;
		arg.cancel_arg = cancel_arg;
		arg.report_unchanged = report_unchanged;
		arg.no_ignores = no_ignores;
		if (!no_ignores) {
			err = add_ignores_from_parent_paths(&ignores,
			    worktree->root_path, path);
			if (err)
				goto done;
		}
		arg.ignores = &ignores;
		err = got_fileindex_diff_dir(fileindex, fd,
		    worktree->root_path, path, repo, &fdiff_cb, &arg);
	}
done:
	free_ignores(&ignores);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(ondisk_path);
	return err;
}

static void
free_commitable(struct got_commitable *ct)
{
	free(ct->path);
	free(ct->in_repo_path);
	free(ct->ondisk_path);
	free(ct->blob_id);
	free(ct->base_blob_id);
	free(ct->staged_blob_id);
	free(ct->base_commit_id);
	free(ct);
}

struct collect_commitables_arg {
	struct got_pathlist_head *commitable_paths;
	struct got_repository *repo;
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	int have_staged_files;
	int allow_bad_symlinks;
	int diff_header_shown;
	int commit_conflicts;
	FILE *diff_outfile;
	FILE *f1;
	FILE *f2;
};

/*
 * Create a file which contains the target path of a symlink so we can feed
 * it as content to the diff engine.
 */
static const struct got_error *
get_symlink_target_file(int *fd, int dirfd, const char *de_name,
    const char *abspath)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	ssize_t target_len, outlen;

	*fd = -1;

	if (dirfd != -1) {
		target_len = readlinkat(dirfd, de_name, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlinkat", abspath);
	} else {
		target_len = readlink(abspath, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlink", abspath);
	}

	*fd = got_opentempfd();
	if (*fd == -1)
		return got_error_from_errno("got_opentempfd");

	outlen = write(*fd, target_path, target_len);
	if (outlen == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (lseek(*fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", abspath);
		goto done;
	}
done:
	if (err) {
		close(*fd);
		*fd = -1;
	}
	return err;
}

static const struct got_error *
append_ct_diff(struct got_commitable *ct, int *diff_header_shown,
    FILE *diff_outfile, FILE *f1, FILE *f2, int dirfd, const char *de_name,
    int diff_staged, struct got_repository *repo, struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL;
	int fd = -1, fd1 = -1, fd2 = -1;
	FILE *ondisk_file = NULL;
	char *label1 = NULL;
	struct stat sb;
	off_t size1 = 0;
	int f2_exists = 0;
	char *id_str = NULL;

	memset(&sb, 0, sizeof(sb));

	if (diff_staged) {
		if (ct->staged_status != GOT_STATUS_MODIFY &&
		    ct->staged_status != GOT_STATUS_ADD &&
		    ct->staged_status != GOT_STATUS_DELETE)
			return NULL;
	} else {
		if (ct->status != GOT_STATUS_MODIFY &&
		    ct->status != GOT_STATUS_ADD &&
		    ct->status != GOT_STATUS_DELETE &&
		    ct->status != GOT_STATUS_CONFLICT)
			return NULL;
	}

	err = got_opentemp_truncate(f1);
	if (err)
		return got_error_from_errno("got_opentemp_truncate");
	err = got_opentemp_truncate(f2);
	if (err)
		return got_error_from_errno("got_opentemp_truncate");

	if (!*diff_header_shown) {
		err = got_object_id_str(&id_str, worktree->base_commit_id);
		if (err)
			return err;
		fprintf(diff_outfile, "diff %s%s\n", diff_staged ? "-s " : "",
		    got_worktree_get_root_path(worktree));
		fprintf(diff_outfile, "commit - %s\n", id_str);
		fprintf(diff_outfile, "path + %s%s\n",
		    got_worktree_get_root_path(worktree),
		    diff_staged ? " (staged changes)" : "");
		*diff_header_shown = 1;
	}

	if (diff_staged) {
		const char *label1 = NULL, *label2 = NULL;
		switch (ct->staged_status) {
		case GOT_STATUS_MODIFY:
			label1 = ct->path;
			label2 = ct->path;
			break;
		case GOT_STATUS_ADD:
			label2 = ct->path;
			break;
		case GOT_STATUS_DELETE:
			label1 = ct->path;
			break;
		default:
			return got_error(GOT_ERR_FILE_STATUS);
		}
		fd1 = got_opentempfd();
		if (fd1 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
		fd2 = got_opentempfd();
		if (fd2 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
		err = got_diff_objects_as_blobs(NULL, NULL, f1, f2,
		    fd1, fd2, ct->base_blob_id, ct->staged_blob_id,
		    label1, label2, GOT_DIFF_ALGORITHM_PATIENCE, 3, 0, 0,
		    NULL, repo, diff_outfile);
		goto done;
	}

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (ct->status != GOT_STATUS_ADD) {
		err = got_object_open_as_blob(&blob1, repo, ct->base_blob_id,
		    8192, fd1);
		if (err)
			goto done;
	}

	if (ct->status != GOT_STATUS_DELETE) {
		if (dirfd != -1) {
			fd = openat(dirfd, de_name,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				if (!got_err_open_nofollow_on_symlink()) {
					err = got_error_from_errno2("openat",
					    ct->ondisk_path);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, ct->ondisk_path);
				if (err)
					goto done;
			}
		} else {
			fd = open(ct->ondisk_path,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				if (!got_err_open_nofollow_on_symlink()) {
					err = got_error_from_errno2("open",
					    ct->ondisk_path);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, ct->ondisk_path);
				if (err)
					goto done;
			}
		}
		if (fstatat(fd, ct->ondisk_path, &sb,
		    AT_SYMLINK_NOFOLLOW) == -1) {
			err = got_error_from_errno2("fstatat", ct->ondisk_path);
			goto done;
		}
		ondisk_file = fdopen(fd, "r");
		if (ondisk_file == NULL) {
			err = got_error_from_errno2("fdopen", ct->ondisk_path);
			goto done;
		}
		fd = -1;
		f2_exists = 1;
	}

	if (blob1) {
		err = got_object_blob_dump_to_file(&size1, NULL, NULL,
		    f1, blob1);
		if (err)
			goto done;
	}

	err = got_diff_blob_file(NULL, NULL, blob1, f1, size1, label1,
	    ondisk_file ? ondisk_file : f2, f2_exists, &sb, ct->path,
	    GOT_DIFF_ALGORITHM_PATIENCE, 3, 0, 0, NULL, diff_outfile);
done:
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob1)
		got_object_blob_close(blob1);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (ondisk_file && fclose(ondisk_file) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
collect_commitables(void *arg, unsigned char status,
    unsigned char staged_status, const char *relpath,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	struct collect_commitables_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_commitable *ct = NULL;
	struct got_pathlist_entry *new = NULL;
	char *parent_path = NULL, *path = NULL;
	struct stat sb;

	if (a->have_staged_files) {
		if (staged_status != GOT_STATUS_MODIFY &&
		    staged_status != GOT_STATUS_ADD &&
		    staged_status != GOT_STATUS_DELETE)
			return NULL;
	} else {
		if (status == GOT_STATUS_CONFLICT && !a->commit_conflicts) {
			printf("C  %s\n", relpath);
			return got_error(GOT_ERR_COMMIT_CONFLICT);
		}

		if (status != GOT_STATUS_MODIFY &&
		    status != GOT_STATUS_MODE_CHANGE &&
		    status != GOT_STATUS_ADD &&
		    status != GOT_STATUS_DELETE &&
		    status != GOT_STATUS_CONFLICT)
			return NULL;
	}

	if (asprintf(&path, "/%s", relpath) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	if (strcmp(path, "/") == 0) {
		parent_path = strdup("");
		if (parent_path == NULL)
			return got_error_from_errno("strdup");
	} else {
		err = got_path_dirname(&parent_path, path);
		if (err)
			return err;
	}

	ct = calloc(1, sizeof(*ct));
	if (ct == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (asprintf(&ct->ondisk_path, "%s/%s", a->worktree->root_path,
	    relpath) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY) {
		struct got_fileindex_entry *ie;
		ie = got_fileindex_entry_get(a->fileindex, path, strlen(path));
		switch (got_fileindex_entry_staged_filetype_get(ie)) {
		case GOT_FILEIDX_MODE_REGULAR_FILE:
		case GOT_FILEIDX_MODE_BAD_SYMLINK:
			ct->mode = S_IFREG;
			break;
		case GOT_FILEIDX_MODE_SYMLINK:
			ct->mode = S_IFLNK;
			break;
		default:
			err = got_error_path(path, GOT_ERR_BAD_FILETYPE);
			goto done;
		}
		ct->mode |= got_fileindex_entry_perms_get(ie);
	} else if (status != GOT_STATUS_DELETE &&
	    staged_status != GOT_STATUS_DELETE) {
		if (dirfd != -1) {
			if (fstatat(dirfd, de_name, &sb,
			    AT_SYMLINK_NOFOLLOW) == -1) {
				err = got_error_from_errno2("fstatat",
				    ct->ondisk_path);
				goto done;
			}
		} else if (lstat(ct->ondisk_path, &sb) == -1) {
			err = got_error_from_errno2("lstat", ct->ondisk_path);
			goto done;
		}
		ct->mode = sb.st_mode;
	}

	if (asprintf(&ct->in_repo_path, "%s%s%s", a->worktree->path_prefix,
	    got_path_is_root_dir(a->worktree->path_prefix) ? "" : "/",
	    relpath) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (S_ISLNK(ct->mode) && staged_status == GOT_STATUS_NO_CHANGE &&
	    status == GOT_STATUS_ADD && !a->allow_bad_symlinks) {
		int is_bad_symlink;
		char target_path[PATH_MAX];
		ssize_t target_len;
		target_len = readlink(ct->ondisk_path, target_path,
		    sizeof(target_path));
		if (target_len == -1) {
			err = got_error_from_errno2("readlink",
			    ct->ondisk_path);
			goto done;
		}
		err = is_bad_symlink_target(&is_bad_symlink, target_path,
		    target_len, ct->ondisk_path, a->worktree->root_path);
		if (err)
			goto done;
		if (is_bad_symlink) {
			err = got_error_path(ct->ondisk_path,
			    GOT_ERR_BAD_SYMLINK);
			goto done;
		}
	}

	ct->status = status;
	ct->staged_status = staged_status;
	ct->blob_id = NULL; /* will be filled in when blob gets created */
	if (ct->status != GOT_STATUS_ADD &&
	    ct->staged_status != GOT_STATUS_ADD) {
		ct->base_blob_id = got_object_id_dup(blob_id);
		if (ct->base_blob_id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
		ct->base_commit_id = got_object_id_dup(commit_id);
		if (ct->base_commit_id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
	}
	if (ct->staged_status == GOT_STATUS_ADD ||
	    ct->staged_status == GOT_STATUS_MODIFY) {
		ct->staged_blob_id = got_object_id_dup(staged_blob_id);
		if (ct->staged_blob_id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
	}
	ct->path = strdup(path);
	if (ct->path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	err = got_pathlist_insert(&new, a->commitable_paths, ct->path, ct);
	if (err)
		goto done;

	if (a->diff_outfile && ct && new != NULL) {
		err = append_ct_diff(ct, &a->diff_header_shown,
		    a->diff_outfile, a->f1, a->f2, dirfd, de_name,
		    a->have_staged_files, a->repo, a->worktree);
		if (err)
			goto done;
	}
done:
	if (ct && (err || new == NULL))
		free_commitable(ct);
	free(parent_path);
	free(path);
	return err;
}

static const struct got_error *write_tree(struct got_object_id **, int *,
    struct got_tree_object *, const char *, struct got_pathlist_head *,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *);

static const struct got_error *
write_subtree(struct got_object_id **new_subtree_id, int *nentries,
    struct got_tree_entry *te, const char *parent_path,
    struct got_pathlist_head *commitable_paths,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *subtree;
	char *subpath;

	if (asprintf(&subpath, "%s%s%s", parent_path,
	    got_path_is_root_dir(parent_path) ? "" : "/", te->name) == -1)
		return got_error_from_errno("asprintf");

	err = got_object_open_as_tree(&subtree, repo, &te->id);
	if (err)
		return err;

	err = write_tree(new_subtree_id, nentries, subtree, subpath,
	    commitable_paths, status_cb, status_arg, repo);
	got_object_tree_close(subtree);
	free(subpath);
	return err;
}

static const struct got_error *
match_ct_parent_path(int *match, struct got_commitable *ct, const char *path)
{
	const struct got_error *err = NULL;
	char *ct_parent_path = NULL;

	*match = 0;

	if (strchr(ct->in_repo_path, '/') == NULL) {
		*match = got_path_is_root_dir(path);
		return NULL;
	}

	err = got_path_dirname(&ct_parent_path, ct->in_repo_path);
	if (err)
		return err;
	*match = (strcmp(path, ct_parent_path) == 0);
	free(ct_parent_path);
	return err;
}

static mode_t
get_ct_file_mode(struct got_commitable *ct)
{
	if (S_ISLNK(ct->mode))
		return S_IFLNK;

	return S_IFREG | (ct->mode & ((S_IRWXU | S_IRWXG | S_IRWXO)));
}

static const struct got_error *
alloc_modified_blob_tree_entry(struct got_tree_entry **new_te,
    struct got_tree_entry *te, struct got_commitable *ct)
{
	const struct got_error *err = NULL;

	*new_te = NULL;

	err = got_object_tree_entry_dup(new_te, te);
	if (err)
		goto done;

	(*new_te)->mode = get_ct_file_mode(ct);

	if (ct->staged_status == GOT_STATUS_MODIFY)
		memcpy(&(*new_te)->id, ct->staged_blob_id,
		    sizeof((*new_te)->id));
	else
		memcpy(&(*new_te)->id, ct->blob_id, sizeof((*new_te)->id));
done:
	if (err && *new_te) {
		free(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
alloc_added_blob_tree_entry(struct got_tree_entry **new_te,
    struct got_commitable *ct)
{
	const struct got_error *err = NULL;
	char *ct_name = NULL;

	 *new_te = NULL;

	*new_te = calloc(1, sizeof(**new_te));
	if (*new_te == NULL)
		return got_error_from_errno("calloc");

	err = got_path_basename(&ct_name, ct->path);
	if (err)
		goto done;
	if (strlcpy((*new_te)->name, ct_name, sizeof((*new_te)->name)) >=
	    sizeof((*new_te)->name)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	(*new_te)->mode = get_ct_file_mode(ct);

	if (ct->staged_status == GOT_STATUS_ADD)
		memcpy(&(*new_te)->id, ct->staged_blob_id,
		    sizeof((*new_te)->id));
	else
		memcpy(&(*new_te)->id, ct->blob_id, sizeof((*new_te)->id));
done:
	free(ct_name);
	if (err && *new_te) {
		free(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
insert_tree_entry(struct got_tree_entry *new_te,
    struct got_pathlist_head *paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *new_pe;

	err = got_pathlist_insert(&new_pe, paths, new_te->name, new_te);
	if (err)
		return err;
	if (new_pe == NULL)
		return got_error(GOT_ERR_TREE_DUP_ENTRY);
	return NULL;
}

static const struct got_error *
report_ct_status(struct got_commitable *ct,
    got_worktree_status_cb status_cb, void *status_arg)
{
	const char *ct_path = ct->path;
	unsigned char status;

	if (status_cb == NULL) /* no commit progress output desired */
		return NULL;

	while (ct_path[0] == '/')
		ct_path++;

	if (ct->staged_status != GOT_STATUS_NO_CHANGE)
		status = ct->staged_status;
	else
		status = ct->status;

	return (*status_cb)(status_arg, status, GOT_STATUS_NO_CHANGE,
	    ct_path, ct->blob_id, NULL, NULL, -1, NULL);
}

static const struct got_error *
match_modified_subtree(int *modified, struct got_tree_entry *te,
    const char *base_tree_path, struct got_pathlist_head *commitable_paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	char *te_path;

	*modified = 0;

	if (asprintf(&te_path, "%s%s%s", base_tree_path,
	    got_path_is_root_dir(base_tree_path) ? "" : "/",
	    te->name) == -1)
		return got_error_from_errno("asprintf");

	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = pe->data;
		*modified = got_path_is_child(ct->in_repo_path, te_path,
		    strlen(te_path));
		if (*modified)
			break;
	}

	free(te_path);
	return err;
}

static const struct got_error *
match_deleted_or_modified_ct(struct got_commitable **ctp,
    struct got_tree_entry *te, const char *base_tree_path,
    struct got_pathlist_head *commitable_paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;

	*ctp = NULL;

	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = pe->data;
		char *ct_name = NULL;
		int path_matches;

		if (ct->staged_status == GOT_STATUS_NO_CHANGE) {
			if (ct->status != GOT_STATUS_MODIFY &&
			    ct->status != GOT_STATUS_MODE_CHANGE &&
			    ct->status != GOT_STATUS_DELETE &&
			    ct->status != GOT_STATUS_CONFLICT)
				continue;
		} else {
			if (ct->staged_status != GOT_STATUS_MODIFY &&
			    ct->staged_status != GOT_STATUS_DELETE)
				continue;
		}

		if (got_object_id_cmp(ct->base_blob_id, &te->id) != 0)
			continue;

		err = match_ct_parent_path(&path_matches, ct, base_tree_path);
		if (err)
			return err;
		if (!path_matches)
			continue;

		err = got_path_basename(&ct_name, pe->path);
		if (err)
			return err;

		if (strcmp(te->name, ct_name) != 0) {
			free(ct_name);
			continue;
		}
		free(ct_name);

		*ctp = ct;
		break;
	}

	return err;
}

static const struct got_error *
make_subtree_for_added_blob(struct got_tree_entry **new_tep,
    const char *child_path, const char *path_base_tree,
    struct got_pathlist_head *commitable_paths,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *new_te;
	char *subtree_path;
	struct got_object_id *id = NULL;
	int nentries;

	*new_tep = NULL;

	if (asprintf(&subtree_path, "%s%s%s", path_base_tree,
	    got_path_is_root_dir(path_base_tree) ? "" : "/",
	    child_path) == -1)
		return got_error_from_errno("asprintf");

	new_te = calloc(1, sizeof(*new_te));
	if (new_te == NULL)
		return got_error_from_errno("calloc");
	new_te->mode = S_IFDIR;

	if (strlcpy(new_te->name, child_path, sizeof(new_te->name)) >=
	    sizeof(new_te->name)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}
	err = write_tree(&id, &nentries, NULL, subtree_path,
	    commitable_paths, status_cb, status_arg, repo);
	if (err) {
		free(new_te);
		goto done;
	}
	memcpy(&new_te->id, id, sizeof(new_te->id));
done:
	free(id);
	free(subtree_path);
	if (err == NULL)
		*new_tep = new_te;
	return err;
}

static const struct got_error *
write_tree(struct got_object_id **new_tree_id, int *nentries,
    struct got_tree_object *base_tree, const char *path_base_tree,
    struct got_pathlist_head *commitable_paths,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_head paths;
	struct got_tree_entry *te, *new_te = NULL;
	struct got_pathlist_entry *pe;

	RB_INIT(&paths);
	*nentries = 0;

	/* Insert, and recurse into, newly added entries first. */
	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = pe->data;
		char *child_path = NULL, *slash;

		if ((ct->status != GOT_STATUS_ADD &&
		    ct->staged_status != GOT_STATUS_ADD) ||
		    (ct->flags & GOT_COMMITABLE_ADDED))
			continue;

		if (!got_path_is_child(ct->in_repo_path, path_base_tree,
		    strlen(path_base_tree)))
			continue;

		err = got_path_skip_common_ancestor(&child_path, path_base_tree,
		    ct->in_repo_path);
		if (err)
			goto done;

		slash = strchr(child_path, '/');
		if (slash == NULL) {
			err = alloc_added_blob_tree_entry(&new_te, ct);
			if (err)
				goto done;
			err = report_ct_status(ct, status_cb, status_arg);
			if (err)
				goto done;
			ct->flags |= GOT_COMMITABLE_ADDED;
			err = insert_tree_entry(new_te, &paths);
			if (err)
				goto done;
			(*nentries)++;
		} else {
			*slash = '\0'; /* trim trailing path components */
			if (base_tree == NULL ||
			    got_object_tree_find_entry(base_tree, child_path)
			    == NULL) {
				err = make_subtree_for_added_blob(&new_te,
				    child_path, path_base_tree,
				    commitable_paths, status_cb, status_arg,
				    repo);
				if (err)
					goto done;
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
				(*nentries)++;
			}
		}
	}

	if (base_tree) {
		int i, nbase_entries;
		/* Handle modified and deleted entries. */
		nbase_entries = got_object_tree_get_nentries(base_tree);
		for (i = 0; i < nbase_entries; i++) {
			struct got_commitable *ct = NULL;

			te = got_object_tree_get_entry(base_tree, i);
			if (te == NULL) {
				err = got_error_fmt(GOT_ERR_BAD_OBJ_DATA,
				    "cannot get tree entry %d of %d", i + 1,
				    nbase_entries);
				goto done;
			}
			if (got_object_tree_entry_is_submodule(te)) {
				/* Entry is a submodule; just copy it. */
				err = got_object_tree_entry_dup(&new_te, te);
				if (err)
					goto done;
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
				(*nentries)++;
				continue;
			}

			if (S_ISDIR(te->mode)) {
				int modified;
				err = got_object_tree_entry_dup(&new_te, te);
				if (err)
					goto done;
				err = match_modified_subtree(&modified, te,
				    path_base_tree, commitable_paths);
				if (err)
					goto done;
				/* Avoid recursion into unmodified subtrees. */
				if (modified) {
					struct got_object_id *new_id;
					int nsubentries;
					err = write_subtree(&new_id,
					    &nsubentries, te,
					    path_base_tree, commitable_paths,
					    status_cb, status_arg, repo);
					if (err)
						goto done;
					if (nsubentries == 0) {
						/* All entries were deleted. */
						free(new_id);
						continue;
					}
					memcpy(&new_te->id, new_id,
					    sizeof(new_te->id));
					free(new_id);
				}
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
				(*nentries)++;
				continue;
			}

			err = match_deleted_or_modified_ct(&ct, te,
			    path_base_tree, commitable_paths);
			if (err)
				goto done;
			if (ct) {
				/* NB: Deleted entries get dropped here. */
				if (ct->status == GOT_STATUS_MODIFY ||
				    ct->status == GOT_STATUS_MODE_CHANGE ||
				    ct->status == GOT_STATUS_CONFLICT ||
				    ct->staged_status == GOT_STATUS_MODIFY) {
					err = alloc_modified_blob_tree_entry(
					    &new_te, te, ct);
					if (err)
						goto done;
					err = insert_tree_entry(new_te, &paths);
					if (err)
						goto done;
					(*nentries)++;
				}
				err = report_ct_status(ct, status_cb,
				    status_arg);
				if (err)
					goto done;
			} else {
				/* Entry is unchanged; just copy it. */
				err = got_object_tree_entry_dup(&new_te, te);
				if (err)
					goto done;
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
				(*nentries)++;
			}
		}
	}

	/* Write new list of entries; deleted entries have been dropped. */
	err = got_object_tree_create(new_tree_id, &paths, *nentries, repo);
done:
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_NONE);
	return err;
}

static const struct got_error *
update_fileindex_after_commit(struct got_worktree *worktree,
    struct got_pathlist_head *commitable_paths,
    struct got_object_id *new_base_commit_id,
    struct got_fileindex *fileindex, int have_staged_files)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	char *relpath = NULL;

	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_fileindex_entry *ie;
		struct got_commitable *ct = pe->data;

		ie = got_fileindex_entry_get(fileindex, pe->path, pe->path_len);

		err = got_path_skip_common_ancestor(&relpath,
		    worktree->root_path, ct->ondisk_path);
		if (err)
			goto done;

		if (ie) {
			if (ct->status == GOT_STATUS_DELETE ||
			    ct->staged_status == GOT_STATUS_DELETE) {
				got_fileindex_entry_remove(fileindex, ie);
			} else if (ct->staged_status == GOT_STATUS_ADD ||
			    ct->staged_status == GOT_STATUS_MODIFY) {
				got_fileindex_entry_stage_set(ie,
				    GOT_FILEIDX_STAGE_NONE);
				got_fileindex_entry_staged_filetype_set(ie, 0);

				err = got_fileindex_entry_update(ie,
				    worktree->root_fd, relpath,
				    ct->staged_blob_id, new_base_commit_id,
				    !have_staged_files);
			} else
				err = got_fileindex_entry_update(ie,
				    worktree->root_fd, relpath,
				    ct->blob_id, new_base_commit_id,
				    !have_staged_files);
		} else {
			err = got_fileindex_entry_alloc(&ie, pe->path);
			if (err)
				goto done;
			err = got_fileindex_entry_update(ie,
			    worktree->root_fd, relpath, ct->blob_id,
			    new_base_commit_id, 1);
			if (err) {
				got_fileindex_entry_free(ie);
				goto done;
			}
			err = got_fileindex_entry_add(fileindex, ie);
			if (err) {
				got_fileindex_entry_free(ie);
				goto done;
			}
		}
		free(relpath);
		relpath = NULL;
	}
done:
	free(relpath);
	return err;
}

static const struct got_error *
check_out_of_date(const char *in_repo_path, unsigned char status,
    unsigned char staged_status, struct got_object_id *base_blob_id,
    struct got_object_id *base_commit_id,
    struct got_object_id *head_commit_id, struct got_repository *repo,
    int ood_errcode)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id = NULL;

	if (status != GOT_STATUS_ADD && staged_status != GOT_STATUS_ADD) {
		/* Trivial case: base commit == head commit */
		if (got_object_id_cmp(base_commit_id, head_commit_id) == 0)
			return NULL;
		/*
		 * Ensure file content which local changes were based
		 * on matches file content in the branch head.
		 */
		err = got_object_open_as_commit(&commit, repo, head_commit_id);
		if (err)
			goto done;
		err = got_object_id_by_path(&id, repo, commit, in_repo_path);
		if (err) {
			if (err->code == GOT_ERR_NO_TREE_ENTRY)
				err = got_error(ood_errcode);
			goto done;
		} else if (got_object_id_cmp(id, base_blob_id) != 0)
			err = got_error(ood_errcode);
	} else {
		/* Require that added files don't exist in the branch head. */
		err = got_object_open_as_commit(&commit, repo, head_commit_id);
		if (err)
			goto done;
		err = got_object_id_by_path(&id, repo, commit, in_repo_path);
		if (err && err->code != GOT_ERR_NO_TREE_ENTRY)
			goto done;
		err = id ? got_error(ood_errcode) : NULL;
	}
done:
	free(id);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
commit_worktree(struct got_object_id **new_commit_id,
    struct got_pathlist_head *commitable_paths,
    struct got_object_id *head_commit_id,
    struct got_object_id *parent_id2,
    struct got_worktree *worktree,
    const char *author, time_t author_time, const char *committer,
    char *diff_path, got_worktree_commit_msg_cb commit_msg_cb, void *commit_arg,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	struct got_commit_object *head_commit = NULL;
	struct got_tree_object *head_tree = NULL;
	struct got_object_id *new_tree_id = NULL;
	int nentries, nparents = 0;
	struct got_object_id_queue parent_ids;
	struct got_object_qid *pid = NULL;
	char *logmsg = NULL;
	time_t timestamp;

	*new_commit_id = NULL;

	STAILQ_INIT(&parent_ids);

	err = got_object_open_as_commit(&head_commit, repo, head_commit_id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&head_tree, repo, head_commit->tree_id);
	if (err)
		goto done;

	if (commit_msg_cb != NULL) {
		err = commit_msg_cb(commitable_paths, diff_path,
		    &logmsg, commit_arg);
		if (err)
			goto done;
	}

	if (logmsg == NULL || strlen(logmsg) == 0) {
		err = got_error(GOT_ERR_COMMIT_MSG_EMPTY);
		goto done;
	}

	/* Create blobs from added and modified files and record their IDs. */
	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = pe->data;
		char *ondisk_path;

		/* Blobs for staged files already exist. */
		if (ct->staged_status == GOT_STATUS_ADD ||
		    ct->staged_status == GOT_STATUS_MODIFY)
			continue;

		if (ct->status != GOT_STATUS_ADD &&
		    ct->status != GOT_STATUS_MODIFY &&
		    ct->status != GOT_STATUS_MODE_CHANGE &&
		    ct->status != GOT_STATUS_CONFLICT)
			continue;

		if (asprintf(&ondisk_path, "%s/%s",
		    worktree->root_path, pe->path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = got_object_blob_create(&ct->blob_id, ondisk_path, repo);
		free(ondisk_path);
		if (err)
			goto done;
	}

	/* Recursively write new tree objects. */
	err = write_tree(&new_tree_id, &nentries, head_tree, "/",
	    commitable_paths, status_cb, status_arg, repo);
	if (err)
		goto done;

	err = got_object_qid_alloc(&pid, head_commit_id);
	if (err)
		goto done;
	STAILQ_INSERT_TAIL(&parent_ids, pid, entry);
	nparents++;
	if (parent_id2) {
		err = got_object_qid_alloc(&pid, parent_id2);
		if (err)
			goto done;
		STAILQ_INSERT_TAIL(&parent_ids, pid, entry);
		nparents++;
	}
	timestamp = time(NULL);
	if (committer == NULL)
		author_time = timestamp;
	err = got_object_commit_create(new_commit_id, new_tree_id, &parent_ids,
	    nparents, author, author_time, committer, timestamp, logmsg, repo);
	if (logmsg != NULL)
		free(logmsg);
	if (err)
		goto done;
done:
	got_object_id_queue_free(&parent_ids);
	if (head_tree)
		got_object_tree_close(head_tree);
	if (head_commit)
		got_object_commit_close(head_commit);
	return err;
}

static const struct got_error *
check_path_is_commitable(const char *path,
    struct got_pathlist_head *commitable_paths)
{
	struct got_pathlist_entry *cpe = NULL;
	size_t path_len = strlen(path);

	RB_FOREACH(cpe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = cpe->data;
		const char *ct_path = ct->path;

		while (ct_path[0] == '/')
			ct_path++;

		if (strcmp(path, ct_path) == 0 ||
		    got_path_is_child(ct_path, path, path_len))
			break;
	}

	if (cpe == NULL)
		return got_error_path(path, GOT_ERR_BAD_PATH);

	return NULL;
}

static const struct got_error *
check_staged_file(void *arg, struct got_fileindex_entry *ie)
{
	int *have_staged_files = arg;

	if (got_fileindex_entry_stage_get(ie) != GOT_FILEIDX_STAGE_NONE) {
		*have_staged_files = 1;
		return got_error(GOT_ERR_CANCELLED);
	}

	return NULL;
}

static const struct got_error *
check_non_staged_files(struct got_fileindex *fileindex,
    struct got_pathlist_head *paths)
{
	struct got_pathlist_entry *pe;
	struct got_fileindex_entry *ie;

	RB_FOREACH(pe, got_pathlist_head, paths) {
		if (pe->path[0] == '\0')
			continue;
		ie = got_fileindex_entry_get(fileindex, pe->path, pe->path_len);
		if (ie == NULL)
			return got_error_path(pe->path, GOT_ERR_BAD_PATH);
		if (got_fileindex_entry_stage_get(ie) == GOT_FILEIDX_STAGE_NONE)
			return got_error_path(pe->path,
			    GOT_ERR_FILE_NOT_STAGED);
	}

	return NULL;
}

static void
print_load_info(int print_colored, int print_found, int print_trees,
    int ncolored, int nfound, int ntrees)
{
	if (print_colored) {
		printf("%d commit%s colored", ncolored,
		    ncolored == 1 ? "" : "s");
	}
	if (print_found) {
		printf("%s%d object%s found",
		    ncolored > 0 ? "; " : "",
		    nfound, nfound == 1 ? "" : "s");
	}
	if (print_trees) {
		printf("; %d tree%s scanned", ntrees,
		    ntrees == 1 ? "" : "s");
	}
}

struct got_send_progress_arg {
	char last_scaled_packsize[FMT_SCALED_STRSIZE];
	int verbosity;
	int last_ncolored;
	int last_nfound;
	int last_ntrees;
	int loading_done;
	int last_ncommits;
	int last_nobj_total;
	int last_p_deltify;
	int last_p_written;
	int last_p_sent;
	int printed_something;
	int sent_something;
	struct got_pathlist_head *delete_branches;
};

static const struct got_error *
send_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written, off_t bytes_sent, const char *refname,
    const char *errmsg, int success)
{
	struct got_send_progress_arg *a = arg;
	char scaled_packsize[FMT_SCALED_STRSIZE];
	char scaled_sent[FMT_SCALED_STRSIZE];
	int p_deltify = 0, p_written = 0, p_sent = 0;
	int print_colored = 0, print_found = 0, print_trees = 0;
	int print_searching = 0, print_total = 0;
	int print_deltify = 0, print_written = 0, print_sent = 0;

	if (a->verbosity < 0)
		return NULL;

	if (refname) {
		const char *status = success ? "accepted" : "rejected";

		if (success) {
			struct got_pathlist_entry *pe;
			RB_FOREACH(pe, got_pathlist_head, a->delete_branches) {
				const char *branchname = pe->path;
				if (got_path_cmp(branchname, refname,
				    strlen(branchname), strlen(refname)) == 0) {
					status = "deleted";
					a->sent_something = 1;
					break;
				}
			}
		}

		if (a->printed_something)
			putchar('\n');
		printf("Server has %s %s", status, refname);
		if (errmsg)
			printf(": %s", errmsg);
		a->printed_something = 1;
		return NULL;
	}

	if (a->last_ncolored != ncolored) {
		print_colored = 1;
		a->last_ncolored = ncolored;
	}

	if (a->last_nfound != nfound) {
		print_colored = 1;
		print_found = 1;
		a->last_nfound = nfound;
	}

	if (a->last_ntrees != ntrees) {
		print_colored = 1;
		print_found = 1;
		print_trees = 1;
		a->last_ntrees = ntrees;
	}

	if ((print_colored || print_found || print_trees) &&
	    !a->loading_done) {
		printf("\r");
		print_load_info(print_colored, print_found, print_trees,
		    ncolored, nfound, ntrees);
		a->printed_something = 1;
		fflush(stdout);
		return NULL;
	} else if (!a->loading_done) {
		printf("\r");
		print_load_info(1, 1, 1, ncolored, nfound, ntrees);
		printf("\n");
		a->loading_done = 1;
	}

	if (fmt_scaled(packfile_size, scaled_packsize) == -1)
		return got_error_from_errno("fmt_scaled");
	if (fmt_scaled(bytes_sent, scaled_sent) == -1)
		return got_error_from_errno("fmt_scaled");

	if (a->last_ncommits != ncommits) {
		print_searching = 1;
		a->last_ncommits = ncommits;
	}

	if (a->last_nobj_total != nobj_total) {
		print_searching = 1;
		print_total = 1;
		a->last_nobj_total = nobj_total;
	}

	if (packfile_size > 0 && (a->last_scaled_packsize[0] == '\0' ||
	    strcmp(scaled_packsize, a->last_scaled_packsize)) != 0) {
		if (strlcpy(a->last_scaled_packsize, scaled_packsize,
		    FMT_SCALED_STRSIZE) >= FMT_SCALED_STRSIZE)
			return got_error(GOT_ERR_NO_SPACE);
	}

	if (nobj_deltify > 0 || nobj_written > 0) {
		if (nobj_deltify > 0) {
			p_deltify = (nobj_deltify * 100) / nobj_total;
			if (p_deltify != a->last_p_deltify) {
				a->last_p_deltify = p_deltify;
				print_searching = 1;
				print_total = 1;
				print_deltify = 1;
			}
		}
		if (nobj_written > 0) {
			p_written = (nobj_written * 100) / nobj_total;
			if (p_written != a->last_p_written) {
				a->last_p_written = p_written;
				print_searching = 1;
				print_total = 1;
				print_deltify = 1;
				print_written = 1;
			}
		}
	}

	if (bytes_sent > 0) {
		p_sent = (bytes_sent * 100) / packfile_size;
		if (p_sent != a->last_p_sent) {
			a->last_p_sent = p_sent;
			print_searching = 1;
			print_total = 1;
			print_deltify = 1;
			print_written = 1;
			print_sent = 1;
		}
		a->sent_something = 1;
	}

	if (print_searching || print_total || print_deltify || print_written ||
	    print_sent)
		printf("\r");
	if (print_searching)
		printf("packing %d reference%s", ncommits,
		    ncommits == 1 ? "" : "s");
	if (print_total)
		printf("; %d object%s", nobj_total,
		    nobj_total == 1 ? "" : "s");
	if (print_deltify)
		printf("; deltify: %d%%", p_deltify);
	if (print_sent)
		printf("; uploading pack: %*s %d%%", FMT_SCALED_STRSIZE - 2,
		    scaled_packsize, p_sent);
	else if (print_written)
		printf("; writing pack: %*s %d%%", FMT_SCALED_STRSIZE - 2,
		    scaled_packsize, p_written);
	if (print_searching || print_total || print_deltify ||
	    print_written || print_sent) {
		a->printed_something = 1;
		fflush(stdout);
	}
	return NULL;
}

struct got_fetch_progress_arg {
	char last_scaled_size[FMT_SCALED_STRSIZE];
	int last_p_indexed;
	int last_p_resolved;
	int verbosity;

	struct got_repository *repo;
};

static const struct got_error *
fetch_progress(void *arg, const char *message, off_t packfile_size,
    int nobj_total, int nobj_indexed, int nobj_loose, int nobj_resolved)
{
	struct got_fetch_progress_arg *a = arg;
	char scaled_size[FMT_SCALED_STRSIZE];
	int p_indexed, p_resolved;
	int print_size = 0, print_indexed = 0, print_resolved = 0;

	if (a->verbosity < 0)
		return NULL;

	if (message && message[0] != '\0') {
		printf("\rserver: %s", message);
		fflush(stdout);
		return NULL;
	}

	if (packfile_size > 0 || nobj_indexed > 0) {
		if (fmt_scaled(packfile_size, scaled_size) == 0 &&
		    (a->last_scaled_size[0] == '\0' ||
		    strcmp(scaled_size, a->last_scaled_size)) != 0) {
			print_size = 1;
			if (strlcpy(a->last_scaled_size, scaled_size,
			    FMT_SCALED_STRSIZE) >= FMT_SCALED_STRSIZE)
				return got_error(GOT_ERR_NO_SPACE);
		}
		if (nobj_indexed > 0) {
			p_indexed = (nobj_indexed * 100) / nobj_total;
			if (p_indexed != a->last_p_indexed) {
				a->last_p_indexed = p_indexed;
				print_indexed = 1;
				print_size = 1;
			}
		}
		if (nobj_resolved > 0) {
			p_resolved = (nobj_resolved * 100) /
			    (nobj_total - nobj_loose);
			if (p_resolved != a->last_p_resolved) {
				a->last_p_resolved = p_resolved;
				print_resolved = 1;
				print_indexed = 1;
				print_size = 1;
			}
		}

	}
	if (print_size || print_indexed || print_resolved)
		printf("\r");
	if (print_size)
		printf("%*s fetched", FMT_SCALED_STRSIZE - 2, scaled_size);
	if (print_indexed)
		printf("; indexing %d%%", p_indexed);
	if (print_resolved)
		printf("; resolving deltas %d%%", p_resolved);
	if (print_size || print_indexed || print_resolved) {
		putchar('\n');
		fflush(stdout);
	}

	return NULL;
}

static const struct got_error *
create_symref(const char *refname, struct got_reference *target_ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *head_symref;

	err = got_ref_alloc_symref(&head_symref, refname, target_ref);
	if (err)
		return err;

	err = got_ref_write(head_symref, repo);
	if (err == NULL && verbosity > 0) {
		printf("Created reference %s: %s\n", GOT_REF_HEAD,
		    got_ref_get_name(target_ref));
	}
	got_ref_close(head_symref);
	return err;
}

static const struct got_error *
create_ref(const char *refname, struct got_object_id *id,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
	got_ref_close(ref);

	if (err == NULL && verbosity >= 0)
		printf("Created reference %s: %s\n", refname, id_str);
done:
	free(id_str);
	return err;
}

static const struct got_error *
update_ref(struct got_reference *ref, struct got_object_id *new_id,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *new_id_str = NULL;
	struct got_object_id *old_id = NULL;

	err = got_object_id_str(&new_id_str, new_id);
	if (err)
		goto done;

	if (strncmp(got_ref_get_name(ref), "refs/tags/", 10) == 0) {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;
		if (verbosity >= 0) {
			printf("Rejecting update of existing tag %s: %s\n",
			    got_ref_get_name(ref), new_id_str);
		}
		goto done;
	}

	if (got_ref_is_symbolic(ref)) {
		if (verbosity >= 0) {
			printf("Replacing reference %s: %s\n",
			    got_ref_get_name(ref),
			    got_ref_get_symref_target(ref));
		}
		err = got_ref_change_symref_to_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	} else {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;

		err = got_ref_change_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	}

	if (verbosity >= 0)
		printf("Updated %s: %s\n", got_ref_get_name(ref),
		    new_id_str);
done:
	free(old_id);
	free(new_id_str);
	return err;
}

static const struct got_error *
fetch_updated_remote(const char *proto, const char *host, const char *port,
    const char *server_path, const char *jumphost, const char *identity_file,
    int verbosity, const struct got_remote_repo *remote,
    struct got_repository *repo, struct got_reference *head_ref,
    const char *head_refname)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	struct got_pathlist_entry *pe;
	struct got_pathlist_head learned_refs;
	struct got_pathlist_head symrefs;
	struct got_pathlist_head wanted_branches;
	struct got_pathlist_head wanted_refs;
	struct got_object_id *pack_hash;
	struct got_fetch_progress_arg fpa;
	int fetchfd = -1;
	pid_t fetchpid = -1;

	RB_INIT(&learned_refs);
	RB_INIT(&symrefs);
	RB_INIT(&wanted_branches);
	RB_INIT(&wanted_refs);

	err = got_pathlist_insert(NULL, &wanted_branches, head_refname,
	    NULL);
	if (err)
		goto done;

	err = got_fetch_connect(&fetchpid, &fetchfd, proto, host,
	    port, server_path, jumphost, identity_file, verbosity);
	if (err)
		goto done;

	fpa.last_scaled_size[0] = '\0';
	fpa.last_p_indexed = -1;
	fpa.last_p_resolved = -1;
	fpa.verbosity = verbosity;
	fpa.repo = repo;

	err = got_fetch_pack(&pack_hash, &learned_refs, &symrefs,
	    remote->name, 1, 0, &wanted_branches, &wanted_refs, 0, verbosity,
	    fetchfd, repo, head_refname, NULL, 0, fetch_progress, &fpa);
	if (err)
		goto done;

	/* Update references provided with the pack file. */
	RB_FOREACH(pe, got_pathlist_head, &learned_refs) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		struct got_reference *ref;

		err = got_ref_open(&ref, repo, refname, 0);
		if (err) {
			if (err->code != GOT_ERR_NOT_REF)
				goto done;
			err = create_ref(refname, id, verbosity, repo);
			if (err)
				goto done;
		} else {
			err = update_ref(ref, id, verbosity, repo);
			unlock_err = got_ref_unlock(ref);
			if (unlock_err && err == NULL)
				err = unlock_err;
			got_ref_close(ref);
			if (err)
				goto done;
		}
	}

	/* Set the HEAD reference if the server provided one. */
	RB_FOREACH(pe, got_pathlist_head, &symrefs) {
		struct got_reference *target_ref;
		const char *refname = pe->path;
		const char *target = pe->data;
		char *remote_refname = NULL, *remote_target = NULL;

		if (strcmp(refname, GOT_REF_HEAD) != 0)
			continue;

		err = got_ref_open(&target_ref, repo, target, 0);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF) {
				err = NULL;
				continue;
			}
			goto done;
		}

		err = create_symref(refname, target_ref, verbosity, repo);
		got_ref_close(target_ref);
		if (err)
			goto done;

		if (remote->mirror_references)
			continue;

		if (strncmp("refs/heads/", target, 11) != 0)
			continue;

		if (asprintf(&remote_refname,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    refname) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&remote_target,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    target + 11) == -1) {
			err = got_error_from_errno("asprintf");
			free(remote_refname);
			goto done;
		}
		err = got_ref_open(&target_ref, repo, remote_target, 0);
		if (err) {
			free(remote_refname);
			free(remote_target);
			if (err->code == GOT_ERR_NOT_REF) {
				err = NULL;
				continue;
			}
			goto done;
		}
		err = create_symref(remote_refname, target_ref,
		    verbosity - 1, repo);
		free(remote_refname);
		free(remote_target);
		got_ref_close(target_ref);
		if (err)
			goto done;
	}

done:
	got_pathlist_free(&learned_refs, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&symrefs, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&wanted_branches, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&wanted_refs, GOT_PATHLIST_FREE_NONE);
	return err;
}


const struct got_error *
got_worktree_cvg_commit(struct got_object_id **new_commit_id,
    struct got_worktree *worktree, struct got_pathlist_head *paths,
    const char *author, time_t author_time, const char *committer,
    int allow_bad_symlinks, int show_diff, int commit_conflicts,
    got_worktree_commit_msg_cb commit_msg_cb, void *commit_arg,
    got_worktree_status_cb status_cb, void *status_arg,
    const char *proto, const char *host, const char *port,
    const char *server_path, const char *jumphost, const char *identity_file,
    int verbosity, const struct got_remote_repo *remote,
    got_cancel_cb check_cancelled,
    struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlockerr = NULL, *sync_err;
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	struct got_pathlist_head commitable_paths;
	struct collect_commitables_arg cc_arg;
	struct got_pathlist_entry *pe;
	struct got_reference *head_ref = NULL, *head_ref2 = NULL;
	struct got_reference *commit_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct got_object_id *head_commit_id2 = NULL;
	char *head_refname = NULL;
	char *commit_refname = NULL;
	char *diff_path = NULL;
	int have_staged_files = 0;
	int sendfd = -1;
	pid_t sendpid = -1;
	struct got_send_progress_arg spa;
	struct got_pathlist_head commit_reflist;
	struct got_pathlist_head tag_names;
	struct got_pathlist_head delete_branches;

	*new_commit_id = NULL;

	memset(&cc_arg, 0, sizeof(cc_arg));
	RB_INIT(&commitable_paths);
	RB_INIT(&commit_reflist);
	RB_INIT(&tag_names);
	RB_INIT(&delete_branches);

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		goto done;

	err = got_worktree_cvg_get_commit_ref_name(&commit_refname,
	    worktree);
	if (err)
		goto done;

	head_refname = worktree->head_ref_name;
	err = got_ref_open(&head_ref, repo, head_refname, 0);
	if (err)
		goto done;
	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	err = got_ref_alloc(&commit_ref, commit_refname, head_commit_id);
	if (err)
		goto done;
	err = got_ref_write(commit_ref, repo);
	if (err)
		goto done;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	err = got_fileindex_for_each_entry_safe(fileindex, check_staged_file,
	    &have_staged_files);
	if (err && err->code != GOT_ERR_CANCELLED)
		goto done;
	if (have_staged_files) {
		err = check_non_staged_files(fileindex, paths);
		if (err)
			goto done;
	}

	cc_arg.commitable_paths = &commitable_paths;
	cc_arg.worktree = worktree;
	cc_arg.fileindex = fileindex;
	cc_arg.repo = repo;
	cc_arg.have_staged_files = have_staged_files;
	cc_arg.allow_bad_symlinks = allow_bad_symlinks;
	cc_arg.diff_header_shown = 0;
	cc_arg.commit_conflicts = commit_conflicts;
	if (show_diff) {
		err = got_opentemp_named(&diff_path, &cc_arg.diff_outfile,
		    GOT_TMPDIR_STR "/got", ".diff");
		if (err)
			goto done;
		cc_arg.f1 = got_opentemp();
		if (cc_arg.f1 == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
		cc_arg.f2 = got_opentemp();
		if (cc_arg.f2 == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
	}

	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    collect_commitables, &cc_arg, NULL, NULL, 0, 0);
		if (err)
			goto done;
	}

	if (show_diff) {
		if (fflush(cc_arg.diff_outfile) == EOF) {
			err = got_error_from_errno("fflush");
			goto done;
		}
	}

	if (RB_EMPTY(&commitable_paths)) {
		err = got_error(GOT_ERR_COMMIT_NO_CHANGES);
		goto done;
	}

	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = check_path_is_commitable(pe->path, &commitable_paths);
		if (err)
			goto done;
	}

	RB_FOREACH(pe, got_pathlist_head, &commitable_paths) {
		struct got_commitable *ct = pe->data;
		const char *ct_path = ct->in_repo_path;

		while (ct_path[0] == '/')
			ct_path++;
		err = check_out_of_date(ct_path, ct->status,
		    ct->staged_status, ct->base_blob_id, ct->base_commit_id,
		    head_commit_id, repo, GOT_ERR_COMMIT_OUT_OF_DATE);
		if (err)
			goto done;
	}

	err = commit_worktree(new_commit_id, &commitable_paths,
	    head_commit_id, NULL, worktree, author, author_time, committer,
	    (diff_path && cc_arg.diff_header_shown) ? diff_path : NULL,
	    commit_msg_cb, commit_arg, status_cb, status_arg, repo);
	if (err)
		goto done;

	/*
	 * Check if a concurrent commit to our branch has occurred.
	 * Lock the reference here to prevent concurrent modification.
	 */
	err = got_ref_open(&head_ref2, repo, head_refname, 1);
	if (err)
		goto done;
	err = got_ref_resolve(&head_commit_id2, repo, head_ref2);
	if (err)
		goto done;
	if (got_object_id_cmp(head_commit_id, head_commit_id2) != 0) {
		err = got_error(GOT_ERR_COMMIT_HEAD_CHANGED);
		goto done;
	}

	err = got_pathlist_insert(&pe, &commit_reflist, commit_refname,
	    head_refname);
	if (err)
		goto done;

	/* Update commit ref in repository. */
	err = got_ref_change_ref(commit_ref, *new_commit_id);
	if (err)
		goto done;
	err = got_ref_write(commit_ref, repo);
	if (err)
		goto done;

	if (verbosity >= 0) {
		printf("Connecting to \"%s\" %s://%s%s%s%s%s\n",
		    remote->name, proto, host,
		    port ? ":" : "", port ? port : "",
		    *server_path == '/' ? "" : "/", server_path);
	}

	/* Attempt send to remote branch. */
	err = got_send_connect(&sendpid, &sendfd, proto, host, port,
	    server_path, jumphost, identity_file, verbosity);
	if (err)
		goto done;

	memset(&spa, 0, sizeof(spa));
	spa.last_scaled_packsize[0] = '\0';
	spa.last_p_deltify = -1;
	spa.last_p_written = -1;
	spa.verbosity = verbosity;
	spa.delete_branches = &delete_branches;
	err = got_send_pack(remote->name, &commit_reflist, &tag_names,
	    &delete_branches, verbosity, 0, sendfd, repo, send_progress, &spa,
	    check_cancelled, NULL);
	if (spa.printed_something)
		putchar('\n');
	if (err != NULL && err->code == GOT_ERR_SEND_ANCESTRY) {
		/*
		 * Fetch new changes since remote has diverged.
		 * No trivial-rebase yet; require update to be run manually.
		 */
		err = fetch_updated_remote(proto, host, port, server_path,
		    jumphost, identity_file, verbosity, remote, repo,
		    head_ref, head_refname);
		if (err == NULL)
			goto done;
		err = got_error(GOT_ERR_COMMIT_OUT_OF_DATE);
		goto done;
		/* XXX: Rebase commit over fetched remote branch. */
	}
	if (err) {
		goto done;
	}

	/* Update branch head in repository. */
	err = got_ref_change_ref(head_ref2, *new_commit_id);
	if (err)
		goto done;
	err = got_ref_write(head_ref2, repo);
	if (err)
		goto done;

	err = got_worktree_set_base_commit_id(worktree, repo, *new_commit_id);
	if (err)
		goto done;

	err = ref_base_commit(worktree, repo);
	if (err)
		goto done;

	/* XXX: fileindex must be updated for other fetched changes? */
	err = update_fileindex_after_commit(worktree, &commitable_paths,
	    *new_commit_id, fileindex, have_staged_files);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	if (head_ref2) {
		unlockerr = got_ref_unlock(head_ref2);
		if (unlockerr && err == NULL)
			err = unlockerr;
		got_ref_close(head_ref2);
	}
	if (commit_ref)
		got_ref_close(commit_ref);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	RB_FOREACH(pe, got_pathlist_head, &commitable_paths) {
		struct got_commitable *ct = pe->data;

		free_commitable(ct);
	}
	got_pathlist_free(&commitable_paths, GOT_PATHLIST_FREE_NONE);
	if (diff_path && unlink(diff_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", diff_path);
	if (cc_arg.diff_outfile && fclose(cc_arg.diff_outfile) == EOF &&
	    err == NULL)
		err = got_error_from_errno("fclose");
	free(head_commit_id);
	free(head_commit_id2);
	free(commit_refname);
	free(fileindex_path);
	free(diff_path);
	return err;
}

const struct got_error *
got_worktree_cvg_get_commit_ref_name(char **refname,
    struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree, GOT_WORKTREE_COMMIT_REF_PREFIX);
}
