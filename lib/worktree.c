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

#include "got_compat.h"

#include <sys/stat.h>
#include <sys/queue.h>

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
#include <zlib.h>
#include <fnmatch.h>
#include <libgen.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_opentemp.h"
#include "got_diff.h"

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
#include "got_lib_gotconfig.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#define GOT_MERGE_LABEL_MERGED	"merged change"
#define GOT_MERGE_LABEL_BASE	"3-way merge base"

static mode_t
apply_umask(mode_t mode)
{
	mode_t um;

	um = umask(000);
	umask(um);
	return mode & ~um;
}

static const struct got_error *
create_meta_file(const char *path_got, const char *name, const char *content)
{
	const struct got_error *err = NULL;
	char *path;

	if (asprintf(&path, "%s/%s", path_got, name) == -1)
		return got_error_from_errno("asprintf");

	err = got_path_create_file(path, content);
	free(path);
	return err;
}

static const struct got_error *
update_meta_file(const char *path_got, const char *name, const char *content)
{
	const struct got_error *err = NULL;
	FILE *tmpfile = NULL;
	char *tmppath = NULL;
	char *path = NULL;

	if (asprintf(&path, "%s/%s", path_got, name) == -1) {
		err = got_error_from_errno("asprintf");
		path = NULL;
		goto done;
	}

	err = got_opentemp_named(&tmppath, &tmpfile, path, "");
	if (err)
		goto done;

	if (content) {
		int len = fprintf(tmpfile, "%s\n", content);
		if (len != strlen(content) + 1) {
			err = got_error_from_errno2("fprintf", tmppath);
			goto done;
		}
	}

	if (rename(tmppath, path) != 0) {
		err = got_error_from_errno3("rename", tmppath, path);
		unlink(tmppath);
		goto done;
	}

done:
	if (fclose(tmpfile) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", tmppath);
	free(tmppath);
	return err;
}

static const struct got_error *
write_head_ref(const char *path_got, struct got_reference *head_ref)
{
	const struct got_error *err = NULL;
	char *refstr = NULL;

	if (got_ref_is_symbolic(head_ref)) {
		refstr = got_ref_to_str(head_ref);
		if (refstr == NULL)
			return got_error_from_errno("got_ref_to_str");
	} else {
		refstr = strdup(got_ref_get_name(head_ref));
		if (refstr == NULL)
			return got_error_from_errno("strdup");
	}
	err = update_meta_file(path_got, GOT_WORKTREE_HEAD_REF, refstr);
	free(refstr);
	return err;
}

const struct got_error *
got_worktree_init(const char *path, struct got_reference *head_ref,
    const char *prefix, const char *meta_dir, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL;
	uuid_t uuid;
	uint32_t uuid_status;
	int obj_type;
	char *path_got = NULL;
	char *formatstr = NULL;
	char *absprefix = NULL;
	char *basestr = NULL;
	char *uuidstr = NULL;

	if (strcmp(path, got_repo_get_path(repo)) == 0) {
		err = got_error(GOT_ERR_WORKTREE_REPO);
		goto done;
	}

	err = got_ref_resolve(&commit_id, repo, head_ref);
	if (err)
		return err;
	err = got_object_get_type(&obj_type, repo, commit_id);
	if (err)
		return err;
	if (obj_type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (!got_path_is_absolute(prefix)) {
		if (asprintf(&absprefix, "/%s", prefix) == -1)
			return got_error_from_errno("asprintf");
	}

	/* Create top-level directory (may already exist). */
	if (mkdir(path, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno2("mkdir", path);
		goto done;
	}

	/* Create .got/.cvg directory (may already exist). */
	if (asprintf(&path_got, "%s/%s", path, meta_dir) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	if (mkdir(path_got, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno2("mkdir", path_got);
		goto done;
	}

	/* Create an empty lock file. */
	err = create_meta_file(path_got, GOT_WORKTREE_LOCK, NULL);
	if (err)
		goto done;

	/* Create an empty file index. */
	err = create_meta_file(path_got, GOT_WORKTREE_FILE_INDEX, NULL);
	if (err)
		goto done;

	/* Write the HEAD reference. */
	err = write_head_ref(path_got, head_ref);
	if (err)
		goto done;

	/* Record our base commit. */
	/* TODO: This should be recording the hash algo type as well. */
	err = got_object_id_str(&basestr, commit_id);
	if (err)
		goto done;
	err = create_meta_file(path_got, GOT_WORKTREE_BASE_COMMIT, basestr);
	if (err)
		goto done;

	/* Store path to repository. */
	err = create_meta_file(path_got, GOT_WORKTREE_REPOSITORY,
	    got_repo_get_path(repo));
	if (err)
		goto done;

	/* Store in-repository path prefix. */
	err = create_meta_file(path_got, GOT_WORKTREE_PATH_PREFIX,
	    absprefix ? absprefix : prefix);
	if (err)
		goto done;

	/* Generate UUID. */
	uuid_create(&uuid, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status, "uuid_create");
		goto done;
	}
	uuid_to_string(&uuid, &uuidstr, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status, "uuid_to_string");
		goto done;
	}
	err = create_meta_file(path_got, GOT_WORKTREE_UUID, uuidstr);
	if (err)
		goto done;

	/* Stamp work tree with format file. */
	if (asprintf(&formatstr, "%d", GOT_WORKTREE_FORMAT_VERSION) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = create_meta_file(path_got, GOT_WORKTREE_FORMAT, formatstr);
	if (err)
		goto done;

done:
	free(commit_id);
	free(path_got);
	free(formatstr);
	free(absprefix);
	free(basestr);
	free(uuidstr);
	return err;
}

const struct got_error *
got_worktree_match_path_prefix(int *match, struct got_worktree *worktree,
    const char *path_prefix)
{
	char *absprefix = NULL;

	if (!got_path_is_absolute(path_prefix)) {
		if (asprintf(&absprefix, "/%s", path_prefix) == -1)
			return got_error_from_errno("asprintf");
	}
	*match = (strcmp(absprefix ? absprefix : path_prefix,
	    worktree->path_prefix) == 0);
	free(absprefix);
	return NULL;
}

const char *
got_worktree_get_head_ref_name(struct got_worktree *worktree)
{
	return worktree->head_ref_name;
}

const struct got_error *
got_worktree_set_head_ref(struct got_worktree *worktree,
    struct got_reference *head_ref)
{
	const struct got_error *err = NULL;
	char *path_got = NULL, *head_ref_name = NULL;

	if (asprintf(&path_got, "%s/%s", worktree->root_path,
	    worktree->meta_dir) == -1) {
		err = got_error_from_errno("asprintf");
		path_got = NULL;
		goto done;
	}

	head_ref_name = strdup(got_ref_get_name(head_ref));
	if (head_ref_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	err = write_head_ref(path_got, head_ref);
	if (err)
		goto done;

	free(worktree->head_ref_name);
	worktree->head_ref_name = head_ref_name;
done:
	free(path_got);
	if (err)
		free(head_ref_name);
	return err;
}

struct got_object_id *
got_worktree_get_base_commit_id(struct got_worktree *worktree)
{
	return worktree->base_commit_id;
}

const struct got_error *
got_worktree_set_base_commit_id(struct got_worktree *worktree,
    struct got_repository *repo, struct got_object_id *commit_id)
{
	const struct got_error *err;
	struct got_object *obj = NULL;
	char *id_str = NULL;
	char *path_got = NULL;

	if (asprintf(&path_got, "%s/%s", worktree->root_path,
	    worktree->meta_dir) == -1) {
		err = got_error_from_errno("asprintf");
		path_got = NULL;
		goto done;
	}

	err = got_object_open(&obj, repo, commit_id);
	if (err)
		return err;

	if (obj->type != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	/* Record our base commit. */
	/* TODO: This should be recording the hash algo type as well. */
	err = got_object_id_str(&id_str, commit_id);
	if (err)
		goto done;
	err = update_meta_file(path_got, GOT_WORKTREE_BASE_COMMIT, id_str);
	if (err)
		goto done;

	free(worktree->base_commit_id);
	worktree->base_commit_id = got_object_id_dup(commit_id);
	if (worktree->base_commit_id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}
done:
	if (obj)
		got_object_close(obj);
	free(id_str);
	free(path_got);
	return err;
}

const struct got_gotconfig *
got_worktree_get_gotconfig(struct got_worktree *worktree)
{
	return worktree->gotconfig;
}

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
add_dir_on_disk(struct got_worktree *worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *abspath;

	/* We only accept worktree-relative paths here. */
	if (got_path_is_absolute(path)) {
		return got_error_fmt(GOT_ERR_BAD_PATH,
		    "%s does not accept absolute paths: %s",
		    __func__, path);
	}

	if (asprintf(&abspath, "%s/%s", worktree->root_path, path) == -1)
		return got_error_from_errno("asprintf");

	err = got_path_mkdir(abspath);
	if (err && err->code == GOT_ERR_ERRNO && errno == EEXIST) {
		struct stat sb;
		err = NULL;
		if (lstat(abspath, &sb) == -1) {
			err = got_error_from_errno2("lstat", abspath);
		} else if (!S_ISDIR(sb.st_mode)) {
			/* TODO directory is obstructed; do something */
			err = got_error_path(abspath, GOT_ERR_FILE_OBSTRUCTED);
		}
	}
	free(abspath);
	return err;
}

static const struct got_error *
check_file_contents_equal(int *same, FILE *f1, FILE *f2)
{
	const struct got_error *err = NULL;
	uint8_t fbuf1[8192];
	uint8_t fbuf2[8192];
	size_t flen1 = 0, flen2 = 0;

	*same = 1;

	for (;;) {
		flen1 = fread(fbuf1, 1, sizeof(fbuf1), f1);
		if (flen1 == 0 && ferror(f1)) {
			err = got_error_from_errno("fread");
			break;
		}
		flen2 = fread(fbuf2, 1, sizeof(fbuf2), f2);
		if (flen2 == 0 && ferror(f2)) {
			err = got_error_from_errno("fread");
			break;
		}
		if (flen1 == 0) {
			if (flen2 != 0)
				*same = 0;
			break;
		} else if (flen2 == 0) {
			if (flen1 != 0)
				*same = 0;
			break;
		} else if (flen1 == flen2) {
			if (memcmp(fbuf1, fbuf2, flen2) != 0) {
				*same = 0;
				break;
			}
		} else {
			*same = 0;
			break;
		}
	}

	return err;
}

static const struct got_error *
check_files_equal(int *same, FILE *f1, FILE *f2)
{
	struct stat sb;
	size_t size1, size2;

	*same = 1;

	if (fstat(fileno(f1), &sb) != 0)
		return got_error_from_errno("fstat");
	size1 = sb.st_size;

	if (fstat(fileno(f2), &sb) != 0)
		return got_error_from_errno("fstat");
	size2 = sb.st_size;

	if (size1 != size2) {
		*same = 0;
		return NULL;
	}

	if (fseek(f1, 0L, SEEK_SET) == -1)
		return got_ferror(f1, GOT_ERR_IO);
	if (fseek(f2, 0L, SEEK_SET) == -1)
		return got_ferror(f2, GOT_ERR_IO);

	return check_file_contents_equal(same, f1, f2);
}

static const struct got_error *
copy_file_to_fd(off_t *outsize, FILE *f, int outfd)
{
	uint8_t fbuf[65536];
	size_t flen;
	ssize_t outlen;

	*outsize = 0;

	if (fseek(f, 0L, SEEK_SET) == -1)
		return got_ferror(f, GOT_ERR_IO);

	for (;;) {
		flen = fread(fbuf, 1, sizeof(fbuf), f);
		if (flen == 0) {
			if (ferror(f))
				return got_error_from_errno("fread");
			if (feof(f))
				break;
		}
		outlen = write(outfd, fbuf, flen);
		if (outlen == -1)
			return got_error_from_errno("write");
		if (outlen != flen)
			return got_error(GOT_ERR_IO);
		*outsize += outlen;
	}

	return NULL;
}

static const struct got_error *
merge_binary_file(int *overlapcnt, int merged_fd,
    FILE *f_deriv, FILE *f_orig, FILE *f_deriv2,
    const char *label_deriv, const char *label_orig, const char *label_deriv2,
    const char *ondisk_path)
{
	const struct got_error *err = NULL;
	int same_content, changed_deriv, changed_deriv2;
	int fd_orig = -1, fd_deriv = -1, fd_deriv2 = -1;
	off_t size_orig = 0, size_deriv = 0, size_deriv2 = 0;
	char *path_orig = NULL, *path_deriv = NULL, *path_deriv2 = NULL;
	char *base_path_orig = NULL, *base_path_deriv = NULL;
	char *base_path_deriv2 = NULL;

	*overlapcnt = 0;

	err = check_files_equal(&same_content, f_deriv, f_deriv2);
	if (err)
		return err;

	if (same_content)
		return copy_file_to_fd(&size_deriv, f_deriv, merged_fd);

	err = check_files_equal(&same_content, f_deriv, f_orig);
	if (err)
		return err;
	changed_deriv = !same_content;
	err = check_files_equal(&same_content, f_deriv2, f_orig);
	if (err)
		return err;
	changed_deriv2 = !same_content;

	if (changed_deriv && changed_deriv2) {
		*overlapcnt = 1;
		if (asprintf(&base_path_orig, "%s-orig", ondisk_path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&base_path_deriv, "%s-1", ondisk_path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&base_path_deriv2, "%s-2", ondisk_path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = got_opentemp_named_fd(&path_orig, &fd_orig,
		    base_path_orig, "");
		if (err)
			goto done;
		err = got_opentemp_named_fd(&path_deriv, &fd_deriv,
		    base_path_deriv, "");
		if (err)
			goto done;
		err = got_opentemp_named_fd(&path_deriv2, &fd_deriv2,
		    base_path_deriv2, "");
		if (err)
			goto done;
		err = copy_file_to_fd(&size_orig, f_orig, fd_orig);
		if (err)
			goto done;
		err = copy_file_to_fd(&size_deriv, f_deriv, fd_deriv);
		if (err)
			goto done;
		err = copy_file_to_fd(&size_deriv2, f_deriv2, fd_deriv2);
		if (err)
			goto done;
		if (dprintf(merged_fd, "Binary files differ and cannot be "
		    "merged automatically:\n") < 0) {
			err = got_error_from_errno("dprintf");
			goto done;
		}
		if (dprintf(merged_fd, "%s%s%s\nfile %s\n",
		    GOT_DIFF_CONFLICT_MARKER_BEGIN,
		    label_deriv ? " " : "",
		    label_deriv ? label_deriv : "",
		    path_deriv) < 0) {
			err = got_error_from_errno("dprintf");
			goto done;
		}
		if (size_orig > 0) {
			if (dprintf(merged_fd, "%s%s%s\nfile %s\n",
			    GOT_DIFF_CONFLICT_MARKER_ORIG,
			    label_orig ? " " : "",
			    label_orig ? label_orig : "",
			    path_orig) < 0) {
				err = got_error_from_errno("dprintf");
				goto done;
			}
		}
		if (dprintf(merged_fd, "%s\nfile %s\n%s%s%s\n",
		    GOT_DIFF_CONFLICT_MARKER_SEP,
		    path_deriv2,
		    GOT_DIFF_CONFLICT_MARKER_END,
		    label_deriv2 ?  " " : "",
		    label_deriv2 ? label_deriv2 : "") < 0) {
			err = got_error_from_errno("dprintf");
			goto done;
		}
	} else if (changed_deriv)
		err = copy_file_to_fd(&size_deriv, f_deriv, merged_fd);
	else if (changed_deriv2)
		err = copy_file_to_fd(&size_deriv2, f_deriv2, merged_fd);
done:
	if (size_orig == 0 && path_orig && unlink(path_orig) == -1 &&
	    err == NULL)
		err = got_error_from_errno2("unlink", path_orig);
	if (fd_orig != -1 && close(fd_orig) == -1 && err == NULL)
		err = got_error_from_errno2("close", path_orig);
	if (fd_deriv != -1 && close(fd_deriv) == -1 && err == NULL)
		err = got_error_from_errno2("close", path_deriv);
	if (fd_deriv2 != -1 && close(fd_deriv2) == -1 && err == NULL)
		err = got_error_from_errno2("close", path_deriv2);
	free(path_orig);
	free(path_deriv);
	free(path_deriv2);
	free(base_path_orig);
	free(base_path_deriv);
	free(base_path_deriv2);
	return err;
}

/*
 * Perform a 3-way merge where the file f_orig acts as the common
 * ancestor, the file f_deriv acts as the first derived version,
 * and the file f_deriv2 acts as the second derived version.
 * The merge result will be written to a new file at ondisk_path; any
 * existing file at this path will be replaced.
 */
static const struct got_error *
merge_file(int *local_changes_subsumed, struct got_worktree *worktree,
    FILE *f_orig, FILE *f_deriv, FILE *f_deriv2, const char *ondisk_path,
    const char *path, uint16_t st_mode,
    const char *label_orig, const char *label_deriv, const char *label_deriv2,
    enum got_diff_algorithm diff_algo, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	int merged_fd = -1;
	FILE *f_merged = NULL;
	char *merged_path = NULL, *base_path = NULL;
	int overlapcnt = 0;
	char *parent = NULL;

	*local_changes_subsumed = 0;

	err = got_path_dirname(&parent, ondisk_path);
	if (err)
		return err;

	if (asprintf(&base_path, "%s/got-merged", parent) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(&merged_path, &merged_fd, base_path, "");
	if (err)
		goto done;

	err = got_merge_diff3(&overlapcnt, merged_fd, f_deriv, f_orig,
	    f_deriv2, label_deriv, label_orig, label_deriv2, diff_algo);
	if (err) {
		if (err->code != GOT_ERR_FILE_BINARY)
			goto done;
		err = merge_binary_file(&overlapcnt, merged_fd, f_deriv,
		    f_orig, f_deriv2, label_deriv, label_orig, label_deriv2,
		    ondisk_path);
		if (err)
			goto done;
	}

	err = (*progress_cb)(progress_arg,
	    overlapcnt > 0 ? GOT_STATUS_CONFLICT : GOT_STATUS_MERGE, path);
	if (err)
		goto done;

	if (fsync(merged_fd) != 0) {
		err = got_error_from_errno("fsync");
		goto done;
	}

	f_merged = fdopen(merged_fd, "r");
	if (f_merged == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	merged_fd = -1;

	/* Check if a clean merge has subsumed all local changes. */
	if (overlapcnt == 0) {
		err = check_files_equal(local_changes_subsumed, f_deriv,
		    f_merged);
		if (err)
			goto done;
	}

	if (fchmod(fileno(f_merged), apply_umask(st_mode)) != 0) {
		err = got_error_from_errno2("fchmod", merged_path);
		goto done;
	}

	if (rename(merged_path, ondisk_path) != 0) {
		err = got_error_from_errno3("rename", merged_path,
		    ondisk_path);
		goto done;
	}
done:
	if (err) {
		if (merged_path)
			unlink(merged_path);
	}
	if (merged_fd != -1 && close(merged_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (f_merged && fclose(f_merged) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(merged_path);
	free(base_path);
	free(parent);
	return err;
}

static const struct got_error *
update_symlink(const char *ondisk_path, const char *target_path,
    size_t target_len)
{
	/* This is not atomic but matches what 'ln -sf' does. */
	if (unlink(ondisk_path) == -1)
		return got_error_from_errno2("unlink", ondisk_path);
	if (symlink(target_path, ondisk_path) == -1)
		return got_error_from_errno3("symlink", target_path,
		    ondisk_path);
	return NULL;
}

/*
 * Overwrite a symlink (or a regular file in case there was a "bad" symlink)
 * in the work tree with a file that contains conflict markers and the
 * conflicting target paths of the original version, a "derived version"
 * of a symlink from an incoming change, and a local version of the symlink.
 *
 * The original versions's target path can be NULL if it is not available,
 * such as if both derived versions added a new symlink at the same path.
 *
 * The incoming derived symlink target is NULL in case the incoming change
 * has deleted this symlink.
 */
static const struct got_error *
install_symlink_conflict(const char *deriv_target,
    struct got_object_id *deriv_base_commit_id, const char *orig_target,
    const char *label_orig, const char *local_target, const char *ondisk_path)
{
	const struct got_error *err;
	char *id_str = NULL, *label_deriv = NULL, *path = NULL;
	FILE *f = NULL;

	err = got_object_id_str(&id_str, deriv_base_commit_id);
	if (err)
		return got_error_from_errno("asprintf");

	if (asprintf(&label_deriv, "%s: commit %s",
	    GOT_MERGE_LABEL_MERGED, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named(&path, &f, "got-symlink-conflict", "");
	if (err)
		goto done;

	if (fchmod(fileno(f), apply_umask(GOT_DEFAULT_FILE_MODE)) == -1) {
		err = got_error_from_errno2("fchmod", path);
		goto done;
	}

	if (fprintf(f, "%s %s\n%s\n%s%s%s%s%s\n%s\n%s\n",
	    GOT_DIFF_CONFLICT_MARKER_BEGIN, label_deriv,
	    deriv_target ? deriv_target : "(symlink was deleted)",
	    orig_target ? label_orig : "",
	    orig_target ? "\n" : "",
	    orig_target ? orig_target : "",
	    orig_target ? "\n" : "",
	    GOT_DIFF_CONFLICT_MARKER_SEP,
	    local_target, GOT_DIFF_CONFLICT_MARKER_END) < 0) {
		err = got_error_from_errno2("fprintf", path);
		goto done;
	}

	if (unlink(ondisk_path) == -1) {
		err = got_error_from_errno2("unlink", ondisk_path);
		goto done;
	}
	if (rename(path, ondisk_path) == -1) {
		err = got_error_from_errno3("rename", path, ondisk_path);
		goto done;
	}
done:
	if (f != NULL && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path);
	free(path);
	free(id_str);
	free(label_deriv);
	return err;
}

/* forward declaration */
static const struct got_error *
merge_blob(int *, struct got_worktree *, struct got_blob_object *,
    const char *, const char *, uint16_t, const char *,
    struct got_blob_object *, struct got_object_id *,
    struct got_repository *, got_worktree_checkout_cb, void *);

/*
 * Merge a symlink into the work tree, where blob_orig acts as the common
 * ancestor, deriv_target is the link target of the first derived version,
 * and the symlink on disk acts as the second derived version.
 * Assume that contents of both blobs represent symlinks.
 */
static const struct got_error *
merge_symlink(struct got_worktree *worktree,
    struct got_blob_object *blob_orig, const char *ondisk_path,
    const char *path, const char *label_orig, const char *deriv_target,
    struct got_object_id *deriv_base_commit_id, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	char *ancestor_target = NULL;
	struct stat sb;
	ssize_t ondisk_len, deriv_len;
	char ondisk_target[PATH_MAX];
	int have_local_change = 0;
	int have_incoming_change = 0;

	if (lstat(ondisk_path, &sb) == -1)
		return got_error_from_errno2("lstat", ondisk_path);

	ondisk_len = readlink(ondisk_path, ondisk_target,
	    sizeof(ondisk_target));
	if (ondisk_len == -1) {
		err = got_error_from_errno2("readlink",
		    ondisk_path);
		goto done;
	}
	ondisk_target[ondisk_len] = '\0';

	if (blob_orig) {
		err = got_object_blob_read_to_str(&ancestor_target, blob_orig);
		if (err)
			goto done;
	}

	if (ancestor_target == NULL ||
	    (ondisk_len != strlen(ancestor_target) ||
	    memcmp(ondisk_target, ancestor_target, ondisk_len) != 0))
		have_local_change = 1;

	deriv_len = strlen(deriv_target);
	if (ancestor_target == NULL ||
	    (deriv_len != strlen(ancestor_target) ||
	    memcmp(deriv_target, ancestor_target, deriv_len) != 0))
		have_incoming_change = 1;

	if (!have_local_change && !have_incoming_change) {
		if (ancestor_target) {
			/* Both sides made the same change. */
			err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE,
			    path);
		} else if (deriv_len == ondisk_len &&
		    memcmp(ondisk_target, deriv_target, deriv_len) == 0) {
			/* Both sides added the same symlink. */
			err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE,
			    path);
		} else {
			/* Both sides added symlinks which don't match. */
			err = install_symlink_conflict(deriv_target,
			    deriv_base_commit_id, ancestor_target,
			    label_orig, ondisk_target, ondisk_path);
			if (err)
				goto done;
			err = (*progress_cb)(progress_arg, GOT_STATUS_CONFLICT,
			    path);
		}
	} else if (!have_local_change && have_incoming_change) {
		/* Apply the incoming change. */
		err = update_symlink(ondisk_path, deriv_target,
		    strlen(deriv_target));
		if (err)
			goto done;
		err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE, path);
	} else if (have_local_change && have_incoming_change) {
		if (deriv_len == ondisk_len &&
		    memcmp(deriv_target, ondisk_target, deriv_len) == 0) {
			/* Both sides made the same change. */
			err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE,
			    path);
		} else {
			err = install_symlink_conflict(deriv_target,
			    deriv_base_commit_id, ancestor_target, label_orig,
			    ondisk_target, ondisk_path);
			if (err)
				goto done;
			err = (*progress_cb)(progress_arg, GOT_STATUS_CONFLICT,
			    path);
		}
	}

done:
	free(ancestor_target);
	return err;
}

static const struct got_error *
dump_symlink_target_path_to_file(FILE **outfile, const char *ondisk_path)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	ssize_t target_len;
	size_t n;
	FILE *f;

	*outfile = NULL;

	f = got_opentemp();
	if (f == NULL)
		return got_error_from_errno("got_opentemp");
	target_len = readlink(ondisk_path, target_path, sizeof(target_path));
	if (target_len == -1) {
		err = got_error_from_errno2("readlink", ondisk_path);
		goto done;
	}
	n = fwrite(target_path, 1, target_len, f);
	if (n != target_len) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	if (fflush(f) == EOF) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	if (fseek(f, 0L, SEEK_SET) == -1) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
done:
	if (err)
		fclose(f);
	else
		*outfile = f;
	return err;
}

/*
 * Perform a 3-way merge where blob_orig acts as the common ancestor,
 * blob_deriv acts as the first derived version, and the file on disk
 * acts as the second derived version.
 */
static const struct got_error *
merge_blob(int *local_changes_subsumed, struct got_worktree *worktree,
    struct got_blob_object *blob_orig, const char *ondisk_path,
    const char *path, uint16_t st_mode, const char *label_orig,
    struct got_blob_object *blob_deriv,
    struct got_object_id *deriv_base_commit_id, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	FILE *f_orig = NULL, *f_deriv = NULL, *f_deriv2 = NULL;
	char *blob_orig_path = NULL;
	char *blob_deriv_path = NULL, *base_path = NULL, *id_str = NULL;
	char *label_deriv = NULL, *parent = NULL;

	*local_changes_subsumed = 0;

	err = got_path_dirname(&parent, ondisk_path);
	if (err)
		return err;

	if (blob_orig) {
		if (asprintf(&base_path, "%s/got-merge-blob-orig",
		    parent) == -1) {
			err = got_error_from_errno("asprintf");
			base_path = NULL;
			goto done;
		}

		err = got_opentemp_named(&blob_orig_path, &f_orig,
		    base_path, "");
		if (err)
			goto done;
		err = got_object_blob_dump_to_file(NULL, NULL, NULL, f_orig,
		    blob_orig);
		if (err)
			goto done;
		free(base_path);
	} else {
		/*
		 * No common ancestor exists. This is an "add vs add" conflict
		 * and we simply use an empty ancestor file to make both files
		 * appear in the merged result in their entirety.
		 */
		f_orig = got_opentemp();
		if (f_orig == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
	}

	if (asprintf(&base_path, "%s/got-merge-blob-deriv", parent) == -1) {
		err = got_error_from_errno("asprintf");
		base_path = NULL;
		goto done;
	}

	err = got_opentemp_named(&blob_deriv_path, &f_deriv, base_path, "");
	if (err)
		goto done;
	err = got_object_blob_dump_to_file(NULL, NULL, NULL, f_deriv,
	    blob_deriv);
	if (err)
		goto done;

	err = got_object_id_str(&id_str, deriv_base_commit_id);
	if (err)
		goto done;
	if (asprintf(&label_deriv, "%s: commit %s",
	    GOT_MERGE_LABEL_MERGED, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	/*
	 * In order the run a 3-way merge with a symlink we copy the symlink's
	 * target path into a temporary file and use that file with diff3.
	 */
	if (S_ISLNK(st_mode)) {
		err = dump_symlink_target_path_to_file(&f_deriv2, ondisk_path);
		if (err)
			goto done;
	} else {
		int fd;
		fd = open(ondisk_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd == -1) {
			err = got_error_from_errno2("open", ondisk_path);
			goto done;
		}
		f_deriv2 = fdopen(fd, "r");
		if (f_deriv2 == NULL) {
			err = got_error_from_errno2("fdopen", ondisk_path);
			close(fd);
			goto done;
		}
	}

	err = merge_file(local_changes_subsumed, worktree, f_orig, f_deriv,
	    f_deriv2, ondisk_path, path, st_mode, label_orig, label_deriv,
	    NULL, GOT_DIFF_ALGORITHM_MYERS, repo, progress_cb, progress_arg);
done:
	if (f_orig && fclose(f_orig) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f_deriv && fclose(f_deriv) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f_deriv2 && fclose(f_deriv2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(base_path);
	if (blob_orig_path) {
		unlink(blob_orig_path);
		free(blob_orig_path);
	}
	if (blob_deriv_path) {
		unlink(blob_deriv_path);
		free(blob_deriv_path);
	}
	free(id_str);
	free(label_deriv);
	free(parent);
	return err;
}

static const struct got_error *
create_fileindex_entry(struct got_fileindex_entry **new_iep,
    struct got_fileindex *fileindex, struct got_object_id *base_commit_id,
    int wt_fd, const char *path, struct got_object_id *blob_id,
    int update_timestamps)
{
	const struct got_error *err = NULL;
	struct got_fileindex_entry *new_ie;

	*new_iep = NULL;

	err = got_fileindex_entry_alloc(&new_ie, path);
	if (err)
		return err;

	err = got_fileindex_entry_update(new_ie, wt_fd, path,
	    blob_id, base_commit_id, update_timestamps);
	if (err)
		goto done;

	err = got_fileindex_entry_add(fileindex, new_ie);
done:
	if (err)
		got_fileindex_entry_free(new_ie);
	else
		*new_iep = new_ie;
	return err;
}

static mode_t
get_ondisk_perms(int executable, mode_t st_mode)
{
	mode_t xbits = S_IXUSR;

	if (executable) {
		/* Map read bits to execute bits. */
		if (st_mode & S_IRGRP)
			xbits |= S_IXGRP;
		if (st_mode & S_IROTH)
			xbits |= S_IXOTH;
		return st_mode | xbits;
	}

	return st_mode;
}

/* forward declaration */
static const struct got_error *
install_blob(struct got_worktree *worktree, const char *ondisk_path,
    const char *path, mode_t te_mode, mode_t st_mode,
    struct got_blob_object *blob, int restoring_missing_file,
    int reverting_versioned_file, int installing_bad_symlink,
    int path_is_unversioned, int adding_merged_file, int *update_timestamps,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg);

/*
 * This function assumes that the provided symlink target points at a
 * safe location in the work tree!
 */
static const struct got_error *
replace_existing_symlink(int *did_something, const char *ondisk_path,
    const char *target_path, size_t target_len)
{
	const struct got_error *err = NULL;
	ssize_t elen;
	char etarget[PATH_MAX];
	int fd;

	*did_something = 0;

	/*
	 * "Bad" symlinks (those pointing outside the work tree or into the
	 * .got directory) are installed in the work tree as a regular file
	 * which contains the bad symlink target path.
	 * The new symlink target has already been checked for safety by our
	 * caller. If we can successfully open a regular file then we simply
	 * replace this file with a symlink below.
	 */
	fd = open(ondisk_path, O_RDWR | O_EXCL | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		if (!got_err_open_nofollow_on_symlink())
			return got_error_from_errno2("open", ondisk_path);

		/* We are updating an existing on-disk symlink. */
		elen = readlink(ondisk_path, etarget, sizeof(etarget));
		if (elen == -1)
			return got_error_from_errno2("readlink", ondisk_path);

		if (elen == target_len &&
		    memcmp(etarget, target_path, target_len) == 0)
			return NULL; /* nothing to do */
	}

	*did_something = 1;
	err = update_symlink(ondisk_path, target_path, target_len);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", ondisk_path);
	return err;
}

static const struct got_error *
is_bad_symlink_target(int *is_bad_symlink, const char *target_path,
    size_t target_len, const char *ondisk_path, const char *wtroot_path,
    const char *meta_dir)
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

	/* Do not allow symlinks pointing into the meta directory. */
	if (asprintf(&path_got, "%s/%s", wtroot_path, meta_dir) == -1)
		return got_error_from_errno("asprintf");
	if (got_path_is_child(canonpath, path_got, strlen(path_got)))
		*is_bad_symlink = 1;

	free(path_got);
	return NULL;
}

static const struct got_error *
install_symlink(int *is_bad_symlink, struct got_worktree *worktree,
    const char *ondisk_path, const char *path, struct got_blob_object *blob,
    int restoring_missing_file, int reverting_versioned_file,
    int path_is_unversioned, int allow_bad_symlinks,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	size_t len, target_len = 0;
	const uint8_t *buf = got_object_blob_get_read_buf(blob);
	size_t hdrlen = got_object_blob_get_hdrlen(blob);

	*is_bad_symlink = 0;

	/*
	 * Blob object content specifies the target path of the link.
	 * If a symbolic link cannot be installed we instead create
	 * a regular file which contains the link target path stored
	 * in the blob object.
	 */
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;

		if (len + target_len >= sizeof(target_path)) {
			/* Path too long; install as a regular file. */
			*is_bad_symlink = 1;
			got_object_blob_rewind(blob);
			return install_blob(worktree, ondisk_path, path,
			    GOT_DEFAULT_FILE_MODE, GOT_DEFAULT_FILE_MODE, blob,
			    restoring_missing_file, reverting_versioned_file,
			    1, path_is_unversioned, 0, NULL, repo, progress_cb,
			    progress_arg);
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

	err = is_bad_symlink_target(is_bad_symlink, target_path, target_len,
	    ondisk_path, worktree->root_path, worktree->meta_dir);
	if (err)
		return err;

	if (*is_bad_symlink && !allow_bad_symlinks) {
		/* install as a regular file */
		got_object_blob_rewind(blob);
		err = install_blob(worktree, ondisk_path, path,
		    GOT_DEFAULT_FILE_MODE, GOT_DEFAULT_FILE_MODE, blob,
		    restoring_missing_file, reverting_versioned_file, 1,
		    path_is_unversioned, 0, NULL, repo,
		    progress_cb, progress_arg);
		return err;
	}

	if (symlink(target_path, ondisk_path) == -1) {
		if (errno == EEXIST) {
			int symlink_replaced;
			if (path_is_unversioned) {
				err = (*progress_cb)(progress_arg,
				    GOT_STATUS_UNVERSIONED, path);
				return err;
			}
			err = replace_existing_symlink(&symlink_replaced,
			    ondisk_path, target_path, target_len);
			if (err)
				return err;
			if (progress_cb) {
				if (symlink_replaced) {
					err = (*progress_cb)(progress_arg,
					    reverting_versioned_file ?
					    GOT_STATUS_REVERT :
					    GOT_STATUS_UPDATE, path);
				} else {
					err = (*progress_cb)(progress_arg,
					    GOT_STATUS_EXISTS, path);
				}
			}
			return err; /* Nothing else to do. */
		}

		if (errno == ENOENT) {
			char *parent;
			err = got_path_dirname(&parent, ondisk_path);
			if (err)
				return err;
			err = got_path_mkdir(parent);
			free(parent);
			if (err)
				return err;
			/*
			 * Retry, and fall through to error handling
			 * below if this second attempt fails.
			 */
			if (symlink(target_path, ondisk_path) != -1) {
				err = NULL; /* success */
				if (progress_cb) {
					err = (*progress_cb)(progress_arg,
					    reverting_versioned_file ?
					    GOT_STATUS_REVERT : GOT_STATUS_ADD,
					    path);
				}
				return err;
			}
		}

		/* Handle errors from first or second creation attempt. */
		if (errno == ENAMETOOLONG) {
			/* bad target path; install as a regular file */
			*is_bad_symlink = 1;
			got_object_blob_rewind(blob);
			err = install_blob(worktree, ondisk_path, path,
			    GOT_DEFAULT_FILE_MODE, GOT_DEFAULT_FILE_MODE, blob,
			    restoring_missing_file, reverting_versioned_file, 1,
			    path_is_unversioned, 0, NULL, repo,
			    progress_cb, progress_arg);
		} else if (errno == ENOTDIR) {
			err = got_error_path(ondisk_path,
			    GOT_ERR_FILE_OBSTRUCTED);
		} else {
			err = got_error_from_errno3("symlink",
			    target_path, ondisk_path);
		}
	} else if (progress_cb)
		err = (*progress_cb)(progress_arg, reverting_versioned_file ?
		    GOT_STATUS_REVERT : GOT_STATUS_ADD, path);
	return err;
}

static const struct got_error *
install_blob(struct got_worktree *worktree, const char *ondisk_path,
    const char *path, mode_t te_mode, mode_t st_mode,
    struct got_blob_object *blob, int restoring_missing_file,
    int reverting_versioned_file, int installing_bad_symlink,
    int path_is_unversioned, int adding_merged_file,
    int *update_timestamps, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	int fd = -1;
	size_t len, hdrlen;
	int update = 0;
	char *tmppath = NULL;
	mode_t mode;

	if (update_timestamps)
		*update_timestamps = 1;

	mode = get_ondisk_perms(te_mode & S_IXUSR, GOT_DEFAULT_FILE_MODE);
	fd = open(ondisk_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, mode);
	if (fd == -1) {
		if (errno == ENOENT || errno == ENOTDIR) {
			char *parent;
			err = got_path_dirname(&parent, path);
			if (err)
				return err;
			err = add_dir_on_disk(worktree, parent);
			if (err && err->code == GOT_ERR_FILE_OBSTRUCTED)
				err = got_error_path(path, err->code);
			free(parent);
			if (err)
				return err;
			fd = open(ondisk_path,
			    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
			    mode);
			if (fd == -1)
				return got_error_from_errno2("open",
				    ondisk_path);
		} else if (errno == EEXIST) {
			if (path_is_unversioned) {
				if (update_timestamps)
					*update_timestamps = 0;
				err = (*progress_cb)(progress_arg,
				    adding_merged_file ?
				    GOT_STATUS_ADD : GOT_STATUS_EXISTS, path);
				goto done;
			}
			if (!(S_ISLNK(st_mode) && S_ISREG(te_mode)) &&
			    !S_ISREG(st_mode) && !installing_bad_symlink) {
				/* TODO file is obstructed; do something */
				err = got_error_path(ondisk_path,
				    GOT_ERR_FILE_OBSTRUCTED);
				goto done;
			} else {
				err = got_opentemp_named_fd(&tmppath, &fd,
				    ondisk_path, "");
				if (err)
					goto done;
				update = 1;

				if (fchmod(fd, apply_umask(mode)) == -1) {
					err = got_error_from_errno2("fchmod",
					    tmppath);
					goto done;
				}
			}
		} else
			return got_error_from_errno2("open", ondisk_path);
	}

	if (progress_cb) {
		if (restoring_missing_file)
			err = (*progress_cb)(progress_arg, GOT_STATUS_MISSING,
			    path);
		else if (reverting_versioned_file)
			err = (*progress_cb)(progress_arg, GOT_STATUS_REVERT,
			    path);
		else
			err = (*progress_cb)(progress_arg,
			    update ? GOT_STATUS_UPDATE : GOT_STATUS_ADD, path);
		if (err)
			goto done;
	}

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		const uint8_t *buf = got_object_blob_get_read_buf(blob);
		err = got_object_blob_read_block(&len, blob);
		if (err)
			break;
		if (len > 0) {
			/* Skip blob object header first time around. */
			ssize_t outlen = write(fd, buf + hdrlen, len - hdrlen);
			if (outlen == -1) {
				err = got_error_from_errno("write");
				goto done;
			} else if (outlen != len - hdrlen) {
				err = got_error(GOT_ERR_IO);
				goto done;
			}
			hdrlen = 0;
		}
	} while (len != 0);

	if (fsync(fd) != 0) {
		err = got_error_from_errno("fsync");
		goto done;
	}

	if (update) {
		if (S_ISLNK(st_mode) && unlink(ondisk_path) == -1) {
			err = got_error_from_errno2("unlink", ondisk_path);
			goto done;
		}
		if (rename(tmppath, ondisk_path) != 0) {
			err = got_error_from_errno3("rename", tmppath,
			    ondisk_path);
			goto done;
		}
		free(tmppath);
		tmppath = NULL;
	}

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (tmppath != NULL && unlink(tmppath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmppath);
	free(tmppath);
	return err;
}

/*
 * Detect whether a file is in STATUS_MODIFY or in STATUS_CONFLICT.
 * The latter is determined by the presence of conflict markers on
 * newly added lines.
 */
static const struct got_error *
get_modified_file_status(unsigned char *status,
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

		c = diff_chunk_get(r, n);

		/*
		 * Upgrade NO_CHANGE to MODIFY in case there are
		 * chunks which contain changes.
		 */
		if (*status == GOT_STATUS_NO_CHANGE &&
		    (diff_chunk_type(c) == CHUNK_MINUS ||
		    diff_chunk_type(c) == CHUNK_PLUS))
			*status = GOT_STATUS_MODIFY;

		/*
		 * We can optimise conflict detection a little by
		 * advancing straight to the next chunk if this
		 * one has no added lines.
		 */
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
file_is_binary(int *is_binary , FILE *f)
{
	char buf[8192];
	size_t r;
	off_t pos;

	*is_binary = 0;

	pos = ftello(f);
	if (pos == -1)
		return got_error_from_errno("ftello");

	if (fseeko(f, 0L, SEEK_SET) == -1)
		return got_ferror(f, GOT_ERR_IO);

	r = fread(buf, 1, sizeof(buf), f);
	if (r == 0 && ferror(f))
		return got_error_from_errno("fread");

	if (r > 0)
		*is_binary = memchr(buf, '\0', r) != NULL;

	if (fseeko(f, pos, SEEK_SET) == -1)
		return got_ferror(f, GOT_ERR_IO);

	return NULL;
}

static const struct got_error *
get_file_status(unsigned char *status, struct stat *sb,
    struct got_fileindex_entry *ie, const char *abspath,
    int dirfd, const char *de_name, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id id;
	int fd = -1, fd1 = -1;
	FILE *f = NULL;
	uint8_t fbuf[8192];
	struct got_blob_object *blob = NULL;
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

	if (staged_status == GOT_STATUS_NO_CHANGE &&
	    S_ISREG(sb->st_mode) &&
	    got_fileindex_entry_filetype_get(ie) ==
	    GOT_FILEIDX_MODE_REGULAR_FILE &&
	    ie->size != (sb->st_size & 0xffffffff)) {
		int is_binary;

		/* The size of regular files differs. */
		*status = GOT_STATUS_MODIFY;

		/*
		 * We can skip the diff engine for binary files on disk.
		 * Text files still need to be checked for conflict markers.
		 */
		err = file_is_binary(&is_binary, f);
		if (err || is_binary)
			goto done;
	}

	err = get_modified_file_status(status, blob, ie->path, sb, f);
	if (err)
		goto done;

	if (*status == GOT_STATUS_NO_CHANGE && xbit_differs(ie, sb->st_mode))
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

/*
 * Update timestamps in the file index if a file is unmodified and
 * we had to run a full content comparison to find out.
 */
static const struct got_error *
sync_timestamps(int wt_fd, const char *path, unsigned char status,
    struct got_fileindex_entry *ie, struct stat *sb)
{
	if (status == GOT_STATUS_NO_CHANGE && stat_info_differs(ie, sb))
		return got_fileindex_entry_update(ie, wt_fd, path,
		    &ie->blob, &ie->commit, 1);

	return NULL;
}

static const struct got_error *remove_ondisk_file(const char *, const char *);

static const struct got_error *
update_blob(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_fileindex_entry *ie,
    struct got_tree_entry *te, const char *path,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	char *ondisk_path = NULL;
	unsigned char status = GOT_STATUS_NO_CHANGE;
	struct stat sb;
	int fd1 = -1, fd2 = -1;
	int update_timestamps = 0;

	if (asprintf(&ondisk_path, "%s/%s", worktree->root_path, path) == -1)
		return got_error_from_errno("asprintf");

	if (ie) {
		if (get_staged_status(ie) != GOT_STATUS_NO_CHANGE) {
			err = got_error_path(ie->path, GOT_ERR_FILE_STAGED);
			goto done;
		}
		err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL,
		    repo);
		if (err)
			goto done;
		if (status == GOT_STATUS_MISSING || status == GOT_STATUS_DELETE)
			sb.st_mode = got_fileindex_perms_to_st(ie);
	} else {
		if (stat(ondisk_path, &sb) == -1) {
			if (errno != ENOENT && errno != ENOTDIR) {
				err = got_error_from_errno2("stat",
				    ondisk_path);
				goto done;
			}
			sb.st_mode = GOT_DEFAULT_FILE_MODE;
			status = GOT_STATUS_UNVERSIONED;
		} else {
			if (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode))
				status = GOT_STATUS_UNVERSIONED;
			else
				status = GOT_STATUS_OBSTRUCTED;
		}
	}

	if (status == GOT_STATUS_OBSTRUCTED) {
		if (ie)
			got_fileindex_entry_mark_skipped(ie);
		err = (*progress_cb)(progress_arg, status, path);
		goto done;
	}
	if (status == GOT_STATUS_CONFLICT) {
		if (ie)
			got_fileindex_entry_mark_skipped(ie);
		err = (*progress_cb)(progress_arg, GOT_STATUS_CANNOT_UPDATE,
		    path);
		goto done;
	}

	if (S_ISDIR(te->mode)) { /* file changing into a directory */
		if (status == GOT_STATUS_UNVERSIONED) {
			err = (*progress_cb)(progress_arg, status, path);
		} else if (status != GOT_STATUS_NO_CHANGE &&
		    status != GOT_STATUS_DELETE &&
		    status != GOT_STATUS_NONEXISTENT &&
		    status != GOT_STATUS_MISSING) {
			err = (*progress_cb)(progress_arg,
			    GOT_STATUS_CANNOT_DELETE, path);
		} else if (ie) {
			if (status != GOT_STATUS_DELETE &&
			    status != GOT_STATUS_NONEXISTENT &&
			    status != GOT_STATUS_MISSING) {
				err = remove_ondisk_file(worktree->root_path,
				    ie->path);
				if (err && !(err->code == GOT_ERR_ERRNO &&
				    errno == ENOENT))
					goto done;
			}
			got_fileindex_entry_remove(fileindex, ie);
			err = (*progress_cb)(progress_arg, GOT_STATUS_DELETE,
			    ie->path);
		}
		goto done; /* nothing else to do */
	}

	if (ie && status != GOT_STATUS_MISSING && S_ISREG(sb.st_mode) &&
	    (S_ISLNK(te->mode) ||
	    (te->mode & S_IXUSR) == (sb.st_mode & S_IXUSR))) {
		/*
		 * This is a regular file or an installed bad symlink.
		 * If the file index indicates that this file is already
		 * up-to-date with respect to the repository we can skip
		 * updating contents of this file.
		 */
		if (got_fileindex_entry_has_commit(ie) &&
		    got_object_id_cmp(&ie->commit,
		    worktree->base_commit_id) == 0) {
			/* Same commit. */
			err = sync_timestamps(worktree->root_fd,
			    path, status, ie, &sb);
			if (err)
				goto done;
			err = (*progress_cb)(progress_arg, GOT_STATUS_EXISTS,
			    path);
			goto done;
		}
		if (got_fileindex_entry_has_blob(ie) &&
		    got_object_id_cmp(&ie->blob, &te->id) == 0) {
			/* Different commit but the same blob. */
			if (got_fileindex_entry_has_commit(ie)) {
				/* Update the base commit ID of this file. */
				memcpy(&ie->commit, worktree->base_commit_id,
				    sizeof(ie->commit));
			}
			err = sync_timestamps(worktree->root_fd,
			    path, status, ie, &sb);
			if (err)
				goto done;
			err = (*progress_cb)(progress_arg, GOT_STATUS_EXISTS,
			    path);
			goto done;
		}
	}

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}
	err = got_object_open_as_blob(&blob, repo, &te->id, 8192, fd1);
	if (err)
		goto done;

	if (status == GOT_STATUS_MODIFY || status == GOT_STATUS_ADD) {
		struct got_blob_object *blob2 = NULL;
		char *label_orig = NULL;
		if (got_fileindex_entry_has_blob(ie)) {
			fd2 = got_opentempfd();
			if (fd2 == -1) {
				err = got_error_from_errno("got_opentempfd");
				goto done;
			}
			struct got_object_id id2;
			got_fileindex_entry_get_blob_id(&id2, ie);
			err = got_object_open_as_blob(&blob2, repo, &id2, 8192,
			    fd2);
			if (err)
				goto done;
		}
		if (got_fileindex_entry_has_commit(ie)) {
			char id_str[GOT_HASH_DIGEST_STRING_MAXLEN];

			if (got_hash_digest_to_str(ie->commit.hash, id_str,
			    sizeof(id_str), ie->commit.algo) == NULL) {
				err = got_error_path(id_str,
				    GOT_ERR_BAD_OBJ_ID_STR);
				goto done;
			}
			if (asprintf(&label_orig, "%s: commit %s",
			    GOT_MERGE_LABEL_BASE, id_str) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		}
		if (S_ISLNK(te->mode) && S_ISLNK(sb.st_mode)) {
			char *link_target;
			err = got_object_blob_read_to_str(&link_target, blob);
			if (err)
				goto done;
			err = merge_symlink(worktree, blob2, ondisk_path, path,
			    label_orig, link_target, worktree->base_commit_id,
			    repo, progress_cb, progress_arg);
			free(link_target);
		} else {
			err = merge_blob(&update_timestamps, worktree, blob2,
			    ondisk_path, path, sb.st_mode, label_orig, blob,
			    worktree->base_commit_id, repo,
			    progress_cb, progress_arg);
		}
		free(label_orig);
		if (fd2 != -1 && close(fd2) == -1 && err == NULL) {
			err = got_error_from_errno("close");
			goto done;
		}
		if (blob2)
			got_object_blob_close(blob2);
		if (err)
			goto done;
		/*
		 * Do not update timestamps of files with local changes.
		 * Otherwise, a future status walk would treat them as
		 * unmodified files again.
		 */
		err = got_fileindex_entry_update(ie, worktree->root_fd, path,
		    &blob->id, worktree->base_commit_id, update_timestamps);
	} else if (status == GOT_STATUS_MODE_CHANGE) {
		err = got_fileindex_entry_update(ie, worktree->root_fd, path,
		    &blob->id, worktree->base_commit_id, 0);
	} else if (status == GOT_STATUS_DELETE) {
		err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE, path);
		if (err)
			goto done;
		err = got_fileindex_entry_update(ie, worktree->root_fd, path,
		    &blob->id, worktree->base_commit_id, 0);
		if (err)
			goto done;
	} else {
		int is_bad_symlink = 0;
		if (S_ISLNK(te->mode)) {
			err = install_symlink(&is_bad_symlink, worktree,
			    ondisk_path, path, blob,
			    status == GOT_STATUS_MISSING, 0,
			    status == GOT_STATUS_UNVERSIONED, 0,
			    repo, progress_cb, progress_arg);
		} else {
			err = install_blob(worktree, ondisk_path, path,
			    te->mode, sb.st_mode, blob,
			    status == GOT_STATUS_MISSING, 0, 0,
			    status == GOT_STATUS_UNVERSIONED, 0,
			    &update_timestamps,
			    repo, progress_cb, progress_arg);
		}
		if (err)
			goto done;

		if (ie) {
			err = got_fileindex_entry_update(ie,
			    worktree->root_fd, path, &blob->id,
			    worktree->base_commit_id, 1);
		} else {
			err = create_fileindex_entry(&ie, fileindex,
			    worktree->base_commit_id, worktree->root_fd, path,
			    &blob->id, update_timestamps);
		}
		if (err)
			goto done;

		if (is_bad_symlink) {
			got_fileindex_entry_filetype_set(ie,
			    GOT_FILEIDX_MODE_BAD_SYMLINK);
		}
	}

	if (fd1 != -1 && close(fd1) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		goto done;
	}
	got_object_blob_close(blob);
done:
	free(ondisk_path);
	return err;
}

static const struct got_error *
remove_ondisk_file(const char *root_path, const char *path)
{
	const struct got_error *err = NULL;
	char *ondisk_path = NULL, *parent = NULL;

	if (asprintf(&ondisk_path, "%s/%s", root_path, path) == -1)
		return got_error_from_errno("asprintf");

	if (unlink(ondisk_path) == -1) {
		if (errno != ENOENT)
			err = got_error_from_errno2("unlink", ondisk_path);
	} else {
		size_t root_len = strlen(root_path);
		err = got_path_dirname(&parent, ondisk_path);
		if (err)
			goto done;
		while (got_path_cmp(parent, root_path,
		    strlen(parent), root_len) != 0) {
			free(ondisk_path);
			ondisk_path = parent;
			parent = NULL;
			if (rmdir(ondisk_path) == -1) {
				if (errno != ENOTEMPTY)
					err = got_error_from_errno2("rmdir",
					    ondisk_path);
				break;
			}
			err = got_path_dirname(&parent, ondisk_path);
			if (err)
				break;
		}
	}
done:
	free(ondisk_path);
	free(parent);
	return err;
}

static const struct got_error *
delete_blob(struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_fileindex_entry *ie, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	unsigned char status;
	struct stat sb;
	char *ondisk_path;

	if (get_staged_status(ie) != GOT_STATUS_NO_CHANGE)
		return got_error_path(ie->path, GOT_ERR_FILE_STAGED);

	if (asprintf(&ondisk_path, "%s/%s", worktree->root_path, ie->path)
	    == -1)
		return got_error_from_errno("asprintf");

	err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL, repo);
	if (err)
		goto done;

	if (S_ISLNK(sb.st_mode) && status != GOT_STATUS_NO_CHANGE) {
		char ondisk_target[PATH_MAX];
		ssize_t ondisk_len = readlink(ondisk_path, ondisk_target,
		    sizeof(ondisk_target));
		if (ondisk_len == -1) {
			err = got_error_from_errno2("readlink", ondisk_path);
			goto done;
		}
		ondisk_target[ondisk_len] = '\0';
		err = install_symlink_conflict(NULL, worktree->base_commit_id,
		    NULL, NULL, /* XXX pass common ancestor info? */
		    ondisk_target, ondisk_path);
		if (err)
			goto done;
		err = (*progress_cb)(progress_arg, GOT_STATUS_CONFLICT,
		    ie->path);
		goto done;
	}

	if (status == GOT_STATUS_MODIFY || status == GOT_STATUS_CONFLICT ||
	    status == GOT_STATUS_ADD) {
		err = (*progress_cb)(progress_arg, GOT_STATUS_MERGE, ie->path);
		if (err)
			goto done;
		/*
		 * Preserve the working file and change the deleted blob's
		 * entry into a schedule-add entry.
		 */
		err = got_fileindex_entry_update(ie, worktree->root_fd,
		    ie->path, NULL, NULL, 0);
	} else {
		err = (*progress_cb)(progress_arg, GOT_STATUS_DELETE, ie->path);
		if (err)
			goto done;
		if (status == GOT_STATUS_NO_CHANGE) {
			err = remove_ondisk_file(worktree->root_path, ie->path);
			if (err)
				goto done;
		}
		got_fileindex_entry_remove(fileindex, ie);
	}
done:
	free(ondisk_path);
	return err;
}

struct diff_cb_arg {
    struct got_fileindex *fileindex;
    struct got_worktree *worktree;
    struct got_repository *repo;
    got_worktree_checkout_cb progress_cb;
    void *progress_arg;
    got_cancel_cb cancel_cb;
    void *cancel_arg;
};

static const struct got_error *
diff_old_new(void *arg, struct got_fileindex_entry *ie,
    struct got_tree_entry *te, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_cb_arg *a = arg;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	return update_blob(a->worktree, a->fileindex, ie, te,
	    ie->path, a->repo, a->progress_cb, a->progress_arg);
}

static const struct got_error *
diff_old(void *arg, struct got_fileindex_entry *ie, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_cb_arg *a = arg;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	return delete_blob(a->worktree, a->fileindex, ie,
	    a->repo, a->progress_cb, a->progress_arg);
}

static const struct got_error *
diff_new(void *arg, struct got_tree_entry *te, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_cb_arg *a = arg;
	char *path;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	if (got_object_tree_entry_is_submodule(te))
		return NULL;

	if (!S_ISREG(te->mode) && !S_ISLNK(te->mode))
		return NULL;

	if (asprintf(&path, "%s%s%s", parent_path,
	    parent_path[0] ? "/" : "", te->name)
	    == -1)
		return got_error_from_errno("asprintf");

	err = update_blob(a->worktree, a->fileindex, NULL, te, path,
	    a->repo, a->progress_cb, a->progress_arg);

	free(path);
	return err;
}

const struct got_error *
got_worktree_get_uuid(char **uuidstr, struct got_worktree *worktree)
{
	uint32_t uuid_status;

	uuid_to_string(&worktree->uuid, uuidstr, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		*uuidstr = NULL;
		return got_error_uuid(uuid_status, "uuid_to_string");
	}

	return NULL;
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

const struct got_error *
got_worktree_get_logmsg_ref_name(char **refname, struct got_worktree *worktree,
    const char *prefix)
{
	return get_ref_name(refname, worktree, prefix);
}

static const struct got_error *
get_base_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree, GOT_WORKTREE_BASE_REF_PREFIX);
}

static const struct got_error *
get_rebase_tmp_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_REBASE_TMP_REF_PREFIX);
}

static const struct got_error *
get_newbase_symref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree, GOT_WORKTREE_NEWBASE_REF_PREFIX);
}

static const struct got_error *
get_rebase_branch_symref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_REBASE_BRANCH_REF_PREFIX);
}

static const struct got_error *
get_rebase_commit_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_REBASE_COMMIT_REF_PREFIX);
}

static const struct got_error *
get_histedit_tmp_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_HISTEDIT_TMP_REF_PREFIX);
}

static const struct got_error *
get_histedit_branch_symref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_HISTEDIT_BRANCH_REF_PREFIX);
}

static const struct got_error *
get_histedit_base_commit_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_HISTEDIT_BASE_COMMIT_REF_PREFIX);
}

static const struct got_error *
get_histedit_commit_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_HISTEDIT_COMMIT_REF_PREFIX);
}

const struct got_error *
got_worktree_get_histedit_script_path(char **path,
    struct got_worktree *worktree)
{
	if (asprintf(path, "%s/%s/%s", worktree->root_path,
	    worktree->meta_dir, GOT_WORKTREE_HISTEDIT_SCRIPT) == -1) {
		*path = NULL;
		return got_error_from_errno("asprintf");
	}
	return NULL;
}

static const struct got_error *
get_merge_branch_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_MERGE_BRANCH_REF_PREFIX);
}

static const struct got_error *
get_merge_commit_ref_name(char **refname, struct got_worktree *worktree)
{
	return get_ref_name(refname, worktree,
	    GOT_WORKTREE_MERGE_COMMIT_REF_PREFIX);
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
	    worktree->meta_dir, GOT_WORKTREE_FILE_INDEX) == -1) {
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

	*fileindex = got_fileindex_alloc(algo);
	*fileindex_path = NULL;
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

struct bump_base_commit_id_arg {
	struct got_object_id *base_commit_id;
	const char *path;
	size_t path_len;
	const char *entry_name;
	got_worktree_checkout_cb progress_cb;
	void *progress_arg;
};

static const struct got_error *
bump_base_commit_id(void *arg, struct got_fileindex_entry *ie)
{
	const struct got_error *err;
	struct bump_base_commit_id_arg *a = arg;

	if (a->entry_name) {
		if (strcmp(ie->path, a->path) != 0)
			return NULL;
	} else if (!got_path_is_child(ie->path, a->path, a->path_len))
		return NULL;

	if (got_fileindex_entry_was_skipped(ie))
		return NULL;

	if (got_object_id_cmp(&ie->commit, a->base_commit_id) == 0)
		return NULL;

	if (a->progress_cb) {
		err = (*a->progress_cb)(a->progress_arg, GOT_STATUS_BUMP_BASE,
		    ie->path);
		if (err)
			return err;
	}
	memcpy(&ie->commit, a->base_commit_id, sizeof(ie->commit));
	return NULL;
}

/* Bump base commit ID of all files within an updated part of the work tree. */
static const struct got_error *
bump_base_commit_id_everywhere(struct got_worktree *worktree,
    struct got_fileindex *fileindex,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	struct bump_base_commit_id_arg bbc_arg;

	bbc_arg.base_commit_id = worktree->base_commit_id;
	bbc_arg.entry_name = NULL;
	bbc_arg.path = "";
	bbc_arg.path_len = 0;
	bbc_arg.progress_cb = progress_cb;
	bbc_arg.progress_arg = progress_arg;

	return got_fileindex_for_each_entry_safe(fileindex,
	    bump_base_commit_id, &bbc_arg);
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
	nanosleep(&timeout,  NULL);
done:
	if (new_index)
		fclose(new_index);
	free(new_fileindex_path);
	return err;
}

static const struct got_error *
find_tree_entry_for_checkout(int *entry_type, char **tree_relpath,
    struct got_object_id **tree_id, const char *wt_relpath,
    struct got_commit_object *base_commit, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	char *in_repo_path = NULL;
	int is_root_wt = got_path_is_root_dir(worktree->path_prefix);

	*entry_type = GOT_OBJ_TYPE_ANY;
	*tree_relpath = NULL;
	*tree_id = NULL;

	if (wt_relpath[0] == '\0') {
		/* Check out all files within the work tree. */
		*entry_type = GOT_OBJ_TYPE_TREE;
		*tree_relpath = strdup("");
		if (*tree_relpath == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		err = got_object_id_by_path(tree_id, repo, base_commit,
		    worktree->path_prefix);
		if (err)
			goto done;
		return NULL;
	}

	/* Check out a subset of files in the work tree. */

	if (asprintf(&in_repo_path, "%s%s%s", worktree->path_prefix,
	    is_root_wt ? "" : "/", wt_relpath) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_object_id_by_path(&id, repo, base_commit, in_repo_path);
	if (err)
		goto done;

	free(in_repo_path);
	in_repo_path = NULL;

	err = got_object_get_type(entry_type, repo, id);
	if (err)
		goto done;

	if (*entry_type == GOT_OBJ_TYPE_BLOB) {
		/* Check out a single file. */
		if (strchr(wt_relpath, '/')  == NULL) {
			/* Check out a single file in work tree's root dir. */
			in_repo_path = strdup(worktree->path_prefix);
			if (in_repo_path == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
			*tree_relpath = strdup("");
			if (*tree_relpath == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			/* Check out a single file in a subdirectory. */
			err = got_path_dirname(tree_relpath, wt_relpath);
			if (err)
				return err;
			if (asprintf(&in_repo_path, "%s%s%s",
			    worktree->path_prefix, is_root_wt ? "" : "/",
			    *tree_relpath) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		}
		err = got_object_id_by_path(tree_id, repo,
		    base_commit, in_repo_path);
	} else {
		/* Check out all files within a subdirectory. */
		*tree_id = got_object_id_dup(id);
		if (*tree_id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
		*tree_relpath = strdup(wt_relpath);
		if (*tree_relpath == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
done:
	free(id);
	free(in_repo_path);
	if (err) {
		*entry_type = GOT_OBJ_TYPE_ANY;
		free(*tree_relpath);
		*tree_relpath = NULL;
		free(*tree_id);
		*tree_id = NULL;
	}
	return err;
}

static const struct got_error *
checkout_files(struct got_worktree *worktree, struct got_fileindex *fileindex,
    const char *relpath, struct got_object_id *tree_id, const char *entry_name,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	struct got_fileindex_diff_tree_cb diff_cb;
	struct diff_cb_arg arg;

	err = ref_base_commit(worktree, repo);
	if (err) {
		if (!(err->code == GOT_ERR_ERRNO &&
		    (errno == EACCES || errno == EROFS)))
			goto done;
		err = (*progress_cb)(progress_arg,
		    GOT_STATUS_BASE_REF_ERR, worktree->root_path);
		if (err)
			return err;
	}

	err = got_object_open_as_commit(&commit, repo,
	    worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;

	if (entry_name &&
	    got_object_tree_find_entry(tree, entry_name) == NULL) {
		err = got_error_path(entry_name, GOT_ERR_NO_TREE_ENTRY);
		goto done;
	}

	diff_cb.diff_old_new = diff_old_new;
	diff_cb.diff_old = diff_old;
	diff_cb.diff_new = diff_new;
	arg.fileindex = fileindex;
	arg.worktree = worktree;
	arg.repo = repo;
	arg.progress_cb = progress_cb;
	arg.progress_arg = progress_arg;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	err = got_fileindex_diff_tree(fileindex, tree, relpath,
	    entry_name, repo, &diff_cb, &arg);
done:
	if (tree)
		got_object_tree_close(tree);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

const struct got_error *
got_worktree_checkout_files(struct got_worktree *worktree,
    struct got_pathlist_head *paths, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	struct got_pathlist_entry *pe;
	struct tree_path_data {
		STAILQ_ENTRY(tree_path_data) entry;
		struct got_object_id *tree_id;
		int entry_type;
		char *relpath;
		char *entry_name;
	} *tpd = NULL;
	STAILQ_HEAD(tree_paths, tree_path_data) tree_paths;

	STAILQ_INIT(&tree_paths);

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_object_open_as_commit(&commit, repo,
	    worktree->base_commit_id);
	if (err)
		goto done;

	/* Map all specified paths to in-repository trees. */
	RB_FOREACH(pe, got_pathlist_head, paths) {
		tpd = malloc(sizeof(*tpd));
		if (tpd == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}

		err = find_tree_entry_for_checkout(&tpd->entry_type,
		    &tpd->relpath, &tpd->tree_id, pe->path, commit,
		    worktree, repo);
		if (err) {
			free(tpd);
			goto done;
		}

		if (tpd->entry_type == GOT_OBJ_TYPE_BLOB) {
			err = got_path_basename(&tpd->entry_name, pe->path);
			if (err) {
				free(tpd->relpath);
				free(tpd->tree_id);
				free(tpd);
				goto done;
			}
		} else
			tpd->entry_name = NULL;

		STAILQ_INSERT_TAIL(&tree_paths, tpd, entry);
	}

	/*
	 * Read the file index.
	 * Checking out files is supposed to be an idempotent operation.
	 * If the on-disk file index is incomplete we will try to complete it.
	 */
	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	tpd = STAILQ_FIRST(&tree_paths);
	RB_FOREACH(pe, got_pathlist_head, paths) {
		struct bump_base_commit_id_arg bbc_arg;

		err = checkout_files(worktree, fileindex, tpd->relpath,
		    tpd->tree_id, tpd->entry_name, repo,
		    progress_cb, progress_arg, cancel_cb, cancel_arg);
		if (err)
			break;

		bbc_arg.base_commit_id = worktree->base_commit_id;
		bbc_arg.entry_name = tpd->entry_name;
		bbc_arg.path = pe->path;
		bbc_arg.path_len = pe->path_len;
		bbc_arg.progress_cb = progress_cb;
		bbc_arg.progress_arg = progress_arg;
		err = got_fileindex_for_each_entry_safe(fileindex,
		    bump_base_commit_id, &bbc_arg);
		if (err)
			break;

		tpd = STAILQ_NEXT(tpd, entry);
	}
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	if (tree)
		got_object_tree_close(tree);
	if (commit)
		got_object_commit_close(commit);
	if (fileindex)
		got_fileindex_free(fileindex);
	while (!STAILQ_EMPTY(&tree_paths)) {
		tpd = STAILQ_FIRST(&tree_paths);
		STAILQ_REMOVE_HEAD(&tree_paths, entry);
		free(tpd->relpath);
		free(tpd->tree_id);
		free(tpd);
	}
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

static const struct got_error *
add_file(struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_fileindex_entry *ie, const char *ondisk_path,
    const char *path2, struct got_blob_object *blob2, mode_t mode2,
    int restoring_missing_file, int reverting_versioned_file,
    int path_is_unversioned, int allow_bad_symlinks,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	int is_bad_symlink = 0;

	if (S_ISLNK(mode2)) {
		err = install_symlink(&is_bad_symlink,
		    worktree, ondisk_path, path2, blob2,
		    restoring_missing_file,
		    reverting_versioned_file,
		    path_is_unversioned, allow_bad_symlinks,
		    repo, progress_cb, progress_arg);
	} else {
		err = install_blob(worktree, ondisk_path, path2,
		    mode2, GOT_DEFAULT_FILE_MODE, blob2,
		    restoring_missing_file, reverting_versioned_file, 0,
		    path_is_unversioned, 1, NULL, repo,
		    progress_cb, progress_arg);
	}
	if (err)
		return err;
	if (ie == NULL) {
		/* Adding an unversioned file. */
		err = got_fileindex_entry_alloc(&ie, path2);
		if (err)
			return err;
		err = got_fileindex_entry_update(ie,
		    worktree->root_fd, path2, NULL, NULL, 1);
		if (err) {
			got_fileindex_entry_free(ie);
			return err;
		}
		err = got_fileindex_entry_add(fileindex, ie);
		if (err) {
			got_fileindex_entry_free(ie);
			return err;
		}
	} else {
		/* Re-adding a locally deleted file. */
		err = got_fileindex_entry_update(ie,
		    worktree->root_fd, path2, &ie->blob,
		    worktree->base_commit_id, 0);
		if (err)
			return err;
	}

	if (is_bad_symlink) {
		got_fileindex_entry_filetype_set(ie,
		    GOT_FILEIDX_MODE_BAD_SYMLINK);
	}

	return NULL;
}

struct merge_file_cb_arg {
    struct got_worktree *worktree;
    struct got_fileindex *fileindex;
    got_worktree_checkout_cb progress_cb;
    void *progress_arg;
    got_cancel_cb cancel_cb;
    void *cancel_arg;
    const char *label_orig;
    struct got_object_id *commit_id2;
    int allow_bad_symlinks;
};

static const struct got_error *
merge_file_cb(void *arg, struct got_blob_object *blob1,
    struct got_blob_object *blob2, FILE *f1, FILE *f2,
    struct got_object_id *id1, struct got_object_id *id2,
    const char *path1, const char *path2,
    mode_t mode1, mode_t mode2, struct got_repository *repo)
{
	static const struct got_error *err = NULL;
	struct merge_file_cb_arg *a = arg;
	struct got_fileindex_entry *ie;
	char *ondisk_path = NULL;
	struct stat sb;
	unsigned char status;
	int local_changes_subsumed;
	FILE *f_orig = NULL, *f_deriv = NULL, *f_deriv2 = NULL;
	char *id_str = NULL, *label_deriv2 = NULL;
	struct got_object_id *id = NULL;

	if (blob1 && blob2) {
		ie = got_fileindex_entry_get(a->fileindex, path2,
		    strlen(path2));
		if (ie == NULL)
			return (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_MISSING, path2);

		if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
		    path2) == -1)
			return got_error_from_errno("asprintf");

		err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL,
		    repo);
		if (err)
			goto done;

		if (status == GOT_STATUS_DELETE) {
			err = (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_MERGE, path2);
			goto done;
		}
		if (status != GOT_STATUS_NO_CHANGE &&
		    status != GOT_STATUS_MODIFY &&
		    status != GOT_STATUS_CONFLICT &&
		    status != GOT_STATUS_ADD) {
			err = (*a->progress_cb)(a->progress_arg, status, path2);
			goto done;
		}

		if (S_ISLNK(mode1) && S_ISLNK(mode2)) {
			char *link_target2;
			err = got_object_blob_read_to_str(&link_target2, blob2);
			if (err)
				goto done;
			err = merge_symlink(a->worktree, blob1, ondisk_path,
			    path2, a->label_orig, link_target2, a->commit_id2,
			    repo, a->progress_cb, a->progress_arg);
			free(link_target2);
		} else {
			int fd;

			f_orig = got_opentemp();
			if (f_orig == NULL) {
				err = got_error_from_errno("got_opentemp");
				goto done;
			}
			err = got_object_blob_dump_to_file(NULL, NULL, NULL,
			    f_orig, blob1);
			if (err)
				goto done;

			f_deriv2 = got_opentemp();
			if (f_deriv2 == NULL)
				goto done;
			err = got_object_blob_dump_to_file(NULL, NULL, NULL,
			    f_deriv2, blob2);
			if (err)
				goto done;

			fd = open(ondisk_path,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				err = got_error_from_errno2("open",
				    ondisk_path);
				goto done;
			}
			f_deriv = fdopen(fd, "r");
			if (f_deriv == NULL) {
				err = got_error_from_errno2("fdopen",
				    ondisk_path);
				close(fd);
				goto done;
			}
			err = got_object_id_str(&id_str, a->commit_id2);
			if (err)
				goto done;
			if (asprintf(&label_deriv2, "%s: commit %s",
			    GOT_MERGE_LABEL_MERGED, id_str) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = merge_file(&local_changes_subsumed, a->worktree,
			    f_orig, f_deriv, f_deriv2, ondisk_path, path2,
			    mode2, a->label_orig, NULL, label_deriv2,
			    GOT_DIFF_ALGORITHM_PATIENCE, repo,
			    a->progress_cb, a->progress_arg);
		}
	} else if (blob1) {
		ie = got_fileindex_entry_get(a->fileindex, path1,
		    strlen(path1));
		if (ie == NULL)
			return (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_MISSING, path1);

		if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
		    path1) == -1)
			return got_error_from_errno("asprintf");

		err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL,
		    repo);
		if (err)
			goto done;

		switch (status) {
		case GOT_STATUS_NO_CHANGE:
			err = (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_DELETE, path1);
			if (err)
				goto done;
			err = remove_ondisk_file(a->worktree->root_path, path1);
			if (err)
				goto done;
			if (ie)
				got_fileindex_entry_mark_deleted_from_disk(ie);
			break;
		case GOT_STATUS_DELETE:
		case GOT_STATUS_MISSING:
			err = (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_DELETE, path1);
			if (err)
				goto done;
			if (ie)
				got_fileindex_entry_mark_deleted_from_disk(ie);
			break;
		case GOT_STATUS_MODIFY: {
			FILE *blob1_f;
			off_t blob1_size;
			int obj_type;
			/*
			 * Delete the file only if its content already
			 * exists in the repository.
			 */
			err = got_object_blob_file_create(&id, &blob1_f,
			    &blob1_size, path1, repo);
			if (err)
				goto done;
			if (fclose(blob1_f) == EOF) {
				err = got_error_from_errno("fclose");
				goto done;
			}

			/* Implied existence check. */
			err = got_object_get_type(&obj_type, repo, id);
			if (err) {
				if (err->code != GOT_ERR_NO_OBJ)
					goto done;
				err = (*a->progress_cb)(a->progress_arg,
				    GOT_STATUS_CANNOT_DELETE, path1);
				goto done;
			} else if (obj_type != GOT_OBJ_TYPE_BLOB) {
				err = (*a->progress_cb)(a->progress_arg,
				    GOT_STATUS_CANNOT_DELETE, path1);
				goto done;
			}
			err = (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_DELETE, path1);
			if (err)
				goto done;
			err = remove_ondisk_file(a->worktree->root_path,
			    path1);
			if (err)
				goto done;
			if (ie)
				got_fileindex_entry_mark_deleted_from_disk(ie);
			break;
		}
		case GOT_STATUS_ADD: {
			FILE *blob1_f;
			off_t blob1_size;
			/*
			 * Delete the file only if its content already exists
			 * in the repository, or if the file does not exist
			 * on disk. No content will be lost in either case.
			 */
			err = got_object_blob_file_create(&id, &blob1_f,
			    &blob1_size, path1, repo);
			if (err) {
				if (err->code == GOT_ERR_ERRNO &&
				    (errno == ENOENT || errno == ENOTDIR)) {
					/* The file does not exist on disk. */
					err = (*a->progress_cb)(a->progress_arg,
					    GOT_STATUS_DELETE, path1);
					if (err)
						goto done;
					if (ie)
						got_fileindex_entry_remove(
						    a->fileindex, ie);
				}
				goto done;
			}
			if (fclose(blob1_f) == EOF) {
				err = got_error_from_errno("fclose");
				goto done;
			}
			if (got_object_id_cmp(id, id1) == 0) {
				err = (*a->progress_cb)(a->progress_arg,
				    GOT_STATUS_DELETE, path1);
				if (err)
					goto done;
				err = remove_ondisk_file(a->worktree->root_path,
				    path1);
				if (err)
					goto done;
				if (ie)
					got_fileindex_entry_remove(a->fileindex,
					    ie);
			} else {
				err = (*a->progress_cb)(a->progress_arg,
				    GOT_STATUS_CANNOT_DELETE, path1);
			}
			if (err)
				goto done;
			break;
		}
		case GOT_STATUS_CONFLICT:
			err = (*a->progress_cb)(a->progress_arg,
			    GOT_STATUS_CANNOT_DELETE, path1);
			if (err)
				goto done;
			break;
		case GOT_STATUS_OBSTRUCTED:
			err = (*a->progress_cb)(a->progress_arg, status, path1);
			if (err)
				goto done;
			break;
		default:
			break;
		}
	} else if (blob2) {
		if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
		    path2) == -1)
			return got_error_from_errno("asprintf");
		ie = got_fileindex_entry_get(a->fileindex, path2,
		    strlen(path2));
		if (ie) {
			err = get_file_status(&status, &sb, ie, ondisk_path,
			    -1, NULL, repo);
			if (err)
				goto done;
			if (status != GOT_STATUS_NO_CHANGE &&
			    status != GOT_STATUS_MODIFY &&
			    status != GOT_STATUS_CONFLICT &&
			    status != GOT_STATUS_ADD &&
			    status != GOT_STATUS_DELETE) {
				err = (*a->progress_cb)(a->progress_arg,
				    status, path2);
				goto done;
			}
			if (S_ISLNK(mode2) && S_ISLNK(sb.st_mode)) {
				char *link_target2;
				err = got_object_blob_read_to_str(&link_target2,
				    blob2);
				if (err)
					goto done;
				err = merge_symlink(a->worktree, NULL,
				    ondisk_path, path2, a->label_orig,
				    link_target2, a->commit_id2, repo,
				    a->progress_cb, a->progress_arg);
				free(link_target2);
			} else if (S_ISREG(sb.st_mode)) {
				err = merge_blob(&local_changes_subsumed,
				    a->worktree, NULL, ondisk_path, path2,
				    sb.st_mode, a->label_orig, blob2,
				    a->commit_id2, repo, a->progress_cb,
				    a->progress_arg);
			} else if (status != GOT_STATUS_DELETE) {
				err = got_error_path(ondisk_path,
				    GOT_ERR_FILE_OBSTRUCTED);
			}
			if (err)
				goto done;
			if (status == GOT_STATUS_DELETE) {
				/* Re-add file with content from new blob. */
				err = add_file(a->worktree, a->fileindex, ie,
				    ondisk_path, path2, blob2, mode2,
				    0, 0, 0, a->allow_bad_symlinks,
				    repo, a->progress_cb, a->progress_arg);
				if (err)
					goto done;
			}
		} else {
			err = add_file(a->worktree, a->fileindex, NULL,
			     ondisk_path, path2, blob2, mode2,
			     0, 0, 1, a->allow_bad_symlinks,
			    repo, a->progress_cb, a->progress_arg);
			if (err)
				goto done;
		}
	}
done:
	if (f_orig && fclose(f_orig) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f_deriv && fclose(f_deriv) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f_deriv2 && fclose(f_deriv2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(id_str);
	free(id);
	free(label_deriv2);
	free(ondisk_path);
	return err;
}

struct check_mixed_commits_args {
	struct got_worktree *worktree;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
};

static const struct got_error *
check_mixed_commits(void *arg, struct got_fileindex_entry *ie)
{
	const struct got_error *err = NULL;
	struct check_mixed_commits_args *a = arg;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	/* Reject merges into a work tree with mixed base commits. */
	if (got_fileindex_entry_has_commit(ie) &&
	    got_object_id_cmp(&ie->commit, a->worktree->base_commit_id) != 0)
		return got_error(GOT_ERR_MIXED_COMMITS);

	return NULL;
}

const struct got_error *
got_worktree_get_state(char *state, struct got_repository *repo,
    struct got_worktree *worktree,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error	*err;
	struct got_object_id	*base_id, *head_id = NULL;
	struct got_reference	*head_ref;
	struct got_fileindex	*fileindex = NULL;
	char			*fileindex_path = NULL;
	struct check_mixed_commits_args cma;

	if (worktree == NULL)
		return got_error(GOT_ERR_NOT_WORKTREE);

	err = got_ref_open(&head_ref, repo,
	    got_worktree_get_head_ref_name(worktree), 0);
	if (err)
		return err;

	err = got_ref_resolve(&head_id, repo, head_ref);
	if (err)
		goto done;

	*state = GOT_WORKTREE_STATE_UNKNOWN;
	base_id = got_worktree_get_base_commit_id(worktree);

	cma.worktree = worktree;
	cma.cancel_cb = cancel_cb;
	cma.cancel_arg = cancel_arg;

	if (got_object_id_cmp(base_id, head_id) == 0) {
		err = open_fileindex(&fileindex, &fileindex_path, worktree,
		    got_repo_get_object_format(repo));
		if (err)
			goto done;

		err = got_fileindex_for_each_entry_safe(fileindex,
		    check_mixed_commits, &cma);
		if (err == NULL)
			*state = GOT_WORKTREE_STATE_UPTODATE;
		else if (err->code == GOT_ERR_MIXED_COMMITS) {
			*state = GOT_WORKTREE_STATE_OUTOFDATE;
			err = NULL;
		}
	} else
		*state = GOT_WORKTREE_STATE_OUTOFDATE;

done:
	free(head_id);
	free(fileindex_path);
	got_ref_close(head_ref);
	if (fileindex != NULL)
		got_fileindex_free(fileindex);
	return err;
}

struct check_merge_conflicts_arg {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	struct got_repository *repo;
};

static const struct got_error *
check_merge_conflicts(void *arg, struct got_blob_object *blob1,
    struct got_blob_object *blob2, FILE *f1, FILE *f2,
    struct got_object_id *id1, struct got_object_id *id2,
    const char *path1, const char *path2,
    mode_t mode1, mode_t mode2, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct check_merge_conflicts_arg *a = arg;
	unsigned char status;
	struct stat sb;
	struct got_fileindex_entry *ie;
	const char *path = path2 ? path2 : path1;
	struct got_object_id *id = id2 ? id2 : id1;
	char *ondisk_path;

	if (id == NULL)
		return NULL;

	ie = got_fileindex_entry_get(a->fileindex, path, strlen(path));
	if (ie == NULL)
		return NULL;

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path, ie->path)
	    == -1)
		return got_error_from_errno("asprintf");

	/* Reject merges into a work tree with conflicted files. */
	err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL, a->repo);
	free(ondisk_path);
	if (err)
		return err;
	if (status == GOT_STATUS_CONFLICT)
		return got_error(GOT_ERR_CONFLICTS);

	return NULL;
}

static const struct got_error *
merge_files(struct got_worktree *worktree, struct got_fileindex *fileindex,
    const char *fileindex_path, struct got_object_id *commit_id1,
    struct got_object_id *commit_id2, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *sync_err;
	struct got_object_id *tree_id1 = NULL, *tree_id2 = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_commit_object *commit1 = NULL, *commit2 = NULL;
	struct check_merge_conflicts_arg cmc_arg;
	struct merge_file_cb_arg arg;
	char *label_orig = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	int fd1 = -1, fd2 = -1;

	if (commit_id1) {
		err = got_object_open_as_commit(&commit1, repo, commit_id1);
		if (err)
			goto done;
		err = got_object_id_by_path(&tree_id1, repo, commit1,
		    worktree->path_prefix);
		if (err && err->code != GOT_ERR_NO_TREE_ENTRY)
			goto done;
	}
	if (tree_id1) {
		char *id_str;

		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;

		err = got_object_id_str(&id_str, commit_id1);
		if (err)
			goto done;

		if (asprintf(&label_orig, "%s: commit %s",
		    GOT_MERGE_LABEL_BASE, id_str) == -1) {
			err = got_error_from_errno("asprintf");
			free(id_str);
			goto done;
		}
		free(id_str);

		f1 = got_opentemp();
		if (f1 == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
	}

	err = got_object_open_as_commit(&commit2, repo, commit_id2);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id2, repo, commit2,
	    worktree->path_prefix);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	f2 = got_opentemp();
	if (f2 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
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

	cmc_arg.worktree = worktree;
	cmc_arg.fileindex = fileindex;
	cmc_arg.repo = repo;
	err = got_diff_tree(tree1, tree2, f1, f2, fd1, fd2, "", "", repo,
	    check_merge_conflicts, &cmc_arg, 0);
	if (err)
		goto done;

	arg.worktree = worktree;
	arg.fileindex = fileindex;
	arg.progress_cb = progress_cb;
	arg.progress_arg = progress_arg;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	arg.label_orig = label_orig;
	arg.commit_id2 = commit_id2;
	arg.allow_bad_symlinks = 1; /* preserve bad symlinks across merges */
	err = got_diff_tree(tree1, tree2, f1, f2, fd1, fd2, "", "", repo,
	    merge_file_cb, &arg, 1);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	if (commit1)
		got_object_commit_close(commit1);
	if (commit2)
		got_object_commit_close(commit2);
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(label_orig);
	return err;
}

const struct got_error *
got_worktree_merge_files(struct got_worktree *worktree,
    struct got_object_id *commit_id1, struct got_object_id *commit_id2,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err, *unlockerr;
	char *fileindex_path = NULL;
	struct got_fileindex *fileindex = NULL;
	struct check_mixed_commits_args cma;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	cma.worktree = worktree;
	cma.cancel_cb = cancel_cb;
	cma.cancel_arg = cancel_arg;

	err = got_fileindex_for_each_entry_safe(fileindex, check_mixed_commits,
	    &cma);
	if (err)
		goto done;

	err = merge_files(worktree, fileindex, fileindex_path, commit_id1,
	    commit_id2, repo, progress_cb, progress_arg,
	    cancel_cb, cancel_arg);
done:
	if (fileindex)
		got_fileindex_free(fileindex);
	free(fileindex_path);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
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
	const struct got_error *err;
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
	got_pathlist_free(ignores, GOT_PATHLIST_FREE_ALL);
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

		/* Skip blank lines. */
		if (line[0] == '\0')
			continue;

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
		free(ignorelist);
	}
	return err;
}

static int
match_path(const char *pattern, size_t pattern_len, const char *path,
    int flags)
{
	char buf[PATH_MAX];
	const char *pat = pattern;
	size_t len = pattern_len;

	/*
	 * For gitignore(5) compatibility, ignore leading slashes.
	 */
	while (len > 0 && pat[0] == '/') {
		pat++;
		len--;
	}

	/*
	 * Trailing slashes signify directories.
	 * Append a * to make such patterns conform to fnmatch rules.
	 */
	if (pat > 0 && pat[len - 1] == '/') {
		if (snprintf(buf, sizeof(buf), "%s*", pat) >= sizeof(buf))
			return FNM_NOMATCH; /* XXX */

		return fnmatch(buf, path, flags);
	}

	return fnmatch(pat, path, flags);
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
		pe = RB_PREV(got_pathlist_head, ignores, pe);
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
	got_pathlist_free(&missing_children, GOT_PATHLIST_FREE_NONE);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(ondisk_path);
	return err;
}

const struct got_error *
got_worktree_status(struct got_worktree *worktree,
    struct got_pathlist_head *paths, struct got_repository *repo,
    int no_ignores, got_worktree_status_cb status_cb, void *status_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	char *fileindex_path = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_pathlist_entry *pe;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		return err;

	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    status_cb, status_arg, cancel_cb, cancel_arg,
		    no_ignores, 0);
		if (err)
			break;
	}
	free(fileindex_path);
	got_fileindex_free(fileindex);
	return err;
}

const struct got_error *
got_worktree_resolve_path(char **wt_path, struct got_worktree *worktree,
    const char *arg)
{
	const struct got_error *err = NULL;
	char *resolved = NULL, *cwd = NULL, *path = NULL;
	size_t len;
	struct stat sb;
	char *abspath = NULL;
	char canonpath[PATH_MAX];

	*wt_path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno("getcwd");

	if (lstat(arg, &sb) == -1) {
		if (errno != ENOENT) {
			err = got_error_from_errno2("lstat", arg);
			goto done;
		}
		sb.st_mode = 0;
	}
	if (S_ISLNK(sb.st_mode)) {
		/*
		 * We cannot use realpath(3) with symlinks since we want to
		 * operate on the symlink itself.
		 * But we can make the path absolute, assuming it is relative
		 * to the current working directory, and then canonicalize it.
		 */
		if (!got_path_is_absolute(arg)) {
			if (asprintf(&abspath, "%s/%s", cwd, arg) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}

		}
		err = got_canonpath(abspath ? abspath : arg, canonpath,
		    sizeof(canonpath));
		if (err)
			goto done;
		resolved = strdup(canonpath);
		if (resolved == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		resolved = realpath(arg, NULL);
		if (resolved == NULL) {
			if (errno != ENOENT) {
				err = got_error_from_errno2("realpath", arg);
				goto done;
			}
			if (asprintf(&abspath, "%s/%s", cwd, arg) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = got_canonpath(abspath, canonpath,
			    sizeof(canonpath));
			if (err)
				goto done;
			resolved = strdup(canonpath);
			if (resolved == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	if (strncmp(got_worktree_get_root_path(worktree), resolved,
	    strlen(got_worktree_get_root_path(worktree)))) {
		err = got_error_path(resolved, GOT_ERR_BAD_PATH);
		goto done;
	}

	if (strlen(resolved) > strlen(got_worktree_get_root_path(worktree))) {
		err = got_path_skip_common_ancestor(&path,
		    got_worktree_get_root_path(worktree), resolved);
		if (err)
			goto done;
	} else {
		path = strdup("");
		if (path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	/* XXX status walk can't deal with trailing slash! */
	len = strlen(path);
	while (len > 0 && path[len - 1] == '/') {
		path[len - 1] = '\0';
		len--;
	}
done:
	free(abspath);
	free(resolved);
	free(cwd);
	if (err == NULL)
		*wt_path = path;
	else
		free(path);
	return err;
}

struct schedule_addition_args {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	got_worktree_checkout_cb progress_cb;
	void *progress_arg;
	struct got_repository *repo;
};

static int
add_noop_status(unsigned char status)
{
	return (status == GOT_STATUS_ADD ||
	    status == GOT_STATUS_MODIFY ||
	    status == GOT_STATUS_CONFLICT ||
	    status == GOT_STATUS_MODE_CHANGE ||
	    status == GOT_STATUS_NO_CHANGE);
}

static const struct got_error *
schedule_addition(void *arg, unsigned char status, unsigned char staged_status,
    const char *relpath, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	struct schedule_addition_args *a = arg;
	const struct got_error *err = NULL;
	struct got_fileindex_entry *ie;
	struct stat sb;
	char *ondisk_path;

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
	    relpath) == -1)
		return got_error_from_errno("asprintf");

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie) {
		err = get_file_status(&status, &sb, ie, ondisk_path, dirfd,
		    de_name, a->repo);
		if (err)
			goto done;
		/* Re-adding an existing entry is a no-op. */
		if (staged_status == GOT_STATUS_NO_CHANGE &&
		    add_noop_status(status))
			goto done;
		err = got_error_path(relpath, GOT_ERR_FILE_STATUS);
		if (err)
			goto done;
	}

	if (status != GOT_STATUS_UNVERSIONED) {
		if (status == GOT_STATUS_NONEXISTENT)
			err = got_error_set_errno(ENOENT, ondisk_path);
		else
			err = got_error_path(ondisk_path, GOT_ERR_FILE_STATUS);
		goto done;
	}

	err = got_fileindex_entry_alloc(&ie, relpath);
	if (err)
		goto done;
	err = got_fileindex_entry_update(ie, a->worktree->root_fd,
	    relpath, NULL, NULL, 1);
	if (err) {
		got_fileindex_entry_free(ie);
		goto done;
	}
	err = got_fileindex_entry_add(a->fileindex, ie);
	if (err) {
		got_fileindex_entry_free(ie);
		goto done;
	}
done:
	free(ondisk_path);
	if (err)
		return err;
	if (staged_status == GOT_STATUS_NO_CHANGE && add_noop_status(status))
		return NULL;
	return (*a->progress_cb)(a->progress_arg, GOT_STATUS_ADD, relpath);
}

const struct got_error *
got_worktree_schedule_add(struct got_worktree *worktree,
    struct got_pathlist_head *paths,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    struct got_repository *repo, int no_ignores)
{
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	struct got_pathlist_entry *pe;
	struct schedule_addition_args saa;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	saa.worktree = worktree;
	saa.fileindex = fileindex;
	saa.progress_cb = progress_cb;
	saa.progress_arg = progress_arg;
	saa.repo = repo;

	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
			schedule_addition, &saa, NULL, NULL, no_ignores, 0);
		if (err)
			break;
	}
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

struct schedule_deletion_args {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	got_worktree_delete_cb progress_cb;
	void *progress_arg;
	struct got_repository *repo;
	int delete_local_mods;
	int keep_on_disk;
	int ignore_missing_paths;
	const char *status_path;
	size_t status_path_len;
	const char *status_codes;
};

static const struct got_error *
schedule_for_deletion(void *arg, unsigned char status,
    unsigned char staged_status, const char *relpath,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	struct schedule_deletion_args *a = arg;
	const struct got_error *err = NULL;
	struct got_fileindex_entry *ie = NULL;
	struct stat sb;
	char *ondisk_path;

	if (status == GOT_STATUS_NONEXISTENT) {
		if (a->ignore_missing_paths)
			return NULL;
		return got_error_set_errno(ENOENT, relpath);
	}

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie == NULL)
		return got_error_path(relpath, GOT_ERR_FILE_STATUS);

	staged_status = get_staged_status(ie);
	if (staged_status != GOT_STATUS_NO_CHANGE) {
		if (staged_status == GOT_STATUS_DELETE)
			return NULL;
		return got_error_path(relpath, GOT_ERR_FILE_STAGED);
	}

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
	    relpath) == -1)
		return got_error_from_errno("asprintf");

	err = get_file_status(&status, &sb, ie, ondisk_path, dirfd, de_name,
	    a->repo);
	if (err)
		goto done;

	if (a->status_codes) {
		size_t ncodes = strlen(a->status_codes);
		int i;
		for (i = 0; i < ncodes ; i++) {
			if (status == a->status_codes[i])
				break;
		}
		if (i == ncodes) {
			/* Do not delete files in non-matching status. */
			free(ondisk_path);
			return NULL;
		}
		if (a->status_codes[i] != GOT_STATUS_MODIFY &&
		    a->status_codes[i] != GOT_STATUS_MISSING) {
			static char msg[64];
			snprintf(msg, sizeof(msg),
			    "invalid status code '%c'", a->status_codes[i]);
			err = got_error_msg(GOT_ERR_FILE_STATUS, msg);
			goto done;
		}
	}

	if (status != GOT_STATUS_NO_CHANGE) {
		if (status == GOT_STATUS_DELETE)
			goto done;
		if (status == GOT_STATUS_MODIFY && !a->delete_local_mods) {
			err = got_error_path(relpath, GOT_ERR_FILE_MODIFIED);
			goto done;
		}
		if (status == GOT_STATUS_MISSING && !a->ignore_missing_paths) {
			err = got_error_set_errno(ENOENT, relpath);
			goto done;
		}
		if (status != GOT_STATUS_MODIFY &&
		    status != GOT_STATUS_MISSING) {
			err = got_error_path(relpath, GOT_ERR_FILE_STATUS);
			goto done;
		}
	}

	if (!a->keep_on_disk && status != GOT_STATUS_MISSING) {
		size_t root_len;

		if (dirfd != -1) {
			if (unlinkat(dirfd, de_name, 0) == -1) {
				err = got_error_from_errno2("unlinkat",
				    ondisk_path);
				goto done;
			}
		} else if (unlink(ondisk_path) == -1) {
			err = got_error_from_errno2("unlink", ondisk_path);
			goto done;
		}

		root_len = strlen(a->worktree->root_path);
		do {
			char *parent;

			err = got_path_dirname(&parent, ondisk_path);
			if (err)
				goto done;
			free(ondisk_path);
			ondisk_path = parent;
			if (got_path_cmp(ondisk_path, a->status_path,
			    strlen(ondisk_path), a->status_path_len) != 0 &&
			    !got_path_is_child(ondisk_path, a->status_path,
			    a->status_path_len))
				break;
			if (rmdir(ondisk_path) == -1) {
				if (errno != ENOTEMPTY)
					err = got_error_from_errno2("rmdir",
					    ondisk_path);
				break;
			}
		} while (got_path_cmp(ondisk_path, a->worktree->root_path,
		    strlen(ondisk_path), root_len) != 0);
	}

	if (got_fileindex_entry_has_blob(ie))
		got_fileindex_entry_mark_deleted_from_disk(ie);
	else
		got_fileindex_entry_remove(a->fileindex, ie);
done:
	free(ondisk_path);
	if (err)
		return err;
	if (status == GOT_STATUS_DELETE)
		return NULL;
	return (*a->progress_cb)(a->progress_arg, GOT_STATUS_DELETE,
	    staged_status, relpath);
}

const struct got_error *
got_worktree_schedule_delete(struct got_worktree *worktree,
    struct got_pathlist_head *paths, int delete_local_mods,
    const char *status_codes,
    got_worktree_delete_cb progress_cb, void *progress_arg,
    struct got_repository *repo, int keep_on_disk, int ignore_missing_paths)
{
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	struct got_pathlist_entry *pe;
	struct schedule_deletion_args sda;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	sda.worktree = worktree;
	sda.fileindex = fileindex;
	sda.progress_cb = progress_cb;
	sda.progress_arg = progress_arg;
	sda.repo = repo;
	sda.delete_local_mods = delete_local_mods;
	sda.keep_on_disk = keep_on_disk;
	sda.ignore_missing_paths = ignore_missing_paths;
	sda.status_codes = status_codes;

	RB_FOREACH(pe, got_pathlist_head, paths) {
		char *ondisk_status_path;

		if (asprintf(&ondisk_status_path, "%s%s%s",
		    got_worktree_get_root_path(worktree),
		    pe->path[0] == '\0' ? "" : "/", pe->path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		sda.status_path = ondisk_status_path;
		sda.status_path_len = strlen(ondisk_status_path);
		err = worktree_status(worktree, pe->path, fileindex, repo,
			schedule_for_deletion, &sda, NULL, NULL, 1, 1);
		free(ondisk_status_path);
		if (err)
			break;
	}
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

static const struct got_error *
copy_one_line(FILE *infile, FILE *outfile, FILE *rejectfile)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0, n;
	ssize_t linelen;

	linelen = getline(&line, &linesize, infile);
	if (linelen == -1) {
		if (ferror(infile)) {
			err = got_error_from_errno("getline");
			goto done;
		}
		return NULL;
	}
	if (outfile) {
		n = fwrite(line, 1, linelen, outfile);
		if (n != linelen) {
			err = got_ferror(outfile, GOT_ERR_IO);
			goto done;
		}
	}
	if (rejectfile) {
		n = fwrite(line, 1, linelen, rejectfile);
		if (n != linelen)
			err = got_ferror(rejectfile, GOT_ERR_IO);
	}
done:
	free(line);
	return err;
}

static const struct got_error *
skip_one_line(FILE *f)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	linelen = getline(&line, &linesize, f);
	if (linelen == -1) {
		if (ferror(f))
			return got_error_from_errno("getline");
		return NULL;
	}
	free(line);
	return NULL;
}

static const struct got_error *
copy_change(FILE *f1, FILE *f2, int *line_cur1, int *line_cur2,
    int start_old, int end_old, int start_new, int end_new,
    FILE *outfile, FILE *rejectfile)
{
	const struct got_error *err;

	/* Copy old file's lines leading up to patch. */
	while (!feof(f1) && *line_cur1 < start_old) {
		err = copy_one_line(f1, outfile, NULL);
		if (err)
			return err;
		(*line_cur1)++;
	}
	/* Skip new file's lines leading up to patch. */
	while (!feof(f2) && *line_cur2 < start_new) {
		if (rejectfile)
			err = copy_one_line(f2, NULL, rejectfile);
		else
			err = skip_one_line(f2);
		if (err)
			return err;
		(*line_cur2)++;
	}
	/* Copy patched lines. */
	while (!feof(f2) && *line_cur2 <= end_new) {
		err = copy_one_line(f2, outfile, NULL);
		if (err)
			return err;
		(*line_cur2)++;
	}
	/* Skip over old file's replaced lines. */
	while (!feof(f1) && *line_cur1 <= end_old) {
		if (rejectfile)
			err = copy_one_line(f1, NULL, rejectfile);
		else
			err = skip_one_line(f1);
		if (err)
			return err;
		(*line_cur1)++;
	}

	return NULL;
}

static const struct got_error *
copy_remaining_content(FILE *f1, FILE *f2, int *line_cur1, int *line_cur2,
    FILE *outfile, FILE *rejectfile)
{
	const struct got_error *err;

	if (outfile) {
		/* Copy old file's lines until EOF. */
		while (!feof(f1)) {
			err = copy_one_line(f1, outfile, NULL);
			if (err)
				return err;
			(*line_cur1)++;
		}
	}
	if (rejectfile) {
		/* Copy new file's lines until EOF. */
		while (!feof(f2)) {
			err = copy_one_line(f2, NULL, rejectfile);
			if (err)
				return err;
			(*line_cur2)++;
		}
	}

	return NULL;
}

static const struct got_error *
accept_or_reject_binary_change(int *choice, const char *path,
    got_worktree_patch_cb patch_cb, void *patch_arg)
{
	const struct got_error	*err;
	FILE			*f;

	*choice = GOT_PATCH_CHOICE_NONE;

	f = got_opentemp();
	if (f == NULL)
		return got_error_from_errno("got_opentemp");

	if (fprintf(f, "Binary files %s and %s differ\n", path, path) < 0) {
		err = got_error_msg(GOT_ERR_IO, "fprintf");
		goto done;
	}
	if (fseeko(f, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	err = (*patch_cb)(choice, patch_arg, GOT_STATUS_MODIFY, path, f, 1, 1);

done:
	if (f != NULL && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static int
diff_result_has_binary(struct diff_result *r)
{
	return (r->left->atomizer_flags | r->right->atomizer_flags) &
	    DIFF_ATOMIZER_FOUND_BINARY_DATA;
}

static const struct got_error *
apply_or_reject_change(int *choice, int *nchunks_used,
    struct diff_result *diff_result, int n,
    const char *relpath, FILE *f1, FILE *f2, int *line_cur1, int *line_cur2,
    FILE *outfile, FILE *rejectfile, int changeno, int nchanges,
    got_worktree_patch_cb patch_cb, void *patch_arg)
{
	const struct got_error *err = NULL;
	struct diff_chunk_context cc = {};
	int start_old, end_old, start_new, end_new;
	FILE *hunkfile;
	struct diff_output_unidiff_state *diff_state;
	struct diff_input_info diff_info;
	int rc;

	*choice = GOT_PATCH_CHOICE_NONE;

	/* Get changed line numbers without context lines for copy_change(). */
	diff_chunk_context_load_change(&cc, NULL, diff_result, n, 0);
	start_old = cc.left.start;
	end_old = cc.left.end;
	start_new = cc.right.start;
	end_new = cc.right.end;

	/* Get the same change with context lines for display. */
	memset(&cc, 0, sizeof(cc));
	diff_chunk_context_load_change(&cc, nchunks_used, diff_result, n, 3);

	memset(&diff_info, 0, sizeof(diff_info));
	diff_info.left_path = relpath;
	diff_info.right_path = relpath;

	diff_state = diff_output_unidiff_state_alloc();
	if (diff_state == NULL)
		return got_error_set_errno(ENOMEM,
		    "diff_output_unidiff_state_alloc");

	hunkfile = got_opentemp();
	if (hunkfile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	rc = diff_output_unidiff_chunk(NULL, hunkfile, diff_state, &diff_info,
	    diff_result, &cc);
	if (rc != DIFF_RC_OK) {
		err = got_error_set_errno(rc, "diff_output_unidiff_chunk");
		goto done;
	}

	if (fseek(hunkfile, 0L, SEEK_SET) == -1) {
		err = got_ferror(hunkfile, GOT_ERR_IO);
		goto done;
	}

	err = (*patch_cb)(choice, patch_arg, GOT_STATUS_MODIFY, relpath,
	    hunkfile, changeno, nchanges);
	if (err)
		goto done;

	switch (*choice) {
	case GOT_PATCH_CHOICE_YES:
		err = copy_change(f1, f2, line_cur1, line_cur2, start_old,
		    end_old, start_new, end_new, outfile, rejectfile);
		break;
	case GOT_PATCH_CHOICE_NO:
		err = copy_change(f1, f2, line_cur1, line_cur2, start_old,
		    end_old, start_new, end_new, rejectfile, outfile);
		break;
	case GOT_PATCH_CHOICE_QUIT:
		break;
	default:
		err = got_error(GOT_ERR_PATCH_CHOICE);
		break;
	}
done:
	diff_output_unidiff_state_free(diff_state);
	if (hunkfile && fclose(hunkfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

struct revert_file_args {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	got_worktree_checkout_cb progress_cb;
	void *progress_arg;
	got_worktree_patch_cb patch_cb;
	void *patch_arg;
	struct got_repository *repo;
	int unlink_added_files;
	struct got_pathlist_head *added_files_to_unlink;
};

static const struct got_error *
create_patched_content(char **path_outfile, int *confirm_binary_change,
    int reverse_patch, struct got_object_id *blob_id, const char *path2,
    int dirfd2, const char *de_name2,
    const char *relpath, struct got_repository *repo,
    got_worktree_patch_cb patch_cb, void *patch_arg)
{
	const struct got_error *err, *free_err;
	struct got_blob_object *blob = NULL;
	FILE *f1 = NULL, *f2 = NULL, *outfile = NULL;
	int fd = -1, fd2 = -1;
	char link_target[PATH_MAX];
	ssize_t link_len = 0;
	char *path1 = NULL, *id_str = NULL;
	struct stat sb2;
	struct got_diffreg_result *diffreg_result = NULL;
	int choice, line_cur1 = 1, line_cur2 = 1, have_content = 0;
	int i = 0, n = 0, nchunks_used = 0, nchanges = 0;

	*path_outfile = NULL;
	*confirm_binary_change = 0;

	err = got_object_id_str(&id_str, blob_id);
	if (err)
		return err;

	if (dirfd2 != -1) {
		fd2 = openat(dirfd2, de_name2,
		    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd2 == -1) {
			if (!got_err_open_nofollow_on_symlink()) {
				err = got_error_from_errno2("openat", path2);
				goto done;
			}
			link_len = readlinkat(dirfd2, de_name2,
			    link_target, sizeof(link_target));
			if (link_len == -1) {
				return got_error_from_errno2("readlinkat",
				    path2);
			}
			sb2.st_mode = S_IFLNK;
			sb2.st_size = link_len;
		}
	} else {
		fd2 = open(path2, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd2 == -1) {
			if (!got_err_open_nofollow_on_symlink()) {
				err = got_error_from_errno2("open", path2);
				goto done;
			}
			link_len = readlink(path2, link_target,
			    sizeof(link_target));
			if (link_len == -1)
				return got_error_from_errno2("readlink", path2);
			sb2.st_mode = S_IFLNK;
			sb2.st_size = link_len;
		}
	}
	if (fd2 != -1) {
		if (fstat(fd2, &sb2) == -1) {
			err = got_error_from_errno2("fstat", path2);
			goto done;
		}

		f2 = fdopen(fd2, "r");
		if (f2 == NULL) {
			err = got_error_from_errno2("fdopen", path2);
			goto done;
		}
		fd2 = -1;
	} else {
		size_t n;
		f2 = got_opentemp();
		if (f2 == NULL) {
			err = got_error_from_errno2("got_opentemp", path2);
			goto done;
		}
		n = fwrite(link_target, 1, link_len, f2);
		if (n != link_len) {
			err = got_ferror(f2, GOT_ERR_IO);
			goto done;
		}
		if (fflush(f2) == EOF) {
			err = got_error_from_errno("fflush");
			goto done;
		}
		rewind(f2);
	}

	fd = got_opentempfd();
	if (fd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	err = got_object_open_as_blob(&blob, repo, blob_id, 8192, fd);
	if (err)
		goto done;

	err = got_opentemp_named(&path1, &f1, "got-patched-blob", "");
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, f1, blob);
	if (err)
		goto done;

	err = got_diff_files(&diffreg_result, f1, 1, id_str, f2, 1, path2,
	    3, 0, 1, NULL, GOT_DIFF_ALGORITHM_MYERS);
	if (err)
		goto done;

	if (diff_result_has_binary(diffreg_result->result)) {
		err = accept_or_reject_binary_change(&choice, relpath,
		    patch_cb, patch_arg);
		if (err == NULL && choice == GOT_PATCH_CHOICE_YES)
			*confirm_binary_change = 1;
		goto done;
	}

	err = got_opentemp_named(path_outfile, &outfile, "got-patched-content",
	    "");
	if (err)
		goto done;

	if (fseek(f1, 0L, SEEK_SET) == -1)
		return got_ferror(f1, GOT_ERR_IO);
	if (fseek(f2, 0L, SEEK_SET) == -1)
		return got_ferror(f2, GOT_ERR_IO);

	/* Count the number of actual changes in the diff result. */
	for (n = 0; n < diffreg_result->result->chunks.len; n += nchunks_used) {
		struct diff_chunk_context cc = {};
		diff_chunk_context_load_change(&cc, &nchunks_used,
		    diffreg_result->result, n, 0);
		nchanges++;
	}
	for (n = 0; n < diffreg_result->result->chunks.len; n += nchunks_used) {
		err = apply_or_reject_change(&choice, &nchunks_used,
		    diffreg_result->result, n, relpath, f1, f2,
		    &line_cur1, &line_cur2,
		    reverse_patch ? NULL : outfile,
		    reverse_patch ? outfile : NULL,
		    ++i, nchanges, patch_cb, patch_arg);
		if (err)
			goto done;
		if (choice == GOT_PATCH_CHOICE_YES)
			have_content = 1;
		else if (choice == GOT_PATCH_CHOICE_QUIT)
			break;
	}
	if (have_content) {
		err = copy_remaining_content(f1, f2, &line_cur1, &line_cur2,
		    reverse_patch ? NULL : outfile,
		    reverse_patch ? outfile : NULL);
		if (err)
			goto done;

		if (!S_ISLNK(sb2.st_mode)) {
			mode_t mode;

			mode = apply_umask(sb2.st_mode);
			if (fchmod(fileno(outfile), mode) == -1) {
				err = got_error_from_errno2("fchmod", path2);
				goto done;
			}
		}
	}
done:
	free(id_str);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	free_err = got_diffreg_result_free(diffreg_result);
	if (err == NULL)
		err = free_err;
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path1);
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path2);
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno2("close", path2);
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", *path_outfile);
	if (path1 && unlink(path1) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path1);
	if (err || !have_content) {
		if (*path_outfile && unlink(*path_outfile) == -1 && err == NULL)
			err = got_error_from_errno2("unlink", *path_outfile);
		free(*path_outfile);
		*path_outfile = NULL;
	}
	free(path1);
	return err;
}

static const struct got_error *
revert_file(void *arg, unsigned char status, unsigned char staged_status,
    const char *relpath, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	struct revert_file_args *a = arg;
	const struct got_error *err = NULL;
	char *parent_path = NULL;
	struct got_fileindex_entry *ie;
	struct got_commit_object *base_commit = NULL;
	struct got_tree_object *tree = NULL;
	struct got_object_id *tree_id = NULL;
	const struct got_tree_entry *te = NULL;
	char *tree_path = NULL, *te_name;
	char *ondisk_path = NULL, *path_content = NULL;
	struct got_blob_object *blob = NULL;
	int fd = -1;

	/* Reverting a staged deletion is a no-op. */
	if (status == GOT_STATUS_DELETE &&
	    staged_status != GOT_STATUS_NO_CHANGE)
		return NULL;

	if (status == GOT_STATUS_UNVERSIONED)
		return (*a->progress_cb)(a->progress_arg,
		    GOT_STATUS_UNVERSIONED, relpath);

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie == NULL)
		return got_error_path(relpath, GOT_ERR_BAD_PATH);

	/* Construct in-repository path of tree which contains this blob. */
	err = got_path_dirname(&parent_path, ie->path);
	if (err) {
		if (err->code != GOT_ERR_BAD_PATH)
			goto done;
		parent_path = strdup("/");
		if (parent_path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
	if (got_path_is_root_dir(a->worktree->path_prefix)) {
		tree_path = strdup(parent_path);
		if (tree_path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		if (got_path_is_root_dir(parent_path)) {
			tree_path = strdup(a->worktree->path_prefix);
			if (tree_path == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			if (asprintf(&tree_path, "%s/%s",
			    a->worktree->path_prefix, parent_path) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		}
	}

	err = got_object_open_as_commit(&base_commit, a->repo,
	    a->worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id, a->repo, base_commit, tree_path);
	if (err) {
		if (!(err->code == GOT_ERR_NO_TREE_ENTRY &&
		    (status == GOT_STATUS_ADD ||
		    staged_status == GOT_STATUS_ADD)))
			goto done;
	} else {
		err = got_object_open_as_tree(&tree, a->repo, tree_id);
		if (err)
			goto done;

		err = got_path_basename(&te_name, ie->path);
		if (err)
			goto done;

		te = got_object_tree_find_entry(tree, te_name);
		free(te_name);
		if (te == NULL && status != GOT_STATUS_ADD &&
		    staged_status != GOT_STATUS_ADD) {
			err = got_error_path(ie->path, GOT_ERR_NO_TREE_ENTRY);
			goto done;
		}
	}

	switch (status) {
	case GOT_STATUS_ADD:
		if (a->patch_cb) {
			int choice = GOT_PATCH_CHOICE_NONE;
			err = (*a->patch_cb)(&choice, a->patch_arg,
			    status, ie->path, NULL, 1, 1);
			if (err)
				goto done;
			if (choice != GOT_PATCH_CHOICE_YES)
				break;
		}
		err = (*a->progress_cb)(a->progress_arg, GOT_STATUS_REVERT,
		    ie->path);
		if (err)
			goto done;
		got_fileindex_entry_remove(a->fileindex, ie);
		if (a->unlink_added_files) {
			int do_unlink = a->added_files_to_unlink ? 0 : 1;

			if (a->added_files_to_unlink) {
				struct got_pathlist_entry *pe;

				RB_FOREACH(pe, got_pathlist_head,
				    a->added_files_to_unlink) {
					if (got_path_cmp(pe->path, relpath,
					    pe->path_len, strlen(relpath)))
						continue;
					do_unlink = 1;
					break;
				}
			}

			if (do_unlink) {
				if (asprintf(&ondisk_path, "%s/%s",
				    got_worktree_get_root_path(a->worktree),
				    relpath) == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
				if (unlink(ondisk_path) == -1) {
					err = got_error_from_errno2("unlink",
					    ondisk_path);
					break;
				}
			}
		}
		break;
	case GOT_STATUS_DELETE:
		if (a->patch_cb) {
			int choice = GOT_PATCH_CHOICE_NONE;
			err = (*a->patch_cb)(&choice, a->patch_arg,
			    status, ie->path, NULL, 1, 1);
			if (err)
				goto done;
			if (choice != GOT_PATCH_CHOICE_YES)
				break;
		}
		/* fall through */
	case GOT_STATUS_MODIFY:
	case GOT_STATUS_MODE_CHANGE:
	case GOT_STATUS_CONFLICT:
	case GOT_STATUS_MISSING: {
		struct got_object_id id;
		if (staged_status == GOT_STATUS_ADD ||
		    staged_status == GOT_STATUS_MODIFY)
			got_fileindex_entry_get_staged_blob_id(&id, ie);
		else
			got_fileindex_entry_get_blob_id(&id, ie);
		fd = got_opentempfd();
		if (fd == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}

		err = got_object_open_as_blob(&blob, a->repo, &id, 8192, fd);
		if (err)
			goto done;

		if (asprintf(&ondisk_path, "%s/%s",
		    got_worktree_get_root_path(a->worktree), relpath) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}

		if (a->patch_cb && (status == GOT_STATUS_MODIFY ||
		    status == GOT_STATUS_CONFLICT)) {
			int is_bad_symlink = 0, revert_binary_file = 0;

			err = create_patched_content(&path_content,
			    &revert_binary_file, 1, &id, ondisk_path, dirfd,
			    de_name, ie->path, a->repo,
			    a->patch_cb, a->patch_arg);
			if (err != NULL)
				goto done;
			if (revert_binary_file){
				err = install_blob(a->worktree, ondisk_path,
				    ie->path,
				    te ? te->mode : GOT_DEFAULT_FILE_MODE,
				    got_fileindex_perms_to_st(ie), blob,
				    0, 1, 0, 0, 0, NULL, a->repo,
				    a->progress_cb, a->progress_arg);
				if (err != NULL)
					goto done;
			}
			if (path_content == NULL)
				break;
			if (te && S_ISLNK(te->mode)) {
				if (unlink(path_content) == -1) {
					err = got_error_from_errno2("unlink",
					    path_content);
					break;
				}
				err = install_symlink(&is_bad_symlink,
				    a->worktree, ondisk_path, ie->path,
				    blob, 0, 1, 0, 0, a->repo,
				    a->progress_cb, a->progress_arg);
			} else {
				if (rename(path_content, ondisk_path) == -1) {
					err = got_error_from_errno3("rename",
					    path_content, ondisk_path);
					goto done;
				}
			}
			if (staged_status == GOT_STATUS_ADD ||
			    staged_status == GOT_STATUS_MODIFY) {
				got_fileindex_entry_get_blob_id(&id, ie);
				err = got_fileindex_entry_update(ie,
				    a->worktree->root_fd, relpath, &id,
				    &ie->commit, 0);
				if (err)
					goto done;
			} else {
				err = got_fileindex_entry_update(ie,
				    a->worktree->root_fd, relpath, &blob->id,
				    &ie->commit, 0);
				if (err)
					goto done;
			}
		} else {
			int is_bad_symlink = 0;
			if (te && S_ISLNK(te->mode)) {
				err = install_symlink(&is_bad_symlink,
				    a->worktree, ondisk_path, ie->path,
				    blob, 0, 1, 0, 0, a->repo,
				    a->progress_cb, a->progress_arg);
			} else {
				err = install_blob(a->worktree, ondisk_path,
				    ie->path,
				    te ? te->mode : GOT_DEFAULT_FILE_MODE,
				    got_fileindex_perms_to_st(ie), blob,
				    0, 1, 0, 0, 0, NULL, a->repo,
				    a->progress_cb, a->progress_arg);
			}
			if (err)
				goto done;

			if (staged_status == GOT_STATUS_ADD ||
			    staged_status == GOT_STATUS_MODIFY) {
				got_fileindex_entry_get_blob_id(&id, ie);
				err = got_fileindex_entry_update(ie,
				    a->worktree->root_fd, relpath, &id,
				    &ie->commit, 0);
				if (err)
					goto done;
			} else {
				err = got_fileindex_entry_update(ie,
				    a->worktree->root_fd, relpath, &blob->id,
				    &ie->commit, 0);
				if (err)
					goto done;
			}
			if (is_bad_symlink) {
				got_fileindex_entry_filetype_set(ie,
				    GOT_FILEIDX_MODE_BAD_SYMLINK);
			}
		}
		break;
	}
	default:
		break;
	}
done:
	free(ondisk_path);
	free(path_content);
	free(parent_path);
	free(tree_path);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (tree)
		got_object_tree_close(tree);
	free(tree_id);
	if (base_commit)
		got_object_commit_close(base_commit);
	return err;
}

const struct got_error *
got_worktree_revert(struct got_worktree *worktree,
    struct got_pathlist_head *paths,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_patch_cb patch_cb, void *patch_arg,
    struct got_repository *repo)
{
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	const struct got_error *err = NULL, *unlockerr = NULL;
	const struct got_error *sync_err = NULL;
	struct got_pathlist_entry *pe;
	struct revert_file_args rfa;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	rfa.worktree = worktree;
	rfa.fileindex = fileindex;
	rfa.progress_cb = progress_cb;
	rfa.progress_arg = progress_arg;
	rfa.patch_cb = patch_cb;
	rfa.patch_arg = patch_arg;
	rfa.repo = repo;
	rfa.unlink_added_files = 0;
	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    revert_file, &rfa, NULL, NULL, 1, 0);
		if (err)
			break;
	}
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
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
		    target_len, ct->ondisk_path, a->worktree->root_path,
		    a->worktree->meta_dir);
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

	if (a->diff_outfile) {
		err = append_ct_diff(ct, &a->diff_header_shown,
		    a->diff_outfile, a->f1, a->f2, dirfd, de_name,
		    a->have_staged_files, a->repo, a->worktree);
		if (err)
			goto done;
	}

	err = got_pathlist_insert(&new, a->commitable_paths, ct->path, ct);
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
	const struct got_error *err = NULL, *unlockerr = NULL;
	struct got_pathlist_entry *pe;
	const char *head_ref_name = NULL;
	struct got_commit_object *head_commit = NULL;
	struct got_reference *head_ref2 = NULL;
	struct got_object_id *head_commit_id2 = NULL;
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
	if (author_time == 0)
		author_time = timestamp;
	err = got_object_commit_create(new_commit_id, new_tree_id, &parent_ids,
	    nparents, author, author_time, committer, timestamp, logmsg, repo);
	if (logmsg != NULL)
		free(logmsg);
	if (err)
		goto done;

	/* Check if a concurrent commit to our branch has occurred. */
	head_ref_name = got_worktree_get_head_ref_name(worktree);
	if (head_ref_name == NULL) {
		err = got_error_from_errno("got_worktree_get_head_ref_name");
		goto done;
	}
	/* Lock the reference here to prevent concurrent modification. */
	err = got_ref_open(&head_ref2, repo, head_ref_name, 1);
	if (err)
		goto done;
	err = got_ref_resolve(&head_commit_id2, repo, head_ref2);
	if (err)
		goto done;
	if (got_object_id_cmp(head_commit_id, head_commit_id2) != 0) {
		err = got_error(GOT_ERR_COMMIT_HEAD_CHANGED);
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
done:
	got_object_id_queue_free(&parent_ids);
	if (head_tree)
		got_object_tree_close(head_tree);
	if (head_commit)
		got_object_commit_close(head_commit);
	free(head_commit_id2);
	if (head_ref2) {
		unlockerr = got_ref_unlock(head_ref2);
		if (unlockerr && err == NULL)
			err = unlockerr;
		got_ref_close(head_ref2);
	}
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
		return got_error_path(path, GOT_ERR_COMMIT_NO_CHANGES);

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

const struct got_error *
got_worktree_commit(struct got_object_id **new_commit_id,
    struct got_worktree *worktree, struct got_pathlist_head *paths,
    const char *author, time_t author_time, const char *committer,
    int allow_bad_symlinks, int show_diff, int commit_conflicts,
    got_worktree_commit_msg_cb commit_msg_cb, void *commit_arg,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlockerr = NULL, *sync_err;
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	struct got_pathlist_head commitable_paths;
	struct collect_commitables_arg cc_arg;
	struct got_pathlist_entry *pe;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	char *diff_path = NULL;
	int have_staged_files = 0;

	*new_commit_id = NULL;

	memset(&cc_arg, 0, sizeof(cc_arg));
	RB_INIT(&commitable_paths);

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		goto done;

	err = got_ref_open(&head_ref, repo, worktree->head_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
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

	err = update_fileindex_after_commit(worktree, &commitable_paths,
	    *new_commit_id, fileindex, have_staged_files);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	if (fileindex)
		got_fileindex_free(fileindex);
	free(fileindex_path);
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
	free(diff_path);
	if (cc_arg.diff_outfile && fclose(cc_arg.diff_outfile) == EOF &&
	    err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

const char *
got_commitable_get_path(struct got_commitable *ct)
{
	return ct->path;
}

unsigned int
got_commitable_get_status(struct got_commitable *ct)
{
	return ct->status;
}

struct check_rebase_ok_arg {
	struct got_worktree *worktree;
	struct got_repository *repo;
};

static const struct got_error *
check_rebase_ok(void *arg, struct got_fileindex_entry *ie)
{
	const struct got_error *err = NULL;
	struct check_rebase_ok_arg *a = arg;
	unsigned char status;
	struct stat sb;
	char *ondisk_path;

	/* Reject rebase of a work tree with mixed base commits. */
	if (got_object_id_cmp(&ie->commit, a->worktree->base_commit_id))
		return got_error(GOT_ERR_MIXED_COMMITS);

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path, ie->path)
	    == -1)
		return got_error_from_errno("asprintf");

	/* Reject rebase of a work tree with modified or staged files. */
	err = get_file_status(&status, &sb, ie, ondisk_path, -1, NULL, a->repo);
	free(ondisk_path);
	if (err)
		return err;

	if (status != GOT_STATUS_NO_CHANGE)
		return got_error(GOT_ERR_MODIFIED);
	if (get_staged_status(ie) != GOT_STATUS_NO_CHANGE)
		return got_error_path(ie->path, GOT_ERR_FILE_STAGED);

	return NULL;
}

const struct got_error *
got_worktree_rebase_prepare(struct got_reference **new_base_branch_ref,
    struct got_reference **tmp_branch, struct got_fileindex **fileindex,
    struct got_worktree *worktree, struct got_reference *branch,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *tmp_branch_name = NULL, *new_base_branch_ref_name = NULL;
	char *branch_ref_name = NULL;
	char *fileindex_path = NULL;
	struct check_rebase_ok_arg ok_arg;
	struct got_reference *wt_branch = NULL, *branch_ref = NULL;
	struct got_object_id *wt_branch_tip = NULL;

	*new_base_branch_ref = NULL;
	*tmp_branch = NULL;
	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	ok_arg.worktree = worktree;
	ok_arg.repo = repo;
	err = got_fileindex_for_each_entry_safe(*fileindex, check_rebase_ok,
	    &ok_arg);
	if (err)
		goto done;

	err = get_rebase_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;

	err = get_newbase_symref_name(&new_base_branch_ref_name, worktree);
	if (err)
		goto done;

	err = get_rebase_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&wt_branch, repo, worktree->head_ref_name,
	    0);
	if (err)
		goto done;

	err = got_ref_resolve(&wt_branch_tip, repo, wt_branch);
	if (err)
		goto done;
	if (got_object_id_cmp(worktree->base_commit_id, wt_branch_tip) != 0) {
		err = got_error(GOT_ERR_REBASE_OUT_OF_DATE);
		goto done;
	}

	err = got_ref_alloc_symref(new_base_branch_ref,
	    new_base_branch_ref_name, wt_branch);
	if (err)
		goto done;
	err = got_ref_write(*new_base_branch_ref, repo);
	if (err)
		goto done;

	/* TODO Lock original branch's ref while rebasing? */

	err = got_ref_alloc_symref(&branch_ref, branch_ref_name, branch);
	if (err)
		goto done;

	err = got_ref_write(branch_ref, repo);
	if (err)
		goto done;

	err = got_ref_alloc(tmp_branch, tmp_branch_name,
	    worktree->base_commit_id);
	if (err)
		goto done;
	err = got_ref_write(*tmp_branch, repo);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, *tmp_branch);
	if (err)
		goto done;
done:
	free(fileindex_path);
	free(tmp_branch_name);
	free(new_base_branch_ref_name);
	free(branch_ref_name);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (wt_branch)
		got_ref_close(wt_branch);
	free(wt_branch_tip);
	if (err) {
		if (*new_base_branch_ref) {
			got_ref_close(*new_base_branch_ref);
			*new_base_branch_ref = NULL;
		}
		if (*tmp_branch) {
			got_ref_close(*tmp_branch);
			*tmp_branch = NULL;
		}
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *
got_worktree_rebase_continue(struct got_object_id **commit_id,
    struct got_reference **new_base_branch, struct got_reference **tmp_branch,
    struct got_reference **branch, struct got_fileindex **fileindex,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_ref_name = NULL, *new_base_branch_ref_name = NULL;
	char *tmp_branch_name = NULL, *branch_ref_name = NULL;
	struct got_reference *commit_ref = NULL, *branch_ref = NULL;
	char *fileindex_path = NULL;
	int have_staged_files = 0;

	*commit_id = NULL;
	*new_base_branch = NULL;
	*tmp_branch = NULL;
	*branch = NULL;
	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	err = got_fileindex_for_each_entry_safe(*fileindex, check_staged_file,
	    &have_staged_files);
	if (err && err->code != GOT_ERR_CANCELLED)
		goto done;
	if (have_staged_files) {
		err = got_error(GOT_ERR_STAGED_PATHS);
		goto done;
	}

	err = get_rebase_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;

	err = get_rebase_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = get_rebase_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;

	err = get_newbase_symref_name(&new_base_branch_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&branch_ref, repo, branch_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_open(branch, repo,
	    got_ref_get_symref_target(branch_ref), 0);
	if (err)
		goto done;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(commit_id, repo, commit_ref);
	if (err)
		goto done;

	err = got_ref_open(new_base_branch, repo,
	    new_base_branch_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_open(tmp_branch, repo, tmp_branch_name, 0);
	if (err)
		goto done;
done:
	free(commit_ref_name);
	free(branch_ref_name);
	free(fileindex_path);
	if (commit_ref)
		got_ref_close(commit_ref);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (err) {
		free(*commit_id);
		*commit_id = NULL;
		if (*tmp_branch) {
			got_ref_close(*tmp_branch);
			*tmp_branch = NULL;
		}
		if (*new_base_branch) {
			got_ref_close(*new_base_branch);
			*new_base_branch = NULL;
		}
		if (*branch) {
			got_ref_close(*branch);
			*branch = NULL;
		}
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *
got_worktree_rebase_in_progress(int *in_progress, struct got_worktree *worktree)
{
	const struct got_error *err;
	char *tmp_branch_name = NULL;

	err = get_rebase_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		return err;

	*in_progress = (strcmp(tmp_branch_name, worktree->head_ref_name) == 0);
	free(tmp_branch_name);
	return NULL;
}

const struct got_error *
got_worktree_rebase_info(char **new_base_branch_name, char **branch_name,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *new_base_branch_ref_name = NULL;
	char *branch_ref_name = NULL;
	struct got_reference *branch_ref = NULL, *branch = NULL;
	struct got_reference *new_base_branch = NULL;

	*new_base_branch_name = NULL;
	*branch_name = NULL;

	err = get_rebase_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = get_newbase_symref_name(&new_base_branch_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&branch_ref, repo, branch_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_open(&branch, repo,
	    got_ref_get_symref_target(branch_ref), 0);
	if (err)
		goto done;

	err = got_ref_open(&new_base_branch, repo,
	    new_base_branch_ref_name, 0);
	if (err)
		goto done;

	if (!got_ref_is_symbolic(new_base_branch)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "%s is not a symbolic reference",
		    got_ref_get_name(branch_ref));
		goto done;
	}

	*new_base_branch_name = strdup(got_ref_get_symref_target(
	    new_base_branch));
	if (*new_base_branch_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	*branch_name = strdup(got_ref_get_name(branch));
	if (*branch_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
done:
	free(branch_ref_name);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (new_base_branch)
		got_ref_close(new_base_branch);
	if (branch)
		got_ref_close(branch);
	return err;
}

static const struct got_error *
collect_rebase_commit_msg(struct got_pathlist_head *commitable_paths,
    const char *diff_path, char **logmsg, void *arg)
{
	*logmsg = arg;
	return NULL;
}

static const struct got_error *
rebase_status(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	return NULL;
}

struct collect_merged_paths_arg {
	got_worktree_checkout_cb progress_cb;
	void *progress_arg;
	struct got_pathlist_head *merged_paths;
};

static const struct got_error *
collect_merged_paths(void *arg, unsigned char status, const char *path)
{
	const struct got_error *err;
	struct collect_merged_paths_arg *a = arg;
	char *p;
	struct got_pathlist_entry *new;

	err = (*a->progress_cb)(a->progress_arg, status, path);
	if (err)
		return err;

	if (status != GOT_STATUS_MERGE &&
	    status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_DELETE &&
	    status != GOT_STATUS_CONFLICT)
		return NULL;

	p = strdup(path);
	if (p == NULL)
		return got_error_from_errno("strdup");

	err = got_pathlist_insert(&new, a->merged_paths, p, NULL);
	if (err || new == NULL)
		free(p);
	return err;
}

static const struct got_error *
store_commit_id(const char *commit_ref_name, struct got_object_id *commit_id,
    int is_rebase, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *commit_ref = NULL;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = got_ref_alloc(&commit_ref, commit_ref_name, commit_id);
		if (err)
			goto done;
		err = got_ref_write(commit_ref, repo);
		if (err)
			goto done;
	} else if (is_rebase) {
		struct got_object_id *stored_id;
		int cmp;

		err = got_ref_resolve(&stored_id, repo, commit_ref);
		if (err)
			goto done;
		cmp = got_object_id_cmp(commit_id, stored_id);
		free(stored_id);
		if (cmp != 0) {
			err = got_error(GOT_ERR_REBASE_COMMITID);
			goto done;
		}
	}
done:
	if (commit_ref)
		got_ref_close(commit_ref);
	return err;
}

static const struct got_error *
rebase_merge_files(struct got_pathlist_head *merged_paths,
    const char *commit_ref_name, struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_object_id *parent_commit_id,
    struct got_object_id *commit_id, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_reference *commit_ref = NULL;
	struct collect_merged_paths_arg cmp_arg;
	char *fileindex_path;

	/* Work tree is locked/unlocked during rebase preparation/teardown. */

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		return err;

	cmp_arg.progress_cb = progress_cb;
	cmp_arg.progress_arg = progress_arg;
	cmp_arg.merged_paths = merged_paths;
	err = merge_files(worktree, fileindex, fileindex_path,
	    parent_commit_id, commit_id, repo, collect_merged_paths,
	    &cmp_arg, cancel_cb, cancel_arg);
	if (commit_ref)
		got_ref_close(commit_ref);
	return err;
}

const struct got_error *
got_worktree_rebase_merge_files(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_object_id *parent_commit_id, struct got_object_id *commit_id,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	char *commit_ref_name;

	err = get_rebase_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		return err;

	err = store_commit_id(commit_ref_name, commit_id, 1, repo);
	if (err)
		goto done;

	err = rebase_merge_files(merged_paths, commit_ref_name, worktree,
	    fileindex, parent_commit_id, commit_id, repo, progress_cb,
	    progress_arg, cancel_cb, cancel_arg);
done:
	free(commit_ref_name);
	return err;
}

const struct got_error *
got_worktree_histedit_merge_files(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_object_id *parent_commit_id, struct got_object_id *commit_id,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	char *commit_ref_name;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		return err;

	err = store_commit_id(commit_ref_name, commit_id, 0, repo);
	if (err)
		goto done;

	err = rebase_merge_files(merged_paths, commit_ref_name, worktree,
	    fileindex, parent_commit_id, commit_id, repo, progress_cb,
	    progress_arg, cancel_cb, cancel_arg);
done:
	free(commit_ref_name);
	return err;
}

static const struct got_error *
rebase_commit(struct got_object_id **new_commit_id,
    struct got_pathlist_head *merged_paths, struct got_reference *commit_ref,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *tmp_branch, const char *committer,
    struct got_commit_object *orig_commit, const char *new_logmsg,
    int allow_conflict, struct got_repository *repo)
{
	const struct got_error *err, *sync_err;
	struct got_pathlist_head commitable_paths;
	struct collect_commitables_arg cc_arg;
	char *fileindex_path = NULL;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	char *logmsg = NULL;

	memset(&cc_arg, 0, sizeof(cc_arg));
	RB_INIT(&commitable_paths);
	*new_commit_id = NULL;

	/* Work tree is locked/unlocked during rebase preparation/teardown. */

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		return err;

	cc_arg.commitable_paths = &commitable_paths;
	cc_arg.worktree = worktree;
	cc_arg.repo = repo;
	cc_arg.have_staged_files = 0;
	cc_arg.commit_conflicts = allow_conflict;
	cc_arg.allow_bad_symlinks = 1; /* preserve bad symlinks across merges */
	/*
	 * If possible get the status of individual files directly to
	 * avoid crawling the entire work tree once per rebased commit.
	 *
	 * Ideally, merged_paths would contain a list of commitables
	 * we could use so we could skip worktree_status() entirely.
	 * However, we would then need carefully keep track of cumulative
	 * effects of operations such as file additions and deletions
	 * in 'got histedit -f' (folding multiple commits into one),
	 * and this extra complexity is not really worth it.
	 */
	if (merged_paths) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, merged_paths) {
			err = worktree_status(worktree, pe->path, fileindex,
			    repo, collect_commitables, &cc_arg, NULL, NULL, 1,
			    0);
			if (err)
				goto done;
		}
	} else {
		err = worktree_status(worktree, "", fileindex, repo,
		    collect_commitables, &cc_arg, NULL, NULL, 1, 0);
		if (err)
			goto done;
	}

	if (RB_EMPTY(&commitable_paths)) {
		/* No-op change; commit will be elided. */
		err = got_ref_delete(commit_ref, repo);
		if (err)
			goto done;
		err = got_error(GOT_ERR_COMMIT_NO_CHANGES);
		goto done;
	}

	err = got_ref_open(&head_ref, repo, worktree->head_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	if (new_logmsg) {
		logmsg = strdup(new_logmsg);
		if (logmsg == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		err = got_object_commit_get_logmsg(&logmsg, orig_commit);
		if (err)
			goto done;
	}

	/* NB: commit_worktree will call free(logmsg) */
	err = commit_worktree(new_commit_id, &commitable_paths, head_commit_id,
	    NULL, worktree, got_object_commit_get_author(orig_commit),
	    got_object_commit_get_author_time(orig_commit),
	    committer ? committer :
	    got_object_commit_get_committer(orig_commit), NULL,
	    collect_rebase_commit_msg, logmsg, rebase_status, NULL, repo);
	if (err)
		goto done;

	err = got_ref_change_ref(tmp_branch, *new_commit_id);
	if (err)
		goto done;

	err = got_ref_delete(commit_ref, repo);
	if (err)
		goto done;

	err = update_fileindex_after_commit(worktree, &commitable_paths,
	    *new_commit_id, fileindex, 0);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	free(head_commit_id);
	if (head_ref)
		got_ref_close(head_ref);
	if (err) {
		free(*new_commit_id);
		*new_commit_id = NULL;
	}
	return err;
}

const struct got_error *
got_worktree_rebase_commit(struct got_object_id **new_commit_id,
    struct got_pathlist_head *merged_paths, struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    const char *committer, struct got_commit_object *orig_commit,
    struct got_object_id *orig_commit_id, int allow_conflict,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_ref_name;
	struct got_reference *commit_ref = NULL;
	struct got_object_id *commit_id = NULL;

	err = get_rebase_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		return err;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;
	err = got_ref_resolve(&commit_id, repo, commit_ref);
	if (err)
		goto done;
	if (got_object_id_cmp(commit_id, orig_commit_id) != 0) {
		err = got_error(GOT_ERR_REBASE_COMMITID);
		goto done;
	}

	err = rebase_commit(new_commit_id, merged_paths, commit_ref,
	    worktree, fileindex, tmp_branch, committer, orig_commit,
	    NULL, allow_conflict, repo);
done:
	if (commit_ref)
		got_ref_close(commit_ref);
	free(commit_ref_name);
	free(commit_id);
	return err;
}

const struct got_error *
got_worktree_histedit_commit(struct got_object_id **new_commit_id,
    struct got_pathlist_head *merged_paths, struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    const char *committer, struct got_commit_object *orig_commit,
    struct got_object_id *orig_commit_id, const char *new_logmsg,
    int allow_conflict, struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_ref_name;
	struct got_reference *commit_ref = NULL;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		return err;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;

	err = rebase_commit(new_commit_id, merged_paths, commit_ref,
	    worktree, fileindex, tmp_branch, committer, orig_commit,
	    new_logmsg, allow_conflict, repo);
done:
	if (commit_ref)
		got_ref_close(commit_ref);
	free(commit_ref_name);
	return err;
}

const struct got_error *
got_worktree_rebase_postpone(struct got_worktree *worktree,
    struct got_fileindex *fileindex)
{
	if (fileindex)
		got_fileindex_free(fileindex);
	return lock_worktree(worktree, LOCK_SH);
}

static const struct got_error *
delete_ref(const char *name, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *ref;

	err = got_ref_open(&ref, repo, name, 0);
	if (err) {
		if (err->code == GOT_ERR_NOT_REF)
			return NULL;
		return err;
	}

	err = got_ref_delete(ref, repo);
	got_ref_close(ref);
	return err;
}

static const struct got_error *
delete_rebase_refs(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *tmp_branch_name = NULL, *new_base_branch_ref_name = NULL;
	char *branch_ref_name = NULL, *commit_ref_name = NULL;

	err = get_rebase_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;
	err = delete_ref(tmp_branch_name, repo);
	if (err)
		goto done;

	err = get_newbase_symref_name(&new_base_branch_ref_name, worktree);
	if (err)
		goto done;
	err = delete_ref(new_base_branch_ref_name, repo);
	if (err)
		goto done;

	err = get_rebase_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;
	err = delete_ref(branch_ref_name, repo);
	if (err)
		goto done;

	err = get_rebase_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;
	err = delete_ref(commit_ref_name, repo);
	if (err)
		goto done;

done:
	free(tmp_branch_name);
	free(new_base_branch_ref_name);
	free(branch_ref_name);
	free(commit_ref_name);
	return err;
}

static const struct got_error *
create_backup_ref(const char *backup_ref_prefix, struct got_reference *branch,
    struct got_object_id *new_commit_id, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *ref = NULL;
	struct got_object_id *old_commit_id = NULL;
	const char *branch_name = NULL;
	char *new_id_str = NULL;
	char *refname = NULL;

	branch_name = got_ref_get_name(branch);
	if (strncmp(branch_name, "refs/heads/", 11) != 0)
		return got_error(GOT_ERR_BAD_REF_NAME); /* should not happen */
	branch_name += 11;

	err = got_object_id_str(&new_id_str, new_commit_id);
	if (err)
		return err;

	if (asprintf(&refname, "%s/%s/%s", backup_ref_prefix, branch_name,
	    new_id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_ref_resolve(&old_commit_id, repo, branch);
	if (err)
		goto done;

	err = got_ref_alloc(&ref, refname, old_commit_id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	free(new_id_str);
	free(refname);
	free(old_commit_id);
	if (ref)
		got_ref_close(ref);
	return err;
}

const struct got_error *
got_worktree_rebase_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    struct got_reference *rebased_branch, struct got_repository *repo,
    int create_backup)
{
	const struct got_error *err, *unlockerr, *sync_err;
	struct got_object_id *new_head_commit_id = NULL;
	char *fileindex_path = NULL;

	err = got_ref_resolve(&new_head_commit_id, repo, tmp_branch);
	if (err)
		return err;

	if (create_backup) {
		err = create_backup_ref(GOT_WORKTREE_REBASE_BACKUP_REF_PREFIX,
		    rebased_branch, new_head_commit_id, repo);
		if (err)
			goto done;
	}

	err = got_ref_change_ref(rebased_branch, new_head_commit_id);
	if (err)
		goto done;

	err = got_ref_write(rebased_branch, repo);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, rebased_branch);
	if (err)
		goto done;

	err = delete_rebase_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;
	err = bump_base_commit_id_everywhere(worktree, fileindex, NULL, NULL);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	got_fileindex_free(fileindex);
	free(fileindex_path);
	free(new_head_commit_id);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

static const struct got_error *
get_paths_changed_between_commits(struct got_pathlist_head *paths,
    struct got_object_id *id1, struct got_object_id *id2,
    struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_commit_object	*commit1 = NULL, *commit2 = NULL;
	struct got_tree_object		*tree1 = NULL, *tree2 = NULL;

	if (id1) {
		err = got_object_open_as_commit(&commit1, repo, id1);
		if (err)
			goto done;

		err = got_object_open_as_tree(&tree1, repo,
		    got_object_commit_get_tree_id(commit1));
		if (err)
			goto done;
	}

	if (id2) {
		err = got_object_open_as_commit(&commit2, repo, id2);
		if (err)
			goto done;

		err = got_object_open_as_tree(&tree2, repo,
		    got_object_commit_get_tree_id(commit2));
		if (err)
			goto done;
	}

	err = got_diff_tree(tree1, tree2, NULL, NULL, -1, -1, "", "", repo,
	    got_diff_tree_collect_changed_paths, paths, 0);
	if (err)
		goto done;
done:
	if (commit1)
		got_object_commit_close(commit1);
	if (commit2)
		got_object_commit_close(commit2);
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	return err;
}

static const struct got_error *
get_paths_added_between_commits(struct got_pathlist_head *added_paths,
    struct got_object_id *id1, struct got_object_id *id2,
    const char *path_prefix, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_pathlist_head merged_paths;
	struct got_pathlist_entry *pe;
	char *abspath = NULL, *wt_path = NULL;

	RB_INIT(&merged_paths);

	err = get_paths_changed_between_commits(&merged_paths, id1, id2, repo);
	if (err)
		goto done;

	RB_FOREACH(pe, got_pathlist_head,  &merged_paths) {
		struct got_diff_changed_path *change = pe->data;

		if (change->status != GOT_STATUS_ADD)
			continue;

		if (got_path_is_root_dir(path_prefix)) {
			wt_path = strdup(pe->path);
			if (wt_path == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			if (asprintf(&abspath, "/%s", pe->path) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}

			err = got_path_skip_common_ancestor(&wt_path,
			    path_prefix, abspath);
			if (err)
				goto done;
			free(abspath);
			abspath = NULL;
		}

		err = got_pathlist_insert(NULL, added_paths, wt_path, NULL);
		if (err)
			goto done;
		wt_path = NULL;
	}

done:
	got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_ALL);
	free(abspath);
	free(wt_path);
	return err;
}

static const struct got_error *
get_paths_added_in_commit(struct got_pathlist_head *added_paths,
    struct got_object_id *id, const char *path_prefix,
    struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_commit_object	*commit = NULL;
	struct got_object_qid		*pid;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		goto done;

	pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));

	err = get_paths_added_between_commits(added_paths,
	    pid ? &pid->id : NULL, id, path_prefix, repo);
	if (err)
		goto done;
done:
	if (commit)
		got_object_commit_close(commit);
	return err;
}

const struct got_error *
got_worktree_rebase_abort(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo,
    struct got_reference *new_base_branch,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err, *unlockerr, *sync_err;
	struct got_reference *resolved = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_object_id *merged_commit_id = NULL;
	struct got_commit_object *commit = NULL;
	char *fileindex_path = NULL;
	char *commit_ref_name = NULL;
	struct got_reference *commit_ref = NULL;
	struct revert_file_args rfa;
	struct got_object_id *tree_id = NULL;
	struct got_pathlist_head added_paths;

	RB_INIT(&added_paths);

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = get_rebase_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(&merged_commit_id, repo, commit_ref);
	if (err)
		goto done;

	/*
	 * Determine which files in added status can be safely removed
	 * from disk while reverting changes in the work tree.
	 * We want to avoid deleting unrelated files which were added by
	 * the user for conflict resolution purposes.
	 */
	err = get_paths_added_in_commit(&added_paths, merged_commit_id,
	    got_worktree_get_path_prefix(worktree), repo);
	if (err)
		goto done;

	err = got_ref_open(&resolved, repo,
	    got_ref_get_symref_target(new_base_branch), 0);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, resolved);
	if (err)
		goto done;

	/*
	 * XXX commits to the base branch could have happened while
	 * we were busy rebasing; should we store the original commit ID
	 * when rebase begins and read it back here?
	 */
	err = got_ref_resolve(&commit_id, repo, resolved);
	if (err)
		goto done;

	err = got_worktree_set_base_commit_id(worktree, repo, commit_id);
	if (err)
		goto done;

	err = got_object_open_as_commit(&commit, repo,
	    worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id, repo, commit,
	    worktree->path_prefix);
	if (err)
		goto done;

	err = delete_rebase_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	rfa.worktree = worktree;
	rfa.fileindex = fileindex;
	rfa.progress_cb = progress_cb;
	rfa.progress_arg = progress_arg;
	rfa.patch_cb = NULL;
	rfa.patch_arg = NULL;
	rfa.repo = repo;
	rfa.unlink_added_files = 1;
	rfa.added_files_to_unlink = &added_paths;
	err = worktree_status(worktree, "", fileindex, repo,
	    revert_file, &rfa, NULL, NULL, 1, 0);
	if (err)
		goto sync;

	err = checkout_files(worktree, fileindex, "", tree_id, NULL,
	    repo, progress_cb, progress_arg, NULL, NULL);
sync:
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	got_pathlist_free(&added_paths, GOT_PATHLIST_FREE_PATH);
	got_ref_close(resolved);
	free(tree_id);
	free(commit_id);
	free(merged_commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (fileindex)
		got_fileindex_free(fileindex);
	free(fileindex_path);
	free(commit_ref_name);
	if (commit_ref)
		got_ref_close(commit_ref);

	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_histedit_prepare(struct got_reference **tmp_branch,
    struct got_reference **branch_ref, struct got_object_id **base_commit_id,
    struct got_fileindex **fileindex, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *tmp_branch_name = NULL;
	char *branch_ref_name = NULL;
	char *base_commit_ref_name = NULL;
	char *fileindex_path = NULL;
	struct check_rebase_ok_arg ok_arg;
	struct got_reference *wt_branch = NULL;
	struct got_reference *base_commit_ref = NULL;

	*tmp_branch = NULL;
	*branch_ref = NULL;
	*base_commit_id = NULL;
	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	ok_arg.worktree = worktree;
	ok_arg.repo = repo;
	err = got_fileindex_for_each_entry_safe(*fileindex, check_rebase_ok,
	    &ok_arg);
	if (err)
		goto done;

	err = get_histedit_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;

	err = get_histedit_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = get_histedit_base_commit_ref_name(&base_commit_ref_name,
	    worktree);
	if (err)
		goto done;

	err = got_ref_open(&wt_branch, repo, worktree->head_ref_name,
	    0);
	if (err)
		goto done;

	err = got_ref_alloc_symref(branch_ref, branch_ref_name, wt_branch);
	if (err)
		goto done;

	err = got_ref_write(*branch_ref, repo);
	if (err)
		goto done;

	err = got_ref_alloc(&base_commit_ref, base_commit_ref_name,
	    worktree->base_commit_id);
	if (err)
		goto done;
	err = got_ref_write(base_commit_ref, repo);
	if (err)
		goto done;
	*base_commit_id = got_object_id_dup(worktree->base_commit_id);
	if (*base_commit_id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}

	err = got_ref_alloc(tmp_branch, tmp_branch_name,
	    worktree->base_commit_id);
	if (err)
		goto done;
	err = got_ref_write(*tmp_branch, repo);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, *tmp_branch);
	if (err)
		goto done;
done:
	free(fileindex_path);
	free(tmp_branch_name);
	free(branch_ref_name);
	free(base_commit_ref_name);
	if (wt_branch)
		got_ref_close(wt_branch);
	if (err) {
		if (*branch_ref) {
			got_ref_close(*branch_ref);
			*branch_ref = NULL;
		}
		if (*tmp_branch) {
			got_ref_close(*tmp_branch);
			*tmp_branch = NULL;
		}
		free(*base_commit_id);
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *
got_worktree_histedit_postpone(struct got_worktree *worktree,
    struct got_fileindex *fileindex)
{
	if (fileindex)
		got_fileindex_free(fileindex);
	return lock_worktree(worktree, LOCK_SH);
}

const struct got_error *
got_worktree_histedit_in_progress(int *in_progress,
    struct got_worktree *worktree)
{
	const struct got_error *err;
	char *tmp_branch_name = NULL;

	err = get_histedit_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		return err;

	*in_progress = (strcmp(tmp_branch_name, worktree->head_ref_name) == 0);
	free(tmp_branch_name);
	return NULL;
}

const struct got_error *
got_worktree_histedit_continue(struct got_object_id **commit_id,
    struct got_reference **tmp_branch, struct got_reference **branch_ref,
    struct got_object_id **base_commit_id, struct got_fileindex **fileindex,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_ref_name = NULL, *base_commit_ref_name = NULL;
	char *tmp_branch_name = NULL, *branch_ref_name = NULL;
	struct got_reference *commit_ref = NULL;
	struct got_reference *base_commit_ref = NULL;
	char *fileindex_path = NULL;
	int have_staged_files = 0;

	*commit_id = NULL;
	*tmp_branch = NULL;
	*branch_ref = NULL;
	*base_commit_id = NULL;
	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	err = got_fileindex_for_each_entry_safe(*fileindex, check_staged_file,
	    &have_staged_files);
	if (err && err->code != GOT_ERR_CANCELLED)
		goto done;
	if (have_staged_files) {
		err = got_error(GOT_ERR_STAGED_PATHS);
		goto done;
	}

	err = get_histedit_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;

	err = get_histedit_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;

	err = get_histedit_base_commit_ref_name(&base_commit_ref_name,
	    worktree);
	if (err)
		goto done;

	err = got_ref_open(branch_ref, repo, branch_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;
	err = got_ref_resolve(commit_id, repo, commit_ref);
	if (err)
		goto done;

	err = got_ref_open(&base_commit_ref, repo, base_commit_ref_name, 0);
	if (err)
		goto done;
	err = got_ref_resolve(base_commit_id, repo, base_commit_ref);
	if (err)
		goto done;

	err = got_ref_open(tmp_branch, repo, tmp_branch_name, 0);
	if (err)
		goto done;
done:
	free(commit_ref_name);
	free(branch_ref_name);
	free(fileindex_path);
	if (commit_ref)
		got_ref_close(commit_ref);
	if (base_commit_ref)
		got_ref_close(base_commit_ref);
	if (err) {
		free(*commit_id);
		*commit_id = NULL;
		free(*base_commit_id);
		*base_commit_id = NULL;
		if (*tmp_branch) {
			got_ref_close(*tmp_branch);
			*tmp_branch = NULL;
		}
		if (*branch_ref) {
			got_ref_close(*branch_ref);
			*branch_ref = NULL;
		}
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_EX);
	}
	return err;
}

const struct got_error *
got_worktree_histedit_info(char **branch_name,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *branch_ref = NULL;
	char *branch_ref_name = NULL;

	*branch_name = NULL;

	err = get_histedit_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&branch_ref, repo, branch_ref_name, 0);
	if (err)
		goto done;

	if (!got_ref_is_symbolic(branch_ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "%s is not a symbolic reference",
		    got_ref_get_name(branch_ref));
		goto done;
	}

	*branch_name = strdup(got_ref_get_symref_target(branch_ref));
	if (*branch_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
done:
	free(branch_ref_name);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (err) {
		free(*branch_name);
		*branch_name = NULL;
	}
	return err;
}

static const struct got_error *
delete_histedit_refs(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *tmp_branch_name = NULL, *base_commit_ref_name = NULL;
	char *branch_ref_name = NULL, *commit_ref_name = NULL;

	err = get_histedit_tmp_ref_name(&tmp_branch_name, worktree);
	if (err)
		goto done;
	err = delete_ref(tmp_branch_name, repo);
	if (err)
		goto done;

	err = get_histedit_base_commit_ref_name(&base_commit_ref_name,
	    worktree);
	if (err)
		goto done;
	err = delete_ref(base_commit_ref_name, repo);
	if (err)
		goto done;

	err = get_histedit_branch_symref_name(&branch_ref_name, worktree);
	if (err)
		goto done;
	err = delete_ref(branch_ref_name, repo);
	if (err)
		goto done;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;
	err = delete_ref(commit_ref_name, repo);
	if (err)
		goto done;
done:
	free(tmp_branch_name);
	free(base_commit_ref_name);
	free(branch_ref_name);
	free(commit_ref_name);
	return err;
}

const struct got_error *
got_worktree_histedit_abort(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo,
    struct got_reference *branch, struct got_object_id *base_commit_id,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    int restore_working_files)
{
	const struct got_error *err, *unlockerr, *sync_err;
	struct got_reference *resolved = NULL;
	char *fileindex_path = NULL;
	struct got_object_id *merged_commit_id = NULL;
	struct got_commit_object *commit = NULL;
	char *commit_ref_name = NULL;
	struct got_reference *commit_ref = NULL;
	struct got_object_id *tree_id = NULL;
	struct revert_file_args rfa;
	struct got_pathlist_head added_paths;

	RB_INIT(&added_paths);

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		/* Can happen on early abort due to invalid histedit script. */
		commit_ref = NULL;
	}

	if (commit_ref) {
		err = got_ref_resolve(&merged_commit_id, repo, commit_ref);
		if (err)
			goto done;

		/*
		 * Determine which files in added status can be safely removed
		 * from disk while reverting changes in the work tree.
		 * We want to avoid deleting unrelated files added by the
		 * user during conflict resolution or during histedit -e.
		 */
		err = get_paths_added_in_commit(&added_paths, merged_commit_id,
		    got_worktree_get_path_prefix(worktree), repo);
		if (err)
			goto done;
	}

	err = got_ref_open(&resolved, repo,
	    got_ref_get_symref_target(branch), 0);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, resolved);
	if (err)
		goto done;

	err = got_worktree_set_base_commit_id(worktree, repo, base_commit_id);
	if (err)
		goto done;

	err = delete_histedit_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	if (restore_working_files) {
		err = got_object_open_as_commit(&commit, repo,
		    worktree->base_commit_id);
		if (err)
			goto done;

		err = got_object_id_by_path(&tree_id, repo, commit,
		    worktree->path_prefix);
		if (err)
			goto done;

		rfa.worktree = worktree;
		rfa.fileindex = fileindex;
		rfa.progress_cb = progress_cb;
		rfa.progress_arg = progress_arg;
		rfa.patch_cb = NULL;
		rfa.patch_arg = NULL;
		rfa.repo = repo;
		rfa.unlink_added_files = 1;
		rfa.added_files_to_unlink = &added_paths;
		err = worktree_status(worktree, "", fileindex, repo,
		    revert_file, &rfa, NULL, NULL, 1, 0);
		if (err)
			goto sync;

		err = checkout_files(worktree, fileindex, "", tree_id, NULL,
		    repo, progress_cb, progress_arg, NULL, NULL);
	}
sync:
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	if (resolved)
		got_ref_close(resolved);
	if (commit_ref)
		got_ref_close(commit_ref);
	free(merged_commit_id);
	free(tree_id);
	free(fileindex_path);
	free(commit_ref_name);

	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_histedit_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    struct got_reference *edited_branch, struct got_repository *repo)
{
	const struct got_error *err, *unlockerr, *sync_err;
	struct got_object_id *new_head_commit_id = NULL;
	struct got_reference *resolved = NULL;
	char *fileindex_path = NULL;

	err = got_ref_resolve(&new_head_commit_id, repo, tmp_branch);
	if (err)
		return err;

	err = got_ref_open(&resolved, repo,
	    got_ref_get_symref_target(edited_branch), 0);
	if (err)
		goto done;

	err = create_backup_ref(GOT_WORKTREE_HISTEDIT_BACKUP_REF_PREFIX,
	    resolved, new_head_commit_id, repo);
	if (err)
		goto done;

	err = got_ref_change_ref(resolved, new_head_commit_id);
	if (err)
		goto done;

	err = got_ref_write(resolved, repo);
	if (err)
		goto done;

	err = got_worktree_set_head_ref(worktree, resolved);
	if (err)
		goto done;

	err = delete_histedit_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;
	err = bump_base_commit_id_everywhere(worktree, fileindex, NULL, NULL);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	got_fileindex_free(fileindex);
	free(fileindex_path);
	free(new_head_commit_id);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_histedit_skip_commit(struct got_worktree *worktree,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_ref_name;

	err = get_histedit_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		return err;

	err = store_commit_id(commit_ref_name, commit_id, 0, repo);
	if (err)
		goto done;

	err = delete_ref(commit_ref_name, repo);
done:
	free(commit_ref_name);
	return err;
}

const struct got_error *
got_worktree_integrate_prepare(struct got_fileindex **fileindex,
    struct got_reference **branch_ref, struct got_reference **base_branch_ref,
    struct got_worktree *worktree, const char *refname,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *fileindex_path = NULL;
	struct check_rebase_ok_arg ok_arg;

	*fileindex = NULL;
	*branch_ref = NULL;
	*base_branch_ref = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	if (strcmp(refname, got_worktree_get_head_ref_name(worktree)) == 0) {
		err = got_error_msg(GOT_ERR_SAME_BRANCH,
		    "cannot integrate a branch into itself; "
		    "update -b or different branch name required");
		goto done;
	}

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	/* Preconditions are the same as for rebase. */
	ok_arg.worktree = worktree;
	ok_arg.repo = repo;
	err = got_fileindex_for_each_entry_safe(*fileindex, check_rebase_ok,
	    &ok_arg);
	if (err)
		goto done;

	err = got_ref_open(branch_ref, repo, refname, 1);
	if (err)
		goto done;

	err = got_ref_open(base_branch_ref, repo,
	    got_worktree_get_head_ref_name(worktree), 1);
done:
	if (err) {
		if (*branch_ref) {
			got_ref_close(*branch_ref);
			*branch_ref = NULL;
		}
		if (*base_branch_ref) {
			got_ref_close(*base_branch_ref);
			*base_branch_ref = NULL;
		}
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *
got_worktree_integrate_continue(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo,
    struct got_reference *branch_ref, struct got_reference *base_branch_ref,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	char *fileindex_path = NULL;
	struct got_object_id *tree_id = NULL, *commit_id = NULL;
	struct got_commit_object *commit =  NULL;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	err = got_ref_resolve(&commit_id, repo, branch_ref);
	if (err)
		goto done;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id, repo, commit,
	    worktree->path_prefix);
	if (err)
		goto done;

	err = got_worktree_set_base_commit_id(worktree, repo, commit_id);
	if (err)
		goto done;

	err = checkout_files(worktree, fileindex, "", tree_id, NULL, repo,
	    progress_cb, progress_arg, cancel_cb, cancel_arg);
	if (err)
		goto sync;

	err = got_ref_change_ref(base_branch_ref, commit_id);
	if (err)
		goto sync;

	err = got_ref_write(base_branch_ref, repo);
	if (err)
		goto sync;

	err = bump_base_commit_id_everywhere(worktree, fileindex, NULL, NULL);
sync:
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;

done:
	unlockerr = got_ref_unlock(branch_ref);
	if (unlockerr && err == NULL)
		err = unlockerr;
	got_ref_close(branch_ref);

	unlockerr = got_ref_unlock(base_branch_ref);
	if (unlockerr && err == NULL)
		err = unlockerr;
	got_ref_close(base_branch_ref);

	got_fileindex_free(fileindex);
	free(fileindex_path);
	free(tree_id);
	if (commit)
		got_object_commit_close(commit);

	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_integrate_abort(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo,
    struct got_reference *branch_ref, struct got_reference *base_branch_ref)
{
	const struct got_error *err = NULL, *unlockerr = NULL;

	got_fileindex_free(fileindex);

	err = lock_worktree(worktree, LOCK_SH);

	unlockerr = got_ref_unlock(branch_ref);
	if (unlockerr && err == NULL)
		err = unlockerr;
	got_ref_close(branch_ref);

	unlockerr = got_ref_unlock(base_branch_ref);
	if (unlockerr && err == NULL)
		err = unlockerr;
	got_ref_close(base_branch_ref);

	return err;
}

const struct got_error *
got_worktree_merge_postpone(struct got_worktree *worktree,
    struct got_fileindex *fileindex)
{
	const struct got_error *err, *sync_err;
	char *fileindex_path = NULL;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	sync_err = sync_fileindex(fileindex, fileindex_path);

	err = lock_worktree(worktree, LOCK_SH);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	got_fileindex_free(fileindex);
	free(fileindex_path);
	return err;
}

static const struct got_error *
delete_merge_refs(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *branch_refname = NULL, *commit_refname = NULL;

	err = get_merge_branch_ref_name(&branch_refname, worktree);
	if (err)
		goto done;
	err = delete_ref(branch_refname, repo);
	if (err)
		goto done;

	err = get_merge_commit_ref_name(&commit_refname, worktree);
	if (err)
		goto done;
	err = delete_ref(commit_refname, repo);
	if (err)
		goto done;

done:
	free(branch_refname);
	free(commit_refname);
	return err;
}

struct merge_commit_msg_arg {
	struct got_worktree *worktree;
	const char *branch_name;
};

static const struct got_error *
merge_commit_msg_cb(struct got_pathlist_head *commitable_paths,
    const char *diff_path, char **logmsg, void *arg)
{
	struct merge_commit_msg_arg *a = arg;

	if (asprintf(logmsg, "merge %s into %s\n", a->branch_name,
	    got_worktree_get_head_ref_name(a->worktree)) == -1)
		return got_error_from_errno("asprintf");

	return NULL;
}


const struct got_error *
got_worktree_merge_branch(struct got_worktree *worktree,
    struct got_fileindex *fileindex,
    struct got_object_id *yca_commit_id,
    struct got_object_id *branch_tip,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	char *fileindex_path = NULL;
	struct check_mixed_commits_args cma;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	cma.worktree = worktree;
	cma.cancel_cb = cancel_cb;
	cma.cancel_arg = cancel_arg;

	err = got_fileindex_for_each_entry_safe(fileindex, check_mixed_commits,
	    &cma);
	if (err)
		goto done;

	err = merge_files(worktree, fileindex, fileindex_path, yca_commit_id,
	    branch_tip, repo, progress_cb, progress_arg,
	    cancel_cb, cancel_arg);
done:
	free(fileindex_path);
	return err;
}

const struct got_error *
got_worktree_merge_commit(struct got_object_id **new_commit_id,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    const char *author, time_t author_time, const char *committer,
    int allow_bad_symlinks, struct got_object_id *branch_tip,
    const char *branch_name, int allow_conflict, struct got_repository *repo,
    got_worktree_status_cb status_cb, void *status_arg)
{
	const struct got_error *err = NULL, *sync_err;
	struct got_pathlist_head commitable_paths;
	struct collect_commitables_arg cc_arg;
	struct got_pathlist_entry *pe;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	int have_staged_files = 0;
	struct merge_commit_msg_arg mcm_arg;
	char *fileindex_path = NULL;

	memset(&cc_arg, 0, sizeof(cc_arg));
	*new_commit_id = NULL;

	RB_INIT(&commitable_paths);

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	err = got_ref_open(&head_ref, repo, worktree->head_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	err = got_fileindex_for_each_entry_safe(fileindex, check_staged_file,
	    &have_staged_files);
	if (err && err->code != GOT_ERR_CANCELLED)
		goto done;
	if (have_staged_files) {
		err = got_error(GOT_ERR_MERGE_STAGED_PATHS);
		goto done;
	}

	cc_arg.commitable_paths = &commitable_paths;
	cc_arg.worktree = worktree;
	cc_arg.fileindex = fileindex;
	cc_arg.repo = repo;
	cc_arg.have_staged_files = have_staged_files;
	cc_arg.allow_bad_symlinks = allow_bad_symlinks;
	cc_arg.commit_conflicts = allow_conflict;
	err = worktree_status(worktree, "", fileindex, repo,
	    collect_commitables, &cc_arg, NULL, NULL, 1, 0);
	if (err)
		goto done;

	mcm_arg.worktree = worktree;
	mcm_arg.branch_name = branch_name;
	err = commit_worktree(new_commit_id, &commitable_paths,
	    head_commit_id, branch_tip, worktree, author, author_time,
	    committer, NULL, merge_commit_msg_cb, &mcm_arg, status_cb,
	    status_arg, repo);
	if (err)
		goto done;

	err = update_fileindex_after_commit(worktree, &commitable_paths,
	    *new_commit_id, fileindex, have_staged_files);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	RB_FOREACH(pe, got_pathlist_head, &commitable_paths) {
		struct got_commitable *ct = pe->data;

		free_commitable(ct);
	}
	got_pathlist_free(&commitable_paths, GOT_PATHLIST_FREE_NONE);
	free(fileindex_path);
	return err;
}

const struct got_error *
got_worktree_merge_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo)
{
	const struct got_error *err, *unlockerr, *sync_err;
	char *fileindex_path = NULL;

	err = delete_merge_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;
	err = bump_base_commit_id_everywhere(worktree, fileindex, NULL, NULL);
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	got_fileindex_free(fileindex);
	free(fileindex_path);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_merge_in_progress(int *in_progress, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *branch_refname = NULL;
	struct got_reference *branch_ref = NULL;

	*in_progress = 0;

	err = get_merge_branch_ref_name(&branch_refname, worktree);
	if (err)
		return err;
	err = got_ref_open(&branch_ref, repo, branch_refname, 0);
	free(branch_refname);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			return err;
	} else
		*in_progress = 1;

	return NULL;
}

const struct got_error *got_worktree_merge_prepare(
    struct got_fileindex **fileindex, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *fileindex_path = NULL;
	struct got_reference *wt_branch = NULL;
	struct got_object_id *wt_branch_tip = NULL;
	struct check_rebase_ok_arg ok_arg;

	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	/* Preconditions are the same as for rebase. */
	ok_arg.worktree = worktree;
	ok_arg.repo = repo;
	err = got_fileindex_for_each_entry_safe(*fileindex, check_rebase_ok,
	    &ok_arg);
	if (err)
		goto done;

	err = got_ref_open(&wt_branch, repo, worktree->head_ref_name,
	    0);
	if (err)
		goto done;

	err = got_ref_resolve(&wt_branch_tip, repo, wt_branch);
	if (err)
		goto done;

	if (got_object_id_cmp(worktree->base_commit_id, wt_branch_tip) != 0) {
		err = got_error(GOT_ERR_MERGE_OUT_OF_DATE);
		goto done;
	}

done:
	free(fileindex_path);
	if (wt_branch)
		got_ref_close(wt_branch);
	free(wt_branch_tip);
	if (err) {
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *got_worktree_merge_write_refs(
    struct got_worktree *worktree, struct got_reference *branch,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *branch_refname = NULL, *commit_refname = NULL;
	struct got_reference *branch_ref = NULL, *commit_ref = NULL;
	struct got_object_id *branch_tip = NULL;

	err = get_merge_branch_ref_name(&branch_refname, worktree);
	if (err)
		return err;

	err = get_merge_commit_ref_name(&commit_refname, worktree);
	if (err)
		return err;

	err = got_ref_resolve(&branch_tip, repo, branch);
	if (err)
		goto done;

	err = got_ref_alloc_symref(&branch_ref, branch_refname, branch);
	if (err)
		goto done;
	err = got_ref_write(branch_ref, repo);
	if (err)
		goto done;

	err = got_ref_alloc(&commit_ref, commit_refname, branch_tip);
	if (err)
		goto done;
	err = got_ref_write(commit_ref, repo);
	if (err)
		goto done;

done:
	free(branch_refname);
	free(commit_refname);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (commit_ref)
		got_ref_close(commit_ref);
	free(branch_tip);
	return err;
}

const struct got_error *
got_worktree_merge_continue(char **branch_name,
    struct got_object_id **branch_tip, struct got_fileindex **fileindex,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *commit_refname = NULL, *branch_refname = NULL;
	struct got_reference *commit_ref = NULL, *branch_ref = NULL;
	char *fileindex_path = NULL;
	int have_staged_files = 0;

	*branch_name = NULL;
	*branch_tip = NULL;
	*fileindex = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	err = got_fileindex_for_each_entry_safe(*fileindex, check_staged_file,
	    &have_staged_files);
	if (err && err->code != GOT_ERR_CANCELLED)
		goto done;
	if (have_staged_files) {
		err = got_error(GOT_ERR_STAGED_PATHS);
		goto done;
	}

	err = get_merge_branch_ref_name(&branch_refname, worktree);
	if (err)
		goto done;

	err = get_merge_commit_ref_name(&commit_refname, worktree);
	if (err)
		goto done;

	err = got_ref_open(&branch_ref, repo, branch_refname, 0);
	if (err)
		goto done;

	if (!got_ref_is_symbolic(branch_ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "%s is not a symbolic reference",
		    got_ref_get_name(branch_ref));
		goto done;
	}
	*branch_name = strdup(got_ref_get_symref_target(branch_ref));
	if (*branch_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	err = got_ref_open(&commit_ref, repo, commit_refname, 0);
	if (err)
		goto done;

	err = got_ref_resolve(branch_tip, repo, commit_ref);
	if (err)
		goto done;
done:
	free(commit_refname);
	free(branch_refname);
	free(fileindex_path);
	if (commit_ref)
		got_ref_close(commit_ref);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (err) {
		if (*branch_name) {
			free(*branch_name);
			*branch_name = NULL;
		}
		free(*branch_tip);
		*branch_tip = NULL;
		if (*fileindex) {
			got_fileindex_free(*fileindex);
			*fileindex = NULL;
		}
		lock_worktree(worktree, LOCK_SH);
	}
	return err;
}

const struct got_error *
got_worktree_merge_info(char **branch_name, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *branch_refname = NULL;
	struct got_reference *branch_ref = NULL;

	*branch_name = NULL;

	err = get_merge_branch_ref_name(&branch_refname, worktree);
	if (err)
		goto done;

	err = got_ref_open(&branch_ref, repo, branch_refname, 0);
	if (err)
		goto done;

	if (!got_ref_is_symbolic(branch_ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "%s is not a symbolic reference",
		    got_ref_get_name(branch_ref));
		goto done;
	}
	*branch_name = strdup(got_ref_get_symref_target(branch_ref));
	if (*branch_name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

done:
	free(branch_refname);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (err) {
		if (*branch_name) {
			free(*branch_name);
			*branch_name = NULL;
		}
	}
	return err;
}

const struct got_error *
got_worktree_merge_abort(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err, *unlockerr, *sync_err;
	struct got_commit_object *commit = NULL;
	char *fileindex_path = NULL;
	struct revert_file_args rfa;
	char *commit_ref_name = NULL;
	struct got_reference *commit_ref = NULL;
	struct got_object_id *merged_commit_id = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_pathlist_head added_paths;

	RB_INIT(&added_paths);

	err = get_merge_commit_ref_name(&commit_ref_name, worktree);
	if (err)
		goto done;

	err = got_ref_open(&commit_ref, repo, commit_ref_name, 0);
	if (err)
		goto done;

	err = got_ref_resolve(&merged_commit_id, repo, commit_ref);
	if (err)
		goto done;

	/*
	 * Determine which files in added status can be safely removed
	 * from disk while reverting changes in the work tree.
	 * We want to avoid deleting unrelated files which were added by
	 * the user for conflict resolution purposes.
	 */
	err = get_paths_added_between_commits(&added_paths,
	    got_worktree_get_base_commit_id(worktree), merged_commit_id,
	    got_worktree_get_path_prefix(worktree), repo);
	if (err)
		goto done;


	err = got_object_open_as_commit(&commit, repo,
	    worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id, repo, commit,
	    worktree->path_prefix);
	if (err)
		goto done;

	err = delete_merge_refs(worktree, repo);
	if (err)
		goto done;

	err = get_fileindex_path(&fileindex_path, worktree);
	if (err)
		goto done;

	rfa.worktree = worktree;
	rfa.fileindex = fileindex;
	rfa.progress_cb = progress_cb;
	rfa.progress_arg = progress_arg;
	rfa.patch_cb = NULL;
	rfa.patch_arg = NULL;
	rfa.repo = repo;
	rfa.unlink_added_files = 1;
	rfa.added_files_to_unlink = &added_paths;
	err = worktree_status(worktree, "", fileindex, repo,
	    revert_file, &rfa, NULL, NULL, 1, 0);
	if (err)
		goto sync;

	err = checkout_files(worktree, fileindex, "", tree_id, NULL,
	    repo, progress_cb, progress_arg, NULL, NULL);
sync:
	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(tree_id);
	free(merged_commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (fileindex)
		got_fileindex_free(fileindex);
	free(fileindex_path);
	if (commit_ref)
		got_ref_close(commit_ref);
	free(commit_ref_name);

	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

struct check_stage_ok_arg {
	struct got_object_id *head_commit_id;
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	struct got_repository *repo;
	int have_changes;
};

static const struct got_error *
check_stage_ok(void *arg, unsigned char status,
    unsigned char staged_status, const char *relpath,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	struct check_stage_ok_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_fileindex_entry *ie;
	struct got_object_id base_commit_id;
	struct got_object_id *base_commit_idp = NULL;
	char *in_repo_path = NULL, *p;

	if (status == GOT_STATUS_UNVERSIONED ||
	    status == GOT_STATUS_NO_CHANGE)
		return NULL;
	if (status == GOT_STATUS_NONEXISTENT)
		return got_error_set_errno(ENOENT, relpath);

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie == NULL)
		return got_error_path(relpath, GOT_ERR_FILE_STATUS);

	if (asprintf(&in_repo_path, "%s%s%s", a->worktree->path_prefix,
	    got_path_is_root_dir(a->worktree->path_prefix) ? "" : "/",
	    relpath) == -1)
		return got_error_from_errno("asprintf");

	if (got_fileindex_entry_has_commit(ie)) {
		base_commit_idp = got_fileindex_entry_get_commit_id(
		    &base_commit_id, ie);
	}

	if (status == GOT_STATUS_CONFLICT) {
		err = got_error_path(ie->path, GOT_ERR_STAGE_CONFLICT);
		goto done;
	} else if (status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_MODIFY &&
	    status != GOT_STATUS_DELETE) {
		err = got_error_path(ie->path, GOT_ERR_FILE_STATUS);
		goto done;
	}

	a->have_changes = 1;

	p = in_repo_path;
	while (p[0] == '/')
		p++;
	err = check_out_of_date(p, status, staged_status,
	    blob_id, base_commit_idp, a->head_commit_id, a->repo,
	    GOT_ERR_STAGE_OUT_OF_DATE);
done:
	free(in_repo_path);
	return err;
}

struct stage_path_arg {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	struct got_repository *repo;
	got_worktree_status_cb status_cb;
	void *status_arg;
	got_worktree_patch_cb patch_cb;
	void *patch_arg;
	int staged_something;
	int allow_bad_symlinks;
};

static const struct got_error *
stage_path(void *arg, unsigned char status,
    unsigned char staged_status, const char *relpath,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	struct stage_path_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_fileindex_entry *ie;
	char *ondisk_path = NULL, *path_content = NULL;
	uint32_t stage;
	struct got_object_id *new_staged_blob_id = NULL;
	struct stat sb;

	if (status == GOT_STATUS_UNVERSIONED)
		return NULL;

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie == NULL)
		return got_error_path(relpath, GOT_ERR_FILE_STATUS);

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path,
	    relpath)== -1)
		return got_error_from_errno("asprintf");

	switch (status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_MODIFY:
		/* XXX could sb.st_mode be passed in by our caller? */
		if (lstat(ondisk_path, &sb) == -1) {
			err = got_error_from_errno2("lstat", ondisk_path);
			break;
		}
		if (a->patch_cb) {
			if (status == GOT_STATUS_ADD) {
				int choice = GOT_PATCH_CHOICE_NONE;
				err = (*a->patch_cb)(&choice, a->patch_arg,
				    status, ie->path, NULL, 1, 1);
				if (err)
					break;
				if (choice != GOT_PATCH_CHOICE_YES)
					break;
			} else {
				int stage_binary_file = 0;

				err = create_patched_content(&path_content,
				    &stage_binary_file, 0,
				    staged_blob_id ? staged_blob_id : blob_id,
				    ondisk_path, dirfd, de_name, ie->path,
				    a->repo, a->patch_cb, a->patch_arg);
				if (!stage_binary_file &&
				    (err || path_content == NULL))
					break;
			}
		}
		err = got_object_blob_create(&new_staged_blob_id,
		    path_content ? path_content : ondisk_path, a->repo);
		if (err)
			break;
		memcpy(&ie->staged_blob, new_staged_blob_id,
		    sizeof(ie->staged_blob));
		if (status == GOT_STATUS_ADD || staged_status == GOT_STATUS_ADD)
			stage = GOT_FILEIDX_STAGE_ADD;
		else
			stage = GOT_FILEIDX_STAGE_MODIFY;
		got_fileindex_entry_stage_set(ie, stage);
		if (S_ISLNK(sb.st_mode)) {
			int is_bad_symlink = 0;
			if (!a->allow_bad_symlinks) {
				char target_path[PATH_MAX];
				ssize_t target_len;
				target_len = readlink(ondisk_path, target_path,
				    sizeof(target_path));
				if (target_len == -1) {
					err = got_error_from_errno2("readlink",
					    ondisk_path);
					break;
				}
				err = is_bad_symlink_target(&is_bad_symlink,
				    target_path, target_len, ondisk_path,
				    a->worktree->root_path,
				    a->worktree->meta_dir);
				if (err)
					break;
				if (is_bad_symlink) {
					err = got_error_path(ondisk_path,
					    GOT_ERR_BAD_SYMLINK);
					break;
				}
			}
			if (is_bad_symlink)
				got_fileindex_entry_staged_filetype_set(ie,
				    GOT_FILEIDX_MODE_BAD_SYMLINK);
			else
				got_fileindex_entry_staged_filetype_set(ie,
				    GOT_FILEIDX_MODE_SYMLINK);
		} else {
			got_fileindex_entry_staged_filetype_set(ie,
			    GOT_FILEIDX_MODE_REGULAR_FILE);
		}
		a->staged_something = 1;
		if (a->status_cb == NULL)
			break;
		err = (*a->status_cb)(a->status_arg, GOT_STATUS_NO_CHANGE,
		    get_staged_status(ie), relpath, blob_id,
		    new_staged_blob_id, NULL, dirfd, de_name);
		if (err)
			break;
		/*
		 * When staging the reverse of the staged diff,
		 * implicitly unstage the file.
		 */
		if (got_object_id_cmp(&ie->staged_blob, &ie->blob) == 0) {
			got_fileindex_entry_stage_set(ie,
			    GOT_FILEIDX_STAGE_NONE);
		}
		break;
	case GOT_STATUS_DELETE:
		if (staged_status == GOT_STATUS_DELETE)
			break;
		if (a->patch_cb) {
			int choice = GOT_PATCH_CHOICE_NONE;
			err = (*a->patch_cb)(&choice, a->patch_arg, status,
			    ie->path, NULL, 1, 1);
			if (err)
				break;
			if (choice == GOT_PATCH_CHOICE_NO)
				break;
			if (choice != GOT_PATCH_CHOICE_YES) {
				err = got_error(GOT_ERR_PATCH_CHOICE);
				break;
			}
		}
		stage = GOT_FILEIDX_STAGE_DELETE;
		got_fileindex_entry_stage_set(ie, stage);
		a->staged_something = 1;
		if (a->status_cb == NULL)
			break;
		err = (*a->status_cb)(a->status_arg, GOT_STATUS_NO_CHANGE,
		    get_staged_status(ie), relpath, NULL, NULL, NULL, dirfd,
		    de_name);
		break;
	case GOT_STATUS_NO_CHANGE:
		break;
	case GOT_STATUS_CONFLICT:
		err = got_error_path(relpath, GOT_ERR_STAGE_CONFLICT);
		break;
	case GOT_STATUS_NONEXISTENT:
		err = got_error_set_errno(ENOENT, relpath);
		break;
	default:
		err = got_error_path(relpath, GOT_ERR_FILE_STATUS);
		break;
	}

	if (path_content && unlink(path_content) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path_content);
	free(path_content);
	free(ondisk_path);
	free(new_staged_blob_id);
	return err;
}

const struct got_error *
got_worktree_stage(struct got_worktree *worktree,
    struct got_pathlist_head *paths,
    got_worktree_status_cb status_cb, void *status_arg,
    got_worktree_patch_cb patch_cb, void *patch_arg,
    int allow_bad_symlinks, struct got_repository *repo)
{
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	struct got_pathlist_entry *pe;
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct check_stage_ok_arg oka;
	struct stage_path_arg spa;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_ref_open(&head_ref, repo,
	    got_worktree_get_head_ref_name(worktree), 0);
	if (err)
		goto done;
	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;
	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	/* Check pre-conditions before staging anything. */
	oka.head_commit_id = head_commit_id;
	oka.worktree = worktree;
	oka.fileindex = fileindex;
	oka.repo = repo;
	oka.have_changes = 0;
	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    check_stage_ok, &oka, NULL, NULL, 1, 0);
		if (err)
			goto done;
	}
	if (!oka.have_changes) {
		err = got_error(GOT_ERR_STAGE_NO_CHANGE);
		goto done;
	}

	spa.worktree = worktree;
	spa.fileindex = fileindex;
	spa.repo = repo;
	spa.patch_cb = patch_cb;
	spa.patch_arg = patch_arg;
	spa.status_cb = status_cb;
	spa.status_arg = status_arg;
	spa.staged_something = 0;
	spa.allow_bad_symlinks = allow_bad_symlinks;
	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    stage_path, &spa, NULL, NULL, 1, 0);
		if (err)
			goto done;
	}
	if (!spa.staged_something) {
		err = got_error(GOT_ERR_STAGE_NO_CHANGE);
		goto done;
	}

	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	if (head_ref)
		got_ref_close(head_ref);
	free(head_commit_id);
	free(fileindex_path);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

struct unstage_path_arg {
	struct got_worktree *worktree;
	struct got_fileindex *fileindex;
	struct got_repository *repo;
	got_worktree_checkout_cb progress_cb;
	void *progress_arg;
	got_worktree_patch_cb patch_cb;
	void *patch_arg;
};

static const struct got_error *
create_unstaged_content(char **path_unstaged_content,
    char **path_new_staged_content, int *confirm_binary_change,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    const char *relpath, struct got_repository *repo,
    got_worktree_patch_cb patch_cb, void *patch_arg)
{
	const struct got_error *err, *free_err;
	struct got_blob_object *blob = NULL, *staged_blob = NULL;
	FILE *f1 = NULL, *f2 = NULL, *outfile = NULL, *rejectfile = NULL;
	char *path1 = NULL, *path2 = NULL, *label1 = NULL;
	struct got_diffreg_result *diffreg_result = NULL;
	int choice, line_cur1 = 1, line_cur2 = 1, n = 0, nchunks_used = 0;
	int have_content = 0, have_rejected_content = 0, i = 0, nchanges = 0;
	int fd1 = -1, fd2 = -1;

	*confirm_binary_change = 0;
	*path_unstaged_content = NULL;
	*path_new_staged_content = NULL;

	err = got_object_id_str(&label1, blob_id);
	if (err)
		return err;

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

	err = got_object_open_as_blob(&blob, repo, blob_id, 8192, fd1);
	if (err)
		goto done;

	err = got_opentemp_named(&path1, &f1, "got-unstage-blob-base", "");
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, f1, blob);
	if (err)
		goto done;

	err = got_object_open_as_blob(&staged_blob, repo, staged_blob_id, 8192,
	    fd2);
	if (err)
		goto done;

	err = got_opentemp_named(&path2, &f2, "got-unstage-blob-staged", "");
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, f2, staged_blob);
	if (err)
		goto done;

	err = got_diff_files(&diffreg_result, f1, 1, label1, f2, 1,
	    path2, 3, 0, 1, NULL, GOT_DIFF_ALGORITHM_MYERS);
	if (err)
		goto done;

	if (diff_result_has_binary(diffreg_result->result)) {
		err = accept_or_reject_binary_change(&choice, relpath,
		    patch_cb, patch_arg);
		if (err == NULL && choice == GOT_PATCH_CHOICE_YES)
			*confirm_binary_change = 1;
		goto done;
	}

	err = got_opentemp_named(path_unstaged_content, &outfile,
	    "got-unstaged-content", "");
	if (err)
		goto done;
	err = got_opentemp_named(path_new_staged_content, &rejectfile,
	    "got-new-staged-content", "");
	if (err)
		goto done;

	if (fseek(f1, 0L, SEEK_SET) == -1) {
		err = got_ferror(f1, GOT_ERR_IO);
		goto done;
	}
	if (fseek(f2, 0L, SEEK_SET) == -1) {
		err = got_ferror(f2, GOT_ERR_IO);
		goto done;
	}
	/* Count the number of actual changes in the diff result. */
	for (n = 0; n < diffreg_result->result->chunks.len; n += nchunks_used) {
		struct diff_chunk_context cc = {};
		diff_chunk_context_load_change(&cc, &nchunks_used,
		    diffreg_result->result, n, 0);
		nchanges++;
	}
	for (n = 0; n < diffreg_result->result->chunks.len; n += nchunks_used) {
		err = apply_or_reject_change(&choice, &nchunks_used,
		    diffreg_result->result, n, relpath, f1, f2,
		    &line_cur1, &line_cur2,
		    outfile, rejectfile, ++i, nchanges, patch_cb, patch_arg);
		if (err)
			goto done;
		if (choice == GOT_PATCH_CHOICE_YES)
			have_content = 1;
		else
			have_rejected_content = 1;
		if (choice == GOT_PATCH_CHOICE_QUIT)
			break;
	}
	if (have_content || have_rejected_content)
		err = copy_remaining_content(f1, f2, &line_cur1, &line_cur2,
		    outfile, rejectfile);
done:
	free(label1);
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (staged_blob)
		got_object_blob_close(staged_blob);
	free_err = got_diffreg_result_free(diffreg_result);
	if (free_err && err == NULL)
		err = free_err;
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path1);
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path2);
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", *path_unstaged_content);
	if (rejectfile && fclose(rejectfile) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", *path_new_staged_content);
	if (path1 && unlink(path1) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path1);
	if (path2 && unlink(path2) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path2);
	if (err || !have_content) {
		if (*path_unstaged_content &&
		    unlink(*path_unstaged_content) == -1 && err == NULL)
			err = got_error_from_errno2("unlink",
			    *path_unstaged_content);
		free(*path_unstaged_content);
		*path_unstaged_content = NULL;
	}
	if (err || !have_content || !have_rejected_content) {
		if (*path_new_staged_content &&
		    unlink(*path_new_staged_content) == -1 && err == NULL)
			err = got_error_from_errno2("unlink",
			    *path_new_staged_content);
		free(*path_new_staged_content);
		*path_new_staged_content = NULL;
	}
	free(path1);
	free(path2);
	return err;
}

static const struct got_error *
unstage_hunks(int *confirm_binary_change, struct got_object_id *staged_blob_id,
    struct got_blob_object *blob_base, struct got_object_id *blob_id,
    struct got_fileindex_entry *ie, const char *ondisk_path,
    const char *label_orig, struct got_worktree *worktree,
    struct got_repository *repo,
    got_worktree_patch_cb patch_cb, void *patch_arg,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	char *path_unstaged_content = NULL;
	char *path_new_staged_content = NULL;
	char *parent = NULL, *base_path = NULL;
	char *blob_base_path = NULL;
	struct got_object_id *new_staged_blob_id = NULL;
	FILE *f = NULL, *f_base = NULL, *f_deriv2 = NULL;
	struct stat sb;

	err = create_unstaged_content(&path_unstaged_content,
	    &path_new_staged_content, confirm_binary_change,
	    blob_id, staged_blob_id, ie->path, repo, patch_cb, patch_arg);
	if (err)
		return err;

	if (path_unstaged_content == NULL)
		return NULL;

	if (path_new_staged_content) {
		err = got_object_blob_create(&new_staged_blob_id,
		    path_new_staged_content, repo);
		if (err)
			goto done;
	}

	f = fopen(path_unstaged_content, "re");
	if (f == NULL) {
		err = got_error_from_errno2("fopen",
		    path_unstaged_content);
		goto done;
	}
	if (fstat(fileno(f), &sb) == -1) {
		err = got_error_from_errno2("fstat", path_unstaged_content);
		goto done;
	}
	if (got_fileindex_entry_staged_filetype_get(ie) ==
	    GOT_FILEIDX_MODE_SYMLINK && sb.st_size < PATH_MAX) {
		char link_target[PATH_MAX];
		size_t r;
		r = fread(link_target, 1, sizeof(link_target), f);
		if (r == 0 && ferror(f)) {
			err = got_error_from_errno("fread");
			goto done;
		}
		if (r >= sizeof(link_target)) { /* should not happen */
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		link_target[r] = '\0';
		err = merge_symlink(worktree, blob_base,
		    ondisk_path, ie->path, label_orig, link_target,
		    worktree->base_commit_id, repo, progress_cb,
		    progress_arg);
	} else {
		int local_changes_subsumed;

		err = got_path_dirname(&parent, ondisk_path);
		if (err)
			return err;

		if (asprintf(&base_path, "%s/got-unstage-blob-orig",
		    parent) == -1) {
			err = got_error_from_errno("asprintf");
			base_path = NULL;
			goto done;
		}

		err = got_opentemp_named(&blob_base_path, &f_base,
		    base_path, "");
		if (err)
			goto done;
		err = got_object_blob_dump_to_file(NULL, NULL, NULL, f_base,
		    blob_base);
		if (err)
			goto done;

		/*
		 * In order the run a 3-way merge with a symlink we copy the symlink's
		 * target path into a temporary file and use that file with diff3.
		 */
		if (S_ISLNK(got_fileindex_perms_to_st(ie))) {
			err = dump_symlink_target_path_to_file(&f_deriv2,
			    ondisk_path);
			if (err)
				goto done;
		} else {
			int fd;
			fd = open(ondisk_path,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				err = got_error_from_errno2("open", ondisk_path);
				goto done;
			}
			f_deriv2 = fdopen(fd, "r");
			if (f_deriv2 == NULL) {
				err = got_error_from_errno2("fdopen", ondisk_path);
				close(fd);
				goto done;
			}
		}

		err = merge_file(&local_changes_subsumed, worktree,
		    f_base, f, f_deriv2, ondisk_path, ie->path,
		    got_fileindex_perms_to_st(ie),
		    label_orig, "unstaged", NULL, GOT_DIFF_ALGORITHM_MYERS,
		    repo, progress_cb, progress_arg);
	}
	if (err)
		goto done;

	if (new_staged_blob_id) {
		memcpy(&ie->staged_blob, new_staged_blob_id,
		    sizeof(ie->staged_blob));
	} else {
		got_fileindex_entry_stage_set(ie, GOT_FILEIDX_STAGE_NONE);
		got_fileindex_entry_staged_filetype_set(ie, 0);
	}
done:
	free(new_staged_blob_id);
	if (path_unstaged_content &&
	    unlink(path_unstaged_content) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path_unstaged_content);
	if (path_new_staged_content &&
	    unlink(path_new_staged_content) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", path_new_staged_content);
	if (blob_base_path && unlink(blob_base_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", blob_base_path);
	if (f_base && fclose(f_base) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path_unstaged_content);
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path_unstaged_content);
	if (f_deriv2 && fclose(f_deriv2) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", ondisk_path);
	free(path_unstaged_content);
	free(path_new_staged_content);
	free(blob_base_path);
	free(parent);
	free(base_path);
	return err;
}

static const struct got_error *
unstage_path(void *arg, unsigned char status,
    unsigned char staged_status, const char *relpath,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	const struct got_error *err = NULL;
	struct unstage_path_arg *a = arg;
	struct got_fileindex_entry *ie;
	struct got_blob_object *blob_base = NULL, *blob_staged = NULL;
	char *ondisk_path = NULL;
	char *id_str = NULL, *label_orig = NULL;
	int local_changes_subsumed;
	struct stat sb;
	int fd1 = -1, fd2 = -1;

	if (staged_status != GOT_STATUS_ADD &&
	    staged_status != GOT_STATUS_MODIFY &&
	    staged_status != GOT_STATUS_DELETE)
		return NULL;

	ie = got_fileindex_entry_get(a->fileindex, relpath, strlen(relpath));
	if (ie == NULL)
		return got_error_path(relpath, GOT_ERR_FILE_STATUS);

	if (asprintf(&ondisk_path, "%s/%s", a->worktree->root_path, relpath)
	    == -1)
		return got_error_from_errno("asprintf");

	err = got_object_id_str(&id_str,
	    commit_id ? commit_id : a->worktree->base_commit_id);
	if (err)
		goto done;
	if (asprintf(&label_orig, "%s: commit %s", GOT_MERGE_LABEL_BASE,
	    id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
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

	switch (staged_status) {
	case GOT_STATUS_MODIFY:
		err = got_object_open_as_blob(&blob_base, a->repo,
		    blob_id, 8192, fd1);
		if (err)
			break;
		/* fall through */
	case GOT_STATUS_ADD:
		if (status == GOT_STATUS_MISSING) {
			/* Cannot merge changes into missing files. */
			err = (*a->progress_cb)(a->progress_arg, status,
			    relpath);
			goto done;
		}
		if (a->patch_cb) {
			if (staged_status == GOT_STATUS_ADD) {
				int choice = GOT_PATCH_CHOICE_NONE;
				err = (*a->patch_cb)(&choice, a->patch_arg,
				    staged_status, ie->path, NULL, 1, 1);
				if (err)
					break;
				if (choice != GOT_PATCH_CHOICE_YES)
					break;
			} else {
				int unstage_binary_file = 0;

				err = unstage_hunks(&unstage_binary_file,
				    staged_blob_id, blob_base, blob_id,
				    ie, ondisk_path, label_orig,
				    a->worktree, a->repo,
				    a->patch_cb, a->patch_arg,
				    a->progress_cb, a->progress_arg);
				if (!unstage_binary_file)
					break; /* Done with this file. */
			}
		}
		err = got_object_open_as_blob(&blob_staged, a->repo,
		    staged_blob_id, 8192, fd2);
		if (err)
			break;
		switch (got_fileindex_entry_staged_filetype_get(ie)) {
		case GOT_FILEIDX_MODE_BAD_SYMLINK:
		case GOT_FILEIDX_MODE_REGULAR_FILE:
			err = merge_blob(&local_changes_subsumed, a->worktree,
			    blob_base, ondisk_path, relpath,
			    got_fileindex_perms_to_st(ie), label_orig,
			    blob_staged, commit_id ? commit_id :
			    a->worktree->base_commit_id, a->repo,
			    a->progress_cb, a->progress_arg);
			break;
		case GOT_FILEIDX_MODE_SYMLINK:
			if (S_ISLNK(got_fileindex_perms_to_st(ie))) {
				char *staged_target;
				err = got_object_blob_read_to_str(
				    &staged_target, blob_staged);
				if (err)
					goto done;
				err = merge_symlink(a->worktree, blob_base,
				    ondisk_path, relpath, label_orig,
				    staged_target, commit_id ? commit_id :
				    a->worktree->base_commit_id,
				    a->repo, a->progress_cb, a->progress_arg);
				free(staged_target);
			} else {
				err = merge_blob(&local_changes_subsumed,
				    a->worktree, blob_base, ondisk_path,
				    relpath, got_fileindex_perms_to_st(ie),
				    label_orig, blob_staged,
				    commit_id ? commit_id :
				    a->worktree->base_commit_id, a->repo,
				    a->progress_cb, a->progress_arg);
			}
			break;
		default:
			err = got_error_path(relpath, GOT_ERR_BAD_FILETYPE);
			break;
		}
		if (err == NULL) {
			got_fileindex_entry_stage_set(ie,
			    GOT_FILEIDX_STAGE_NONE);
			got_fileindex_entry_staged_filetype_set(ie, 0);
		}
		break;
	case GOT_STATUS_DELETE:
		if (a->patch_cb) {
			int choice = GOT_PATCH_CHOICE_NONE;
			err = (*a->patch_cb)(&choice, a->patch_arg,
			    staged_status, ie->path, NULL, 1, 1);
			if (err)
				break;
			if (choice == GOT_PATCH_CHOICE_NO)
				break;
			if (choice != GOT_PATCH_CHOICE_YES) {
				err = got_error(GOT_ERR_PATCH_CHOICE);
				break;
			}
		}
		got_fileindex_entry_stage_set(ie, GOT_FILEIDX_STAGE_NONE);
		got_fileindex_entry_staged_filetype_set(ie, 0);
		err = get_file_status(&status, &sb, ie, ondisk_path,
		    dirfd, de_name, a->repo);
		if (err)
			break;
		err = (*a->progress_cb)(a->progress_arg, status, relpath);
		break;
	}
done:
	free(ondisk_path);
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob_base)
		got_object_blob_close(blob_base);
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob_staged)
		got_object_blob_close(blob_staged);
	free(id_str);
	free(label_orig);
	return err;
}

const struct got_error *
got_worktree_unstage(struct got_worktree *worktree,
    struct got_pathlist_head *paths,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_patch_cb patch_cb, void *patch_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL, *sync_err, *unlockerr;
	struct got_pathlist_entry *pe;
	struct got_fileindex *fileindex = NULL;
	char *fileindex_path = NULL;
	struct unstage_path_arg upa;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = open_fileindex(&fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	if (err)
		goto done;

	upa.worktree = worktree;
	upa.fileindex = fileindex;
	upa.repo = repo;
	upa.progress_cb = progress_cb;
	upa.progress_arg = progress_arg;
	upa.patch_cb = patch_cb;
	upa.patch_arg = patch_arg;
	RB_FOREACH(pe, got_pathlist_head, paths) {
		err = worktree_status(worktree, pe->path, fileindex, repo,
		    unstage_path, &upa, NULL, NULL, 1, 0);
		if (err)
			goto done;
	}

	sync_err = sync_fileindex(fileindex, fileindex_path);
	if (sync_err && err == NULL)
		err = sync_err;
done:
	free(fileindex_path);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

struct report_file_info_arg {
	struct got_worktree *worktree;
	got_worktree_path_info_cb info_cb;
	void *info_arg;
	struct got_pathlist_head *paths;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
};

static const struct got_error *
report_file_info(void *arg, struct got_fileindex_entry *ie)
{
	const struct got_error *err;
	struct report_file_info_arg *a = arg;
	struct got_pathlist_entry *pe;
	struct got_object_id blob_id, staged_blob_id, commit_id;
	struct got_object_id *blob_idp = NULL, *staged_blob_idp = NULL;
	struct got_object_id *commit_idp = NULL;
	int stage;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	RB_FOREACH(pe, got_pathlist_head, a->paths) {
		if (pe->path_len == 0 || strcmp(pe->path, ie->path) == 0 ||
		    got_path_is_child(ie->path, pe->path, pe->path_len))
			break;
	}
	if (pe == NULL) /* not found */
		return NULL;

	if (got_fileindex_entry_has_blob(ie))
		blob_idp = got_fileindex_entry_get_blob_id(&blob_id, ie);
	stage = got_fileindex_entry_stage_get(ie);
	if (stage == GOT_FILEIDX_STAGE_MODIFY ||
	    stage == GOT_FILEIDX_STAGE_ADD) {
		staged_blob_idp = got_fileindex_entry_get_staged_blob_id(
		    &staged_blob_id, ie);
	}

	if (got_fileindex_entry_has_commit(ie))
		commit_idp = got_fileindex_entry_get_commit_id(&commit_id, ie);

	return a->info_cb(a->info_arg, ie->path, got_fileindex_perms_to_st(ie),
	    (time_t)ie->mtime_sec, blob_idp, staged_blob_idp, commit_idp);
}

const struct got_error *
got_worktree_path_info_prepare(struct got_fileindex **fileindex,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	char *fileindex_path;

	err = lock_worktree(worktree, LOCK_SH);
	if (err)
		return err;

	err = open_fileindex(fileindex, &fileindex_path, worktree,
	    got_repo_get_object_format(repo));
	free(fileindex_path);
	return err;
}

uint32_t
got_worktree_get_fileindex_version(struct got_fileindex *fileindex)
{
	return got_fileindex_get_version(fileindex);
}

const struct got_error *
got_worktree_path_info(struct got_worktree *worktree,
    struct got_fileindex *fileindex,
    struct got_pathlist_head *paths,
    got_worktree_path_info_cb info_cb, void *info_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)

{
	struct report_file_info_arg arg;

	arg.worktree = worktree;
	arg.info_cb = info_cb;
	arg.info_arg = info_arg;
	arg.paths = paths;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	return got_fileindex_for_each_entry_safe(fileindex, report_file_info,
	    &arg);
}

const struct got_error *
got_worktree_path_info_complete(struct got_fileindex *fileindex,
    struct got_worktree *worktree)
{
	if (fileindex)
		got_fileindex_free(fileindex);
	return lock_worktree(worktree, LOCK_UN);
}

static const struct got_error *
patch_check_path(const char *p, char **path, unsigned char *status,
    unsigned char *staged_status, struct got_fileindex *fileindex,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_fileindex_entry *ie;
	struct stat sb;
	char *ondisk_path = NULL;

	err = got_worktree_resolve_path(path, worktree, p);
	if (err)
		return err;

	if (asprintf(&ondisk_path, "%s%s%s", worktree->root_path,
	    *path[0] ? "/" : "", *path) == -1)
		return got_error_from_errno("asprintf");

	ie = got_fileindex_entry_get(fileindex, *path, strlen(*path));
	if (ie) {
		*staged_status = get_staged_status(ie);
		err = get_file_status(status, &sb, ie, ondisk_path, -1, NULL,
		    repo);
		if (err)
			goto done;
	} else {
		*staged_status = GOT_STATUS_NO_CHANGE;
		*status = GOT_STATUS_UNVERSIONED;
		if (lstat(ondisk_path, &sb) == -1) {
			if (errno != ENOENT) {
				err = got_error_from_errno2("lstat",
				    ondisk_path);
				goto done;
			}
			*status = GOT_STATUS_NONEXISTENT;
		}
	}

done:
	free(ondisk_path);
	return err;
}

static const struct got_error *
patch_can_rm(const char *path, unsigned char status,
    unsigned char staged_status)
{
	if (status == GOT_STATUS_NONEXISTENT)
		return got_error_set_errno(ENOENT, path);
	if (status != GOT_STATUS_NO_CHANGE &&
	    status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_MODIFY &&
	    status != GOT_STATUS_MODE_CHANGE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	if (staged_status == GOT_STATUS_DELETE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

static const struct got_error *
patch_can_add(const char *path, unsigned char status)
{
	if (status != GOT_STATUS_NONEXISTENT)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

static const struct got_error *
patch_can_edit(const char *path, unsigned char status,
    unsigned char staged_status)
{
	if (status == GOT_STATUS_NONEXISTENT)
		return got_error_set_errno(ENOENT, path);
	if (status != GOT_STATUS_NO_CHANGE &&
	    status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_MODIFY)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	if (staged_status == GOT_STATUS_DELETE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

const struct got_error *
got_worktree_patch_prepare(struct got_fileindex **fileindex,
    char **fileindex_path, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	return open_fileindex(fileindex, fileindex_path, worktree,
	    got_repo_get_object_format(repo));
}

const struct got_error *
got_worktree_patch_check_path(const char *old, const char *new,
    char **oldpath, char **newpath, struct got_worktree *worktree,
    struct got_repository *repo, struct got_fileindex *fileindex)
{
	const struct got_error *err = NULL;
	int file_renamed = 0;
	unsigned char status_old, staged_status_old;
	unsigned char status_new, staged_status_new;

	*oldpath = NULL;
	*newpath = NULL;

	err = patch_check_path(old != NULL ? old : new, oldpath,
	    &status_old, &staged_status_old, fileindex, worktree, repo);
	if (err)
		goto done;

	err = patch_check_path(new != NULL ? new : old, newpath,
	    &status_new, &staged_status_new, fileindex, worktree, repo);
	if (err)
		goto done;

	if (old != NULL && new != NULL && strcmp(old, new) != 0)
		file_renamed = 1;

	if (old != NULL && new == NULL)
		err = patch_can_rm(*oldpath, status_old, staged_status_old);
	else if (file_renamed) {
		err = patch_can_rm(*oldpath, status_old, staged_status_old);
		if (err == NULL)
			err = patch_can_add(*newpath, status_new);
	} else if (old == NULL)
		err = patch_can_add(*newpath, status_new);
	else
		err = patch_can_edit(*newpath, status_new, staged_status_new);

done:
	if (err) {
		free(*oldpath);
		*oldpath = NULL;
		free(*newpath);
		*newpath = NULL;
	}
	return err;
}

const struct got_error *
got_worktree_patch_schedule_add(const char *path, struct got_repository *repo,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	struct schedule_addition_args saa;

	memset(&saa, 0, sizeof(saa));
	saa.worktree = worktree;
	saa.fileindex = fileindex;
	saa.progress_cb = progress_cb;
	saa.progress_arg = progress_arg;
	saa.repo = repo;

	return worktree_status(worktree, path, fileindex, repo,
	    schedule_addition, &saa, NULL, NULL, 1, 0);
}

const struct got_error *
got_worktree_patch_schedule_rm(const char *path, struct got_repository *repo,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    got_worktree_delete_cb progress_cb, void *progress_arg)
{
	const struct got_error *err;
	struct schedule_deletion_args sda;
	char *ondisk_status_path;

	memset(&sda, 0, sizeof(sda));
	sda.worktree = worktree;
	sda.fileindex = fileindex;
	sda.progress_cb = progress_cb;
	sda.progress_arg = progress_arg;
	sda.repo = repo;
	sda.delete_local_mods = 0;
	sda.keep_on_disk = 0;
	sda.ignore_missing_paths = 0;
	sda.status_codes = NULL;
	if (asprintf(&ondisk_status_path, "%s/%s",
	    got_worktree_get_root_path(worktree), path) == -1)
		return got_error_from_errno("asprintf");
	sda.status_path = ondisk_status_path;
	sda.status_path_len = strlen(ondisk_status_path);

	err = worktree_status(worktree, path, fileindex, repo,
	    schedule_for_deletion, &sda, NULL, NULL, 1, 1);
	free(ondisk_status_path);
	return err;
}

const struct got_error *
got_worktree_patch_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex,
    const char *fileindex_path)
{
	const struct got_error *err = NULL, *unlock_err;

	if (fileindex) {
		err = sync_fileindex(fileindex, fileindex_path);
		got_fileindex_free(fileindex);
	}

	unlock_err = lock_worktree(worktree, LOCK_UN);
	if (unlock_err && err == NULL)
		err = unlock_err;

	return err;
}
