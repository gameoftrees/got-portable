/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_hash.h"
#include "got_lib_fileindex.h"
#include "got_lib_worktree.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_pack.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/* got_fileindex_entry flags */
#define GOT_FILEIDX_F_PATH_LEN		0x00000fff
#define GOT_FILEIDX_F_STAGE		0x0000f000
#define GOT_FILEIDX_F_STAGE_SHIFT	12
#define GOT_FILEIDX_F_NOT_FLUSHED	0x00010000
#define GOT_FILEIDX_F_NO_BLOB		0x00020000
#define GOT_FILEIDX_F_NO_COMMIT		0x00040000
#define GOT_FILEIDX_F_NO_FILE_ON_DISK	0x00080000
#define GOT_FILEIDX_F_REMOVE_ON_FLUSH	0x00100000
#define GOT_FILEIDX_F_SKIPPED		0x00200000

struct got_fileindex {
	struct got_fileindex_tree entries;
	uint32_t version;
	int nentries; /* Does not include entries marked for removal. */
#define GOT_FILEIDX_MAX_ENTRIES INT32_MAX
	enum got_hash_algorithm algo;
};

mode_t
got_fileindex_entry_perms_get(struct got_fileindex_entry *ie)
{
	return ((ie->mode & GOT_FILEIDX_MODE_PERMS) >>
	    GOT_FILEIDX_MODE_PERMS_SHIFT);
}

static void
fileindex_entry_perms_set(struct got_fileindex_entry *ie, mode_t mode)
{
	ie->mode &= ~GOT_FILEIDX_MODE_PERMS;
	ie->mode |= ((mode << GOT_FILEIDX_MODE_PERMS_SHIFT) &
	    GOT_FILEIDX_MODE_PERMS);
}

mode_t
got_fileindex_perms_to_st(struct got_fileindex_entry *ie)
{
	mode_t perms = got_fileindex_entry_perms_get(ie);
	int type = got_fileindex_entry_filetype_get(ie);
	uint32_t ftype;

	if (type == GOT_FILEIDX_MODE_REGULAR_FILE ||
	    type == GOT_FILEIDX_MODE_BAD_SYMLINK)
		ftype = S_IFREG;
	else
		ftype = S_IFLNK;

	return (ftype | (perms & (S_IRWXU | S_IRWXG | S_IRWXO)));
}

const struct got_error *
got_fileindex_entry_update(struct got_fileindex_entry *ie,
    int wt_fd, const char *ondisk_path, struct got_object_id *blob,
    struct got_object_id *commit, int update_timestamps)
{
	struct stat sb;

	if (fstatat(wt_fd, ondisk_path, &sb, AT_SYMLINK_NOFOLLOW) != 0) {
		if (!((ie->flags & GOT_FILEIDX_F_NO_FILE_ON_DISK) &&
		    errno == ENOENT))
			return got_error_from_errno2("fstatat", ondisk_path);
		sb.st_mode = GOT_DEFAULT_FILE_MODE;
	} else {
		if (sb.st_mode & S_IFDIR)
			return got_error_set_errno(EISDIR, ondisk_path);
		ie->flags &= ~GOT_FILEIDX_F_NO_FILE_ON_DISK;
	}

	if ((ie->flags & GOT_FILEIDX_F_NO_FILE_ON_DISK) == 0) {
		if (update_timestamps) {
			ie->ctime_sec = sb.st_ctim.tv_sec;
			ie->ctime_nsec = sb.st_ctim.tv_nsec;
			ie->mtime_sec = sb.st_mtim.tv_sec;
			ie->mtime_nsec = sb.st_mtim.tv_nsec;
		}
		ie->uid = sb.st_uid;
		ie->gid = sb.st_gid;
		ie->size = (sb.st_size & 0xffffffff);
		if (S_ISLNK(sb.st_mode)) {
			got_fileindex_entry_filetype_set(ie,
			    GOT_FILEIDX_MODE_SYMLINK);
			fileindex_entry_perms_set(ie, 0);
		} else {
			got_fileindex_entry_filetype_set(ie,
			    GOT_FILEIDX_MODE_REGULAR_FILE);
			fileindex_entry_perms_set(ie,
			    sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));
		}
	}

	if (blob) {
		memmove(&ie->blob, blob, sizeof(ie->blob));
		ie->flags &= ~GOT_FILEIDX_F_NO_BLOB;
	} else
		ie->flags |= GOT_FILEIDX_F_NO_BLOB;

	if (commit) {
		memmove(&ie->commit, commit, sizeof(ie->commit));
		ie->flags &= ~GOT_FILEIDX_F_NO_COMMIT;
	} else
		ie->flags |= GOT_FILEIDX_F_NO_COMMIT;

	return NULL;
}

void
got_fileindex_entry_mark_deleted_from_disk(struct got_fileindex_entry *ie)
{
	ie->flags |= GOT_FILEIDX_F_NO_FILE_ON_DISK;
}

void
got_fileindex_entry_mark_skipped(struct got_fileindex_entry *ie)
{
	ie->flags |= GOT_FILEIDX_F_SKIPPED;
}

const struct got_error *
got_fileindex_entry_relpath_allowed(const char *relpath, size_t relpath_len)
{
	const char *forbidden[] = {
		GOT_GIT_DIR,
		GOT_WORKTREE_GOT_DIR,
		GOT_WORKTREE_CVG_DIR
	};
	size_t i;

	for (i = 0; i < nitems(forbidden); i++) {
		if (got_path_cmp(relpath, forbidden[i],
		    relpath_len, strlen(forbidden[i])) == 0 ||
		    got_path_is_child(relpath, forbidden[i],
		    strlen(forbidden[i]))) {
			return got_error_fmt(GOT_ERR_BAD_PATH,
			    "path '%s' cannot be added to the file-index",
			    relpath);
		}
	}

	return NULL;
}

const struct got_error *
got_fileindex_entry_alloc(struct got_fileindex_entry **ie,
    const char *relpath)
{
	const struct got_error *err;
	size_t len;

	len = strlen(relpath);

	err = got_fileindex_entry_relpath_allowed(relpath, len);
	if (err)
		return err;

	*ie = calloc(1, sizeof(**ie));
	if (*ie == NULL)
		return got_error_from_errno("calloc");

	(*ie)->path = strdup(relpath);
	if ((*ie)->path == NULL) {
		const struct got_error *err = got_error_from_errno("strdup");
		free(*ie);
		*ie = NULL;
		return err;
	}

	if (len > GOT_FILEIDX_F_PATH_LEN)
		len = GOT_FILEIDX_F_PATH_LEN;
	(*ie)->flags |= len;

	return NULL;
}

void
got_fileindex_entry_free(struct got_fileindex_entry *ie)
{
	free(ie->path);
	free(ie);
}

size_t
got_fileindex_entry_path_len(const struct got_fileindex_entry *ie)
{
	return (size_t)(ie->flags & GOT_FILEIDX_F_PATH_LEN);
}

uint32_t
got_fileindex_entry_stage_get(const struct got_fileindex_entry *ie)
{
	return ((ie->flags & GOT_FILEIDX_F_STAGE) >> GOT_FILEIDX_F_STAGE_SHIFT);
}

void
got_fileindex_entry_stage_set(struct got_fileindex_entry *ie, uint32_t stage)
{
	ie->flags &= ~GOT_FILEIDX_F_STAGE;
	ie->flags |= ((stage << GOT_FILEIDX_F_STAGE_SHIFT) &
	    GOT_FILEIDX_F_STAGE);
}

int
got_fileindex_entry_filetype_get(struct got_fileindex_entry *ie)
{
	return (ie->mode & GOT_FILEIDX_MODE_FILE_TYPE_ONDISK);
}

void
got_fileindex_entry_filetype_set(struct got_fileindex_entry *ie, int type)
{
	ie->mode &= ~GOT_FILEIDX_MODE_FILE_TYPE_ONDISK;
	ie->mode |= (type & GOT_FILEIDX_MODE_FILE_TYPE_ONDISK);
}

void
got_fileindex_entry_staged_filetype_set(struct got_fileindex_entry *ie,
    int type)
{
	ie->mode &= ~GOT_FILEIDX_MODE_FILE_TYPE_STAGED;
	ie->mode |= ((type << GOT_FILEIDX_MODE_FILE_TYPE_STAGED_SHIFT) &
	    GOT_FILEIDX_MODE_FILE_TYPE_STAGED);
}

int
got_fileindex_entry_staged_filetype_get(struct got_fileindex_entry *ie)
{
	return (ie->mode & GOT_FILEIDX_MODE_FILE_TYPE_STAGED) >>
	    GOT_FILEIDX_MODE_FILE_TYPE_STAGED_SHIFT;
}

int
got_fileindex_entry_has_blob(struct got_fileindex_entry *ie)
{
	return (ie->flags & GOT_FILEIDX_F_NO_BLOB) == 0;
}

int
got_fileindex_entry_has_commit(struct got_fileindex_entry *ie)
{
	return (ie->flags & GOT_FILEIDX_F_NO_COMMIT) == 0;
}

int
got_fileindex_entry_has_file_on_disk(struct got_fileindex_entry *ie)
{
	return (ie->flags & GOT_FILEIDX_F_NO_FILE_ON_DISK) == 0;
}

int
got_fileindex_entry_was_skipped(struct got_fileindex_entry *ie)
{
	return (ie->flags & GOT_FILEIDX_F_SKIPPED) != 0;
}

static const struct got_error *
add_entry(struct got_fileindex *fileindex, struct got_fileindex_entry *ie)
{
	if (fileindex->nentries >= GOT_FILEIDX_MAX_ENTRIES)
		return got_error(GOT_ERR_NO_SPACE);

	if (RB_INSERT(got_fileindex_tree, &fileindex->entries, ie) != NULL)
		return got_error_path(ie->path, GOT_ERR_FILEIDX_DUP_ENTRY);

	fileindex->nentries++;
	return NULL;
}

const struct got_error *
got_fileindex_entry_add(struct got_fileindex *fileindex,
    struct got_fileindex_entry *ie)
{
	/* Flag this entry until it gets written out to disk. */
	ie->flags |= GOT_FILEIDX_F_NOT_FLUSHED;

	return add_entry(fileindex, ie);
}

void
got_fileindex_entry_remove(struct got_fileindex *fileindex,
    struct got_fileindex_entry *ie)
{
	/*
	 * Removing an entry from the RB tree immediately breaks
	 * in-progress iterations over file index entries.
	 * So flag this entry for removal and remove it once the index
	 * is written out to disk. Meanwhile, pretend this entry no longer
	 * exists if we get queried for it again before then.
	 */
	ie->flags |= GOT_FILEIDX_F_REMOVE_ON_FLUSH;
	fileindex->nentries--;
}

struct got_fileindex_entry *
got_fileindex_entry_get(struct got_fileindex *fileindex, const char *path,
    size_t path_len)
{
	struct got_fileindex_entry *ie;
	struct got_fileindex_entry key;
	memset(&key, 0, sizeof(key));
	key.path = (char *)path;
	key.flags = (path_len & GOT_FILEIDX_F_PATH_LEN);
	ie = RB_FIND(got_fileindex_tree, &fileindex->entries, &key);
	if (ie && (ie->flags & GOT_FILEIDX_F_REMOVE_ON_FLUSH))
		return NULL;
	return ie;
}

const struct got_error *
got_fileindex_for_each_entry_safe(struct got_fileindex *fileindex,
    got_fileindex_cb cb, void *cb_arg)
{
	const struct got_error *err;
	struct got_fileindex_entry *ie, *tmp;

	RB_FOREACH_SAFE(ie, got_fileindex_tree, &fileindex->entries, tmp) {
		if (ie->flags & GOT_FILEIDX_F_REMOVE_ON_FLUSH)
			continue;
		err = (*cb)(cb_arg, ie);
		if (err)
			return err;
	}
	return NULL;
}

struct got_fileindex *
got_fileindex_alloc(enum got_hash_algorithm algo)
{
	struct got_fileindex *fileindex;

	fileindex = calloc(1, sizeof(*fileindex));
	if (fileindex == NULL)
		return NULL;

	fileindex->version = GOT_FILE_INDEX_VERSION;
	fileindex->algo = algo;
	RB_INIT(&fileindex->entries);
	return fileindex;
}

void
got_fileindex_free(struct got_fileindex *fileindex)
{
	struct got_fileindex_entry *ie;

	while ((ie = RB_MIN(got_fileindex_tree, &fileindex->entries))) {
		RB_REMOVE(got_fileindex_tree, &fileindex->entries, ie);
		got_fileindex_entry_free(ie);
	}
	free(fileindex);
}

static const struct got_error *
write_fileindex_val64(struct got_hash *ctx, uint64_t val, FILE *outfile)
{
	size_t n;

	val = htobe64(val);
	got_hash_update(ctx, &val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val32(struct got_hash *ctx, uint32_t val, FILE *outfile)
{
	size_t n;

	val = htobe32(val);
	got_hash_update(ctx, &val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val16(struct got_hash *ctx, uint16_t val, FILE *outfile)
{
	size_t n;

	val = htobe16(val);
	got_hash_update(ctx, &val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_path(struct got_hash *ctx, const char *path, FILE *outfile)
{
	size_t n, len, pad = 0;
	static const uint8_t zero[8] = { 0 };

	len = strlen(path);
	while ((len + pad) % 8 != 0)
		pad++;
	if (pad == 0)
		pad = 8; /* NUL-terminate */

	got_hash_update(ctx, path, len);
	n = fwrite(path, 1, len, outfile);
	if (n != len)
		return got_ferror(outfile, GOT_ERR_IO);
	got_hash_update(ctx, zero, pad);
	n = fwrite(zero, 1, pad, outfile);
	if (n != pad)
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_entry(struct got_hash *ctx, struct got_fileindex_entry *ie,
    FILE *outfile)
{
	const struct got_error *err;
	size_t n;
	uint32_t stage;
	size_t digest_len = got_hash_digest_length(ctx->algo);

	err = write_fileindex_val64(ctx, ie->ctime_sec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, ie->ctime_nsec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, ie->mtime_sec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, ie->mtime_nsec, outfile);
	if (err)
		return err;

	err = write_fileindex_val32(ctx, ie->uid, outfile);
	if (err)
		return err;
	err = write_fileindex_val32(ctx, ie->gid, outfile);
	if (err)
		return err;
	err = write_fileindex_val32(ctx, ie->size, outfile);
	if (err)
		return err;

	err = write_fileindex_val16(ctx, ie->mode, outfile);
	if (err)
		return err;

	got_hash_update(ctx, ie->blob.hash, digest_len);
	n = fwrite(ie->blob.hash, 1, digest_len, outfile);
	if (n != digest_len)
		return got_ferror(outfile, GOT_ERR_IO);

	got_hash_update(ctx, ie->commit.hash, digest_len);
	n = fwrite(ie->commit.hash, 1, digest_len, outfile);
	if (n != digest_len)
		return got_ferror(outfile, GOT_ERR_IO);

	err = write_fileindex_val32(ctx, ie->flags, outfile);
	if (err)
		return err;

	err = write_fileindex_path(ctx, ie->path, outfile);
	if (err)
		return err;

	stage = got_fileindex_entry_stage_get(ie);
	if (stage == GOT_FILEIDX_STAGE_MODIFY ||
	    stage == GOT_FILEIDX_STAGE_ADD) {
		got_hash_update(ctx, ie->staged_blob.hash, digest_len);
		n = fwrite(ie->staged_blob.hash, 1, digest_len,
		    outfile);
		if (n != digest_len)
			return got_ferror(outfile, GOT_ERR_IO);
	}

	return NULL;
}

const struct got_error *
got_fileindex_write(struct got_fileindex *fileindex, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_fileindex_hdr hdr;
	struct got_hash ctx;
	uint8_t hash[GOT_HASH_DIGEST_MAXLEN];
	size_t n, digest_len = got_hash_digest_length(fileindex->algo);
	struct got_fileindex_entry *ie, *tmp;

	memset(hash, 0, sizeof(hash));

	got_hash_init(&ctx, fileindex->algo);

	hdr.signature = htobe32(GOT_FILE_INDEX_SIGNATURE);
	hdr.version = htobe32(GOT_FILE_INDEX_VERSION);
	hdr.nentries = htobe32(fileindex->nentries);
	hdr.algo = htobe32(fileindex->algo);

	got_hash_update(&ctx, &hdr.signature, sizeof(hdr.signature));
	got_hash_update(&ctx, &hdr.version, sizeof(hdr.version));
	got_hash_update(&ctx, &hdr.nentries, sizeof(hdr.nentries));
	got_hash_update(&ctx, &hdr.algo, sizeof(hdr.algo));
	n = fwrite(&hdr.signature, 1, sizeof(hdr.signature), outfile);
	if (n != sizeof(hdr.signature))
		return got_ferror(outfile, GOT_ERR_IO);
	n = fwrite(&hdr.version, 1, sizeof(hdr.version), outfile);
	if (n != sizeof(hdr.version))
		return got_ferror(outfile, GOT_ERR_IO);
	n = fwrite(&hdr.nentries, 1, sizeof(hdr.nentries), outfile);
	if (n != sizeof(hdr.nentries))
		return got_ferror(outfile, GOT_ERR_IO);
	n = fwrite(&hdr.algo, 1, sizeof(hdr.algo), outfile);
	if (n != sizeof(hdr.nentries))
		return got_ferror(outfile, GOT_ERR_IO);

	RB_FOREACH_SAFE(ie, got_fileindex_tree, &fileindex->entries, tmp) {
		ie->flags &= ~GOT_FILEIDX_F_NOT_FLUSHED;
		ie->flags &= ~GOT_FILEIDX_F_SKIPPED;
		if (ie->flags & GOT_FILEIDX_F_REMOVE_ON_FLUSH) {
			RB_REMOVE(got_fileindex_tree, &fileindex->entries, ie);
			got_fileindex_entry_free(ie);
			continue;
		}
		err = write_fileindex_entry(&ctx, ie, outfile);
		if (err)
			return err;
	}

	got_hash_final(&ctx, hash);
	n = fwrite(hash, 1, digest_len, outfile);
	if (n != digest_len)
		return got_ferror(outfile, GOT_ERR_IO);

	if (fflush(outfile) != 0)
		return got_error_from_errno("fflush");

	return NULL;
}

static const struct got_error *
read_fileindex_val64(uint64_t *val, struct got_hash *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	got_hash_update(ctx, val, sizeof(*val));
	*val = be64toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_val32(uint32_t *val, struct got_hash *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	got_hash_update(ctx, val, sizeof(*val));
	*val = be32toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_val16(uint16_t *val, struct got_hash *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	got_hash_update(ctx, val, sizeof(*val));
	*val = be16toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_path(char **path, struct got_hash *ctx, FILE *infile)
{
	const size_t chunk_size = 8;
	char p[PATH_MAX];
	size_t n, len = 0;

	do {
		if (len + chunk_size > sizeof(p))
			return got_error(GOT_ERR_FILEIDX_BAD);

		n = fread(&p[len], 1, chunk_size, infile);
		if (n != chunk_size)
			return got_ferror(infile, GOT_ERR_FILEIDX_BAD);

		got_hash_update(ctx, &p[len], chunk_size);
		len += chunk_size;
	} while (memchr(&p[len - chunk_size], '\0', chunk_size) == NULL);

	*path = strdup(p);
	if (*path == NULL)
		return got_error_from_errno("strdup");
	return NULL;
}

static const struct got_error *
read_fileindex_entry(struct got_fileindex_entry **iep, struct got_hash *ctx,
    FILE *infile, uint32_t version, enum got_hash_algorithm algo)
{
	const struct got_error *err;
	struct got_fileindex_entry *ie;
	size_t n, digest_len = got_hash_digest_length(algo);

	*iep = NULL;

	ie = calloc(1, sizeof(*ie));
	if (ie == NULL)
		return got_error_from_errno("calloc");

	err = read_fileindex_val64(&ie->ctime_sec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&ie->ctime_nsec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&ie->mtime_sec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&ie->mtime_nsec, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_val32(&ie->uid, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val32(&ie->gid, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val32(&ie->size, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_val16(&ie->mode, ctx, infile);
	if (err)
		goto done;

	ie->blob.algo = algo;
	n = fread(ie->blob.hash, 1, digest_len, infile);
	if (n != digest_len) {
		err = got_ferror(infile, GOT_ERR_FILEIDX_BAD);
		goto done;
	}
	got_hash_update(ctx, ie->blob.hash, digest_len);

	ie->commit.algo = algo;
	n = fread(ie->commit.hash, 1, digest_len, infile);
	if (n != digest_len) {
		err = got_ferror(infile, GOT_ERR_FILEIDX_BAD);
		goto done;
	}
	got_hash_update(ctx, ie->commit.hash, digest_len);

	err = read_fileindex_val32(&ie->flags, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_path(&ie->path, ctx, infile);
	if (err)
		goto done;

	if (version >= 2) {
		uint32_t stage = got_fileindex_entry_stage_get(ie);
		if (stage == GOT_FILEIDX_STAGE_MODIFY ||
		    stage == GOT_FILEIDX_STAGE_ADD) {
			ie->staged_blob.algo = algo;
			n = fread(ie->staged_blob.hash, 1, digest_len,
			    infile);
			if (n != digest_len) {
				err = got_ferror(infile, GOT_ERR_FILEIDX_BAD);
				goto done;
			}
			got_hash_update(ctx, ie->staged_blob.hash,
			    digest_len);
		}
	} else {
		/* GOT_FILE_INDEX_VERSION 1 does not support staging. */
		ie->flags &= ~GOT_FILEIDX_F_STAGE;
	}

done:
	if (err)
		got_fileindex_entry_free(ie);
	else
		*iep = ie;
	return err;
}

const struct got_error *
got_fileindex_read(struct got_fileindex *fileindex, FILE *infile,
    enum got_hash_algorithm repo_algo)
{
	const struct got_error *err = NULL;
	struct got_fileindex_hdr hdr;
	struct got_hash ctx;
	struct got_fileindex_entry *ie;
	enum got_hash_algorithm algo = repo_algo;
	uint8_t hash_expected[GOT_HASH_DIGEST_MAXLEN];
	uint8_t hash[GOT_HASH_DIGEST_MAXLEN];
	size_t n, digest_len;
	uint32_t version;
	int i;

	n = fread(&hdr.signature, 1, sizeof(hdr.signature), infile);
	if (n != sizeof(hdr.signature)) {
		if (n == 0) /* EOF */
			return NULL;
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	}
	n = fread(&hdr.version, 1, sizeof(hdr.version), infile);
	if (n != sizeof(hdr.version)) {
		if (n == 0) /* EOF */
			return NULL;
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	}
	n = fread(&hdr.nentries, 1, sizeof(hdr.nentries), infile);
	if (n != sizeof(hdr.nentries)) {
		if (n == 0) /* EOF */
			return NULL;
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	}
	version = be32toh(hdr.version);

	if (version >= 3) {
		n = fread(&hdr.algo, 1, sizeof(hdr.algo), infile);
		if (n != sizeof(hdr.algo)) {
			if (n == 0) /* EOF */
				return NULL;
			return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
		}
		algo = be32toh(hdr.algo);
		if (algo != repo_algo) {
			const char *fmt = "unknown";

			if (repo_algo == GOT_HASH_SHA1)
				fmt = "sha1";
			else if (repo_algo == GOT_HASH_SHA256)
				fmt = "sha256";

			return got_error_path(fmt, GOT_ERR_OBJECT_FORMAT);
		}
	}

	digest_len = got_hash_digest_length(algo);

	got_hash_init(&ctx, algo);
	got_hash_update(&ctx, &hdr.signature, sizeof(hdr.signature));
	got_hash_update(&ctx, &hdr.version, sizeof(hdr.version));
	got_hash_update(&ctx, &hdr.nentries, sizeof(hdr.nentries));
	if (version >= 3)
		got_hash_update(&ctx, &hdr.algo, sizeof(hdr.algo));

	hdr.signature = be32toh(hdr.signature);
	hdr.version = be32toh(hdr.version);
	hdr.nentries = be32toh(hdr.nentries);

	if (hdr.signature != GOT_FILE_INDEX_SIGNATURE)
		return got_error(GOT_ERR_FILEIDX_SIG);
	if (hdr.version > GOT_FILE_INDEX_VERSION)
		return got_error(GOT_ERR_FILEIDX_VER);

	fileindex->version = version;
	fileindex->algo = algo;
	for (i = 0; i < hdr.nentries; i++) {
		err = read_fileindex_entry(&ie, &ctx, infile,
		    hdr.version, algo);
		if (err)
			return err;
		err = add_entry(fileindex, ie);
		if (err) {
			got_fileindex_entry_free(ie);
			return err;
		}
	}

	n = fread(hash_expected, 1, digest_len, infile);
	if (n != digest_len)
		return got_ferror(infile, GOT_ERR_FILEIDX_BAD);
	got_hash_final(&ctx, hash);
	if (got_hash_cmp(algo, hash, hash_expected) != 0)
		return got_error(GOT_ERR_FILEIDX_CSUM);

	return NULL;
}

uint32_t
got_fileindex_get_version(struct got_fileindex *fileindex)
{
	return fileindex->version;
}

static struct got_fileindex_entry *
walk_fileindex(struct got_fileindex *fileindex, struct got_fileindex_entry *ie)
{
	struct got_fileindex_entry *next;

	next = RB_NEXT(got_fileindex_tree, &fileindex->entries, ie);

	/* Skip entries which were added or removed by diff callbacks. */
	while (next && (next->flags & (GOT_FILEIDX_F_NOT_FLUSHED |
	    GOT_FILEIDX_F_REMOVE_ON_FLUSH)))
		next = RB_NEXT(got_fileindex_tree, &fileindex->entries, next);

	return next;
}

static const struct got_error *
diff_fileindex_tree(struct got_fileindex *, struct got_fileindex_entry **ie,
    struct got_tree_object *tree, const char *, const char *,
    struct got_repository *, struct got_fileindex_diff_tree_cb *, void *);

static const struct got_error *
walk_tree(struct got_tree_entry **next, struct got_fileindex *fileindex,
    struct got_fileindex_entry **ie, struct got_tree_object *tree, int *tidx,
    const char *path, const char *entry_name, struct got_repository *repo,
    struct got_fileindex_diff_tree_cb *cb, void *cb_arg)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te;

	*next = NULL;

	te = got_object_tree_get_entry(tree, *tidx);
	if (te == NULL)
		return NULL;

	if (!got_object_tree_entry_is_submodule(te) &&
	    S_ISDIR(got_tree_entry_get_mode(te))) {
		char *subpath;
		struct got_tree_object *subtree;

		if (asprintf(&subpath, "%s%s%s", path,
		    path[0] == '\0' ? "" : "/",
		    got_tree_entry_get_name(te)) == -1)
			return got_error_from_errno("asprintf");

		err = got_object_open_as_tree(&subtree, repo,
		    got_tree_entry_get_id(te));
		if (err) {
			free(subpath);
			return err;
		}

		err = diff_fileindex_tree(fileindex, ie, subtree, subpath,
		    entry_name, repo, cb, cb_arg);
		free(subpath);
		got_object_tree_close(subtree);
		if (err)
			return err;
	}

	(*tidx)++;
	*next = got_object_tree_get_entry(tree, *tidx);
	return NULL;
}

static const struct got_error *
diff_fileindex_tree(struct got_fileindex *fileindex,
    struct got_fileindex_entry **ie, struct got_tree_object *tree,
    const char *path, const char *entry_name, struct got_repository *repo,
    struct got_fileindex_diff_tree_cb *cb, void *cb_arg)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te = NULL;
	size_t path_len = strlen(path);
	struct got_fileindex_entry *next;
	int tidx = 0;

	te = got_object_tree_get_entry(tree, tidx);
	while ((*ie && got_path_is_child((*ie)->path, path, path_len)) || te) {
		if (te && *ie) {
			char *te_path;
			const char *te_name = got_tree_entry_get_name(te);
			int cmp;
			if (asprintf(&te_path, "%s/%s", path, te_name) == -1) {
				err = got_error_from_errno("asprintf");
				break;
			}
			cmp = got_path_cmp((*ie)->path, te_path,
			    got_fileindex_entry_path_len(*ie), strlen(te_path));
			free(te_path);
			if (cmp == 0) {
				if (got_path_is_child((*ie)->path, path,
				    path_len) &&
				    !got_object_tree_entry_is_submodule(te) &&
				    (entry_name == NULL ||
				    strcmp(te_name, entry_name) == 0)) {
					err = cb->diff_old_new(cb_arg, *ie, te,
					    path);
					if (err || entry_name)
						break;
				}
				*ie = walk_fileindex(fileindex, *ie);
				err = walk_tree(&te, fileindex, ie, tree, &tidx,
				    path, entry_name, repo, cb, cb_arg);
			} else if (cmp < 0) {
				next = walk_fileindex(fileindex, *ie);
				if (got_path_is_child((*ie)->path, path,
				    path_len) && entry_name == NULL) {
					err = cb->diff_old(cb_arg, *ie, path);
					if (err || entry_name)
						break;
				}
				*ie = next;
			} else {
				if ((entry_name == NULL ||
				    strcmp(te_name, entry_name) == 0)) {
					err = cb->diff_new(cb_arg, te, path);
					if (err || entry_name)
						break;
				}
				err = walk_tree(&te, fileindex, ie, tree, &tidx,
				    path, entry_name, repo, cb, cb_arg);
			}
			if (err)
				break;
		} else if (*ie) {
			next = walk_fileindex(fileindex, *ie);
			if (got_path_is_child((*ie)->path, path, path_len) &&
			    (entry_name == NULL ||
			    (te && strcmp(got_tree_entry_get_name(te),
			    entry_name) == 0))) {
				err = cb->diff_old(cb_arg, *ie, path);
				if (err || entry_name)
					break;
			}
			*ie = next;
		} else if (te) {
			if (!got_object_tree_entry_is_submodule(te) &&
			    (entry_name == NULL ||
			    strcmp(got_tree_entry_get_name(te), entry_name)
			    == 0)) {
				err = cb->diff_new(cb_arg, te, path);
				if (err || entry_name)
					break;
			}
			err = walk_tree(&te, fileindex, ie, tree, &tidx, path,
			    entry_name, repo, cb, cb_arg);
			if (err)
				break;
		}
	}

	return err;
}

const struct got_error *
got_fileindex_diff_tree(struct got_fileindex *fileindex,
    struct got_tree_object *tree, const char *path, const char *entry_name,
    struct got_repository *repo,
    struct got_fileindex_diff_tree_cb *cb, void *cb_arg)
{
	struct got_fileindex_entry *ie;
	ie = RB_MIN(got_fileindex_tree, &fileindex->entries);
	while (ie && !got_path_is_child(ie->path, path, strlen(path)))
		ie = walk_fileindex(fileindex, ie);
	return diff_fileindex_tree(fileindex, &ie, tree, path, entry_name, repo,
	    cb, cb_arg);
}

static const struct got_error *
diff_fileindex_dir(struct got_fileindex *, struct got_fileindex_entry **,
    struct got_pathlist_head *, int, const char *, const char *,
    struct got_repository *, struct got_fileindex_diff_dir_cb *, void *);

static struct dirent *
copy_dirent(const struct dirent *de)
{
	size_t amt = de->d_reclen;
	struct dirent *copy;

	copy = malloc(amt);
	if (copy != NULL) {
		memcpy(copy, de, amt);
	}
	return copy;
}

static const struct got_error *
read_dirlist(struct got_pathlist_head *dirlist, DIR *dir, const char *path)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *new = NULL;
	struct dirent *de = NULL;

	for (;;) {
		errno = 0;
		if ((de = readdir(dir)) == NULL) {
			if (errno != 0) {
				err = got_error_from_errno("readdir");
			}
			break;
		}

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0 ||
		    (path[0] == '\0' &&
		    strcmp(de->d_name, GOT_WORKTREE_GOT_DIR) == 0) ||
		    (path[0] == '\0' &&
		    strcmp(de->d_name, GOT_WORKTREE_CVG_DIR) == 0)) {
			continue;
		}

		de = copy_dirent(de);
		if (de == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		err = got_pathlist_insert(&new, dirlist, de->d_name, de);
		if (err) {
			free(de);
			break;
		}
		if (new == NULL) {
			err = got_error(GOT_ERR_DIR_DUP_ENTRY);
			free(de);
			break;
		}
	}

	return err;
}

static int
have_tracked_file_in_dir(struct got_fileindex *fileindex, const char *path)
{
	struct got_fileindex_entry *ie;
	size_t path_len = strlen(path);
	int cmp;

	ie = RB_ROOT(&fileindex->entries);
	while (ie) {
		if (got_path_is_child(ie->path, path, path_len))
			return 1;
		cmp = got_path_cmp(path, ie->path, path_len,
		    got_fileindex_entry_path_len(ie));
		if (cmp < 0)
			ie = RB_LEFT(ie, entry);
		else if (cmp > 0)
			ie = RB_RIGHT(ie, entry);
		else
			break;
	}

	return 0;
}

static const struct got_error *
walk_dir(struct got_pathlist_entry **next, struct got_fileindex *fileindex,
    struct got_fileindex_entry **ie, struct got_pathlist_entry *dle,
    struct got_pathlist_head *dlh, int fd, const char *path,
    const char *rootpath, struct got_repository *repo, int ignore,
    struct got_fileindex_diff_dir_cb *cb, void *cb_arg)
{
	const struct got_error *err = NULL;
	struct dirent *de = dle->data;
	DIR *subdir = NULL;
	int subdirfd = -1;

	*next = NULL;

	/* Must traverse ignored directories if they contain tracked files. */
	if (de->d_type == DT_DIR && ignore &&
	    have_tracked_file_in_dir(fileindex, path))
		ignore = 0;

	if (de->d_type == DT_DIR && !ignore) {
		char *subpath;
		char *subdirpath;
		struct got_pathlist_head subdirlist;

		RB_INIT(&subdirlist);

		if (asprintf(&subpath, "%s%s%s", path,
		    path[0] == '\0' ? "" : "/", de->d_name) == -1)
			return got_error_from_errno("asprintf");

		if (asprintf(&subdirpath, "%s/%s", rootpath, subpath) == -1) {
			free(subpath);
			return got_error_from_errno("asprintf");
		}

		subdirfd = openat(fd, de->d_name,
		    O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
		if (subdirfd == -1) {
			if (errno == EACCES) {
				*next = RB_NEXT(got_pathlist_head, dlh, dle);
				return NULL;
			}
			err = got_error_from_errno2("openat", subdirpath);
			free(subpath);
			free(subdirpath);
			return err;
		}

		subdir = fdopendir(subdirfd);
		if (subdir == NULL) {
			err = got_error_from_errno2("fdopendir", path);
			close(subdirfd);
			free(subpath);
			free(subdirpath);
			return err;
		}
		subdirfd = -1;
		err = read_dirlist(&subdirlist, subdir, subdirpath);
		if (err) {
			free(subpath);
			free(subdirpath);
			closedir(subdir);
			return err;
		}
		err = diff_fileindex_dir(fileindex, ie, &subdirlist,
		    dirfd(subdir), rootpath, subpath, repo, cb, cb_arg);
		if (subdir && closedir(subdir) == -1 && err == NULL)
			err = got_error_from_errno2("closedir", subdirpath);
		free(subpath);
		free(subdirpath);
		got_pathlist_free(&subdirlist, GOT_PATHLIST_FREE_DATA);
		if (err)
			return err;
	}

	*next = RB_NEXT(got_pathlist_head, dlh, dle);
	return NULL;
}

static const struct got_error *
dirent_type_fixup(struct dirent *de, const char *rootpath, const char *path)
{
	const struct got_error *err;
	char *dir_path;
	int type;

	if (de->d_type != DT_UNKNOWN)
		return NULL;

	/* DT_UNKNOWN occurs on NFS mounts without "readdir plus" RPC. */
	if (asprintf(&dir_path, "%s/%s", rootpath, path) == -1)
		return got_error_from_errno("asprintf");
	err = got_path_dirent_type(&type, dir_path, de);
	free(dir_path);
	if (err)
		return err;

	de->d_type = type;
	return NULL;
}

static const struct got_error *
diff_fileindex_dir(struct got_fileindex *fileindex,
    struct got_fileindex_entry **ie, struct got_pathlist_head *dirlist,
    int dirfd, const char *rootpath, const char *path,
    struct got_repository *repo,
    struct got_fileindex_diff_dir_cb *cb, void *cb_arg)
{
	const struct got_error *err = NULL;
	struct dirent *de = NULL;
	size_t path_len = strlen(path);
	struct got_pathlist_entry *dle;
	int ignore;

	if (cb->diff_traverse) {
		err = cb->diff_traverse(cb_arg, path, dirfd);
		if (err)
			return err;
	}

	dle = RB_MIN(got_pathlist_head, dirlist);
	while ((*ie && got_path_is_child((*ie)->path, path, path_len)) || dle) {
		if (dle && *ie) {
			char *de_path;
			int cmp;
			de = dle->data;
			err = dirent_type_fixup(de, rootpath, path);
			if (err)
				break;
			if (asprintf(&de_path, "%s/%s", path,
			    de->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				break;
			}
			cmp = got_path_cmp((*ie)->path, de_path,
			    got_fileindex_entry_path_len(*ie),
			    strlen(path) + 1 + strlen(de->d_name));
			free(de_path);
			if (cmp == 0) {
				err = cb->diff_old_new(cb_arg, *ie, de, path,
				    dirfd);
				if (err)
					break;
				*ie = walk_fileindex(fileindex, *ie);
				err = walk_dir(&dle, fileindex, ie, dle,
				    dirlist, dirfd, path, rootpath, repo, 0,
				    cb, cb_arg);
			} else if (cmp < 0) {
				err = cb->diff_old(cb_arg, *ie, path);
				if (err)
					break;
				*ie = walk_fileindex(fileindex, *ie);
			} else {
				err = cb->diff_new(&ignore, cb_arg, de, path,
				    dirfd);
				if (err)
					break;
				err = walk_dir(&dle, fileindex, ie, dle,
				    dirlist, dirfd, path, rootpath, repo,
				    ignore, cb, cb_arg);
			}
			if (err)
				break;
		} else if (*ie) {
			err = cb->diff_old(cb_arg, *ie, path);
			if (err)
				break;
			*ie = walk_fileindex(fileindex, *ie);
		} else if (dle) {
			de = dle->data;
			err = dirent_type_fixup(de, rootpath, path);
			if (err)
				break;
			err = cb->diff_new(&ignore, cb_arg, de, path, dirfd);
			if (err)
				break;
			err = walk_dir(&dle, fileindex, ie, dle, dirlist,
			    dirfd, path, rootpath, repo, ignore, cb, cb_arg);
			if (err)
				break;
		}
	}

	return err;
}

const struct got_error *
got_fileindex_diff_dir(struct got_fileindex *fileindex, int fd,
    const char *rootpath, const char *path, struct got_repository *repo,
    struct got_fileindex_diff_dir_cb *cb, void *cb_arg)
{
	const struct got_error *err;
	struct got_fileindex_entry *ie;
	struct got_pathlist_head dirlist;
	int fd2;
	DIR *dir;

	RB_INIT(&dirlist);

	/*
	 * Duplicate the file descriptor so we can call closedir() below
	 * without closing the file descriptor passed in by our caller.
	 */
	fd2 = dup(fd);
	if (fd2 == -1)
		return got_error_from_errno2("dup", path);
	if (lseek(fd2, 0, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", path);
		close(fd2);
		return err;
	}
	dir = fdopendir(fd2);
	if (dir == NULL) {
		err = got_error_from_errno2("fdopendir", path);
		close(fd2);
		return err;
	}
	err = read_dirlist(&dirlist, dir, path);
	if (err) {
		closedir(dir);
		return err;
	}

	ie = RB_MIN(got_fileindex_tree, &fileindex->entries);
	while (ie && !got_path_is_child(ie->path, path, strlen(path)))
		ie = walk_fileindex(fileindex, ie);
	err = diff_fileindex_dir(fileindex, &ie, &dirlist, dirfd(dir),
	    rootpath, path, repo, cb, cb_arg);

	if (closedir(dir) == -1 && err == NULL)
		err = got_error_from_errno2("closedir", path);
	got_pathlist_free(&dirlist, GOT_PATHLIST_FREE_DATA);
	return err;
}

struct got_object_id *
got_fileindex_entry_get_staged_blob_id(struct got_object_id *id,
    struct got_fileindex_entry *ie)
{
	return memcpy(id, &ie->staged_blob, sizeof(*id));
}

struct got_object_id *
got_fileindex_entry_get_blob_id(struct got_object_id *id,
    struct got_fileindex_entry *ie)
{
	return memcpy(id, &ie->blob, sizeof(*id));
}

struct got_object_id *
got_fileindex_entry_get_commit_id(struct got_object_id *id,
    struct got_fileindex_entry *ie)
{
	return memcpy(id, &ie->commit, sizeof(*id));
}

RB_GENERATE(got_fileindex_tree, got_fileindex_entry, entry, got_fileindex_cmp);
