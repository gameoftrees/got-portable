/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
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

#define GOT_GIT_DIR	".git"

/* Mandatory files and directories inside the git directory. */
#define GOT_OBJECTS_DIR		"objects"
#define GOT_REFS_DIR		"refs"
#define GOT_HEAD_FILE		"HEAD"
#define GOT_GITCONFIG		"config"

/* Other files and directories inside the git directory. */
#define GOT_FETCH_HEAD_FILE	"FETCH_HEAD"
#define GOT_ORIG_HEAD_FILE	"ORIG_HEAD"
#define GOT_OBJECTS_PACK_DIR	"objects/pack"
#define GOT_PACKED_REFS_FILE	"packed-refs"

#define GOT_PACK_CACHE_SIZE	32

/*
 * An open repository needs this many temporary files.
 * This limit sets an upper bound on how many raw objects or blobs can
 * be kept open in parallel.
 */
#define GOT_REPO_NUM_TEMPFILES 32

struct got_packidx_bloom_filter {
	RB_ENTRY(got_packidx_bloom_filter) entry;
	char path[PATH_MAX]; /* on-disk path */
	size_t path_len;
	struct bloom *bloom;
};

RB_HEAD(got_packidx_bloom_filter_tree, got_packidx_bloom_filter);

static inline int
got_packidx_bloom_filter_cmp(const struct got_packidx_bloom_filter *f1,
    const struct got_packidx_bloom_filter *f2)
{
	return got_path_cmp(f1->path, f2->path, f1->path_len, f2->path_len);
}

struct got_repo_privsep_child {
	int imsg_fd;
	pid_t pid;
	struct imsgbuf *ibuf;
};

struct got_repository {
	char *path;
	char *path_git_dir;
	int gitdir_fd;
	enum got_hash_algorithm algo;

	struct got_pathlist_head packidx_paths;
	struct timespec pack_path_mtime;

	/* The pack index cache speeds up search for packed objects. */
	struct got_packidx *packidx_cache[GOT_PACK_CACHE_SIZE];

	/*
	 * List of bloom filters for pack index files.
	 * Used to avoid opening a pack index in search of an
	 * object ID which is not contained in this pack index.
	 */
	struct got_packidx_bloom_filter_tree packidx_bloom_filters;

	/*
	 * Open file handles for pack files. Each struct got_pack uses
	 * a number of file descriptors. See struct got_pack for details.
	 */
	struct got_pack packs[GOT_PACK_CACHE_SIZE];

	/* Open file handles for temporary files. */
	int tempfiles[GOT_REPO_NUM_TEMPFILES];
	uint32_t tempfile_use_mask;

	/*
	 * The cache size limit may be lower than GOT_PACK_CACHE_SIZE,
	 * depending on resource limits.
	 */
	int pack_cache_size;

	/*
	 * Index to cache entries which are pinned to avoid eviction.
	 * This may be used to keep one got-index-pack process alive
	 * across searches for arbitrary objects which may be stored
	 * in other pack files.
	 */
	int pinned_pack;
	pid_t pinned_pid;
	int pinned_packidx;

	/* Handles to child processes for reading loose objects. */
	struct got_repo_privsep_child privsep_children[5];
#define GOT_REPO_PRIVSEP_CHILD_OBJECT	0
#define GOT_REPO_PRIVSEP_CHILD_COMMIT	1
#define GOT_REPO_PRIVSEP_CHILD_TREE	2
#define GOT_REPO_PRIVSEP_CHILD_BLOB	3
#define GOT_REPO_PRIVSEP_CHILD_TAG	4

	/* Caches for open objects. */
	struct got_object_cache objcache;
	struct got_object_cache treecache;
	struct got_object_cache commitcache;
	struct got_object_cache tagcache;
	struct got_object_cache rawcache;

	/* Settings read from Git configuration files. */
	int gitconfig_repository_format_version;
	char *gitconfig_author_name;
	char *gitconfig_author_email;
	char *global_gitconfig_author_name;
	char *global_gitconfig_author_email;
	int ngitconfig_remotes;
	struct got_remote_repo *gitconfig_remotes;
	char *gitconfig_owner;
	char **extnames;
	char **extvals;
	int nextensions;

	/* Settings read from got.conf. */
	struct got_gotconfig *gotconfig;

	/* cleanup lockfile */
	struct got_lockfile *cleanup_lock;
};

const struct got_error*got_repo_cache_object(struct got_repository *,
    struct got_object_id *, struct got_object *);
struct got_object *got_repo_get_cached_object(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_tree(struct got_repository *,
    struct got_object_id *, struct got_tree_object *);
struct got_tree_object *got_repo_get_cached_tree(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_commit(struct got_repository *,
    struct got_object_id *, struct got_commit_object *);
struct got_commit_object *got_repo_get_cached_commit(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_tag(struct got_repository *,
    struct got_object_id *, struct got_tag_object *);
struct got_tag_object *got_repo_get_cached_tag(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_raw_object(struct got_repository *,
    struct got_object_id *, struct got_raw_object *);
struct got_raw_object *got_repo_get_cached_raw_object(struct got_repository *,
    struct got_object_id *);
int got_repo_is_packidx_filename(const char *, size_t, enum got_hash_algorithm);
int got_repo_check_packidx_bloom_filter(struct got_repository *,
    const char *, struct got_object_id *);
const struct got_error *got_repo_search_packidx(struct got_packidx **, int *,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_repo_list_packidx(struct got_pathlist_head *,
    struct got_repository *);
const struct got_error *got_repo_get_packidx(struct got_packidx **, const char *,
    struct got_repository *);
const struct got_error *got_repo_cache_pack(struct got_pack **,
    struct got_repository *, const char *, struct got_packidx *);
struct got_pack *got_repo_get_cached_pack(struct got_repository *,
    const char *);
const struct got_error *got_repo_pin_pack(struct got_repository *,
    struct got_packidx *, struct got_pack *);
struct got_pack *got_repo_get_pinned_pack(struct got_repository *);
void got_repo_unpin_pack(struct got_repository *);

const struct got_error *got_repo_read_gitconfig(int *, char **, char **,
    struct got_remote_repo **, int *, char **, char ***, char ***, int *,
    const char *);

const struct got_error *got_repo_temp_fds_get(int *, int *,
    struct got_repository *);
void got_repo_temp_fds_put(int, struct got_repository *);

const struct got_error *got_repo_find_object_id(struct got_object_id *,
    struct got_repository *);
void got_repo_free_gitconfig(struct got_repository *);
