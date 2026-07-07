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

struct got_worktree;
struct got_commitable;
struct got_commit_object;
struct got_fileindex;

/* status codes */
#define GOT_STATUS_NO_CHANGE	' '
#define GOT_STATUS_ADD		'A'
#define GOT_STATUS_EXISTS	'E'
#define GOT_STATUS_UPDATE	'U'
#define GOT_STATUS_DELETE	'D'
#define GOT_STATUS_MODIFY	'M'
#define GOT_STATUS_MODE_CHANGE	'm'
#define GOT_STATUS_CONFLICT	'C'
#define GOT_STATUS_MERGE	'G'
#define GOT_STATUS_MISSING	'!'
#define GOT_STATUS_UNVERSIONED	'?'
#define GOT_STATUS_OBSTRUCTED	'~'
#define GOT_STATUS_NONEXISTENT	'N'
#define GOT_STATUS_REVERT	'R'
#define GOT_STATUS_CANNOT_DELETE 'd'
#define GOT_STATUS_BUMP_BASE	'b'
#define GOT_STATUS_BASE_REF_ERR	'B'
#define GOT_STATUS_CANNOT_UPDATE '#'

/* Also defined in got_lib_worktree.h in case got_worktree.h is not included. */
#define GOT_WORKTREE_GOT_DIR		".got"
#define GOT_WORKTREE_CVG_DIR		".cvg"

/*
 * Attempt to initialize a new work tree on disk.
 * The first argument is the path to a directory where the work tree
 * will be created. The path itself must not yet exist, but the dirname(3)
 * of the path must already exist.
 * The reference provided will be used to determine the new worktree's
 * base commit. The third argument specifies the work tree's path prefix.
 * The fourth argument specifies the meta data directory to use, which
 * should be either GOT_WORKTREE_GOT_DIR or GOT_WORKTREE_CVG_DIR.
 */
const struct got_error *got_worktree_init(const char *, struct got_reference *,
    const char *, const char *, struct got_repository *);

/*
 * Attempt to open a worktree at or above the specified path, using
 * the specified meta data directory which should be either be NULL
 * in which case a meta directory is auto-discovered, or be one of
 * GOT_WORKTREE_GOT_DIR and GOT_WORKTREE_CVG_DIR.
 * The caller must dispose of it with got_worktree_close().
 */
const struct got_error *got_worktree_open(struct got_worktree **,
    const char *path, const char *meta_dir);

/* Dispose of an open work tree. */
const struct got_error *got_worktree_close(struct got_worktree *);

/*
 * Get the path to the root directory of a worktree.
 */
const char *got_worktree_get_root_path(struct got_worktree *);

/*
 * Get the path to the repository associated with a worktree.
 */
const char *got_worktree_get_repo_path(struct got_worktree *);

/*
 * Get the path prefix associated with a worktree.
 */
const char *got_worktree_get_path_prefix(struct got_worktree *);

/*
 * Get the UUID of a work tree as a string.
 * The caller must dispose of the returned UUID string with free(3).
 */
const struct got_error *got_worktree_get_uuid(char **, struct got_worktree *);

/*
 * Get the work tree's format version number.
 */
int got_worktree_get_format_version(struct got_worktree *);

/*
 * Check if a user-provided path prefix matches that of the worktree.
 */
const struct got_error *got_worktree_match_path_prefix(int *,
    struct got_worktree *, const char *);

/*
 * Prefix for references pointing at base commit of backout/cherrypick commits.
 * Reference path takes the form: PREFIX-WORKTREE_UUID-COMMIT_ID
 */
#define GOT_WORKTREE_CHERRYPICK_REF_PREFIX	"refs/got/worktree/cherrypick"
#define GOT_WORKTREE_BACKOUT_REF_PREFIX		"refs/got/worktree/backout"

#define GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN		\
	sizeof(GOT_WORKTREE_CHERRYPICK_REF_PREFIX) - 1
#define GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN		\
	sizeof(GOT_WORKTREE_BACKOUT_REF_PREFIX) - 1
#define GOT_WORKTREE_UUID_STRLEN	36

const struct got_error *got_worktree_get_logmsg_ref_name(char **,
    struct got_worktree *, const char *);
/*
 * Get the name of a work tree's HEAD reference.
 */
const char *got_worktree_get_head_ref_name(struct got_worktree *);

/*
 * Set the branch head reference of the work tree.
 */
const struct got_error *got_worktree_set_head_ref(struct got_worktree *,
    struct got_reference *);

/*
 * Get the current base commit ID of a worktree.
 */
struct got_object_id *got_worktree_get_base_commit_id(struct got_worktree *);

/*
 * Set the base commit Id of a worktree.
 */
const struct got_error *got_worktree_set_base_commit_id(struct got_worktree *,
    struct got_repository *, struct got_object_id *);

/*
 * Get the state of the work tree. If the work tree's global base commit is
 * the tip of the work tree's current branch, and each file in the index is
 * based on this same commit, the char out parameter will be
 * GOT_WORKTREE_STATE_UPTODATE, else it will be GOT_WORKTREE_STATE_OUTOFDATE.
 */
const struct got_error *got_worktree_get_state(char *,
    struct got_repository *, struct got_worktree *,
    got_cancel_cb, void *);

#define GOT_WORKTREE_STATE_UNKNOWN	' '
#define GOT_WORKTREE_STATE_UPTODATE	'*'
#define GOT_WORKTREE_STATE_OUTOFDATE	'~'

/*
 * Obtain a parsed representation of this worktree's got.conf file.
 * Return NULL if this configuration file could not be read.
 */
const struct got_gotconfig *got_worktree_get_gotconfig(struct got_worktree *);

/* A callback function which is invoked when a path is checked out. */
typedef const struct got_error *(*got_worktree_checkout_cb)(void *,
    unsigned char, const char *);

/* A callback function which is invoked when a path is removed. */
typedef const struct got_error *(*got_worktree_delete_cb)(void *,
    unsigned char, unsigned char, const char *);

/*
 * Attempt to check out files into a work tree from its associated repository
 * and path prefix, and update the work tree's file index accordingly.
 * File content is obtained from blobs within the work tree's path prefix
 * inside the tree corresponding to the work tree's base commit.
 * The checkout progress callback will be invoked with the provided
 * void * argument, and the path of each checked out file.
 *
 * It is possible to restrict the checkout operation to specific paths in
 * the work tree, in which case all files outside those paths will remain at
 * their currently recorded base commit. Inconsistent base commits can be
 * repaired later by running another update operation across the entire work
 * tree. Inconsistent base-commits may also occur if this function runs into
 * an error or if the checkout operation is cancelled by the cancel callback.
 * Allspecified paths are relative to the work tree's root. Pass a pathlist
 * with a single empty path "" to check out files across the entire work tree.
 *
 * Some operations may refuse to run while the work tree contains files from
 * multiple base commits.
 */
const struct got_error *got_worktree_checkout_files(struct got_worktree *,
    struct got_pathlist_head *, struct got_repository *,
    got_worktree_checkout_cb, void *, got_cancel_cb, void *);

/* Merge the differences between two commits into a work tree. */
const struct got_error *
got_worktree_merge_files(struct got_worktree *,
    struct got_object_id *, struct got_object_id *,
    struct got_repository *, got_worktree_checkout_cb, void *,
    got_cancel_cb, void *);

/*
 * A callback function which is invoked to report a file's status.
 *
 * If a valid directory file descriptor and a directory entry name are passed,
 * these should be used to open the file instead of opening the file by path.
 * This prevents race conditions if the filesystem is modified concurrently.
 * If the directory descriptor is not available then its value will be -1.
 */
typedef const struct got_error *(*got_worktree_status_cb)(void *,
    unsigned char, unsigned char, const char *, struct got_object_id *,
    struct got_object_id *, struct got_object_id *, int, const char *);

/*
 * Report the status of paths in the work tree.
 * The status callback will be invoked with the provided void * argument,
 * a path, and a corresponding status code.
 */
const struct got_error *got_worktree_status(struct got_worktree *,
    struct got_pathlist_head *, struct got_repository *, int no_ignores,
    got_worktree_status_cb, void *, got_cancel_cb cancel_cb, void *);

/*
 * Try to resolve a user-provided path to an on-disk path in the work tree.
 * The caller must dispose of the resolved path with free(3).
 */
const struct got_error *got_worktree_resolve_path(char **,
    struct got_worktree *, const char *);

/* Schedule files at on-disk paths for addition in the next commit. */
const struct got_error *got_worktree_schedule_add(struct got_worktree *,
    struct got_pathlist_head *, got_worktree_checkout_cb, void *,
    struct got_repository *, int);

/*
 * Remove files from disk and schedule them to be deleted in the next commit.
 * Don't allow deleting files with uncommitted modifications, unless the
 * parameter 'delete_local_mods' is set.
 */
const struct got_error *
got_worktree_schedule_delete(struct got_worktree *,
    struct got_pathlist_head *, int, const char *,
    got_worktree_delete_cb, void *, struct got_repository *, int, int, int);

/* A callback function which is used to select or reject a patch. */
typedef const struct got_error *(*got_worktree_patch_cb)(int *, void *,
    unsigned char, const char *, FILE *, int, int);

/* Values for result output parameter of got_wortree_patch_cb. */
#define GOT_PATCH_CHOICE_NONE	0
#define GOT_PATCH_CHOICE_YES	1
#define GOT_PATCH_CHOICE_NO	2
#define GOT_PATCH_CHOICE_QUIT	3

/*
 * Revert a file at the specified path such that it matches its
 * original state in the worktree's base commit.
 * If the patch callback is not NULL, call it to select patch hunks to
 * revert. Otherwise, revert the whole file found at each path.
 */
const struct got_error *got_worktree_revert(struct got_worktree *,
    struct got_pathlist_head *, got_worktree_checkout_cb, void *,
    got_worktree_patch_cb patch_cb, void *patch_arg,
    struct got_repository *);

/*
 * A callback function which is invoked when a commit message is requested.
 * Passes a pathlist with a struct got_commitable * in the data pointer of
 * each element, the path to a file which contains a diff of changes to be
 * committed (may be NULL), and a pointer to the log message that must be
 * set by the callback and will be freed after committing, and an argument
 * passed through to the callback.
 */
typedef const struct got_error *(*got_worktree_commit_msg_cb)(
    struct got_pathlist_head *, const char *, char **, void *);

/*
 * Create a new commit from changes in the work tree.
 * Return the ID of the newly created commit.
 * The worktree's base commit will be set to this new commit.
 * Files unaffected by this commit operation will retain their
 * current base commit.
 * An author and a non-empty log message must be specified.
 * The name of the committer is optional (may be NULL).
 * An optional author timestamp can be specified. The current time will
 * be used if the specified timestamp is 0.
 * If a path to be committed contains a symlink which points outside
 * of the path space under version control, raise an error unless
 * committing of such paths is being forced by the caller.
 */
const struct got_error *got_worktree_commit(struct got_object_id **,
    struct got_worktree *, struct got_pathlist_head *, const char *, time_t,
    const char *, int, int, int, got_worktree_commit_msg_cb, void *,
    got_worktree_status_cb, void *, struct got_repository *);

/* Get the path of a committable worktree item. */
const char *got_commitable_get_path(struct got_commitable *);

/* Get the status of a committable worktree item. */
unsigned int got_commitable_get_status(struct got_commitable *);

/*
 * Prepare for rebasing a branch onto the work tree's current branch.
 * This function creates references to a temporary branch, the branch
 * being rebased, and the work tree's current branch, under the
 * "got/worktree/rebase/" namespace. These references are used to
 * keep track of rebase operation state and are used as input and/or
 * output arguments with other rebase-related functions.
 * The function also returns a pointer to a fileindex which must be
 * passed back to other rebase-related functions.
 */
const struct got_error *got_worktree_rebase_prepare(struct got_reference **,
    struct got_reference **, struct got_fileindex **, struct got_worktree *,
    struct got_reference *, struct got_repository *);

/*
 * Continue an interrupted rebase operation.
 * This function returns existing references created when rebase was prepared,
 * and the ID of the commit currently being rebased. This should be called
 * before either resuming or aborting a rebase operation.
 * The function also returns a pointer to a fileindex which must be
 * passed back to other rebase-related functions.
 */
const struct got_error *got_worktree_rebase_continue(struct got_object_id **,
    struct got_reference **, struct got_reference **, struct got_reference **,
    struct got_fileindex **, struct got_worktree *, struct got_repository *);

/* Check whether a, potentially interrupted, rebase operation is in progress. */
const struct got_error *got_worktree_rebase_in_progress(int *,
    struct got_worktree *);
/* Return information about an in-progress rebase operation. */
const struct got_error *got_worktree_rebase_info(char **new_base_branch_name,
    char **branch_name, struct got_worktree *, struct got_repository *);

/*
 * Merge changes from the commit currently being rebased into the work tree.
 * Report affected files, including merge conflicts, via the specified
 * progress callback. Also populate a list of affected paths which should
 * be passed to got_worktree_rebase_commit() after a conflict-free merge.
 * This list must be initialized with TAILQ_INIT() and disposed of with
 * got_pathlist_free(list, GOT_PATHLIST_FREE_PATH).
 */
const struct got_error *got_worktree_rebase_merge_files(
    struct got_pathlist_head *, struct got_worktree *, struct got_fileindex *,
    struct got_object_id *, struct got_object_id *, struct got_repository *,
    got_worktree_checkout_cb, void *, got_cancel_cb, void *);

/*
 * Commit changes merged by got_worktree_rebase_merge_files() to a temporary
 * branch and return the ID of the newly created commit. An optional list of
 * merged paths can be provided; otherwise this function will perform a status
 * crawl across the entire work tree to find paths to commit.
 */
const struct got_error *got_worktree_rebase_commit(struct got_object_id **,
    struct got_pathlist_head *, struct got_worktree *, struct got_fileindex *,
    struct got_reference *, const char *, struct got_commit_object *,
    struct got_object_id *, int, struct got_repository *);

/* Postpone the rebase operation. Should be called after a merge conflict. */
const struct got_error *got_worktree_rebase_postpone(struct got_worktree *,
    struct got_fileindex *);

/*
 * Complete the current rebase operation. This should be called once all
 * commits have been rebased successfully.
 * The create_backup parameter controls whether the rebased branch will
 * be backed up via a reference in refs/got/backup/rebase/.
 */
const struct got_error *got_worktree_rebase_complete(struct got_worktree *,
    struct got_fileindex *, struct got_reference *, struct got_reference *,
    struct got_repository *, int create_backup);

/*
 * Abort the current rebase operation.
 * Report reverted files via the specified progress callback.
 */
const struct got_error *got_worktree_rebase_abort(struct got_worktree *,
    struct got_fileindex *, struct got_repository *, struct got_reference *,
    got_worktree_checkout_cb, void *);

/*
 * Prepare for editing the history of the work tree's current branch.
 * This function creates references to a temporary branch, and the
 * work tree's current branch, under the "got/worktree/histedit/" namespace.
 * These references are used to keep track of histedit operation state and
 * are used as input and/or output arguments with other histedit-related
 * functions.
 */
const struct got_error *got_worktree_histedit_prepare(struct got_reference **,
    struct got_reference **, struct got_object_id **, struct got_fileindex **,
    struct got_worktree *, struct got_repository *);

/*
 * Continue an interrupted histedit operation.
 * This function returns existing references created when histedit was
 * prepared and the ID of the commit currently being edited.
 * It should be called before resuming or aborting a histedit operation.
 */
const struct got_error *got_worktree_histedit_continue(struct got_object_id **,
    struct got_reference **, struct got_reference **, struct got_object_id **,
    struct got_fileindex **, struct got_worktree *, struct got_repository *);

/* Check whether a histedit operation is in progress. */
const struct got_error *got_worktree_histedit_in_progress(int *,
    struct got_worktree *);
/* Return information about an in-progress histedit operation. */
const struct got_error *got_worktree_histedit_info(
    char **branch_nane, struct got_worktree *,
    struct got_repository *);

/*
 * Merge changes from the commit currently being edited into the work tree.
 * Report affected files, including merge conflicts, via the specified
 * progress callback. Also populate a list of affected paths which should
 * be passed to got_worktree_histedit_commit() after a conflict-free merge.
 * This list must be initialized with TAILQ_INIT() and disposed of with
 * got_pathlist_free(list, GOT_PATHLIST_FREE_PATH).
 */
const struct got_error *got_worktree_histedit_merge_files(
    struct got_pathlist_head *, struct got_worktree *, struct got_fileindex *,
    struct got_object_id *, struct got_object_id *, struct got_repository *,
    got_worktree_checkout_cb, void *, got_cancel_cb, void *);

/*
 * Commit changes merged by got_worktree_histedit_merge_files() to a temporary
 * branch and return the ID of the newly created commit. An optional list of
 * merged paths can be provided; otherwise this function will perform a status
 * crawl across the entire work tree to find paths to commit.
 * An optional log message can be provided which will be used instead of the
 * commit's original message.
 */
const struct got_error *got_worktree_histedit_commit(struct got_object_id **,
    struct got_pathlist_head *, struct got_worktree *, struct got_fileindex *,
    struct got_reference *, const char *, struct got_commit_object *,
    struct got_object_id *, const char *, int, struct got_repository *);

/*
 * Record the specified commit as skipped during histedit.
 * This should be called for commits which get dropped or get folded into
 * a subsequent commit.
 */
const struct got_error *got_worktree_histedit_skip_commit(struct got_worktree *,
    struct got_object_id *, struct got_repository *);

/* Postpone the histedit operation. */
const struct got_error *got_worktree_histedit_postpone(struct got_worktree *,
    struct got_fileindex *);

/*
 * Complete the current histedit operation. This should be called once all
 * commits have been edited successfully.
 */
const struct got_error *got_worktree_histedit_complete(struct got_worktree *,
    struct got_fileindex *, struct got_reference *, struct got_reference *,
    struct got_repository *);

/*
 * Abort the current histedit operation.
 * Report reverted files via the specified progress callback.
 */
const struct got_error *got_worktree_histedit_abort(struct got_worktree *,
    struct got_fileindex *, struct got_repository *, struct got_reference *,
    struct got_object_id *, got_worktree_checkout_cb, void *, int);

/* Get the path to this work tree's histedit script file. */
const struct got_error *got_worktree_get_histedit_script_path(char **,
    struct got_worktree *);

/*
 * Prepare a work tree for integrating a branch.
 * Return pointers to a fileindex and locked references which must be
 * passed back to other integrate-related functions.
 */
const struct got_error *
got_worktree_integrate_prepare(struct got_fileindex **,
    struct got_reference **, struct got_reference **,
    struct got_worktree *, const char *, struct got_repository *);

/*
 * Carry out a prepared branch integration operation.
 * Report affected files via the specified progress callback.
 */
const struct got_error *got_worktree_integrate_continue(
    struct got_worktree *, struct got_fileindex *, struct got_repository *,
    struct got_reference *, struct got_reference *,
    got_worktree_checkout_cb, void *, got_cancel_cb, void *);

/* Abort a prepared branch integration operation. */
const struct got_error *got_worktree_integrate_abort(struct got_worktree *,
    struct got_fileindex *, struct got_repository *,
    struct got_reference *, struct got_reference *);

/* Postpone the merge operation. Should be called after a merge conflict. */
const struct got_error *got_worktree_merge_postpone(struct got_worktree *,
    struct got_fileindex *);

/* Merge changes from the merge source branch into the worktree. */
const struct got_error *
got_worktree_merge_branch(struct got_worktree *worktree,
    struct got_fileindex *fileindex,
    struct got_object_id *yca_commit_id,
    struct got_object_id *branch_tip,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg);

/* Attempt to commit merged changes. */
const struct got_error *
got_worktree_merge_commit(struct got_object_id **new_commit_id,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    const char *author, time_t author_time, const char *committer,
    int allow_bad_symlinks, struct got_object_id *branch_tip,
    const char *branch_name, int allow_conflict, struct got_repository *repo,
    got_worktree_status_cb status_cb, void *status_arg);

/*
 * Complete the merge operation.
 * This should be called once changes have been successfully committed.
 */
const struct got_error *got_worktree_merge_complete(
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_repository *repo);

/* Check whether a merge operation is in progress. */
const struct got_error *got_worktree_merge_in_progress(int *,
    struct got_worktree *, struct got_repository *);
/* Return information about an in-progress merge operation. */
const struct got_error *
got_worktree_merge_info(char **branch_name, struct got_worktree *,
    struct got_repository *);

/*
 * Prepare for merging a branch into the work tree's current branch: lock the
 * worktree and check that preconditions are satisfied. The function also
 * returns a pointer to a fileindex which must be passed back to other
 * merge-related functions.
 */
const struct got_error *got_worktree_merge_prepare(struct got_fileindex **,
    struct got_worktree *, struct got_repository *);

/*
 * This function creates a reference to the branch being merged, and to
 * this branch's current tip commit, in the "got/worktree/merge/" namespace.
 * These references are used to keep track of merge operation state and are
 * used as input and/or output arguments with other merge-related functions.
 */
const struct got_error *got_worktree_merge_write_refs(struct got_worktree *,
    struct got_reference *, struct got_repository *);

/*
 * Continue an interrupted merge operation.
 * This function returns name of the branch being merged, and the ID of the
 * tip commit being merged.
 * This function should be called before either resuming or aborting a
 * merge operation.
 * The function also returns a pointer to a fileindex which must be
 * passed back to other merge-related functions.
 */
const struct got_error *got_worktree_merge_continue(char **,
    struct got_object_id **, struct got_fileindex **,
    struct got_worktree *, struct got_repository *);

/*
 * Abort the current rebase operation.
 * Report reverted files via the specified progress callback.
 */
const struct got_error *got_worktree_merge_abort(struct got_worktree *,
    struct got_fileindex *, struct got_repository *,
    got_worktree_checkout_cb, void *);

/*
 * Stage the specified paths for commit.
 * If the patch callback is not NULL, call it to select patch hunks for
 * staging. Otherwise, stage the full file content found at each path.
 * If a path being staged contains a symlink which points outside
 * of the path space under version control, raise an error unless
 * staging of such paths is being forced by the caller.
 */
const struct got_error *got_worktree_stage(struct got_worktree *,
    struct got_pathlist_head *, got_worktree_status_cb, void *,
    got_worktree_patch_cb, void *, int, struct got_repository *);

/*
 * Merge staged changes for the specified paths back into the work tree
 * and mark the paths as non-staged again.
 */
const struct got_error *got_worktree_unstage(struct got_worktree *,
    struct got_pathlist_head *, got_worktree_checkout_cb, void *,
    got_worktree_patch_cb, void *, struct got_repository *);

/*
 * Prepare for getting meta data for paths in the work tree.  This
 * function also returns a pointer to a fileindex which must be passed
 * back to other path_info-related functions and *_version() functions.
 */
const struct got_error *
got_worktree_path_info_prepare(struct got_fileindex **,
    struct got_worktree *, struct got_repository *);

/*
 * Get the file-index version.
 */
uint32_t
got_worktree_get_fileindex_version(struct got_fileindex *);

/* A callback function which is invoked with per-path info. */
typedef const struct got_error *(*got_worktree_path_info_cb)(void *,
    const char *path, mode_t mode, time_t mtime,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id);

/*
 * Report work-tree meta data for paths in the work tree.
 * The info callback will be invoked with the provided void * argument,
 * a path, and meta-data arguments (see got_worktree_path_info_cb).
 */
const struct got_error *
got_worktree_path_info(struct got_worktree *, struct got_fileindex *,
    struct got_pathlist_head *, got_worktree_path_info_cb, void *,
    got_cancel_cb , void *);

/*
 * Complete the current path_info operation.
 */
const struct got_error *
got_worktree_path_info_complete(struct got_fileindex *, struct got_worktree *);

/* References pointing at pre-rebase commit backups. */
#define GOT_WORKTREE_REBASE_BACKUP_REF_PREFIX "refs/got/backup/rebase"

/* References pointing at pre-histedit commit backups. */
#define GOT_WORKTREE_HISTEDIT_BACKUP_REF_PREFIX "refs/got/backup/histedit"

/*
 * Prepare for applying a patch.
 */
const struct got_error *
got_worktree_patch_prepare(struct got_fileindex **, char **,
    struct got_worktree *, struct got_repository *);

/*
 * Lookup paths for the "old" and "new" file before patching and check their
 * status.
 */
const struct got_error *
got_worktree_patch_check_path(const char *, const char *, char **, char **,
    struct got_worktree *, struct got_repository *, struct got_fileindex *);

const struct got_error *
got_worktree_patch_schedule_add(const char *, struct got_repository *,
    struct got_worktree *, struct got_fileindex *, got_worktree_checkout_cb,
    void *);

const struct got_error *
got_worktree_patch_schedule_rm(const char *, struct got_repository *,
    struct got_worktree *, struct got_fileindex *, got_worktree_delete_cb,
    void *);

/* Complete the patch operation. */
const struct got_error *
got_worktree_patch_complete(struct got_worktree *, struct got_fileindex *,
    const char *);
