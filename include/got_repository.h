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

struct got_repository;
struct got_pathlist_head;
struct got_tag_object;

/* Open and close repositories. */
const struct got_error *got_repo_open(struct got_repository**, const char *,
    const char *, int *);
const struct got_error *got_repo_close(struct got_repository*);

/* Obtain the on-disk path to the repository. */
const char *got_repo_get_path(struct got_repository *);

/*
 * Obtain the path to a non-bare repository's .git directory.
 * For bare repositories, this returns the same result as got_repo_get_path().
 */
const char *got_repo_get_path_git_dir(struct got_repository *);

/* Obtain the file descriptor of the repository's .git directory. */
int got_repo_get_fd(struct got_repository *);

/* Obtain the object format */
enum got_hash_algorithm got_repo_get_object_format(struct got_repository *);

/* Obtain the commit author name if parsed from gitconfig, else NULL. */
const char *got_repo_get_gitconfig_author_name(struct got_repository *);

/* Obtain the commit author email if parsed from gitconfig, else NULL. */
const char *got_repo_get_gitconfig_author_email(struct got_repository *);

/* Obtain global commit author name parsed ~/.gitconfig, else NULL. */
const char *got_repo_get_global_gitconfig_author_name(struct got_repository *);

/* Obtain global commit author email parsed ~/.gitconfig, else NULL. */
const char *got_repo_get_global_gitconfig_author_email(struct got_repository *);

/* Obtain repository owner name if parsed from gitconfig, else NULL. */
const char *got_repo_get_gitconfig_owner(struct got_repository *);

/* Query if a given Git extension is enabled in gitconfig. */
int got_repo_has_extension(struct got_repository *, const char *);

/* Information about one remote repository. */
struct got_remote_repo {
	char *name;
	char *fetch_url;
	char *send_url;

	/*
	 * If set, fetched references are mirrored 1:1 into our repository.
	 * If not set, references are mapped into "refs/remotes/$name/".
	 */
	int mirror_references;

	/*
	 * If set, fetch all branches by default and ignore the list of
	 * branches below.
	 */
	int fetch_all_branches;

	/* Branches to fetch by default. */
	int nfetch_branches;
	char **fetch_branches;

	/* Branches to send by default. */
	int nsend_branches;
	char **send_branches;

	/* Other arbitrary references to fetch by default. */
	int nfetch_refs;
	char **fetch_refs;
};

/*
 * Return a deep copy of a given remote_repo. The result should be
 * freed with got_repo_free_remote_repo_data() and then free(3).
 * Return NULL on failure.
 */
const struct got_error *got_repo_remote_repo_dup(struct got_remote_repo **,
    const struct got_remote_repo *);

/*
 * Free data allocated for the specified remote repository.
 * Do not free the remote_repo pointer itself.
 */
void got_repo_free_remote_repo_data(struct got_remote_repo *);

/* Obtain the list of remote repositories parsed from gitconfig. */
void got_repo_get_gitconfig_remotes(int *, const struct got_remote_repo **,
    struct got_repository *);

/*
 * Obtain a parsed representation of this repository's got.conf file.
 * Return NULL if this configuration file could not be read.
 */
const struct got_gotconfig *got_repo_get_gotconfig(struct got_repository *);

/*
 * Obtain paths to various directories within a repository.
 * The caller must dispose of a path with free(3).
 */
char *got_repo_get_path_objects(struct got_repository *);
char *got_repo_get_path_objects_pack(struct got_repository *);
char *got_repo_get_path_refs(struct got_repository *);
char *got_repo_get_path_packed_refs(struct got_repository *);
char *got_repo_get_path_gitconfig(struct got_repository *);
char *got_repo_get_path_gotconfig(struct got_repository *);

struct got_reference;
struct got_reflist_head;

/*
 * Obtain a reference, by name, from a repository.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error *got_repo_get_reference(struct got_reference **,
    struct got_repository *, const char *);


/* Indicate whether this is a bare repositiry (contains no git working tree). */
int got_repo_is_bare(struct got_repository *);

/*
 * Attempt to map an input path to a path within the repository.
 *
 * This is useful in cases where the input path might be an on-disk path
 * found in a non-bare Git repository, e.g. when a tab-completed path to
 * a versioned file in a non-bare Git repository is passed to commands
 * such as 'got log' in absolute or relative form.
 * In such cases, the corresponding repository-relative path is returned.
 *
 * If the input path is not located in a non-bare Git repository, the
 * input path is made absolute but is otherwise returned as-is.
 */
const struct got_error *got_repo_map_path(char **, struct got_repository *,
    const char *);

/*
 * Create a new repository with optional specified
 * HEAD ref in an empty directory at a specified path.
 */
const struct got_error *got_repo_init(const char *, const char *,
    enum got_hash_algorithm);

/*
 * Create a new config file for git in the specified repository,
 * resetting parameters such as the object Id hash algorithm.
 * Should only be used if the repository is freshly cloned and has
 * wrong setings in the existing configuration file.
 */
const struct got_error *got_repo_init_gitconfig(struct got_repository *,
    enum got_hash_algorithm);

/* Attempt to find a unique object ID for a given ID string prefix. */
const struct got_error *got_repo_match_object_id_prefix(struct got_object_id **,
    const char *, int, struct got_repository *);

/*
 * Given an object ID string or reference name, attempt to find a corresponding
 * object.
 * The object type may be restricted to commit, tree, blob, or tag.
 * Tags will only be matched if a list of references is provided.
 * GOT_OBJ_TYPE_ANY will match any type of object.
 * A human-readable label can optionally be returned, which the caller should
 * dispose of with free(3).
 * Return GOT_ERR_NO_OBJ if no matching commit can be found.
 */
const struct got_error *got_repo_match_object_id(struct got_object_id **,
    char **, const char *, int, struct got_reflist_head *,
    struct got_repository *);

/*
 * Search the provided list of references for a tag with a given name
 * and target object type.
 * Return GOT_ERR_NO_OBJ if no matching tag can be found.
 */
const struct got_error *got_repo_object_match_tag(struct got_tag_object **,
    const char *, int, struct got_reflist_head *, struct got_repository *);

/* A callback function which is invoked when a path is imported. */
typedef const struct got_error *(*got_repo_import_cb)(void *, const char *);

/*
 * Import an unversioned directory tree into the repository.
 * Creates a root commit, i.e. a commit with zero parents.
 */
const struct got_error *got_repo_import(struct got_object_id **, const char *,
    const char *, const char *, struct got_pathlist_head *,
    struct got_repository *, got_repo_import_cb, void *);

/* Obtain the number and size of loose objects in the repository. */
const struct got_error *got_repo_get_loose_object_info(int *nobjects,
    off_t *ondisk_size, struct got_repository *);

/* Obtain the number and size of packed objects in the repository. */
const struct got_error *got_repo_get_packfile_info(int *npackfiles,
    int *nobjects, off_t *total_packsize, struct got_repository *);

/* Create an array of file descriptors to hand over to got_repo_open for pack */
const struct got_error *got_repo_pack_fds_open(int **);

/* Close the array of file descriptors handed over to got_repo_open for pack */
const struct got_error *got_repo_pack_fds_close(int *);

/* Open/set/close temporary files for internal use. Needed by gotd(8). */
const struct got_error *got_repo_temp_fds_open(int **);
void got_repo_temp_fds_set(struct got_repository *, int *);
const struct got_error *got_repo_temp_fds_close(int *);
