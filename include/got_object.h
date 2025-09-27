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

enum got_hash_algorithm {
	GOT_HASH_SHA1,
	GOT_HASH_SHA256,
};

struct got_object_id {
	uint8_t hash[GOT_OBJECT_ID_MAXLEN];
	enum got_hash_algorithm algo;
};

struct got_blob_object;
struct got_tree_object;
struct got_tree_entry;
struct got_tag_object;
struct got_commit_object;

struct got_object_qid {
	STAILQ_ENTRY(got_object_qid) entry;
	struct got_object_id id;
	void *data; /* managed by API user */
};

STAILQ_HEAD(got_object_id_queue, got_object_qid);

const struct got_error *got_object_qid_alloc(struct got_object_qid **,
    struct got_object_id *);
void got_object_qid_free(struct got_object_qid *);
void got_object_id_queue_free(struct got_object_id_queue *);

/*
 * Deep-copy elements from ID queue src to ID queue dest. Do not copy any
 * qid->data pointers! This is the caller's responsibility if needed.
 */
const struct got_error *got_object_id_queue_copy(
    const struct got_object_id_queue *src, struct got_object_id_queue *dest);

/* Object types. */
#define GOT_OBJ_TYPE_ANY		0 /* wildcard value at run-time */
#define GOT_OBJ_TYPE_COMMIT		1
#define GOT_OBJ_TYPE_TREE		2
#define GOT_OBJ_TYPE_BLOB		3
#define GOT_OBJ_TYPE_TAG		4
/* 5 is reserved */
#define GOT_OBJ_TYPE_OFFSET_DELTA	6
#define GOT_OBJ_TYPE_REF_DELTA		7

/*
 * Labels used in object data.
 */

#define GOT_OBJ_LABEL_COMMIT	"commit"
#define GOT_OBJ_LABEL_TREE	"tree"
#define GOT_OBJ_LABEL_BLOB	"blob"
#define GOT_OBJ_LABEL_TAG	"tag"

#define GOT_COMMIT_LABEL_TREE		"tree "
#define GOT_COMMIT_LABEL_PARENT		"parent "
#define GOT_COMMIT_LABEL_AUTHOR		"author "
#define GOT_COMMIT_LABEL_COMMITTER	"committer "

#define GOT_TAG_LABEL_OBJECT		"object "
#define GOT_TAG_LABEL_TYPE		"type "
#define GOT_TAG_LABEL_TAG		"tag "
#define GOT_TAG_LABEL_TAGGER		"tagger "

struct got_repository;

/*
 * Obtain a string representation of an object ID. The output depends on
 * the hash function used by the repository format.
 */
const struct got_error *got_object_id_str(char **, struct got_object_id *);

/*
 * Compare two object IDs. Return value behaves like memcmp(3).
 */
int got_object_id_cmp(const struct got_object_id *,
    const struct got_object_id *);

/*
 * Created a newly allocated copy of an object ID.
 * The caller should dispose of it with free(3).
 */
struct got_object_id *got_object_id_dup(struct got_object_id *);

/*
 * Get a newly allocated ID of the object which resides at the specified
 * path in the specified tree.
 * The caller should dispose of it with free(3).
 */
const struct got_error *got_object_tree_find_path(struct got_object_id **id,
    mode_t *mode, struct got_repository *repo, struct got_tree_object *tree,
    const char *path);

/*
 * Get a newly allocated ID of the object which resides at the specified
 * path in the tree of the specified commit.
 * The caller should dispose of it with free(3).
 */
const struct got_error *got_object_id_by_path(struct got_object_id **,
    struct got_repository *, struct got_commit_object *, const char *);

/*
 * Obtain the type of an object.
 * Returns one of the GOT_OBJ_TYPE_x values (see above).
 */
const struct got_error *got_object_get_type(int *, struct got_repository *,
    struct got_object_id *);

/*
 * Attempt to resolve the textual representation of an object ID
 * to the ID of an existing object in the repository.
 * The caller should dispose of the ID with free(3).
 */
const struct got_error *got_object_resolve_id_str(struct got_object_id **,
    struct got_repository *, const char *);

/*
 * Attempt to open a commit object in a repository.
 * The caller must dispose of the commit with got_object_commit_close().
 */
const struct got_error *got_object_open_as_commit(struct got_commit_object **,
    struct got_repository *, struct got_object_id *);

/* Dispose of a commit object. */
void got_object_commit_close(struct got_commit_object *);

/* Obtain the ID of the tree created in a commit. */
struct got_object_id *got_object_commit_get_tree_id(struct got_commit_object *);

/* Obtain the number of parent commits of a commit. */
int got_object_commit_get_nparents(struct got_commit_object *);

/* Obtain the list of parent commits of a commit. */
const struct got_object_id_queue *got_object_commit_get_parent_ids(
    struct got_commit_object *);

/* Get the author's name and email address. */
const char *got_object_commit_get_author(struct got_commit_object *);

/* Get an author's commit timestamp in UTC. */
time_t got_object_commit_get_author_time(struct got_commit_object *);

/* Get an author's timezone offset. */
time_t got_object_commit_get_author_gmtoff(struct got_commit_object *);

/* Get the committer's name and email address. */
const char *got_object_commit_get_committer(struct got_commit_object *);

/* Get a committer's commit timestamp in UTC. */
time_t got_object_commit_get_committer_time(struct got_commit_object *);

/* Get a committer's timezone offset. */
time_t got_object_commit_get_committer_gmtoff(struct got_commit_object *);

/*
 * Get the commit log message.
 * PGP-signatures contained in the log message will be stripped.
 * The caller must dispose of it with free(3).
 */
const struct got_error *got_object_commit_get_logmsg(char **,
    struct got_commit_object *);

/* Get the raw commit log message.*/
const char *got_object_commit_get_logmsg_raw(struct got_commit_object *);

/*
 * Attempt to open a tree object in a repository.
 * The caller must dispose of the tree with got_object_tree_close().
 */
const struct got_error *got_object_open_as_tree(struct got_tree_object **,
    struct got_repository *, struct got_object_id *);

/* Dispose of a tree object. */
void got_object_tree_close(struct got_tree_object *);

/* Get the number of entries in this tree object. */
int got_object_tree_get_nentries(struct got_tree_object *);

/* Get the first tree entry from a tree, or NULL if there is none. */
struct got_tree_entry *got_object_tree_get_first_entry(
    struct got_tree_object *);

/* Get the last tree entry from a tree, or NULL if there is none. */
struct got_tree_entry *got_object_tree_get_last_entry(struct got_tree_object *);

/* Get the entry with the specified index from a tree object. */
struct got_tree_entry *got_object_tree_get_entry(
    struct got_tree_object *, int);

/* Find a particular entry in a tree by name. */
struct got_tree_entry *got_object_tree_find_entry(
    struct got_tree_object *, const char *);

/* Get the file permission mode of a tree entry. */
mode_t got_tree_entry_get_mode(struct got_tree_entry *);

/* Get the name of a tree entry. */
const char *got_tree_entry_get_name(struct got_tree_entry *);

/* Get the object ID of a tree entry. */
struct got_object_id *got_tree_entry_get_id(struct got_tree_entry *);

/*
 * Get a string containing the target path of a given a symlink tree entry.
 * The caller should dispose of it with free(3).
 */
const struct got_error *got_tree_entry_get_symlink_target(char **,
    struct got_tree_entry *, struct got_repository *);

/* Get the index of a tree entry. */
int got_tree_entry_get_index(struct got_tree_entry *);

/* Get the next tree entry from a tree, or NULL if there is none. */
struct got_tree_entry *got_tree_entry_get_next(struct got_tree_object *,
    struct got_tree_entry *);

/* Get the previous tree entry from a tree, or NULL if there is none. */
struct got_tree_entry *got_tree_entry_get_prev(struct got_tree_object *,
    struct got_tree_entry *);

/* Return non-zero if the specified tree entry is a Git submodule. */
int got_object_tree_entry_is_submodule(struct got_tree_entry *);

/* Return non-zero if the specified tree entry is a symbolic link. */
int got_object_tree_entry_is_symlink(struct got_tree_entry *);

/*
 * Resolve an in-repository symlink at the specified path in the tree
 * corresponding to the specified commit. If the specified path is not
 * a symlink then set *link_target to NULL.
 * Otherwise, resolve symlinks recursively and return the final link
 * target path. The caller must dispose of it with free(3).
 */
const struct got_error *got_object_resolve_symlinks(char **, const char *,
    struct got_commit_object *, struct got_repository *);

/*
 * Compare two trees and indicate whether the entry at the specified path
 * differs between them. The path must not be the root path "/"; the function
 * got_object_id_cmp() should be used instead to compare the tree roots.
 */
const struct got_error *got_object_tree_path_changed(int *,
    struct got_tree_object *, struct got_tree_object *, const char *,
    struct got_repository *);

/*
 * Attempt to open a blob object in a repository.
 * The size_t argument specifies the block size of an associated read buffer.
 * The caller must dispose of the blob with got_object_blob_close().
 */
const struct got_error *got_object_open_as_blob(struct got_blob_object **,
    struct got_repository *, struct got_object_id *, size_t, int);

/* Dispose of a blob object. */
const struct got_error *got_object_blob_close(struct got_blob_object *);

/*
 * Get the length of header data at the beginning of the blob's read buffer.
 * Note that header data is only present upon the first invocation of
 * got_object_blob_read_block() after the blob is opened.
 */
size_t got_object_blob_get_hdrlen(struct got_blob_object *);

/*
 * Get a pointer to the blob's read buffer.
 * The read buffer is filled by got_object_blob_read_block().
 */
const uint8_t *got_object_blob_get_read_buf(struct got_blob_object *);

/*
 * Read the next chunk of data from a blob, up to the blob's read buffer
 * block size. The size_t output argument indicates how many bytes have
 * been read into the blob's read buffer. Zero bytes will be reported if
 * all data in the blob has been read.
 */
const struct got_error *got_object_blob_read_block(size_t *,
    struct got_blob_object *);

/* Rewind an open blob's data stream back to the beginning. */
void got_object_blob_rewind(struct got_blob_object *);

/*
 * Heuristic to check whether the blob contains binary data.  Rewinds
 * the blob's data stream back after the header.
 */
const struct got_error *got_object_blob_is_binary(int *,
    struct got_blob_object *);

/*
 * getline(3) for blobs.
 */
const struct got_error *got_object_blob_getline(char **, ssize_t *,
    size_t *, struct got_blob_object *);

/*
 * Read the entire content of a blob and write it to the specified file.
 * Flush and rewind the file as well. Indicate the amount of bytes
 * written in the size_t output argument, and the number of lines in the
 * file in the int argument, and line offsets in the off_t argument
 * (NULL can be passed for any output argument).
 */
const struct got_error *got_object_blob_dump_to_file(off_t *, int *,
    off_t **, FILE *, struct got_blob_object *);

/*
 * Read the entire content of a blob into a newly allocated string buffer
 * and terminate it with '\0'. This is intended for blobs which contain a
 * symlink target path. It should not be used to process arbitrary blobs.
 * Use got_object_blob_dump_to_file() or got_tree_entry_get_symlink_target()
 * instead if possible. The caller must dispose of the string with free(3).
 */
const struct got_error *got_object_blob_read_to_str(char **,
    struct got_blob_object *);

/*
 * Attempt to open a tag object in a repository.
 * The caller must dispose of the tree with got_tag_object_close().
 */
const struct got_error *got_object_open_as_tag(struct got_tag_object **,
    struct got_repository *, struct got_object_id *);

/* Dispose of a tag object. */
void got_object_tag_close(struct got_tag_object *);

/* Get the name of a tag. */
const char *got_object_tag_get_name(struct got_tag_object *);

/* Get type of the object a tag points to. */
int got_object_tag_get_object_type(struct got_tag_object *);

/*
 * Get ID of the object a tag points to.
 * This must not be freed by the caller. Use got_object_id_dup() if needed.
 */
struct got_object_id *got_object_tag_get_object_id(struct got_tag_object *);


/* Get the timestamp of the tag. */
time_t got_object_tag_get_tagger_time(struct got_tag_object *);

/* Get the tag's timestamp's GMT offset.  */
time_t got_object_tag_get_tagger_gmtoff(struct got_tag_object *);

/* Get the author of the tag. */
const char *got_object_tag_get_tagger(struct got_tag_object *);

/* Get the tag message associated with the tag. */
const char *got_object_tag_get_message(struct got_tag_object *);

const struct got_error *got_object_commit_add_parent(struct got_commit_object *,
    const char *, enum got_hash_algorithm);

/* Create a new tag object in the repository. */
const struct got_error *got_object_tag_create(struct got_object_id **,
    const char *, struct got_object_id *, const char *,
    time_t, const char *, const char *, struct got_repository *, int verbosity);

/* Increment commit object reference counter. */
void got_object_commit_retain(struct got_commit_object *);
