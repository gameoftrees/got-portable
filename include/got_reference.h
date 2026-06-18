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

/* A reference which points to an arbitrary object. */
struct got_reference;

/* Well-known reference names. */
#define GOT_REF_HEAD		"HEAD"
#define GOT_REF_ORIG_HEAD	"ORIG_HEAD"
#define GOT_REF_MERGE_HEAD	"MERGE_HEAD"
#define GOT_REF_FETCH_HEAD	"FETCH_HEAD"

struct got_repository;
struct got_object_id;

/* Determine whether a given reference name is valid. */
int got_ref_name_is_valid(const char *);

/*
 * Attempt to open the reference with the provided name in a repository.
 * The caller must dispose of the reference with got_ref_close().
 * Optionally, the underlying reference file can be locked before it is opened
 * to prevent concurrent modification of the reference, in which case the file
 * must be unlocked with got_ref_unlock() before got_ref_close() is called.
 */
const struct got_error *got_ref_open(struct got_reference **,
    struct got_repository *, const char *, int);

/*
 * Allocate a new reference for a given object ID.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error *got_ref_alloc(struct got_reference **, const char *,
    struct got_object_id *);

/*
 * Allocate a new symbolic reference which points at a given reference.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error *got_ref_alloc_symref(struct got_reference **,
    const char *, struct got_reference *);

/* Dispose of a reference. */
void got_ref_close(struct got_reference *);

/* Get the name of the reference. */
const char *got_ref_get_name(struct got_reference *);

/* Get the name of the reference which a symbolic reference points at. */
const char *got_ref_get_symref_target(struct got_reference *);

/* Get the last modification timestamp of the reference. */
time_t got_ref_get_mtime(struct got_reference *);

/*
 * Get the modification timestamp of the commit pointed at by the
 * given reference. Will return zero if the commit timestamp is
 * unknown or if the reference does not point at a commit.
 *
 * The cached timestamp will be known after got_ref_list() was called
 * with either got_ref_cmp_by_commit_timestamp_descending() or
 * with got_ref_cmp_tags().
 */
time_t got_ref_get_cached_committer_time(struct got_reference *);

/*
 * Create a duplicate copy of a reference.
 * The caller must dispose of this copy with got_ref_close().
 */
struct got_reference *got_ref_dup(struct got_reference *);

/* Attempt to resolve a symbolic reference to a non-symbolic one. */
const struct got_error *got_ref_resolve_symbolic(struct got_reference **,
    struct got_repository *, struct got_reference *);

/* Attempt to resolve a reference (symbolic or not) to an object ID. */
const struct got_error *got_ref_resolve(struct got_object_id **,
    struct got_repository *, struct got_reference *);

/*
 * Attempt to resolve a reference (symbolic or not) to an object ID,
 * assuming the reference points at a commit or tag object. If the reference
 * points at a tag then return the commit ID which the tag resolves to.
 * Object types other than commit and tag result in GOT_ERR_OBJ_TYPE.
 * 
 */
const struct got_error *got_ref_resolve_commit_or_tag(struct got_object_id **,
    struct got_repository *, struct got_reference *);

/*
 * Return a string representation of a reference.
 * The caller must dispose of it with free(3).
 */
char *got_ref_to_str(struct got_reference *);

/* List of references. */
struct got_reflist_entry {
	TAILQ_ENTRY(got_reflist_entry) entry;
	struct got_reference *ref;
};
TAILQ_HEAD(got_reflist_head, got_reflist_entry);

/* Duplicate a reference list entry. Caller must dispose of it with free(3). */
const struct got_error *got_reflist_entry_dup(struct got_reflist_entry **,
    struct got_reflist_entry *);

/* A function which compares two references. Used with got_ref_list(). */
typedef const struct got_error *(*got_ref_cmp_cb)(void *, int *,
    struct got_reference *, struct got_reference *);

/* An implementation of got_ref_cmp_cb which compares two references by name. */
const struct got_error *got_ref_cmp_by_name(void *, int *,
    struct got_reference *, struct got_reference *);

/* An implementation of got_ref_cmp_cb which compares two tags. */
const struct got_error *got_ref_cmp_tags(void *, int *,
    struct got_reference *, struct got_reference *);

/*
 * An implementation of got_ref_cmp_cb which compares commit timestamps.
 * Requires a struct got_repository * as the void * argument.
 */
const struct got_error *got_ref_cmp_by_commit_timestamp_descending(void *,
    int *, struct got_reference *, struct got_reference *);

/*
 * Append all known references to a caller-provided ref list head.
 * Optionally limit references returned to those within a given
 * reference namespace. Sort the list with the provided reference comparison
 * function, usually got_ref_cmp_by_name().
 */
const struct got_error *got_ref_list(struct got_reflist_head *,
    struct got_repository *, const char *, got_ref_cmp_cb, void *);

/* Free all references on a ref list. */
void got_ref_list_free(struct got_reflist_head *);

/*
 * Insert a reference into a reference list.
 * Return a pointer to the newly allocated list entry in *newp.
 * If *newp is NULL and no error occurred then the specified reference was
 * already an element of the list. If *newp is not NULL then the reference
 * was shallow-copied onto the list and should no longer be closed with
 * got_ref_close(). Instead it will be closed along with other list
 * elements by got_ref_list_free().
 */
const struct got_error *
got_reflist_insert(struct got_reflist_entry **newp,
    struct got_reflist_head *refs, struct got_reference *ref,
    got_ref_cmp_cb cmp_cb, void *cmp_arg);

/* Sort a list of references with the provided comparison callback. */
const struct got_error *
got_reflist_sort(struct got_reflist_head *refs, got_ref_cmp_cb cmp_cb,
    void *cmp_arg);

/* Indicate whether the provided reference is symbolic (points at another
 * reference) or not (points at an object ID). */
int got_ref_is_symbolic(struct got_reference *);

/* Change the object ID a reference points to. */
const struct got_error *
got_ref_change_ref(struct got_reference *, struct got_object_id *);

/* Change the reference name a symbolic reference points to. */
const struct got_error *got_ref_change_symref(struct got_reference *,
    const char *);

/*
 * Change a symbolic reference into a regular reference which points to
 * the provided object ID.
 */
const struct got_error *got_ref_change_symref_to_ref(struct got_reference *,
    struct got_object_id *);

/* Write a reference to its on-disk path in the repository. */
const struct got_error *got_ref_write(struct got_reference *,
    struct got_repository *);

/* Delete a reference from its on-disk path in the repository. */
const struct got_error *got_ref_delete(struct got_reference *,
    struct got_repository *);

/* Unlock a reference which was opened in locked state. */
const struct got_error *got_ref_unlock(struct got_reference *);

/* Map object IDs to references. */
struct got_reflist_object_id_map;

/*
 * Create and populate an object ID map for a given list of references.
 * Map entries will contain deep-copies of elements of the reflist.
 * The caller must dispose of the map with got_reflist_object_id_map_free().
 */
const struct got_error *got_reflist_object_id_map_create(
    struct got_reflist_object_id_map **, struct got_reflist_head *,
    struct got_repository *);

/*
 * Return a list of references which correspond to a given object ID.
 * The returned list must be considered read-only.
 * The caller must _not_ call free(3) on the returned pointer!
 * If no references are associated with the ID, return NULL.
 */
struct got_reflist_head *
got_reflist_object_id_map_lookup(struct got_reflist_object_id_map *,
    struct got_object_id *);

/* Free the specified object ID map. */
void got_reflist_object_id_map_free(struct got_reflist_object_id_map *);
