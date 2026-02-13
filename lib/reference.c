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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>
#include <zlib.h>
#include <time.h>
#include <libgen.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_REF_HEADS	"heads"
#define GOT_REF_TAGS	"tags"
#define GOT_REF_REMOTES	"remotes"

/*
 * We do not resolve tags yet, and don't yet care about sorting refs either,
 * so packed-refs files we write contain a minimal header which disables all
 * packed-refs "traits" supported by Git.
 */
#define GOT_PACKED_REFS_HEADER	"# pack-refs with: "

/* A symbolic reference. */
struct got_symref {
	char *name;
	char *ref;
};

#define GOT_REF_RECURSE_MAX	20

/* A non-symbolic reference (there is no better designation). */
struct got_ref {
	char *name;
	struct got_object_id id;
};

/* A reference which points to an arbitrary object. */
struct got_reference {
	unsigned int flags;
#define GOT_REF_IS_SYMBOLIC	0x01
#define GOT_REF_IS_PACKED	0x02

	union {
		struct got_ref ref;
		struct got_symref symref;
	} ref;

	struct got_lockfile *lf;
	time_t mtime;

	/*
	 * Cached timestamp for got_ref_cmp_by_commit_timestamp_descending()
	 * and got_ref_cmp_tags().
	 */
	time_t committer_time;
};

static const struct got_error *
alloc_ref(struct got_reference **ref, const char *name,
    struct got_object_id *id, int flags, time_t mtime)
{
	const struct got_error *err = NULL;

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno("calloc");

	memcpy(&(*ref)->ref.ref.id, id, sizeof((*ref)->ref.ref.id));
	(*ref)->flags = flags;
	(*ref)->ref.ref.name = strdup(name);
	(*ref)->mtime = mtime;
	if ((*ref)->ref.ref.name == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
	}
	return err;
}

static const struct got_error *
alloc_symref(struct got_reference **ref, const char *name,
    const char *target_ref, int flags)
{
	const struct got_error *err = NULL;

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno("calloc");

	(*ref)->flags = GOT_REF_IS_SYMBOLIC | flags;
	(*ref)->ref.symref.name = strdup(name);
	if ((*ref)->ref.symref.name == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
		return err;
	}
	(*ref)->ref.symref.ref = strdup(target_ref);
	if ((*ref)->ref.symref.ref == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
	}
	return err;
}

static const struct got_error *
parse_symref(struct got_reference **ref, const char *name, const char *line)
{
	if (line[0] == '\0')
		return got_error(GOT_ERR_BAD_REF_DATA);

	return alloc_symref(ref, name, line, 0);
}

static const struct got_error *
parse_ref_line(struct got_reference **ref, const char *name, const char *line,
    time_t mtime, enum got_hash_algorithm algo)
{
	struct got_object_id id;

	if (strncmp(line, "ref: ", 5) == 0) {
		line += 5;
		return parse_symref(ref, name, line);
	}

	if (!got_parse_object_id(&id, line, algo))
		return got_error(GOT_ERR_BAD_REF_DATA);

	return alloc_ref(ref, name, &id, 0, mtime);
}

static const struct got_error *
parse_ref_file(struct got_reference **ref, const char *name,
    const char *absname, const char *abspath, int lock,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	FILE *f;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	struct got_lockfile *lf = NULL;
	struct stat sb;

	if (lock) {
		err = got_lockfile_lock(&lf, abspath, -1);
		if (err) {
			if (err->code == GOT_ERR_ERRNO && errno == ENOENT)
				err = got_error_not_ref(name);
			return err;
		}
	}

	f = fopen(abspath, "rbe");
	if (f == NULL) {
		if (errno != ENOTDIR && errno != ENOENT)
			err = got_error_from_errno2("fopen", abspath);
		else
			err = got_error_not_ref(name);
		if (lock)
			got_lockfile_unlock(lf, -1);
		return err;
	}
	if (fstat(fileno(f), &sb) == -1) {
		err = got_error_from_errno2("fstat", abspath);
		if (lock)
			got_lockfile_unlock(lf, -1);
		goto done;
	}
	if (!S_ISREG(sb.st_mode)) {
		err = got_error(GOT_ERR_NOT_REF);
		if (lock)
			got_lockfile_unlock(lf, -1);
		goto done;
	}

	linelen = getline(&line, &linesize, f);
	if (linelen == -1) {
		if (feof(f))
			err = NULL; /* ignore empty files (could be locks) */
		else {
			if (ferror(f))
				err = got_ferror(f, GOT_ERR_IO);
			else
				err = got_error_from_errno2("getline", abspath);
		}
		if (lock)
			got_lockfile_unlock(lf, -1);
		goto done;
	}
	while (linelen > 0 && line[linelen - 1] == '\n') {
		line[linelen - 1] = '\0';
		linelen--;
	}

	err = parse_ref_line(ref, absname, line, sb.st_mtime, algo);
	if (lock) {
		if (err)
			got_lockfile_unlock(lf, -1);
		else {
			if (*ref)
				(*ref)->lf = lf;
			else
				got_lockfile_unlock(lf, -1);
		}
	}
done:
	free(line);
	if (fclose(f) == EOF && err == NULL) {
		err = got_error_from_errno("fclose");
		if (*ref) {
			if (lock)
				got_ref_unlock(*ref);
			got_ref_close(*ref);
			*ref = NULL;
		}
	}
	return err;
}

static int
is_well_known_ref(const char *refname)
{
	return (strcmp(refname, GOT_REF_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_ORIG_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_MERGE_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_FETCH_HEAD) == 0);
}

static char *
get_refs_dir_path(struct got_repository *repo, const char *refname)
{
	if (is_well_known_ref(refname) || strncmp(refname, "refs/", 5) == 0)
		return strdup(got_repo_get_path_git_dir(repo));

	return got_repo_get_path_refs(repo);
}

const struct got_error *
got_ref_alloc(struct got_reference **ref, const char *name,
    struct got_object_id *id)
{
	if (!got_ref_name_is_valid(name))
		return got_error_path(name, GOT_ERR_BAD_REF_NAME);

	return alloc_ref(ref, name, id, 0, 0);
}

const struct got_error *
got_ref_alloc_symref(struct got_reference **ref, const char *name,
	struct got_reference *target_ref)
{
	if (!got_ref_name_is_valid(name))
		return got_error_path(name, GOT_ERR_BAD_REF_NAME);

	return alloc_symref(ref, name, got_ref_get_name(target_ref), 0);
}

static const struct got_error *
parse_packed_ref_line(struct got_reference **ref, const char *abs_refname,
    const char *line, time_t mtime, enum got_hash_algorithm algo)
{
	struct got_object_id id;
	const char *name;
	size_t digest_string_len;

	*ref = NULL;
	digest_string_len = got_hash_digest_string_length(algo);

	if (line[0] == '#' || line[0] == '^')
		return NULL;

	if (!got_parse_object_id(&id, line, algo))
		return got_error(GOT_ERR_BAD_REF_DATA);

	if (abs_refname) {
		if (strcmp(line + digest_string_len, abs_refname) != 0)
			return NULL;
		name = abs_refname;
	} else
		name = line + digest_string_len;

	return alloc_ref(ref, name, &id, GOT_REF_IS_PACKED, mtime);
}

static const struct got_error *
open_packed_ref(struct got_reference **ref, FILE *f, const char **subdirs,
    int nsubdirs, const char *refname, time_t mtime,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	char *abs_refname;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int i, ref_is_absolute = (strncmp(refname, "refs/", 5) == 0);

	*ref = NULL;

	if (ref_is_absolute)
		abs_refname = (char *)refname;
	do {
		linelen = getline(&line, &linesize, f);
		if (linelen == -1) {
			if (feof(f))
				break;
			err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
			break;
		}
		if (linelen > 0 && line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';
		for (i = 0; i < nsubdirs; i++) {
			if (!ref_is_absolute &&
			    asprintf(&abs_refname, "refs/%s/%s", subdirs[i],
			    refname) == -1)
				return got_error_from_errno("asprintf");
			err = parse_packed_ref_line(ref, abs_refname, line,
			    mtime, algo);
			if (!ref_is_absolute)
				free(abs_refname);
			if (err || *ref != NULL)
				break;
		}
		if (err)
			break;
	} while (*ref == NULL);
	free(line);

	return err;
}

static const struct got_error *
open_ref(struct got_reference **ref, const char *path_refs, const char *subdir,
    const char *name, int lock, enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	char *path = NULL;
	char *absname = NULL;
	int ref_is_absolute = (strncmp(name, "refs/", 5) == 0);
	int ref_is_well_known = (subdir[0] == '\0' && is_well_known_ref(name));

	*ref = NULL;

	if (!got_ref_name_is_valid(name))
		return got_error_path(name, GOT_ERR_BAD_REF_NAME);

	if (ref_is_absolute || ref_is_well_known) {
		if (asprintf(&path, "%s/%s", path_refs, name) == -1)
			return got_error_from_errno("asprintf");
		absname = (char *)name;
	} else {
		if (asprintf(&path, "%s/%s%s%s", path_refs, subdir,
		    subdir[0] ? "/" : "", name) == -1)
			return got_error_from_errno("asprintf");

		if (asprintf(&absname, "refs/%s%s%s",
		    subdir, subdir[0] ? "/" : "", name) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}

	err = parse_ref_file(ref, name, absname, path, lock, algo);
done:
	if (!ref_is_absolute && !ref_is_well_known)
		free(absname);
	free(path);
	return err;
}

const struct got_error *
got_ref_open(struct got_reference **ref, struct got_repository *repo,
    const char *refname, int lock)
{
	const struct got_error *err = NULL;
	char *packed_refs_path = NULL, *path_refs = NULL;
	const char *subdirs[] = {
	    GOT_REF_HEADS, GOT_REF_TAGS, GOT_REF_REMOTES
	};
	size_t i;
	int well_known = is_well_known_ref(refname);
	struct got_lockfile *lf = NULL;

	*ref = NULL;

	path_refs = get_refs_dir_path(repo, refname);
	if (path_refs == NULL) {
		err = got_error_from_errno2("get_refs_dir_path", refname);
		goto done;
	}

	if (well_known) {
		err = open_ref(ref, path_refs, "", refname, lock,
		    got_repo_get_object_format(repo));
	} else {
		FILE *f;

		/* Search on-disk refs before packed refs! */
		for (i = 0; i < nitems(subdirs); i++) {
			err = open_ref(ref, path_refs, subdirs[i], refname,
			    lock, got_repo_get_object_format(repo));
			if ((err && err->code != GOT_ERR_NOT_REF) || *ref)
				goto done;
		}

		packed_refs_path = got_repo_get_path_packed_refs(repo);
		if (packed_refs_path == NULL) {
			err = got_error_from_errno(
			    "got_repo_get_path_packed_refs");
			goto done;
		}

		if (lock) {
			err = got_lockfile_lock(&lf, packed_refs_path, -1);
			if (err)
				goto done;
		}
		f = fopen(packed_refs_path, "rbe");
		if (f != NULL) {
			struct stat sb;
			if (fstat(fileno(f), &sb) == -1) {
				err = got_error_from_errno2("fstat",
				    packed_refs_path);
				goto done;
			}
			err = open_packed_ref(ref, f, subdirs, nitems(subdirs),
			    refname, sb.st_mtime,
			    got_repo_get_object_format(repo));
			if (!err) {
				if (fclose(f) == EOF) {
					err = got_error_from_errno("fclose");
					got_ref_close(*ref);
					*ref = NULL;
				} else if (*ref)
					(*ref)->lf = lf;
			}
		}
	}
done:
	if (!err && *ref == NULL)
		err = got_error_not_ref(refname);
	if (err && lf)
		got_lockfile_unlock(lf, -1);
	free(packed_refs_path);
	free(path_refs);
	return err;
}

void
got_ref_close(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		free(ref->ref.symref.name);
		free(ref->ref.symref.ref);
	} else
		free(ref->ref.ref.name);
	free(ref);
}

struct got_reference *
got_ref_dup(struct got_reference *ref)
{
	struct got_reference *ret;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL)
		return NULL;

	ret->flags = ref->flags;
	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		ret->ref.symref.name = strdup(ref->ref.symref.name);
		if (ret->ref.symref.name == NULL) {
			free(ret);
			return NULL;
		}
		ret->ref.symref.ref = strdup(ref->ref.symref.ref);
		if (ret->ref.symref.ref == NULL) {
			free(ret->ref.symref.name);
			free(ret);
			return NULL;
		}
	} else {
		ret->ref.ref.name = strdup(ref->ref.ref.name);
		if (ret->ref.ref.name == NULL) {
			free(ret);
			return NULL;
		}
		memcpy(&ret->ref.ref.id, &ref->ref.ref.id,
		    sizeof(ret->ref.ref.id));
	}

	return ret;
}

const struct got_error *
got_reflist_entry_dup(struct got_reflist_entry **newp,
    struct got_reflist_entry *re)
{
	const struct got_error *err = NULL;
	struct got_reflist_entry *new;

	*newp = NULL;

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");

	new->ref = got_ref_dup(re->ref);
	if (new->ref == NULL) {
		err = got_error_from_errno("got_ref_dup");
		free(new);
		return err;
	}

	*newp = new;
	return NULL;
}

const struct got_error *
got_ref_resolve_symbolic(struct got_reference **resolved,
    struct got_repository *repo, struct got_reference *ref)
{
	struct got_reference *nextref;
	const struct got_error *err;

	err = got_ref_open(&nextref, repo, ref->ref.symref.ref, 0);
	if (err)
		return err;

	if (nextref->flags & GOT_REF_IS_SYMBOLIC)
		err = got_ref_resolve_symbolic(resolved, repo, nextref);
	else
		*resolved = got_ref_dup(nextref);

	got_ref_close(nextref);
	return err;
}

static const struct got_error *
ref_resolve(struct got_object_id **id, struct got_repository *repo,
    struct got_reference *ref, int recursion)
{
	const struct got_error *err;

	if (recursion <= 0)
		return got_error_msg(GOT_ERR_RECURSION,
		    "reference recursion limit reached");

	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		struct got_reference *resolved = NULL;
		err = got_ref_resolve_symbolic(&resolved, repo, ref);
		if (err == NULL)
			err = ref_resolve(id, repo, resolved, --recursion);
		if (resolved)
			got_ref_close(resolved);
		return err;
	}

	*id = calloc(1, sizeof(**id));
	if (*id == NULL)
		return got_error_from_errno("calloc");
	memcpy(*id, &ref->ref.ref.id, sizeof(**id));
	return NULL;
}

const struct got_error *
got_ref_resolve(struct got_object_id **id, struct got_repository *repo,
    struct got_reference *ref)
{
	return ref_resolve(id, repo, ref, GOT_REF_RECURSE_MAX);
}

char *
got_ref_to_str(struct got_reference *ref)
{
	char *str;

	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return strdup(ref->ref.symref.ref);

	if (got_object_id_str(&str, &ref->ref.ref.id) != NULL)
		return NULL;

	return str;
}

const char *
got_ref_get_name(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return ref->ref.symref.name;

	return ref->ref.ref.name;
}

const char *
got_ref_get_symref_target(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return ref->ref.symref.ref;

	return NULL;
}

time_t
got_ref_get_mtime(struct got_reference *ref)
{
	return ref->mtime;
}

time_t
got_ref_get_cached_committer_time(struct got_reference *ref)
{
	return ref->committer_time;
}

const struct got_error *
got_ref_cmp_by_name(void *arg, int *cmp, struct got_reference *re1,
    struct got_reference* re2)
{
	const char *name1 = got_ref_get_name(re1);
	const char *name2 = got_ref_get_name(re2);

	*cmp = got_path_cmp(name1, name2, strlen(name1), strlen(name2));
	return NULL;
}

static const struct got_error *
get_committer_time(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int obj_type;
	struct got_commit_object *commit = NULL;
	struct got_tag_object *tag = NULL;
	struct got_object_id *id = NULL;

	err = got_ref_resolve(&id, repo, ref);
	if (err) {
		if (err->code == GOT_ERR_NOT_REF && got_ref_is_symbolic(ref))
			return NULL;
		return err;
	}

	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_COMMIT:
		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			goto done;
		ref->committer_time =
		    got_object_commit_get_committer_time(commit);
		break;
	case GOT_OBJ_TYPE_TAG:
		err = got_object_open_as_tag(&tag, repo, id);
		if (err)
			goto done;
		ref->committer_time = got_object_tag_get_tagger_time(tag);
		break;
	default:
		/* best effort for other object types */
		ref->committer_time = got_ref_get_mtime(ref);
		break;
	}
done:
	free(id);
	if (commit)
		got_object_commit_close(commit);
	if (tag)
		got_object_tag_close(tag);
	return err;
}

const struct got_error *
got_ref_cmp_tags(void *arg, int *cmp, struct got_reference *ref1,
    struct got_reference *ref2)
{
	const struct got_error *err = NULL;
	struct got_repository *repo = arg;

	*cmp = 0;

	if (ref1->committer_time == 0) {
		err = get_committer_time(ref1, repo);
		if (err)
			return err;
	}
	if (ref2->committer_time == 0) {
		err = get_committer_time(ref2, repo);
		if (err)
			return err;
	}

	/* Put latest tags first. */
	if (ref1->committer_time < ref2->committer_time)
		*cmp = 1;
	else if (ref1->committer_time > ref2->committer_time)
		*cmp = -1;
	else
		err = got_ref_cmp_by_name(NULL, cmp, ref2, ref1);

	return err;
}

const struct got_error *
got_ref_cmp_by_commit_timestamp_descending(void *arg, int *cmp,
    struct got_reference *ref1, struct got_reference *ref2)
{
	const struct got_error *err = NULL;
	struct got_repository *repo = arg;

	*cmp = 0;

	if (ref1->committer_time == 0) {
		err = get_committer_time(ref1, repo);
		if (err)
			return err;
	}
	if (ref2->committer_time == 0) {
		err = get_committer_time(ref2, repo);
		if (err)
			return err;
	}

	if (ref1->committer_time < ref2->committer_time)
		*cmp = 1;
	else if (ref2->committer_time < ref1->committer_time)
		*cmp = -1;
	else
		return got_ref_cmp_by_name(arg, cmp, ref1, ref2);

	return err;
}

const struct got_error *
got_reflist_insert(struct got_reflist_entry **newp,
    struct got_reflist_head *refs, struct got_reference *ref,
    got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err;
	struct got_reflist_entry *new, *re;
	int cmp;

	*newp = NULL;

	if (cmp_cb != got_ref_cmp_by_name && (ref->flags & GOT_REF_IS_PACKED)) {
		/*
		 * If we are not sorting elements by name then we must still
		 * detect collisions between a packed ref and an on-disk ref
		 * using the same name. On-disk refs take precedence and are
		 * already present on the list before packed refs get added.
		 */
		TAILQ_FOREACH(re, refs, entry) {
			err = got_ref_cmp_by_name(NULL, &cmp, re->ref, ref);
			if (err)
				return err;
			if (cmp == 0)
				return NULL;
		}
	}

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");
	new->ref = ref;
	*newp = new;

	/*
	 * We must de-duplicate entries on insert because packed-refs may
	 * contain redundant entries. On-disk refs take precedence.
	 * This code assumes that on-disk revs are read before packed-refs.
	 * We're iterating the list anyway, so insert elements sorted by name.
	 *
	 * Many callers will provide paths in a somewhat sorted order.
	 * Iterating backwards from the tail of the list should be more
	 * efficient than traversing through the entire list each time
	 * an element is inserted.
	 */
	re = TAILQ_LAST(refs, got_reflist_head);
	while (re) {
		err = (*cmp_cb)(cmp_arg, &cmp, re->ref, new->ref);
		if (err)
			return err;
		if (cmp == 0) {
			/* duplicate */
			free(new);
			*newp = NULL;
			return NULL;
		} else if (cmp < 0) {
			TAILQ_INSERT_AFTER(refs, re, new, entry);
			return NULL;
		}
		re = TAILQ_PREV(re, got_reflist_head, entry);
	}

	TAILQ_INSERT_HEAD(refs, new, entry);
	return NULL;
}

const struct got_error *
got_reflist_sort(struct got_reflist_head *refs,
    got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err = NULL;
	struct got_reflist_entry *re, *tmp, *new;
	struct got_reflist_head sorted;

	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(re, refs, entry, tmp) {
		struct got_reference *ref = re->ref;
		TAILQ_REMOVE(refs, re, entry);
		free(re);
		err = got_reflist_insert(&new, &sorted, ref, cmp_cb, cmp_arg);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		if (err)
			return err;
	}

	TAILQ_CONCAT(refs, &sorted, entry);
	return NULL;
}

static const struct got_error *
gather_on_disk_refs(struct got_reflist_head *refs, const char *path_refs,
    const char *subdir, struct got_repository *repo,
    got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err = NULL;
	DIR *d = NULL;
	char *path_subdir;
	struct got_reference *ref;
	struct got_reflist_entry *new;

	while (subdir[0] == '/')
		subdir++;

	if (asprintf(&path_subdir, "%s/%s", path_refs, subdir) == -1)
		return got_error_from_errno("asprintf");

	d = opendir(path_subdir);
	if (d == NULL) {
		char *refname;

		if (errno != ENOTDIR)
			goto done;

		/* This could be a regular on-disk reference file. */
		free(path_subdir);
		err = got_path_dirname(&path_subdir, subdir);
		if (err)
			return err;
		err = got_path_basename(&refname, subdir);
		if (err) {
			free(path_subdir);
			return err;
		}
		err = open_ref(&ref, path_refs, path_subdir, refname,
		    0, got_repo_get_object_format(repo));
		free(path_subdir);
		free(refname);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF)
				return NULL;
			return err;
		}
		err = got_reflist_insert(&new, refs, ref,
		    cmp_cb, cmp_arg);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		return err;
	}

	for (;;) {
		struct dirent *dent;
		char *child;
		int type;

		dent = readdir(d);
		if (dent == NULL)
			break;

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		err = got_path_dirent_type(&type, path_subdir, dent);
		if (err)
			break;

		switch (type) {
		case DT_REG:
			err = open_ref(&ref, path_refs, subdir, dent->d_name,
			    0, got_repo_get_object_format(repo));
			if (err && err->code == GOT_ERR_BAD_REF_NAME)
				break;
			if (err)
				goto done;
			if (ref) {
				err = got_reflist_insert(&new, refs, ref,
				    cmp_cb, cmp_arg);
				if (err || new == NULL /* duplicate */)
					got_ref_close(ref);
				if (err)
					goto done;
			}
			break;
		case DT_DIR:
			if (asprintf(&child, "%s%s%s", subdir,
			    subdir[0] == '\0' ? "" : "/", dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				break;
			}
			err = gather_on_disk_refs(refs, path_refs, child, repo,
			    cmp_cb, cmp_arg);
			free(child);
			break;
		default:
			break;
		}
	}
done:
	if (d)
		closedir(d);
	free(path_subdir);
	return err;
}

static int
match_packed_ref(struct got_reference *ref, const char *ref_namespace)
{
	const char *name = got_ref_get_name(ref);
	int namespace_is_absolute = (strncmp(ref_namespace, "refs/", 5) == 0);

	if (namespace_is_absolute) {
		return (strcmp(name, ref_namespace) == 0 ||
		    got_path_is_child(name, ref_namespace,
		    strlen(ref_namespace)));
	}

	/* Match all "subdirectories" as we do with on-disk refs. */
	while (*name != '\0') {
		while (*name == '/')
			name++;
		if (strcmp(name, ref_namespace) == 0 ||
		    got_path_is_child(name, ref_namespace,
		    strlen(ref_namespace)))
			return 1;
		while (*name != '\0' && *name != '/')
			name++;
	}

	return 0;
}

const struct got_error *
got_ref_list(struct got_reflist_head *refs, struct got_repository *repo,
    const char *ref_namespace, got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err;
	char *packed_refs_path = NULL, *path_refs = NULL;
	char *abs_namespace = NULL, *buf = NULL;
	const char *ondisk_ref_namespace = NULL;
	char *line = NULL;
	FILE *f = NULL;
	struct got_reference *ref;
	struct got_reflist_entry *new;

	if (ref_namespace == NULL || ref_namespace[0] == '\0') {
		path_refs = get_refs_dir_path(repo, GOT_REF_HEAD);
		if (path_refs == NULL) {
			err = got_error_from_errno("get_refs_dir_path");
			goto done;
		}
		err = open_ref(&ref, path_refs, "", GOT_REF_HEAD, 0,
		    got_repo_get_object_format(repo));
		if (err)
			goto done;
		err = got_reflist_insert(&new, refs, ref, cmp_cb, cmp_arg);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		if (err && err->code != GOT_ERR_NOT_REF)
			goto done;
	} else {
		/* Try listing a single reference. */
		err = got_ref_open(&ref, repo, ref_namespace, 0);
		if (err) {
			if (err->code != GOT_ERR_NOT_REF)
				goto done;
			/* Try to look up references in a given namespace. */
		} else {
			err = got_reflist_insert(&new, refs, ref,
			    cmp_cb, cmp_arg);
			if (err || new == NULL /* duplicate */)
				got_ref_close(ref);
			return err;
		}
	}

	if (ref_namespace) {
		size_t len;
		/* Canonicalize the path to eliminate double-slashes if any. */
		if (asprintf(&abs_namespace, "/%s", ref_namespace) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		len = strlen(abs_namespace) + 1;
		buf = malloc(len);
		if (buf == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		err = got_canonpath(abs_namespace, buf, len);
		if (err)
			goto done;
		ondisk_ref_namespace = buf;
		while (ondisk_ref_namespace[0] == '/')
			ondisk_ref_namespace++;
		if (strncmp(ondisk_ref_namespace, "refs/", 5) == 0)
			ondisk_ref_namespace += 5;
		else if (strcmp(ondisk_ref_namespace, "refs") == 0)
			ondisk_ref_namespace = "";
	}

	/* Gather on-disk refs before parsing packed-refs. */
	free(path_refs);
	path_refs = get_refs_dir_path(repo, "");
	if (path_refs == NULL) {
		err = got_error_from_errno("get_refs_dir_path");
		goto done;
	}
	err = gather_on_disk_refs(refs, path_refs,
	    ondisk_ref_namespace ? ondisk_ref_namespace : "", repo,
	    cmp_cb, cmp_arg);
	if (err)
		goto done;

	/*
	 * The packed-refs file may contain redundant entries, in which
	 * case on-disk refs take precedence.
	 */
	packed_refs_path = got_repo_get_path_packed_refs(repo);
	if (packed_refs_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_packed_refs");
		goto done;
	}

	f = fopen(packed_refs_path, "re");
	if (f) {
		size_t linesize = 0;
		ssize_t linelen;
		struct stat sb;

		if (fstat(fileno(f), &sb) == -1) {
			err = got_error_from_errno2("fstat", packed_refs_path);
			goto done;
		}
		for (;;) {
			linelen = getline(&line, &linesize, f);
			if (linelen == -1) {
				if (feof(f))
					break;
				err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
				goto done;
			}
			if (linelen > 0 && line[linelen - 1] == '\n')
				line[linelen - 1] = '\0';
			err = parse_packed_ref_line(&ref, NULL, line,
			    sb.st_mtime, got_repo_get_object_format(repo));
			if (err)
				goto done;
			if (ref) {
				if (ref_namespace &&
				    !match_packed_ref(ref, ref_namespace)) {
					got_ref_close(ref);
					continue;
				}
				err = got_reflist_insert(&new, refs, ref,
				    cmp_cb, cmp_arg);
				if (err || new == NULL /* duplicate */)
					got_ref_close(ref);
				if (err)
					goto done;
			}
		}
	}
done:
	free(packed_refs_path);
	free(abs_namespace);
	free(buf);
	free(line);
	free(path_refs);
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

void
got_ref_list_free(struct got_reflist_head *refs)
{
	struct got_reflist_entry *re;

	while ((re = TAILQ_FIRST(refs))) {
		TAILQ_REMOVE(refs, re, entry);
		got_ref_close(re->ref);
		free(re);
	}
}

int
got_ref_is_symbolic(struct got_reference *ref)
{
	return (ref->flags & GOT_REF_IS_SYMBOLIC);
}

const struct got_error *
got_ref_change_ref(struct got_reference *ref, struct got_object_id *id)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return got_error(GOT_ERR_BAD_REF_TYPE);

	memcpy(&ref->ref.ref.id, id, sizeof(ref->ref.ref.id));
	return NULL;
}

const struct got_error *
got_ref_change_symref(struct got_reference *ref, const char *refname)
{
	char *new_name;

	if ((ref->flags & GOT_REF_IS_SYMBOLIC) == 0)
		return got_error(GOT_ERR_BAD_REF_TYPE);

	new_name = strdup(refname);
	if (new_name == NULL)
		return got_error_from_errno("strdup");

	free(ref->ref.symref.ref);
	ref->ref.symref.ref = new_name;
	return NULL;
}

const struct got_error *
got_ref_change_symref_to_ref(struct got_reference *symref,
    struct got_object_id *id)
{
	if ((symref->flags & GOT_REF_IS_SYMBOLIC) == 0)
		return got_error(GOT_ERR_BAD_REF_TYPE);

	symref->ref.ref.name = symref->ref.symref.name;
	memcpy(&symref->ref.ref.id, id, sizeof(symref->ref.ref.id));
	symref->flags &= ~GOT_REF_IS_SYMBOLIC;
	return NULL;
}

const struct got_error *
got_ref_write(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	const char *name = got_ref_get_name(ref);
	char *path_refs = NULL, *path = NULL, *tmppath = NULL;
	struct got_lockfile *lf = NULL;
	FILE *f = NULL;
	size_t n;
	struct stat sb;

	path_refs = get_refs_dir_path(repo, name);
	if (path_refs == NULL) {
		err = got_error_from_errno2("get_refs_dir_path", name);
		goto done;
	}

	if (asprintf(&path, "%s/%s", path_refs, name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named(&tmppath, &f, path, "");
	if (err) {
		char *parent;
		if (err->code == GOT_ERR_ERRNO && errno == ENOTDIR) {
			err = got_error_fmt(GOT_ERR_BAD_REF_NAME,
			    "collision with an existing reference: %s",
			    got_ref_get_name(ref));
			goto done;
		}
		if (!(err->code == GOT_ERR_ERRNO && errno == ENOENT))
			goto done;
		err = got_path_dirname(&parent, path);
		if (err)
			goto done;
		err = got_path_mkdir(parent);
		free(parent);
		if (err)
			goto done;
		err = got_opentemp_named(&tmppath, &f, path, "");
		if (err)
			goto done;
	}

	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		n = fprintf(f, "ref: %s\n", ref->ref.symref.ref);
		if (n != strlen(ref->ref.symref.ref) + 6) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	} else {
		char *hex;
		size_t len;

		err = got_object_id_str(&hex, &ref->ref.ref.id);
		if (err)
			goto done;
		len = strlen(hex);
		n = fprintf(f, "%s\n", hex);
		free(hex);
		if (n != len + 1) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	}

	if (ref->lf == NULL) {
		err = got_lockfile_lock(&lf, path, -1);
		if (err)
			goto done;
	}

	/* XXX: check if old content matches our expectations? */

	if (stat(path, &sb) != 0) {
		if (errno != ENOENT) {
			err = got_error_from_errno2("stat", path);
			goto done;
		}
		sb.st_mode = GOT_DEFAULT_FILE_MODE;
	}

	if (fchmod(fileno(f), sb.st_mode) != 0) {
		err = got_error_from_errno2("fchmod", tmppath);
		goto done;
	}

	if (rename(tmppath, path) != 0) {
		err = got_error_from_errno3("rename", tmppath, path);
		goto done;
	}
	free(tmppath);
	tmppath = NULL;

	if (stat(path, &sb) == -1) {
		err = got_error_from_errno2("stat", path);
		goto done;
	}
	ref->mtime = sb.st_mtime;
done:
	if (ref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf, -1);
	if (f) {
		if (fclose(f) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
	free(path_refs);
	free(path);
	if (tmppath) {
		if (unlink(tmppath) == -1 && err == NULL)
			err = got_error_from_errno2("unlink", tmppath);
		free(tmppath);
	}
	return err ? err : unlock_err;
}

static const struct got_error *
delete_packed_ref(struct got_reference *delref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	struct got_lockfile *lf = NULL;
	FILE *f = NULL, *tmpf = NULL;
	char *line = NULL, *packed_refs_path, *tmppath = NULL;
	size_t linesize = 0;
	struct got_reflist_head refs;
	int found_delref = 0;

	/* The packed-refs file does not contain symbolic references. */
	if (delref->flags & GOT_REF_IS_SYMBOLIC)
		return got_error(GOT_ERR_BAD_REF_DATA);

	TAILQ_INIT(&refs);

	packed_refs_path = got_repo_get_path_packed_refs(repo);
	if (packed_refs_path == NULL)
		return got_error_from_errno("got_repo_get_path_packed_refs");

	err = got_opentemp_named(&tmppath, &tmpf, packed_refs_path, "");
	if (err)
		goto done;

	if (delref->lf == NULL) {
		err = got_lockfile_lock(&lf, packed_refs_path, -1);
		if (err)
			goto done;
	}

	f = fopen(packed_refs_path, "re");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", packed_refs_path);
		goto done;
	}
	for (;;) {
		ssize_t linelen;
		struct got_reference *ref;
		struct got_reflist_entry *new;

		linelen = getline(&line, &linesize, f);
		if (linelen == -1) {
			if (feof(f))
				break;
			err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
			goto done;
		}
		if (linelen > 0 && line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';
		err = parse_packed_ref_line(&ref, NULL, line, 0,
		    got_repo_get_object_format(repo));
		if (err)
			goto done;
		if (ref == NULL)
			continue;

		if (strcmp(ref->ref.ref.name, delref->ref.ref.name) == 0 &&
		    got_object_id_cmp(&ref->ref.ref.id,
		    &delref->ref.ref.id) == 0) {
			found_delref = 1;
			got_ref_close(ref);
			continue;
		}

		err = got_reflist_insert(&new, &refs, ref,
		    got_ref_cmp_by_name, NULL);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		if (err)
			goto done;
	}

	if (found_delref) {
		struct got_reflist_entry *re;
		size_t n;
		struct stat sb;

		n = fprintf(tmpf, "%s\n", GOT_PACKED_REFS_HEADER);
		if (n != sizeof(GOT_PACKED_REFS_HEADER)) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}

		TAILQ_FOREACH(re, &refs, entry) {
			char *hex;
			size_t len;

			err = got_object_id_str(&hex, &re->ref->ref.ref.id);
			if (err)
				goto done;
			len = strlen(hex);
			n = fprintf(tmpf, "%s ", hex);
			free(hex);
			if (n != len + 1) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}

			n = fprintf(tmpf, "%s\n", re->ref->ref.ref.name);
			if (n != strlen(re->ref->ref.ref.name) + 1) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
		}

		if (fflush(tmpf) != 0) {
			err = got_error_from_errno("fflush");
			goto done;
		}

		if (fstat(fileno(f), &sb) != 0) {
			if (errno != ENOENT) {
				err = got_error_from_errno2("fstat",
				    packed_refs_path);
				goto done;
			}
			sb.st_mode = GOT_DEFAULT_FILE_MODE;
		}

		if (fchmod(fileno(tmpf), sb.st_mode) != 0) {
			err = got_error_from_errno2("fchmod", tmppath);
			goto done;
		}

		if (rename(tmppath, packed_refs_path) != 0) {
			err = got_error_from_errno3("rename", tmppath,
			    packed_refs_path);
			goto done;
		}
		free(tmppath);
		tmppath = NULL;
	}
done:
	if (delref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf, -1);
	if (f) {
		if (fclose(f) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
	if (tmppath && unlink(tmppath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmppath);
	if (tmpf && fclose(tmpf) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(tmppath);
	free(packed_refs_path);
	free(line);
	got_ref_list_free(&refs);
	return err ? err : unlock_err;
}

static const struct got_error *
delete_loose_ref(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	const char *name = got_ref_get_name(ref);
	char *path_refs = NULL, *path = NULL;
	struct got_lockfile *lf = NULL;

	path_refs = get_refs_dir_path(repo, name);
	if (path_refs == NULL) {
		err = got_error_from_errno2("get_refs_dir_path", name);
		goto done;
	}

	if (asprintf(&path, "%s/%s", path_refs, name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (ref->lf == NULL) {
		err = got_lockfile_lock(&lf, path, -1);
		if (err)
			goto done;
	}

	/* XXX: check if old content matches our expectations? */

	if (unlink(path) == -1)
		err = got_error_from_errno2("unlink", path);
done:
	if (ref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf, -1);

	free(path_refs);
	free(path);
	return err ? err : unlock_err;
}

const struct got_error *
got_ref_delete(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref2;

	if (ref->flags & GOT_REF_IS_PACKED) {
		err = delete_packed_ref(ref, repo);
		if (err)
			return err;

		err = got_ref_open(&ref2, repo, got_ref_get_name(ref), 0);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF)
				return NULL;
			return err;
		}

		err = delete_loose_ref(ref2, repo);
		got_ref_close(ref2);
		return err;
	} else {
		err = delete_loose_ref(ref, repo);
		if (err)
			return err;

		err = got_ref_open(&ref2, repo, got_ref_get_name(ref), 0);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF)
				return NULL;
			return err;
		}

		err = delete_packed_ref(ref2, repo);
		got_ref_close(ref2);
		return err;
	}
}

const struct got_error *
got_ref_unlock(struct got_reference *ref)
{
	const struct got_error *err;
	err = got_lockfile_unlock(ref->lf, -1);
	ref->lf = NULL;
	return err;
}

struct got_reflist_object_id_map {
	struct got_object_idset *idset;
};

struct got_reflist_object_id_map_entry {
	struct got_reflist_head refs;
};

static const struct got_error *
add_object_id_map_entry(struct got_object_idset *idset,
    struct got_object_id *id, struct got_reflist_entry *re)
{
	const struct got_error *err = NULL;
	struct got_reflist_object_id_map_entry *ent;
	struct got_reflist_entry *new;

	ent = got_object_idset_get(idset, id);
	if (ent == NULL) {
		ent = malloc(sizeof(*ent));
		if (ent == NULL)
			return got_error_from_errno("malloc");

		TAILQ_INIT(&ent->refs);
		err = got_object_idset_add(idset, id, ent);
		if (err) {
			free(ent);
			return err;
		}
	}

	err = got_reflist_entry_dup(&new, re);
	if (err)
		return err;

	TAILQ_INSERT_TAIL(&ent->refs, new, entry);
	return NULL;
}

const struct got_error *
got_reflist_object_id_map_create(struct got_reflist_object_id_map **map,
    struct got_reflist_head *refs, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_idset *idset;
	struct got_object_id *id = NULL;
	struct got_reflist_entry *re;

	idset = got_object_idset_alloc();
	if (idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	*map = malloc(sizeof(**map));
	if (*map == NULL) {
		got_object_idset_free(idset);
		return got_error_from_errno("malloc");
	}
	(*map)->idset = idset;

	TAILQ_FOREACH(re, refs, entry) {
		struct got_tag_object *tag = NULL;

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			goto done;

		err = add_object_id_map_entry(idset, id, re);
		if (err)
			goto done;

		if (strstr(got_ref_get_name(re->ref), "/tags/") == NULL) {
			free(id);
			id = NULL;
			continue;
		}

		err = got_object_open_as_tag(&tag, repo, id);
		if (err) {
			if (err->code != GOT_ERR_OBJ_TYPE)
				goto done;
			/* Ref points at something other than a tag. */
			err = NULL;
			tag = NULL;
			free(id);
			id = NULL;
			continue;
		}

		err = add_object_id_map_entry(idset,
		    got_object_tag_get_object_id(tag), re);
		got_object_tag_close(tag);
		if (err)
			goto done;

		free(id);
		id = NULL;
	}
done:
	free(id);
	if (err) {
		got_reflist_object_id_map_free(*map);
		*map = NULL;
	}
	return err;
}

struct got_reflist_head *
got_reflist_object_id_map_lookup(struct got_reflist_object_id_map *map,
    struct got_object_id *id)
{
	struct got_reflist_object_id_map_entry *ent;
	ent = got_object_idset_get(map->idset, id);
	if (ent)
		return &ent->refs;
	return NULL;
}

static const struct got_error *
free_id_map_entry(struct got_object_id *id, void *data, void *arg)
{
	struct got_reflist_object_id_map_entry *ent = data;

	got_ref_list_free(&ent->refs);
	free(ent);
	return NULL;
}

void
got_reflist_object_id_map_free(struct got_reflist_object_id_map *map)
{
	got_object_idset_for_each(map->idset, free_id_map_entry, NULL);
	got_object_idset_free(map->idset);
	free(map);
}
