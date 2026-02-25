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

struct got_object {
	int type;

	int flags;
#define GOT_OBJ_FLAG_PACKED		0x01
#define GOT_OBJ_FLAG_DELTIFIED		0x02

	size_t hdrlen;
	size_t size;
	struct got_object_id id;

	int pack_idx;		/* if packed */
	off_t pack_offset;	/* if packed */
	struct got_delta_chain deltas; /* if deltified */
	int refcnt;		/* > 0 if open and/or cached */
};


/* A callback function which is invoked when a raw object is closed. */
struct got_raw_object;
typedef void (got_object_raw_close_cb)(struct got_raw_object *);

struct got_raw_object {
	FILE *f;		/* NULL if data buffer is being used */
	int fd;			/* -1 unless data buffer is memory-mapped */
	int tempfile_idx;	/* -1 unless using a repository-tempfile */
	uint8_t *data;
	off_t size;
	size_t hdrlen;
	int refcnt;		/* > 0 if open and/or cached */

	int flags;
#define GOT_RAW_OBJ_FLAG_PACKED		0x01
#define GOT_RAW_OBJ_FLAG_DELTIFIED	0x02

	got_object_raw_close_cb *close_cb;
	void *close_arg;
};

struct got_commit_object {
	struct got_object_id *tree_id;
	unsigned int nparents;
	struct got_object_id_queue parent_ids;
	char *author;
	time_t author_time;	/* UTC */
	time_t author_gmtoff;
	char *committer;
	time_t committer_time;	/* UTC */
	time_t committer_gmtoff;
	char *logmsg;
	int refcnt;		/* > 0 if open and/or cached */

	int flags;
#define GOT_COMMIT_FLAG_PACKED		0x01
};

struct got_tree_entry {
	mode_t mode;
	char name[NAME_MAX + 1 /* NUL */];
	struct got_object_id id;
	int idx;
};

struct got_tree_object {
	int nentries;
	struct got_tree_entry *entries;
	int refcnt;
};

struct got_blob_object {
	FILE *f;
	uint8_t *data;
	size_t hdrlen;
	size_t blocksize;
	uint8_t *read_buf;
	struct got_object_id id;
};

struct got_tag_object {
	struct got_object_id id;
	int obj_type;
	char *tag;
	time_t tagger_time;
	time_t tagger_gmtoff;
	char *tagger;
	char *tagmsg;
	int refcnt;		/* > 0 if open and/or cached */
};

struct got_object_id *got_object_get_id(struct got_object *);
const struct got_error *got_object_get_id_str(char **, struct got_object *);
const struct got_error *got_object_get_path(char **, struct got_object_id *,
    struct got_repository *);
const struct got_error *got_object_open_loose_fd(int *, struct got_object_id *,
    struct got_repository *);
const struct got_error *got_object_open_packed(struct got_object **,
    struct got_object_id *, struct got_repository *);
struct got_pack;
struct got_packidx;
const struct got_error *got_object_open_from_packfile(struct got_object **,
    struct got_object_id *, struct got_pack *, struct got_packidx *, int,
    struct got_repository *);
const struct got_error *got_object_read_raw_delta(uint64_t *, uint64_t *,
    off_t *, off_t *, off_t *, off_t *, struct got_object_id **, int,
    struct got_packidx *, int, struct got_object_id *, struct got_repository *);
const struct got_error *got_object_prepare_delta_reuse(struct got_pack **,
    struct got_packidx *, int, struct got_repository *);
const struct got_error *got_object_read_header_privsep(struct got_object **,
    struct got_object_id *, struct got_repository *, int);
const struct got_error *got_object_open(struct got_object **,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_object_raw_open(struct got_raw_object **, int *,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_object_raw_close(struct got_raw_object *);
const struct got_error *got_object_open_by_id_str(struct got_object **,
    struct got_repository *, const char *);
void got_object_close(struct got_object *);
const struct got_error *got_object_commit_open(struct got_commit_object **,
    struct got_repository *, struct got_object *);
const struct got_error *got_object_tree_open(struct got_tree_object **,
    struct got_repository *, struct got_object *);
const struct got_error *got_object_blob_open(struct got_blob_object **,
    struct got_repository *, struct got_object *, size_t, int);
char *got_object_blob_id_str(struct got_blob_object*, char *, size_t);
const struct got_error *got_object_tag_open(struct got_tag_object **,
    struct got_repository *, struct got_object *);
const struct got_error *got_object_tree_entry_dup(struct got_tree_entry **,
    struct got_tree_entry *);

const struct got_error *got_traverse_packed_commits(
    struct got_object_id_queue *, struct got_object_id *, const char *,
    struct got_repository *);

typedef const struct got_error *(*got_object_enumerate_commit_cb)(void *,
    time_t, struct got_object_id *, struct got_repository *);
typedef const struct got_error *(*got_object_enumerate_tree_cb)(void *,
    struct got_tree_object *, time_t, struct got_object_id *, const char *,
    struct got_repository *);

const struct got_error *got_object_enumerate(int *,
    got_object_enumerate_commit_cb, got_object_enumerate_tree_cb, void *,
    struct got_object_id **, int, struct got_object_id **, int,
    struct got_packidx *, struct got_repository *);

const struct got_error *got_object_raw_alloc(struct got_raw_object **,
    uint8_t *, int *, size_t, size_t, off_t);
