/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2019, Ori Bernstein <ori@openbsd.org>
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

/*
 * All code runs under the same UID but sensitive code paths are run in a
 * separate process with tighter pledge(2) promises; data is communicated
 * between processes via imsgbuf_flush(3) and imsgbuf_read(3).
 * This behaviour is transparent to users of the library.
 *
 * We generally transmit data in imsg buffers, split across several messages
 * if necessary. File descriptors are used in cases where this is impractical,
 * such as when accessing pack files or when transferring large blobs.
 *
 * We exec(2) after a fork(2). Parts of our library functionality are
 * accessible via separate executables in a libexec directory.
 */

#define GOT_IMSG_FD_CHILD (STDERR_FILENO + 1)

#ifndef GOT_LIBEXECDIR
#define GOT_LIBEXECDIR /usr/local/bin
#endif

/* Names of helper programs in libexec directory */
#define GOT_PROG_READ_OBJECT	got-read-object
#define GOT_PROG_READ_TREE	got-read-tree
#define GOT_PROG_READ_COMMIT	got-read-commit
#define GOT_PROG_READ_BLOB	got-read-blob
#define GOT_PROG_READ_TAG	got-read-tag
#define GOT_PROG_READ_PACK	got-read-pack
#define GOT_PROG_READ_GITCONFIG	got-read-gitconfig
#define GOT_PROG_READ_GOTCONFIG	got-read-gotconfig
#define GOT_PROG_READ_PATCH	got-read-patch
#define GOT_PROG_FETCH_PACK	got-fetch-pack
#define GOT_PROG_INDEX_PACK	got-index-pack
#define GOT_PROG_SEND_PACK	got-send-pack
#define GOT_PROG_FETCH_HTTP	got-fetch-http

#define GOT_STRINGIFY(x) #x
#define GOT_STRINGVAL(x) GOT_STRINGIFY(x)

/* Paths to helper programs in libexec directory */
#define GOT_PATH_PROG_READ_OBJECT \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_OBJECT)
#define GOT_PATH_PROG_READ_TREE \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_TREE)
#define GOT_PATH_PROG_READ_COMMIT \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_COMMIT)
#define GOT_PATH_PROG_READ_BLOB \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_BLOB)
#define GOT_PATH_PROG_READ_TAG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_TAG)
#define GOT_PATH_PROG_READ_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_PACK)
#define GOT_PATH_PROG_READ_GITCONFIG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_GITCONFIG)
#define GOT_PATH_PROG_READ_GOTCONFIG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_GOTCONFIG)
#define GOT_PATH_PROG_READ_PATCH \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_PATCH)
#define GOT_PATH_PROG_FETCH_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_FETCH_PACK)
#define GOT_PATH_PROG_SEND_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_SEND_PACK)
#define GOT_PATH_PROG_INDEX_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_INDEX_PACK)
#define GOT_PATH_PROG_FETCH_HTTP \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_FETCH_HTTP)

enum got_imsg_type {
	/* An error occurred while processing a request. */
	GOT_IMSG_ERROR,

	/* Stop the child process. */
	GOT_IMSG_STOP,

	/*
	 * Messages concerned with read access to objects in a repository.
	 * Object and pack files are opened by the main process, where
	 * data may be read as a byte string but without any interpretation.
	 * Decompression and parsing of object and pack files occurs in a
	 * separate process which runs under pledge("stdio recvfd").
	 * This sandboxes our own repository parsing code, as well as zlib.
	 */
	GOT_IMSG_OBJECT_REQUEST,
	GOT_IMSG_OBJECT,
	GOT_IMSG_COMMIT_REQUEST,
	GOT_IMSG_COMMIT,
	GOT_IMSG_COMMIT_LOGMSG,
	GOT_IMSG_TREE_REQUEST,
	GOT_IMSG_TREE,
	GOT_IMSG_TREE_ENTRIES,
	GOT_IMSG_BLOB_REQUEST,
	GOT_IMSG_BLOB_OUTFD,
	GOT_IMSG_BLOB,
	GOT_IMSG_TAG_REQUEST,
	GOT_IMSG_TAG,
	GOT_IMSG_TAG_TAGMSG,

	/* Messages related to networking. */
	GOT_IMSG_FETCH_REQUEST,
	GOT_IMSG_FETCH_HAVE_REF,
	GOT_IMSG_FETCH_WANTED_BRANCH,
	GOT_IMSG_FETCH_WANTED_REF,
	GOT_IMSG_FETCH_OUTFD,
	GOT_IMSG_FETCH_SYMREFS,
	GOT_IMSG_FETCH_REF,
	GOT_IMSG_FETCH_SERVER_PROGRESS,
	GOT_IMSG_FETCH_DOWNLOAD_PROGRESS,
	GOT_IMSG_FETCH_DONE,
	GOT_IMSG_IDXPACK_REQUEST,
	GOT_IMSG_IDXPACK_OUTFD,
	GOT_IMSG_IDXPACK_PROGRESS,
	GOT_IMSG_IDXPACK_DONE,
	GOT_IMSG_SEND_REQUEST,
	GOT_IMSG_SEND_REF,
	GOT_IMSG_SEND_REMOTE_REF,
	GOT_IMSG_SEND_REF_STATUS,
	GOT_IMSG_SEND_PACK_REQUEST,
	GOT_IMSG_SEND_PACKFD,
	GOT_IMSG_SEND_UPLOAD_PROGRESS,
	GOT_IMSG_SEND_DONE,

	/* Messages related to pack files. */
	GOT_IMSG_PACKIDX,
	GOT_IMSG_PACK,
	GOT_IMSG_PACKED_OBJECT_REQUEST,
	GOT_IMSG_COMMIT_TRAVERSAL_REQUEST,
	GOT_IMSG_TRAVERSED_COMMITS,
	GOT_IMSG_COMMIT_TRAVERSAL_DONE,
	GOT_IMSG_OBJECT_ENUMERATION_REQUEST,
	GOT_IMSG_ENUMERATED_COMMIT,
	GOT_IMSG_ENUMERATED_TREE,
	GOT_IMSG_TREE_ENUMERATION_DONE,
	GOT_IMSG_OBJECT_ENUMERATION_DONE,
	GOT_IMSG_OBJECT_ENUMERATION_INCOMPLETE,

	/* Message sending file descriptor to a temporary file. */
	GOT_IMSG_TMPFD,

	/* Messages related to gitconfig files. */
	GOT_IMSG_GITCONFIG_PARSE_REQUEST,
	GOT_IMSG_GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST,
	GOT_IMSG_GITCONFIG_REPOSITORY_EXTENSIONS_REQUEST,
	GOT_IMSG_GITCONFIG_AUTHOR_NAME_REQUEST,
	GOT_IMSG_GITCONFIG_AUTHOR_EMAIL_REQUEST,
	GOT_IMSG_GITCONFIG_REMOTES_REQUEST,
	GOT_IMSG_GITCONFIG_INT_VAL,
	GOT_IMSG_GITCONFIG_STR_VAL,
	GOT_IMSG_GITCONFIG_PAIR,
	GOT_IMSG_GITCONFIG_REMOTES,
	GOT_IMSG_GITCONFIG_REMOTE,
	GOT_IMSG_GITCONFIG_OWNER_REQUEST,
	GOT_IMSG_GITCONFIG_OWNER,

	/* Messages related to gotconfig files. */
	GOT_IMSG_GOTCONFIG_PARSE_REQUEST,
	GOT_IMSG_GOTCONFIG_AUTHOR_REQUEST,
	GOT_IMSG_GOTCONFIG_ALLOWEDSIGNERS_REQUEST,
	GOT_IMSG_GOTCONFIG_REVOKEDSIGNERS_REQUEST,
	GOT_IMSG_GOTCONFIG_SIGNERID_REQUEST,
	GOT_IMSG_GOTCONFIG_REMOTES_REQUEST,
	GOT_IMSG_GOTCONFIG_INT_VAL,
	GOT_IMSG_GOTCONFIG_STR_VAL,
	GOT_IMSG_GOTCONFIG_REMOTES,
	GOT_IMSG_GOTCONFIG_REMOTE,

	/* Raw object access. Uncompress object data but do not parse it. */
	GOT_IMSG_RAW_OBJECT_REQUEST,
	GOT_IMSG_RAW_OBJECT_OUTFD,
	GOT_IMSG_PACKED_RAW_OBJECT_REQUEST,
	GOT_IMSG_RAW_OBJECT,

	/* Read raw delta data from pack files. */
	GOT_IMSG_RAW_DELTA_OUTFD,
	GOT_IMSG_RAW_DELTA_REQUEST,
	GOT_IMSG_RAW_DELTA,

	/* Reuse deltas found in a pack file. */
	GOT_IMSG_DELTA_REUSE_REQUEST,
	GOT_IMSG_REUSED_DELTAS,
	GOT_IMSG_DELTA_REUSE_DONE,

	/* Commit coloring in got-read-pack. */
	GOT_IMSG_COMMIT_PAINTING_INIT,
	GOT_IMSG_COMMIT_PAINTING_REQUEST,
	GOT_IMSG_PAINTED_COMMITS,
	GOT_IMSG_COMMIT_PAINTING_DONE,

	/* Transfer a list of object IDs. */
	GOT_IMSG_OBJ_ID_LIST,
	GOT_IMSG_OBJ_ID_LIST_DONE,

	/* Transfer a queue of object IDs. */
	GOT_IMSG_OBJ_ID_QUEUE,
	GOT_IMSG_OBJ_ID_QUEUE_DONE,

	/* Messages related to patch files. */
	GOT_IMSG_PATCH_FILE,
	GOT_IMSG_PATCH_HUNK,
	GOT_IMSG_PATCH_DONE,
	GOT_IMSG_PATCH_LINE,
	GOT_IMSG_PATCH,
	GOT_IMSG_PATCH_EOF,
};

/* Structure for GOT_IMSG_ERROR. */
struct got_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_TREE_REQUEST and GOT_IMSG_OBJECT data.
 */
struct got_imsg_object {
	struct got_object_id id;

	/* These fields are the same as in struct got_object. */
	int type;
	int flags;
	size_t hdrlen;
	size_t size;
	off_t pack_offset;
	int pack_idx;
}  __attribute__((__packed__));

/* Structure for GOT_IMSG_COMMIT data. */
struct got_imsg_commit_object {
	struct got_object_id tree_id;
	size_t author_len;
	time_t author_time;
	time_t author_gmtoff;
	size_t committer_len;
	time_t committer_time;
	time_t committer_gmtoff;
	size_t logmsg_len;
	int nparents;

	/*
	 * Followed by author_len + committer_len data bytes
	 */

	/* Followed by 'nparents' struct got_object_id */

	/*
	 * Followed by 'logmsg_len' bytes of commit log message data in
	 * one or more GOT_IMSG_COMMIT_LOGMSG messages.
	 */
} __attribute__((__packed__));

struct got_imsg_tree_entry {
	char id[GOT_HASH_DIGEST_MAXLEN];
	int algo;
	mode_t mode;
	size_t namelen;
	/* Followed by namelen bytes of entry's name, not NUL-terminated. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_TREE_ENTRIES. */
struct got_imsg_tree_entries {
	size_t nentries; /* Number of tree entries contained in this message. */

	/* Followed by nentries * struct got_imsg_tree_entry */
};

/* Structure for GOT_IMSG_TREE_OBJECT_REPLY data. */
struct got_imsg_tree_object {
	int nentries; /* This many tree entries follow. */
};

/* Structure for GOT_IMSG_BLOB. */
struct got_imsg_blob {
	size_t size;
	size_t hdrlen;

	/*
	 * If size <= GOT_PRIVSEP_INLINE_BLOB_DATA_MAX, blob data follows
	 * in the imsg buffer. Otherwise, blob data has been written to a
	 * file descriptor passed via the GOT_IMSG_BLOB_OUTFD imsg.
	 */
#define GOT_PRIVSEP_INLINE_BLOB_DATA_MAX \
	(MAX_IMSGSIZE - IMSG_HEADER_SIZE - sizeof(struct got_imsg_blob))
};

/* Structure for GOT_IMSG_RAW_OBJECT. */
struct got_imsg_raw_obj {
	off_t size;
	size_t hdrlen;

	/*
	 * If size <= GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX, object data follows
	 * in the imsg buffer. Otherwise, object data has been written to a
	 * file descriptor passed via the GOT_IMSG_RAW_OBJECT_OUTFD imsg.
	 */
#define GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX \
	(MAX_IMSGSIZE - IMSG_HEADER_SIZE - sizeof(struct got_imsg_raw_obj))
};

/* Structure for GOT_IMSG_RAW_DELTA. */
struct got_imsg_raw_delta {
	struct got_object_id base_id;
	uint64_t base_size;
	uint64_t result_size;
	off_t delta_size;
	off_t delta_compressed_size;
	off_t delta_offset;
	off_t delta_out_offset;

	/*
	 * Delta data has been written at delta_out_offset to the file
	 * descriptor passed via the GOT_IMSG_RAW_DELTA_OUTFD imsg.
	 */
};

/* Structures for GOT_IMSG_REUSED_DELTAS. */
struct got_imsg_reused_delta {
	struct got_object_id id;
	struct got_object_id base_id;
	uint64_t base_size;
	uint64_t result_size;
	off_t delta_size;
	off_t delta_compressed_size;
	off_t delta_offset;
};
struct got_imsg_reused_deltas {
	size_t ndeltas;

	/*
	 * Followed by ndeltas * struct got_imsg_reused_delta.
	 */

#define GOT_IMSG_REUSED_DELTAS_MAX_NDELTAS \
	((MAX_IMSGSIZE - IMSG_HEADER_SIZE - \
	sizeof(struct got_imsg_reused_deltas)) \
	/ sizeof(struct got_imsg_reused_delta))
};

/* Structure for GOT_IMSG_PAINTED_COMMITS. */
struct got_imsg_painted_commit {
	struct got_object_id id;
	intptr_t color;
} __attribute__((__packed__));

struct got_imsg_painted_commits {
	int ncommits;
	int present_in_pack;
	/*
	 * Followed by ncommits * struct got_imsg_painted_commit.
	 */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_TAG data. */
struct got_imsg_tag_object {
	struct got_object_id id;
	int obj_type;
	size_t tag_len;
	size_t tagger_len;
	time_t tagger_time;
	time_t tagger_gmtoff;
	size_t tagmsg_len;

	/*
	 * Followed by tag_len + tagger_len data bytes
	 */

	/*
	 * Followed by 'tagmsg_len' bytes of tag message data in
	 * one or more GOT_IMSG_TAG_TAGMSG messages.
	 */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_HAVE_REF data. */
struct got_imsg_fetch_have_ref {
	struct got_object_id id;
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_WANTED_BRANCH data. */
struct got_imsg_fetch_wanted_branch {
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_WANTED_REF data. */
struct got_imsg_fetch_wanted_ref {
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_REQUEST data. */
struct got_imsg_fetch_request {
	int no_head;
	int fetch_all_branches;
	int list_refs_only;
	int verbosity;
	size_t worktree_branch_len;
	size_t remote_head_len;
	size_t n_have_refs;
	size_t n_wanted_branches;
	size_t n_wanted_refs;
	/* Followed by worktree_branch_len bytes of reference name. */
	/* Followed by remote_head_len bytes of reference name. */
	/* Followed by n_have_refs GOT_IMSG_FETCH_HAVE_REF messages. */
	/* Followed by n_wanted_branches times GOT_IMSG_FETCH_WANTED_BRANCH. */
	/* Followed by n_wanted_refs times GOT_IMSG_FETCH_WANTED_REF. */
} __attribute__((__packed__));

/* Structures for GOT_IMSG_FETCH_SYMREFS data. */
struct got_imsg_fetch_symref {
	size_t name_len;
	size_t target_len;

	/*
	 * Followed by name_len + target_len data bytes.
	 */
} __attribute__((__packed__));

struct got_imsg_fetch_symrefs {
	size_t nsymrefs;

	/* Followed by nsymrefs times of got_imsg_fetch_symref data. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_REF data. */
struct got_imsg_fetch_ref {
	/* Describes a reference which will be fetched. */
	struct got_object_id refid;
	/* Followed by reference name in remaining data of imsg buffer. */
};

/* Structure for GOT_IMSG_FETCH_DOWNLOAD_PROGRESS data. */
struct got_imsg_fetch_download_progress {
	/* Number of packfile data bytes downloaded so far. */
	off_t packfile_bytes;
};

/* Structure for GOT_IMSG_SEND_REQUEST data. */
struct got_imsg_send_request {
	int verbosity;
	size_t nrefs;
	/* Followed by nrefs GOT_IMSG_SEND_REF messages. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_SEND_UPLOAD_PROGRESS data. */
struct got_imsg_send_upload_progress {
	/* Number of packfile data bytes uploaded so far. */
	off_t packfile_bytes;
};

/* Structure for GOT_IMSG_SEND_REF data. */
struct got_imsg_send_ref {
	struct got_object_id id;
	int delete;
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_SEND_REMOTE_REF data. */
struct got_imsg_send_remote_ref {
	struct got_object_id id;
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_SEND_REF_STATUS data. */
struct got_imsg_send_ref_status {
	int success;
	size_t name_len;
	size_t errmsg_len;
	/* Followed by name_len data bytes. */
	/* Followed by errmsg_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_IDXPACK_REQUEST data. */
struct got_imsg_index_pack_request {
	struct got_object_id id;
} __attribute__((__packed__));

/* Structure for GOT_IMSG_IDXPACK_PROGRESS data. */
struct got_imsg_index_pack_progress {
	/* Total number of objects in pack file. */
	int nobj_total;

	/* Number of objects indexed so far. */
	int nobj_indexed;

	/* Number of non-deltified objects in pack file. */
	int nobj_loose;

	/* Number of deltified objects resolved so far. */
	int nobj_resolved;
};

/* Structure for GOT_IMSG_PACKIDX. */
struct got_imsg_packidx {
	size_t len;
	off_t packfile_size;
	int algo;
	/* Additionally, a file descriptor is passed via imsg. */
};

/* Structure for GOT_IMSG_PACK. */
struct got_imsg_pack {
	char path_packfile[PATH_MAX];
	off_t filesize;
	int algo;
	/* Additionally, a file descriptor is passed via imsg. */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_OBJECT_REQUEST, GOT_IMSG_BLOB_REQUEST,
 * GOT_IMSG_TREE_REQUEST, GOT_IMSG_COMMIT_REQUEST, and
 * GOT_IMSG_TAG_REQUEST data.
 */
struct got_object_id;

/*
 * Structure for GOT_IMSG_PACKED_OBJECT_REQUEST and
 * GOT_IMSG_PACKED_RAW_OBJECT_REQUEST data.
 */
struct got_imsg_packed_object {
	struct got_object_id id;
	int idx;
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_DELTA data.
 */
struct got_imsg_delta {
	/* These fields are the same as in struct got_delta. */
	off_t offset;
	size_t tslen;
	int type;
	size_t size;
	off_t data_offset;
};

/*
 * Structure for GOT_IMSG_RAW_DELTA_REQUEST data.
 */
struct got_imsg_raw_delta_request {
	struct got_object_id id;
	int idx;
};

/*
 * Structure for GOT_IMSG_OBJ_ID_LIST data.
 * Multiple such messages may be sent back-to-back, where each message
 * contains a chunk of IDs. The entire list must be terminated with a
 * GOT_IMSG_OBJ_ID_LIST_DONE message.
 */
struct got_imsg_object_idlist {
	size_t nids;

	/*
	 * Followed by nids * struct got_object_id.
	 */

#define GOT_IMSG_OBJ_ID_LIST_MAX_NIDS \
	((MAX_IMSGSIZE - IMSG_HEADER_SIZE - \
	sizeof(struct got_imsg_object_idlist)) / sizeof(struct got_object_id))
};

/*
 * Structure for GOT_IMSG_OBJ_ID_QUEUE data.
 * Multiple such messages may be sent back-to-back, where each message
 * contains a chunk of IDs. The entire list must be terminated with a
 * GOT_IMSG_OBJ_ID_QUEUE_DONE message.
 */
struct got_imsg_object_id_queue {
	size_t nids;

	/*
	 * Followed by nids * struct got_object_qid.
	 */

#define GOT_IMSG_OBJ_ID_QUEUE_MAX_NIDS \
	((MAX_IMSGSIZE - IMSG_HEADER_SIZE - \
	sizeof(struct got_imsg_object_id_queue)) / sizeof(struct got_object_qid))
};

/* Structure for GOT_IMSG_COMMIT_TRAVERSAL_REQUEST  */
struct got_imsg_commit_traversal_request {
	struct got_imsg_packed_object iobj;
	size_t path_len;
	/* Followed by path_len bytes of path data */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_TRAVERSED_COMMITS  */
struct got_imsg_traversed_commits {
	size_t ncommits;
	/* Followed by ncommit struct got_object_id */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_ENUMERATED_COMMIT  */
struct got_imsg_enumerated_commit {
	struct got_object_id id;
	time_t mtime;
} __attribute__((__packed__));

/* Structure for GOT_IMSG_ENUMERATED_TREE */
struct got_imsg_enumerated_tree {
	struct got_object_id id;	/* tree ID */
	int nentries;			/* number of tree entries */

	/* Followed by tree's path in remaining data of imsg buffer. */

	/* Followed by nentries * GOT_IMSG_TREE_ENTRY messages. */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_GOTCONFIG_REMOTE and
 * GOT_IMSG_GOTCONFIG_REMOTE data.
 */
struct got_imsg_remote {
	size_t name_len;
	size_t fetch_url_len;
	size_t send_url_len;
	int mirror_references;
	int fetch_all_branches;
	int nfetch_branches;
	int nsend_branches;
	int nfetch_refs;

	/* Followed by name_len data bytes. */
	/* Followed by fetch_url_len + send_url_len data bytes. */
	/* Followed by nfetch_branches GOT_IMSG_GITCONFIG_STR_VAL messages. */
	/* Followed by nsend_branches GOT_IMSG_GITCONFIG_STR_VAL messages. */
	/* Followed by nfetch_refs GOT_IMSG_GITCONFIG_STR_VAL messages. */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_GITCONFIG_REMOTES data.
 */
struct got_imsg_remotes {
	int nremotes; /* This many GOT_IMSG_GITCONFIG_REMOTE messages follow. */
};

/*
 * Structure for GOT_IMSG_GITCONFIG_PAIR.
 */
struct got_imsg_gitconfig_pair {
	size_t	klen;
	size_t	vlen;
	/* Followed by klen data bytes of key string. */
	/* Followed by vlen data bytes of value string. */
};

/*
 * Structure for GOT_IMSG_PATCH data.
 */
struct got_imsg_patch {
	int	git;
	int	xbit;
	char	old[PATH_MAX];
	char	new[PATH_MAX];
	char	cid[GOT_HASH_DIGEST_STRING_MAXLEN];
	char	blob[GOT_HASH_DIGEST_STRING_MAXLEN];
};

/*
 * Structure for GOT_IMSG_PATCH_HUNK data.
 */
struct got_imsg_patch_hunk {
	int	oldfrom;
	int	oldlines;
	int	newfrom;
	int	newlines;
};

struct got_remote_repo;
struct got_pack;
struct got_packidx;
struct got_pathlist_head;

const struct got_error *got_send_ack(pid_t);
const struct got_error *got_privsep_wait_for_child(pid_t);
const struct got_error *got_privsep_flush_imsg(struct imsgbuf *);
const struct got_error *got_privsep_send_stop(int);
const struct got_error *got_privsep_recv_imsg(struct imsg *, struct imsgbuf *,
    size_t);
void got_privsep_send_error(struct imsgbuf *, const struct got_error *);
const struct got_error *got_privsep_send_ack(struct imsgbuf *);
const struct got_error *got_privsep_wait_ack(struct imsgbuf *);
const struct got_error *got_privsep_send_obj_req(struct imsgbuf *, int,
    struct got_object_id *);
const struct got_error *got_privsep_send_raw_obj_req(struct imsgbuf *, int,
    struct got_object_id *);
const struct got_error *got_privsep_send_raw_obj_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_commit_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_tree_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_tag_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_blob_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_blob_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_tmpfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_obj(struct imsgbuf *,
    struct got_object *);
const struct got_error *got_privsep_send_index_pack_req(struct imsgbuf *,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_index_pack_outfd(struct imsgbuf *,
    int);
const struct got_error *got_privsep_recv_index_progress(int *, int *, int *,
    int *, int *, struct imsgbuf *ibuf);
const struct got_error *got_privsep_send_fetch_req(struct imsgbuf *, int,
    struct got_pathlist_head *, int, struct got_pathlist_head *,
    struct got_pathlist_head *, int, const char *, const char *, int, int);
const struct got_error *got_privsep_send_fetch_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_recv_fetch_progress(int *,
    struct got_object_id **, char **, struct got_pathlist_head *, char **,
    off_t *, uint8_t *, struct imsgbuf *);
const struct got_error *got_privsep_send_send_req(struct imsgbuf *, int,
    struct got_pathlist_head *, struct got_pathlist_head *, int);
const struct got_error *got_privsep_recv_send_remote_refs(
    struct got_pathlist_head *, struct imsgbuf *);
const struct got_error *got_privsep_send_packfd(struct imsgbuf *, int);
const struct got_error *got_privsep_recv_send_progress(int *, off_t *,
    int *, char **, char **, struct imsgbuf *);
const struct got_error *got_privsep_get_imsg_obj(struct got_object **,
    struct imsg *, struct imsgbuf *);
const struct got_error *got_privsep_recv_obj(struct got_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_send_raw_obj(struct imsgbuf *, off_t,
    size_t, uint8_t *);
const struct got_error *got_privsep_recv_raw_obj(uint8_t **, off_t *, size_t *,
    struct imsgbuf *);
const struct got_error *got_privsep_send_commit(struct imsgbuf *,
    struct got_commit_object *);
const struct got_error *got_privsep_recv_commit(struct got_commit_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_tree(struct got_tree_object **,
    struct imsgbuf *);
struct got_parsed_tree_entry;
const struct got_error *got_privsep_send_tree(struct imsgbuf *,
    struct got_parsed_tree_entry *, int);
const struct got_error *got_privsep_send_blob(struct imsgbuf *, size_t, size_t,
    const uint8_t *);
const struct got_error *got_privsep_recv_blob(uint8_t **, size_t *, size_t *,
    struct imsgbuf *);
const struct got_error *got_privsep_send_tag(struct imsgbuf *,
    struct got_tag_object *);
const struct got_error *got_privsep_recv_tag(struct got_tag_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_init_pack_child(struct imsgbuf *,
    struct got_pack *, struct got_packidx *);
const struct got_error *got_privsep_send_packed_obj_req(struct imsgbuf *, int,
    struct got_object_id *);
const struct got_error *got_privsep_send_packed_raw_obj_req(struct imsgbuf *,
    int, struct got_object_id *);
const struct got_error *got_privsep_send_pack_child_ready(struct imsgbuf *);

const struct got_error *got_privsep_send_gitconfig_parse_req(struct imsgbuf *,
    int);
const struct got_error *
    got_privsep_send_gitconfig_repository_format_version_req(struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_repository_extensions_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_author_name_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_author_email_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_remotes_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_owner_req(struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_str(char **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_pair(char **, char **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_int(int *, struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_remotes(
    struct got_remote_repo **, int *, struct imsgbuf *);

const struct got_error *got_privsep_send_gotconfig_parse_req(struct imsgbuf *,
    int);
const struct got_error *got_privsep_send_gotconfig_author_req(struct imsgbuf *);
const struct got_error *got_privsep_send_gotconfig_allowed_signers_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gotconfig_revoked_signers_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gotconfig_signer_id_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gotconfig_remotes_req(
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gotconfig_str(char **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gotconfig_remotes(
    struct got_remote_repo **, int *, struct imsgbuf *);

const struct got_error *got_privsep_send_commit_traversal_request(
    struct imsgbuf *, struct got_object_id *, int, const char *);
const struct got_error *got_privsep_recv_traversed_commits(
    struct got_commit_object **, struct got_object_id_queue *,
    struct imsgbuf *);
const struct got_error *got_privsep_send_enumerated_tree(size_t *,
    struct imsgbuf *, struct got_object_id *, const char *,
    struct got_parsed_tree_entry *, int);
const struct got_error *got_privsep_send_object_enumeration_request(
    struct imsgbuf *);
const struct got_error *got_privsep_send_object_enumeration_done(
    struct imsgbuf *);
const struct got_error *got_privsep_send_object_enumeration_incomplete(
    struct imsgbuf *);
const struct got_error *got_privsep_send_enumerated_commit(struct imsgbuf *,
    struct got_object_id *, time_t);
const struct got_error *got_privsep_recv_enumerated_objects(int *,
    struct imsgbuf *, got_object_enumerate_commit_cb,
    got_object_enumerate_tree_cb, void *, struct got_repository *);

const struct got_error *got_privsep_send_raw_delta_req(struct imsgbuf *, int,
    struct got_object_id *);
const struct got_error *got_privsep_send_raw_delta_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_raw_delta(struct imsgbuf *, uint64_t,
    uint64_t,  off_t, off_t, off_t, off_t, struct got_object_id *);
const struct got_error *got_privsep_recv_raw_delta(uint64_t *, uint64_t *,
    off_t *, off_t *, off_t *, off_t *, struct got_object_id **,
    struct imsgbuf *);

const struct got_error *got_privsep_send_object_idlist(struct imsgbuf *,
    struct got_object_id **, size_t);
const struct got_error *got_privsep_send_object_idlist_done(struct imsgbuf *);
const struct got_error *got_privsep_recv_object_idlist(int *,
    struct got_object_id **, size_t *, struct imsgbuf *);

const struct got_error *got_privsep_send_object_id_queue(struct imsgbuf *ibuf,
    struct got_object_id_queue *, size_t);
const struct got_error *got_privsep_recv_object_id_queue(int *,
    struct got_object_id_queue *, size_t *, struct imsgbuf *);

const struct got_error *got_privsep_send_delta_reuse_req(struct imsgbuf *);
const struct got_error *got_privsep_send_reused_deltas(struct imsgbuf *,
    struct got_imsg_reused_delta *, size_t);
const struct got_error *got_privsep_send_reused_deltas_done(struct imsgbuf *);
const struct got_error *got_privsep_recv_reused_deltas(int *,
    struct got_imsg_reused_delta *, size_t *, struct imsgbuf *);

const struct got_error *got_privsep_init_commit_painting(struct imsgbuf *);
const struct got_error *got_privsep_send_painting_request(struct imsgbuf *);
typedef const struct got_error *(*got_privsep_recv_painted_commit_cb)(void *,
    struct got_object_id *, intptr_t);
const struct got_error *got_privsep_send_painted_commits(struct imsgbuf *,
    struct got_object_id_queue *, int *, int, int);
const struct got_error *got_privsep_send_painting_commits_done(struct imsgbuf *);
const struct got_error *got_privsep_recv_painted_commits(
    struct got_object_id_queue *, got_privsep_recv_painted_commit_cb, void *,
    struct imsgbuf *);

void got_privsep_exec_child(int[2], const char *, const char *);
