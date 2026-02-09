/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2020 Ori Bernstein <ori@openbsd.org>
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

/* Error codes */
#define GOT_ERR_OK		0
#define GOT_ERR_ERRNO		1
#define GOT_ERR_NOT_GIT_REPO	2
#define GOT_ERR_BAD_FILETYPE	3
#define GOT_ERR_BAD_PATH	4
#define GOT_ERR_NOT_REF		5
#define GOT_ERR_IO		6
#define GOT_ERR_EOF		7
#define GOT_ERR_DECOMPRESSION	8
#define GOT_ERR_NO_SPACE	9
#define GOT_ERR_BAD_OBJ_HDR	10
#define GOT_ERR_OBJ_TYPE	11
#define GOT_ERR_BAD_OBJ_DATA	12
#define GOT_ERR_AMBIGUOUS_ID	13
#define GOT_ERR_BAD_PACKIDX	14
#define GOT_ERR_PACKIDX_CSUM	15
#define GOT_ERR_BAD_PACKFILE	16
#define GOT_ERR_NO_OBJ		17
#define GOT_ERR_NOT_IMPL	18
#define GOT_ERR_OBJ_NOT_PACKED	19
#define GOT_ERR_BAD_DELTA_CHAIN	20
#define GOT_ERR_BAD_DELTA	21
#define GOT_ERR_COMPRESSION	22
#define GOT_ERR_BAD_OBJ_ID_STR	23
#define GOT_ERR_WORKTREE_EXISTS	26
#define GOT_ERR_WORKTREE_META	27
#define GOT_ERR_WORKTREE_VERS	28
#define GOT_ERR_WORKTREE_BUSY	29
#define GOT_ERR_DIR_OBSTRUCTED	30
#define GOT_ERR_FILE_OBSTRUCTED	31
#define GOT_ERR_RECURSION	32
#define GOT_ERR_TIMEOUT		33
#define GOT_ERR_INTERRUPT	34
#define GOT_ERR_PRIVSEP_READ	35
#define GOT_ERR_PRIVSEP_LEN	36
#define GOT_ERR_PRIVSEP_PIPE	37
#define GOT_ERR_PRIVSEP_NO_FD	38
#define GOT_ERR_PRIVSEP_MSG	39
#define GOT_ERR_PRIVSEP_DIED	40
#define GOT_ERR_PRIVSEP_EXIT	41
#define GOT_ERR_PACK_OFFSET	42
#define GOT_ERR_OBJ_EXISTS	43
#define GOT_ERR_BAD_OBJ_ID	44
#define GOT_ERR_OBJECT_FORMAT	45
#define GOT_ERR_ITER_COMPLETED	46
#define GOT_ERR_RANGE		47
#define GOT_ERR_EXPECTED	48 /* for use in regress tests only */
#define GOT_ERR_CANCELLED	49
#define GOT_ERR_NO_TREE_ENTRY	50
#define GOT_ERR_FILEIDX_SIG	51
#define GOT_ERR_FILEIDX_VER	52
#define GOT_ERR_FILEIDX_CSUM	53
#define GOT_ERR_PATH_PREFIX	54
#define GOT_ERR_ANCESTRY	55
#define GOT_ERR_FILEIDX_BAD	56
#define GOT_ERR_BAD_REF_DATA	57
#define GOT_ERR_TREE_DUP_ENTRY	58
#define GOT_ERR_DIR_DUP_ENTRY	59
#define GOT_ERR_NOT_WORKTREE	60
#define GOT_ERR_UUID_VERSION	61
#define GOT_ERR_UUID_INVALID	62
#define GOT_ERR_UUID		63
#define GOT_ERR_LOCKFILE_TIMEOUT 64
#define GOT_ERR_BAD_REF_NAME	65
#define GOT_ERR_WORKTREE_REPO	66
#define GOT_ERR_FILE_MODIFIED	67
#define GOT_ERR_FILE_STATUS	68
#define GOT_ERR_COMMIT_CONFLICT	69
#define GOT_ERR_BAD_REF_TYPE	70
#define GOT_ERR_COMMIT_NO_AUTHOR 71
#define GOT_ERR_COMMIT_HEAD_CHANGED 72
#define GOT_ERR_COMMIT_OUT_OF_DATE 73
#define GOT_ERR_COMMIT_MSG_EMPTY 74
#define GOT_ERR_DIR_NOT_EMPTY	75
#define GOT_ERR_COMMIT_NO_CHANGES 76
#define GOT_ERR_BRANCH_MOVED	77
#define GOT_ERR_OBJ_TOO_LARGE	78
#define GOT_ERR_SAME_BRANCH	79
#define GOT_ERR_ROOT_COMMIT	80
#define GOT_ERR_MIXED_COMMITS	81
#define GOT_ERR_CONFLICTS	82
#define GOT_ERR_BRANCH_EXISTS	83
#define GOT_ERR_MODIFIED	84
#define GOT_ERR_NOT_REBASING	85
#define GOT_ERR_WRONG_BRANCH	86
#define GOT_ERR_REBASE_COMMITID	87
#define GOT_ERR_REBASING	88
#define GOT_ERR_REBASE_PATH	89
#define GOT_ERR_NOT_HISTEDIT	90
#define GOT_ERR_EMPTY_HISTEDIT	91
#define GOT_ERR_NO_HISTEDIT_CMD	92
#define GOT_ERR_HISTEDIT_SYNTAX	93
#define GOT_ERR_HISTEDIT_CANCEL	94
/* 95 is currently unused */
#define GOT_ERR_HISTEDIT_BUSY	96
#define GOT_ERR_HISTEDIT_CMD	97
#define GOT_ERR_HISTEDIT_PATH	98
#define GOT_ERR_PACKFILE_CSUM	99
#define GOT_ERR_COMMIT_BRANCH	100
#define GOT_ERR_FILE_STAGED	101
#define GOT_ERR_STAGE_NO_CHANGE	102
#define GOT_ERR_STAGE_CONFLICT	103
#define GOT_ERR_STAGE_OUT_OF_DATE 104
#define GOT_ERR_FILE_NOT_STAGED 105
#define GOT_ERR_STAGED_PATHS	106
#define GOT_ERR_PATCH_CHOICE	107
#define GOT_ERR_COMMIT_NO_EMAIL	108
#define GOT_ERR_TAG_EXISTS	109
#define GOT_ERR_GIT_REPO_FORMAT	110
#define GOT_ERR_REBASE_REQUIRED	111
#define GOT_ERR_REGEX		112
#define GOT_ERR_REF_NAME_MINUS	113
#define GOT_ERR_GITCONFIG_SYNTAX 114
#define GOT_ERR_REBASE_OUT_OF_DATE 115
#define GOT_ERR_CACHE_DUP_ENTRY	116
/* 117 is currently unused */
#define GOT_ERR_FETCH_FAILED	118
#define GOT_ERR_PARSE_URI	119
#define GOT_ERR_BAD_PROTO	120
#define GOT_ERR_ADDRINFO	121
#define GOT_ERR_BAD_PACKET	122
#define GOT_ERR_NO_REMOTE	123
#define GOT_ERR_FETCH_NO_BRANCH	124
#define GOT_ERR_FETCH_BAD_REF	125
#define GOT_ERR_TREE_ENTRY_TYPE	126
#define GOT_ERR_PARSE_CONFIG	127
#define GOT_ERR_NO_CONFIG_FILE	128
#define GOT_ERR_BAD_SYMLINK	129
#define GOT_ERR_GIT_REPO_EXT	130
#define GOT_ERR_CANNOT_PACK	131
#define GOT_ERR_LONELY_PACKIDX	132
#define GOT_ERR_OBJ_CSUM	133
#define GOT_ERR_SEND_BAD_REF	134
#define GOT_ERR_SEND_FAILED	135
#define GOT_ERR_SEND_EMPTY	136
#define GOT_ERR_SEND_ANCESTRY	137
#define GOT_ERR_CAPA_DELETE_REFS 138
#define GOT_ERR_SEND_DELETE_REF	139
#define GOT_ERR_SEND_TAG_EXISTS	140
#define GOT_ERR_NOT_MERGING	141
#define GOT_ERR_MERGE_OUT_OF_DATE 142
#define GOT_ERR_MERGE_STAGED_PATHS 143
#define GOT_ERR_MERGE_BUSY	144
#define GOT_ERR_MERGE_PATH	145
#define GOT_ERR_FILE_BINARY	146
#define GOT_ERR_PATCH_MALFORMED	147
#define GOT_ERR_PATCH_TRUNCATED	148
#define GOT_ERR_NO_PATCH	149
#define GOT_ERR_HUNK_FAILED	150
#define GOT_ERR_PATCH_FAILED	151
#define GOT_ERR_FILEIDX_DUP_ENTRY 152
#define GOT_ERR_PIN_PACK	153
#define GOT_ERR_BAD_TAG_SIGNATURE 154
#define GOT_ERR_VERIFY_TAG_SIGNATURE 155
#define GOT_ERR_SIGNING_TAG	156
#define GOT_ERR_BAD_OPTION 157
#define GOT_ERR_BAD_QUERYSTRING	158
#define GOT_ERR_INTEGRATE_BRANCH 159
#define GOT_ERR_BAD_REQUEST	160
#define GOT_ERR_CLIENT_ID	161
#define GOT_ERR_REPO_TEMPFILE	162
#define GOT_ERR_REFS_PROTECTED	163
#define GOT_ERR_REF_PROTECTED	164
#define GOT_ERR_REF_BUSY	165
#define GOT_ERR_COMMIT_BAD_AUTHOR 166
#define GOT_ERR_UID		167
#define GOT_ERR_GID		168
#define GOT_ERR_NO_PROG		169
#define GOT_ERR_MERGE_COMMIT_OUT_OF_DATE 170
#define GOT_ERR_BUNDLE_FORMAT 171
#define GOT_ERR_BAD_KEYWORD	172
#define GOT_ERR_UNKNOWN_CAPA	173
#define GOT_ERR_REF_DUP_ENTRY	174
#define GOT_ERR_DIFF_NOCHANGES	175
#define GOT_ERR_USER		176
#define GOT_ERR_USER_EXISTS	177
#define GOT_ERR_GROUP		178
#define GOT_ERR_GROUP_EXISTS	179
#define GOT_ERR_AUTHORIZED_KEY	180
#define GOT_ERR_CONNECTION_LIMIT 190
#define GOT_ERR_ON_SERVER_SIDE	191
#define GOT_ERR_LOGIN_FAILED	192
#define GOT_ERR_UNKNOWN_COMMAND	193
#define GOT_ERR_NOT_FOUND	194
#define GOT_ERR_MEDIA_TYPE	195
#define GOT_ERR_LOGOUT_FAILED	196

struct got_error {
        int code;
        const char *msg;
};

#define GOT_ERR_MAX_MSG_SIZE	4080 /* includes '\0' */

/*
 * Get an error object from the above list, for a given error code.
 * The error message is fixed.
 */
const struct got_error *got_error(int);

/*
 * Get an error object from the above list, for a given error code.
 * Use the specified error message instead of the default one.
 * Caution: If the message buffer lives in dynamically allocated memory,
 * then this memory likely won't be freed.
 */
const struct got_error *got_error_msg(int, const char *);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3), prefixed with a
 * string.
 */
const struct got_error *got_error_from_errno(const char *);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3), prefixed with two
 * strings.
 */
const struct got_error *got_error_from_errno2(const char *, const char *);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3), prefixed with three
 * strings.
 */
const struct got_error *got_error_from_errno3(const char *, const char *,
    const char *);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3), prefixed with a
 * string built with vsnprintf(3) from the provided format string
 * and the variable-length list of additional arguments.
 */
const struct got_error *got_error_from_errno_fmt(const char *, ...);

/*
 * Set errno to the specified error code and return a statically
 * allocated error object with code GOT_ERR_ERRNO and an error
 * message obtained from strerror(3), optionally prefixed with a
 * string.
 */
const struct got_error *got_error_set_errno(int, const char *);

/*
 * If ferror(3) indicates an error status for the FILE, obtain an error
 * from got_error_from_errno(). Else, obtain the error via got_error()
 * with the error code provided in the second argument.
 */
const struct got_error *got_ferror(FILE *, int);

/*
 * Obtain an error with code GOT_ERR_NO_OBJ and an error message which
 * contains the specified object ID. The message buffer is statically
 * allocated; future invocations of this function will overwrite the
 * message set during earlier invocations.
 */
struct got_object_id; /* forward declaration */
const struct got_error *got_error_no_obj(struct got_object_id *);

/*
 * Obtain an error with code GOT_ERR_OBJ_CSUM and an error message which
 * contains the specified object ID. The message buffer is statically
 * allocated; future invocations of this function will overwrite the
 * message set during earlier invocations.
 */
const struct got_error *got_error_checksum(struct got_object_id *);

/*
 * Obtain an error with code GOT_ERR_NOT_REF and an error message which
 * contains the specified reference name. The message buffer is statically
 * allocated; future invocations of this function will overwrite the
 * message set during earlier invocations.
 */
const struct got_error *got_error_not_ref(const char *);

/* Return an error based on a uuid(3) status code. */
const struct got_error *got_error_uuid(uint32_t, const char *);

/* Return an error with a path prefixed to the error message. */
const struct got_error *got_error_path(const char *, int);

/*
 * Return an error with an error message prefix built by vsnprintf(3)
 * from the provided format string and the variable-length list of
 * additional arguments.
*/
const struct got_error *got_error_fmt(int, const char *, ...)
	__attribute__((__format__ (printf, 2, 3)));

/*
 * Check whether open(2) with O_NOFOLLOW failed on a symlink.
 * This must be called directly after open(2) because it uses errno!
 */
int got_err_open_nofollow_on_symlink(void);
