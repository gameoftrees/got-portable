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

#include <sys/queue.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>
#include <zlib.h>
#include <uuid.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_hash.h"
#include "got_lib_object_parse.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static const struct got_error got_errors[] = {
	{ GOT_ERR_OK,		"no error occurred?!?" },
	{ GOT_ERR_ERRNO,	"see errno" },
	{ GOT_ERR_NOT_GIT_REPO, "no git repository found" },
	{ GOT_ERR_BAD_FILETYPE,	"bad file type" },
	{ GOT_ERR_BAD_PATH,	"bad path" },
	{ GOT_ERR_NOT_REF,	"no such reference found" },
	{ GOT_ERR_IO,		"input/output error" },
	{ GOT_ERR_EOF,		"unexpected end of file" },
	{ GOT_ERR_DECOMPRESSION,"decompression failed" },
	{ GOT_ERR_NO_SPACE,	"buffer too small" },
	{ GOT_ERR_BAD_OBJ_HDR,	"bad object header" },
	{ GOT_ERR_OBJ_TYPE,	"wrong type of object" },
	{ GOT_ERR_BAD_OBJ_DATA,	"bad object data" },
	{ GOT_ERR_AMBIGUOUS_ID, "ambiguous object ID" },
	{ GOT_ERR_BAD_PACKIDX,	"bad pack index file" },
	{ GOT_ERR_PACKIDX_CSUM, "pack index file checksum error" },
	{ GOT_ERR_BAD_PACKFILE,	"bad pack file" },
	{ GOT_ERR_NO_OBJ,	"object not found" },
	{ GOT_ERR_NOT_IMPL,	"feature not implemented" },
	{ GOT_ERR_OBJ_NOT_PACKED,"object is not packed" },
	{ GOT_ERR_BAD_DELTA_CHAIN,"bad delta chain" },
	{ GOT_ERR_BAD_DELTA,	"bad delta" },
	{ GOT_ERR_COMPRESSION,	"compression failed" },
	{ GOT_ERR_BAD_OBJ_ID_STR,"bad object id string" },
	{ GOT_ERR_WORKTREE_EXISTS,"worktree already exists" },
	{ GOT_ERR_WORKTREE_META,"bad worktree meta data" },
	{ GOT_ERR_WORKTREE_VERS,"unsupported worktree format version" },
	{ GOT_ERR_WORKTREE_BUSY,"worktree already locked" },
	{ GOT_ERR_FILE_OBSTRUCTED,"file is obstructed" },
	{ GOT_ERR_RECURSION,	"recursion limit reached" },
	{ GOT_ERR_TIMEOUT,	"operation timed out" },
	{ GOT_ERR_INTERRUPT,	"operation interrupted" },
	{ GOT_ERR_PRIVSEP_READ,	"no data received in imsg" },
	{ GOT_ERR_PRIVSEP_LEN,	"unexpected amount of data received in imsg" },
	{ GOT_ERR_PRIVSEP_PIPE,	"privsep peer process closed pipe" },
	{ GOT_ERR_PRIVSEP_NO_FD,"privsep file descriptor unavailable" },
	{ GOT_ERR_PRIVSEP_MSG,	"received unexpected privsep message" },
	{ GOT_ERR_PRIVSEP_DIED,	"unprivileged process died unexpectedly" },
	{ GOT_ERR_PRIVSEP_EXIT,	"bad exit code from unprivileged process" },
	{ GOT_ERR_PACK_OFFSET,	"bad offset in pack file" },
	{ GOT_ERR_OBJ_EXISTS,	"object already exists" },
	{ GOT_ERR_BAD_OBJ_ID,	"bad object id" },
	{ GOT_ERR_OBJECT_FORMAT, "object format not supported" },
	{ GOT_ERR_ITER_COMPLETED,"iteration completed" },
	{ GOT_ERR_RANGE,	"value out of range" },
	{ GOT_ERR_EXPECTED,	"expected an error but have no error" },
	{ GOT_ERR_CANCELLED,	"operation in progress has been cancelled" },
	{ GOT_ERR_NO_TREE_ENTRY,"no such entry found in tree" },
	{ GOT_ERR_FILEIDX_SIG,	"bad file index signature" },
	{ GOT_ERR_FILEIDX_VER,	"unknown file index format version" },
	{ GOT_ERR_FILEIDX_CSUM,	"bad file index checksum" },
	{ GOT_ERR_PATH_PREFIX,	"worktree already contains items from a "
				"different path prefix" },
	{ GOT_ERR_ANCESTRY,	"target commit is on a different branch" },
	{ GOT_ERR_FILEIDX_BAD,	"file index is corrupt" },
	{ GOT_ERR_BAD_REF_DATA,	"could not parse reference data" },
	{ GOT_ERR_TREE_DUP_ENTRY,"duplicate entry in tree object" },
	{ GOT_ERR_DIR_DUP_ENTRY,"duplicate entry in directory" },
	{ GOT_ERR_NOT_WORKTREE, "no work tree found" },
	{ GOT_ERR_UUID_VERSION, "bad uuid version" },
	{ GOT_ERR_UUID_INVALID, "uuid invalid" },
	{ GOT_ERR_UUID,		"uuid error" },
	{ GOT_ERR_LOCKFILE_TIMEOUT,"lockfile timeout" },
	{ GOT_ERR_BAD_REF_NAME,	"bad reference name" },
	{ GOT_ERR_WORKTREE_REPO,"cannot create worktree inside a git repository" },
	{ GOT_ERR_FILE_MODIFIED,"file contains modifications" },
	{ GOT_ERR_FILE_STATUS,	"file has unexpected status" },
	{ GOT_ERR_COMMIT_CONFLICT,"cannot commit file in conflicted status" },
	{ GOT_ERR_BAD_REF_TYPE,	"bad reference type" },
	{ GOT_ERR_COMMIT_NO_AUTHOR,"GOT_AUTHOR environment variable is not set" },
	{ GOT_ERR_COMMIT_HEAD_CHANGED, "branch head in repository has changed "
	    "while commit was in progress" },
	{ GOT_ERR_COMMIT_OUT_OF_DATE, "work tree must be updated before these "
	    "changes can be committed" },
	{ GOT_ERR_COMMIT_MSG_EMPTY, "commit message cannot be empty" },
	{ GOT_ERR_DIR_NOT_EMPTY, "directory exists and is not empty" },
	{ GOT_ERR_COMMIT_NO_CHANGES, "no changes to commit" },
	{ GOT_ERR_BRANCH_MOVED,	"work tree's head reference now points to a "
	    "different branch; new head reference and/or update -b required" },
	{ GOT_ERR_OBJ_TOO_LARGE,	"object too large" },
	{ GOT_ERR_SAME_BRANCH,	"commit is already contained in this branch" },
	{ GOT_ERR_ROOT_COMMIT,	"specified commit has no parent commit" },
	{ GOT_ERR_MIXED_COMMITS,"work tree contains files from multiple "
	    "base commits; the entire work tree must be updated first" },
	{ GOT_ERR_CONFLICTS,	"work tree contains conflicted files; these "
	    "conflicts must be resolved first" },
	{ GOT_ERR_BRANCH_EXISTS,"specified branch already exists" },
	{ GOT_ERR_MODIFIED,	"work tree contains local changes; these "
	    "changes must be committed or reverted first" },
	{ GOT_ERR_NOT_REBASING,	"rebase operation not in progress" },
	{ GOT_ERR_REBASE_COMMITID,"rebase commit ID mismatch" },
	{ GOT_ERR_WRONG_BRANCH, "update -b required" },
	{ GOT_ERR_REBASING,	"a rebase operation is in progress in this "
	    "work tree and must be continued or aborted first" },
	{ GOT_ERR_REBASE_PATH,	"cannot rebase branch which contains "
	    "changes outside of this work tree's path prefix" },
	{ GOT_ERR_NOT_HISTEDIT,	"histedit operation not in progress" },
	{ GOT_ERR_EMPTY_HISTEDIT,"no commits to edit; perhaps the work tree "
	    "must be updated to an older commit first" },
	{ GOT_ERR_NO_HISTEDIT_CMD,"no histedit commands provided" },
	{ GOT_ERR_HISTEDIT_SYNTAX,"syntax error in histedit command list" },
	{ GOT_ERR_HISTEDIT_CANCEL,"histedit operation cancelled" },
	{ 95, "unused error code" },
	{ GOT_ERR_HISTEDIT_BUSY,"histedit operation is in progress in this "
	    "work tree and must be continued or aborted first" },
	{ GOT_ERR_HISTEDIT_CMD, "bad histedit command" },
	{ GOT_ERR_HISTEDIT_PATH, "cannot edit branch history which contains "
	    "changes outside of this work tree's path prefix" },
	{ GOT_ERR_PACKFILE_CSUM, "pack file checksum error" },
	{ GOT_ERR_COMMIT_BRANCH, "will not commit to a branch outside the "
	    "\"refs/heads/\" reference namespace" },
	{ GOT_ERR_FILE_STAGED, "file is staged" },
	{ GOT_ERR_STAGE_NO_CHANGE, "no changes to stage" },
	{ GOT_ERR_STAGE_CONFLICT, "cannot stage file in conflicted status" },
	{ GOT_ERR_STAGE_OUT_OF_DATE, "work tree must be updated before "
	    "changes can be staged" },
	{ GOT_ERR_FILE_NOT_STAGED, "file is not staged" },
	{ GOT_ERR_STAGED_PATHS, "work tree contains files with staged "
	    "changes; these changes must be committed or unstaged first" },
	{ GOT_ERR_PATCH_CHOICE, "invalid patch choice" },
	{ GOT_ERR_COMMIT_NO_EMAIL, "commit author's email address is required "
	    "for compatibility with Git" },
	{ GOT_ERR_TAG_EXISTS,"specified tag already exists" },
	{ GOT_ERR_GIT_REPO_FORMAT,"unknown git repository format version" },
	{ GOT_ERR_REBASE_REQUIRED,"specified branch must be rebased first" },
	{ GOT_ERR_REGEX, "regular expression error" },
	{ GOT_ERR_REF_NAME_MINUS, "reference name may not start with '-'" },
	{ GOT_ERR_GITCONFIG_SYNTAX, "gitconfig syntax error" },
	{ GOT_ERR_REBASE_OUT_OF_DATE, "work tree must be updated before it "
	    "can be used to rebase a branch" },
	{ GOT_ERR_CACHE_DUP_ENTRY, "duplicate cache entry" },
	{ GOT_ERR_FETCH_FAILED, "fetch failed" },
	{ GOT_ERR_PARSE_URI, "failed to parse uri" },
	{ GOT_ERR_BAD_PROTO, "unknown protocol" },
	{ GOT_ERR_ADDRINFO, "getaddrinfo failed" },
	{ GOT_ERR_BAD_PACKET, "bad packet received" },
	{ GOT_ERR_NO_REMOTE, "remote repository not found" },
	{ GOT_ERR_FETCH_NO_BRANCH, "could not find any branches to fetch" },
	{ GOT_ERR_FETCH_BAD_REF, "reference cannot be fetched" },
	{ GOT_ERR_TREE_ENTRY_TYPE, "unexpected tree entry type" },
	{ GOT_ERR_PARSE_CONFIG, "configuration file syntax error" },
	{ GOT_ERR_NO_CONFIG_FILE, "configuration file doesn't exit" },
	{ GOT_ERR_BAD_SYMLINK, "symbolic link points outside of paths under "
	    "version control" },
	{ GOT_ERR_GIT_REPO_EXT, "unsupported repository format extension" },
	{ GOT_ERR_CANNOT_PACK, "not enough objects to pack" },
	{ GOT_ERR_LONELY_PACKIDX, "pack index has no corresponding pack file; "
	    "pack file must be restored or 'gotadmin cleanup -p' must be run" },
	{ GOT_ERR_OBJ_CSUM, "bad object checksum" },
	{ GOT_ERR_SEND_BAD_REF, "reference cannot be sent" },
	{ GOT_ERR_SEND_FAILED, "could not send pack file" },
	{ GOT_ERR_SEND_EMPTY, "no references to send" },
	{ GOT_ERR_SEND_ANCESTRY, "branch on server has a different ancestry; either fetch changes from server and then rebase or merge local branch before sending, or ignore ancestry with send -f (can lead to data loss on server)" },
	{ GOT_ERR_CAPA_DELETE_REFS, "server cannot delete references" },
	{ GOT_ERR_SEND_DELETE_REF, "reference cannot be deleted" },
	{ GOT_ERR_SEND_TAG_EXISTS, "tag already exists on server" },
	{ GOT_ERR_NOT_MERGING,	"merge operation not in progress" },
	{ GOT_ERR_MERGE_OUT_OF_DATE, "work tree must be updated before it "
	    "can be used to merge a branch" },
	{ GOT_ERR_MERGE_STAGED_PATHS, "work tree contains files with staged "
	    "changes; these changes must be unstaged before merging can "
	    "proceed" },
	{ GOT_ERR_MERGE_BUSY,"a merge operation is in progress in this "
	    "work tree and must be continued or aborted first" },
	{ GOT_ERR_MERGE_PATH,	"cannot merge branch which contains "
	    "changes outside of this work tree's path prefix" },
	{ GOT_ERR_FILE_BINARY, "found a binary file instead of text" },
	{ GOT_ERR_PATCH_MALFORMED, "malformed patch" },
	{ GOT_ERR_PATCH_TRUNCATED, "patch truncated" },
	{ GOT_ERR_NO_PATCH, "no patch found" },
	{ GOT_ERR_HUNK_FAILED, "hunk failed to apply" },
	{ GOT_ERR_PATCH_FAILED, "patch failed to apply" },
	{ GOT_ERR_FILEIDX_DUP_ENTRY, "duplicate file index entry" },
	{ GOT_ERR_PIN_PACK, "could not pin pack file" },
	{ GOT_ERR_BAD_TAG_SIGNATURE, "invalid tag signature" },
	{ GOT_ERR_VERIFY_TAG_SIGNATURE, "cannot verify signature" },
	{ GOT_ERR_SIGNING_TAG, "unable to sign tag" },
	{ GOT_ERR_BAD_OPTION, "option cannot be used" },
	{ GOT_ERR_BAD_QUERYSTRING, "invalid query string" },
	{ GOT_ERR_INTEGRATE_BRANCH, "will not integrate into a reference "
	    "outside the \"refs/heads/\" reference namespace" },
	{ GOT_ERR_BAD_REQUEST, "unexpected request received" },
	{ GOT_ERR_CLIENT_ID, "unknown client identifier" },
	{ GOT_ERR_REPO_TEMPFILE, "no repository tempfile available" },
	{ GOT_ERR_REFS_PROTECTED, "reference namespace is protected" },
	{ GOT_ERR_REF_PROTECTED, "reference is protected" },
	{ GOT_ERR_REF_BUSY, "reference cannot be updated; please try again" },
	{ GOT_ERR_COMMIT_BAD_AUTHOR, "commit author formatting would "
	    "make Git unhappy" },
	{ GOT_ERR_UID, "bad user ID" },
	{ GOT_ERR_GID, "bad group ID" },
	{ GOT_ERR_NO_PROG, "command not found or not accessible" },
	{ GOT_ERR_MERGE_COMMIT_OUT_OF_DATE, "merging cannot proceed because "
	    "the work tree is no longer up-to-date; merge must be aborted "
	    "and retried" },
	{ GOT_ERR_BUNDLE_FORMAT, "unknown git bundle version" },
	{ GOT_ERR_BAD_KEYWORD, "invalid commit keyword" },
	{ GOT_ERR_UNKNOWN_CAPA, "unknown capability" },
	{ GOT_ERR_REF_DUP_ENTRY, "duplicate reference entry" },
	{ GOT_ERR_DIFF_NOCHANGES, "no changes match the requested diff" },
	{ GOT_ERR_USER, "no such user" },
	{ GOT_ERR_USER_EXISTS, "user already exists" },
	{ GOT_ERR_GROUP, "no such group" },
	{ GOT_ERR_GROUP_EXISTS, "group already exists" },
	{ GOT_ERR_AUTHORIZED_KEY, "no authorized key found" },
	{ GOT_ERR_CONNECTION_LIMIT, "connection limit exceeded" },
	{ GOT_ERR_ON_SERVER_SIDE, "see server-side logs for error details" },
	{ GOT_ERR_LOGIN_FAILED, "login failed" },
	{ GOT_ERR_UNKNOWN_COMMAND, "command not found" },
	{ GOT_ERR_NOT_FOUND, "not found" },
	{ GOT_ERR_MEDIA_TYPE,	"malformed media type" },
	{ GOT_ERR_LOGOUT_FAILED, "logout failed" },
	{ GOT_ERR_LOGIN_HINT, "login failed, see hint" },
};

static struct got_custom_error {
	struct got_error err;
	char msg[GOT_ERR_MAX_MSG_SIZE];
} custom_errors[16];

static struct got_custom_error *
get_custom_err(void)
{
	static unsigned int idx;
	return &custom_errors[(idx++) % nitems(custom_errors)];
}

const struct got_error *
got_error(int code)
{
	size_t i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code)
			return &got_errors[i];
	}

	abort();
}

const struct got_error *
got_error_msg(int code, const char *msg)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	size_t i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code) {
			err->code = code;
			strlcpy(cerr->msg, msg, sizeof(cerr->msg));
			err->msg = cerr->msg;
			return err;
		}
	}

	abort();
}

const struct got_error *
got_error_from_errno(const char *prefix)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	char strerr[128];

	strerror_r(errno, strerr, sizeof(strerr));
	snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s", prefix, strerr);

	err->code = GOT_ERR_ERRNO;
	err->msg = cerr->msg;
	return err;
}

const struct got_error *
got_error_from_errno2(const char *prefix, const char *prefix2)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	char strerr[128];

	strerror_r(errno, strerr, sizeof(strerr));
	snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s: %s", prefix, prefix2,
	    strerr);

	err->code = GOT_ERR_ERRNO;
	err->msg = cerr->msg;
	return err;
}

const struct got_error *
got_error_from_errno3(const char *prefix, const char *prefix2,
    const char *prefix3)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	char strerr[128];

	strerror_r(errno, strerr, sizeof(strerr));
	snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s: %s: %s", prefix,
	    prefix2, prefix3, strerr);

	err->code = GOT_ERR_ERRNO;
	err->msg = cerr->msg;
	return err;
}

const struct got_error *
got_error_from_errno_fmt(const char *fmt, ...)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	char buf[PATH_MAX * 4];
	char strerr[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	strerror_r(errno, strerr, sizeof(strerr));
	snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s", buf, strerr);

	err->code = GOT_ERR_ERRNO;
	err->msg = cerr->msg;
	return err;
}

const struct got_error *
got_error_set_errno(int code, const char *prefix)
{
	errno = code;
	return got_error_from_errno(prefix);
}

const struct got_error *
got_ferror(FILE *f, int code)
{
	if (ferror(f))
		return got_error_from_errno("");
	return got_error(code);
}

const struct got_error *
got_error_no_obj(struct got_object_id *id)
{
	char id_str[GOT_OBJECT_ID_HEX_MAXLEN];
	char msg[sizeof("object   not found") + sizeof(id_str)];
	int ret;

	if (!got_object_id_hex(id, id_str, sizeof(id_str)))
		return got_error(GOT_ERR_NO_OBJ);

	ret = snprintf(msg, sizeof(msg), "object %s not found", id_str);
	if (ret < 0 || (size_t)ret >= sizeof(msg))
		return got_error(GOT_ERR_NO_OBJ);

	return got_error_msg(GOT_ERR_NO_OBJ, msg);
}

const struct got_error *
got_error_checksum(struct got_object_id *id)
{
	char id_str[GOT_OBJECT_ID_HEX_MAXLEN];
	char msg[sizeof("checksum failure for object ") + sizeof(id_str)];
	int ret;

	if (!got_object_id_hex(id, id_str, sizeof(id_str)))
		return got_error(GOT_ERR_OBJ_CSUM);

	ret = snprintf(msg, sizeof(msg), "checksum failure for object %s",
	    id_str);
	if (ret < 0 || (size_t)ret >= sizeof(msg))
		return got_error(GOT_ERR_OBJ_CSUM);

	return got_error_msg(GOT_ERR_OBJ_CSUM, msg);
}

const struct got_error *
got_error_not_ref(const char *refname)
{
	char msg[sizeof("reference   not found") + 1004];
	int ret;

	ret = snprintf(msg, sizeof(msg), "reference %s not found", refname);
	if (ret < 0 || (size_t)ret >= sizeof(msg))
		return got_error(GOT_ERR_NOT_REF);

	return got_error_msg(GOT_ERR_NOT_REF, msg);
}

const struct got_error *
got_error_uuid(uint32_t uuid_status, const char *prefix)
{
	switch (uuid_status) {
	case uuid_s_ok:
		return NULL;
	case uuid_s_bad_version:
		return got_error(GOT_ERR_UUID_VERSION);
	case uuid_s_invalid_string_uuid:
		return got_error(GOT_ERR_UUID_INVALID);
	case uuid_s_no_memory:
		return got_error_set_errno(ENOMEM, prefix);
	default:
		return got_error(GOT_ERR_UUID);
	}
}

const struct got_error *
got_error_path(const char *path, int code)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	size_t i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code) {
			err->code = code;
			snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s", path,
			    got_errors[i].msg);
			err->msg = cerr->msg;
			return err;
		}
	}

	abort();
}

const struct got_error *
got_error_fmt(int code, const char *fmt, ...)
{
	struct got_custom_error *cerr = get_custom_err();
	struct got_error *err = &cerr->err;
	char buf[PATH_MAX * 4];
	va_list ap;
	size_t i;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code) {
			err->code = code;
			snprintf(cerr->msg, sizeof(cerr->msg), "%s: %s", buf,
			    got_errors[i].msg);
			err->msg = cerr->msg;
			return err;
		}
	}

	abort();
}

int
got_err_open_nofollow_on_symlink(void)
{
	/*
	 * Check whether open(2) with O_NOFOLLOW failed on a symlink.
	 * Posix mandates ELOOP and OpenBSD follows it. Others return
	 * different error codes. We carry this workaround to help the
	 * portable version a little.
	 */
	return (errno == ELOOP
#ifdef EMLINK
	|| errno == EMLINK
#endif
#ifdef EFTYPE
	|| errno == EFTYPE
#endif
	);
}
