/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
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
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <stdint.h>
#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sha1.h>
#include <sha2.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <err.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"
#include "got_version.h"
#include "got_fetch.h"
#include "got_reference.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_pkt.h"
#include "got_lib_poll.h"
#include "got_lib_gitproto.h"
#include "got_lib_ratelimit.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_object *indexed;
static int chattygot;

static const struct got_capability got_capabilities[] = {
	{ GOT_CAPA_AGENT, "got/" GOT_VERSION_STR },
	{ GOT_CAPA_OBJECT_FORMAT, "sha256" },
	{ GOT_CAPA_OFS_DELTA, NULL },
	{ GOT_CAPA_SIDE_BAND_64K, NULL },
};

static void
match_remote_ref(struct got_pathlist_head *have_refs,
    struct got_object_id *my_id, const char *refname, int algo)
{
	struct got_pathlist_entry *pe;

	/* XXX zero-hash signifies we don't have this ref;
	 * we should use a flag instead */
	memset(my_id, 0, sizeof(*my_id));
	my_id->algo = algo;

	RB_FOREACH(pe, got_pathlist_head, have_refs) {
		struct got_object_id *id = pe->data;
		if (strcmp(pe->path, refname) == 0) {
			memcpy(my_id, id, sizeof(*my_id));
			break;
		}
	}
}

static int
match_branch(const char *branch, const char *wanted_branch)
{
	if (strncmp(branch, "refs/heads/", 11) != 0)
		return 0;

	if (strncmp(wanted_branch, "refs/heads/", 11) == 0)
		wanted_branch += 11;

	return (strcmp(branch + 11, wanted_branch) == 0);
}

static int
match_wanted_ref(const char *refname, const char *wanted_ref)
{
	if (strncmp(refname, "refs/", 5) != 0)
		return 0;
	refname += 5;

	/*
	 * Prevent fetching of references that won't make any
	 * sense outside of the remote repository's context.
	 */
	if (strncmp(refname, "got/", 4) == 0)
		return 0;
	if (strncmp(refname, "remotes/", 8) == 0)
		return 0;

	if (strncmp(wanted_ref, "refs/", 5) == 0)
		wanted_ref += 5;

	/* Allow prefix match. */
	if (got_path_is_child(refname, wanted_ref, strlen(wanted_ref)))
		return 1;

	/* Allow exact match. */
	return (strcmp(refname, wanted_ref) == 0);
}

static const struct got_error *
send_fetch_server_progress(struct imsgbuf *ibuf, const char *msg, size_t msglen)
{
	if (msglen > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	if (msglen == 0)
		return NULL;

	if (imsg_compose(ibuf, GOT_IMSG_FETCH_SERVER_PROGRESS, 0, 0, -1,
	    msg, msglen) == -1)
		return got_error_from_errno(
		    "imsg_compose FETCH_SERVER_PROGRESS");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_fetch_download_progress(struct imsgbuf *ibuf, off_t bytes,
    struct got_ratelimit *rl)
{
	const struct got_error *err;
	int elapsed = 0;

	if (rl) {
		err = got_ratelimit_check(&elapsed, rl);
		if (err || !elapsed)
			return err;
	}

	if (imsg_compose(ibuf, GOT_IMSG_FETCH_DOWNLOAD_PROGRESS, 0, 0, -1,
	    &bytes, sizeof(bytes)) == -1)
		return got_error_from_errno(
		    "imsg_compose FETCH_DOWNLOAD_PROGRESS");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_fetch_done(struct imsgbuf *ibuf, struct got_object_id *pack_hash)
{
	if (imsg_compose(ibuf, GOT_IMSG_FETCH_DONE, 0, 0, -1,
	    pack_hash, sizeof(*pack_hash)) == -1)
		return got_error_from_errno("imsg_compose FETCH");
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
fetch_progress(struct imsgbuf *ibuf, const char *buf, size_t len)
{
	size_t i;

	if (len == 0)
		return NULL;

	/*
	 * Truncate messages which exceed the maximum imsg payload size.
	 * Server may send up to 64k.
	 */
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		len = MAX_IMSGSIZE - IMSG_HEADER_SIZE;

	/*
	 * We only allow printable ASCII for safety reasons and silently
	 * ignore non-ASCII messages, which may be somewhat legitimately
	 * caused by Git servers running in a non-English language locale.
	 */
	for (i = 0; i < len; i++) {
		if (isprint((unsigned char)buf[i]) ||
		    isspace((unsigned char)buf[i]))
			continue;
		return NULL;
	}

	return send_fetch_server_progress(ibuf, buf, len);
}

static const struct got_error *
fetch_error(const char *buf, size_t len)
{
	static char msg[1024];
	size_t i;

	for (i = 0; i < len && i < sizeof(msg) - 1; i++) {
		if (!isprint((unsigned char)buf[i]))
			return got_error_msg(GOT_ERR_BAD_PACKET,
			    "non-printable error message received from server");
		msg[i] = buf[i];
	}
	msg[i] = '\0';
	return got_error_msg(GOT_ERR_FETCH_FAILED, msg);
}

static const struct got_error *
send_fetch_symrefs(struct imsgbuf *ibuf, struct got_pathlist_head *symrefs)
{
	struct ibuf *wbuf;
	size_t len, nsymrefs = 0;
	struct got_pathlist_entry *pe;

	len = sizeof(struct got_imsg_fetch_symrefs);
	RB_FOREACH(pe, got_pathlist_head, symrefs) {
		const char *target = pe->data;
		len += sizeof(struct got_imsg_fetch_symref) +
		    pe->path_len + strlen(target);
		nsymrefs++;
	}

	if (len >= MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_SYMREFS, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create FETCH_SYMREFS");

	/* Keep in sync with struct got_imsg_fetch_symrefs definition! */
	if (imsg_add(wbuf, &nsymrefs, sizeof(nsymrefs)) == -1)
		return got_error_from_errno("imsg_add FETCH_SYMREFS");

	RB_FOREACH(pe, got_pathlist_head, symrefs) {
		const char *name = pe->path;
		size_t name_len = pe->path_len;
		const char *target = pe->data;
		size_t target_len = strlen(target);

		/* Keep in sync with struct got_imsg_fetch_symref definition! */
		if (imsg_add(wbuf, &name_len, sizeof(name_len)) == -1)
			return got_error_from_errno("imsg_add FETCH_SYMREFS");
		if (imsg_add(wbuf, &target_len, sizeof(target_len)) == -1)
			return got_error_from_errno("imsg_add FETCH_SYMREFS");
		if (imsg_add(wbuf, name, name_len) == -1)
			return got_error_from_errno("imsg_add FETCH_SYMREFS");
		if (imsg_add(wbuf, target, target_len) == -1)
			return got_error_from_errno("imsg_add FETCH_SYMREFS");
	}

	imsg_close(ibuf, wbuf);
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_object_format(struct imsgbuf *ibuf, struct got_object_id *pack_hash)
{
	if (imsg_compose(ibuf, GOT_IMSG_FETCH_OBJECT_FORMAT, 0, 0, -1,
	    pack_hash, sizeof(*pack_hash)) == -1)
		return got_error_from_errno("imsg_compose FETCH_OBJECT_FORMAT");
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_fetch_ref(struct imsgbuf *ibuf, struct got_object_id *refid,
    const char *refname)
{
	struct ibuf *wbuf;
	size_t len, reflen = strlen(refname);

	len = sizeof(struct got_imsg_fetch_ref) + reflen;
	if (len >= MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_FETCH_REF, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create FETCH_REF");

	/* Keep in sync with struct got_imsg_fetch_ref definition! */
	if (imsg_add(wbuf, refid, sizeof(*refid)) == -1)
		return got_error_from_errno("imsg_add FETCH_REF");
	if (imsg_add(wbuf, refname, reflen) == -1)
		return got_error_from_errno("imsg_add FETCH_REF");

	imsg_close(ibuf, wbuf);
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
fetch_ref(struct imsgbuf *ibuf, struct got_pathlist_head *have_refs,
    struct got_object_id *have, struct got_object_id *want,
    const char *refname, const char *id_str, int algo)
{
	const struct got_error *err;
	char *theirs = NULL, *mine = NULL;

	if (!got_parse_object_id(want, id_str, algo)) {
		err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
		goto done;
	}

	match_remote_ref(have_refs, have, refname, algo);
	err = send_fetch_ref(ibuf, want, refname);
	if (err)
		goto done;

	if (chattygot)
		fprintf(stderr, "%s: %s will be fetched\n",
		    getprogname(), refname);
	if (chattygot > 1) {
		err = got_object_id_str(&theirs, want);
		if (err)
			goto done;
		err = got_object_id_str(&mine, have);
		if (err)
			goto done;
		fprintf(stderr, "%s: remote: %s\n%s: local:  %s\n",
		    getprogname(), theirs, getprogname(), mine);
	}
done:
	free(theirs);
	free(mine);
	return err;
}

static const struct got_error *
fetch_pack(int fd, int packfd, int expected_algo,
    struct got_object_id *pack_hash,
    struct got_pathlist_head *have_refs, int fetch_all_branches,
    struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, int list_refs_only,
    const char *worktree_branch, const char *remote_head,
    int no_head, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	char buf[GOT_PKT_MAX];
	char hashstr[GOT_HASH_DIGEST_STRING_MAXLEN];
	struct got_object_id *have, *want;
	int is_firstpkt = 1, nref = 0, refsz = 16;
	int i, n, nwant = 0, nhave = 0, acked = 0, eof = 0;
	off_t packsz = 0, last_reported_packsz = 0;
	char *id_str = NULL, *default_id_str = NULL, *refname = NULL;
	char *server_capabilities = NULL, *my_capabilities = NULL;
	const char *default_branch = NULL;
	char *free_default_branch = NULL;
	struct got_pathlist_head symrefs;
	struct got_pathlist_entry *pe;
	int sent_my_capabilites = 0, have_sidebands = 0;
	int found_branch = 0;
	struct got_hash ctx;
	uint8_t sha1_buf[GOT_HASH_DIGEST_MAXLEN];
	size_t sha1_buf_len = 0;
	ssize_t w;
	struct got_ratelimit rl;
	size_t idlen;
	enum got_hash_algorithm algo = GOT_HASH_SHA1;

	RB_INIT(&symrefs);
	got_ratelimit_init(&rl, 0, 500);

	have = malloc(refsz * sizeof(have[0]));
	if (have == NULL)
		return got_error_from_errno("malloc");
	want = malloc(refsz * sizeof(want[0]));
	if (want == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	while (1) {
		err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot,
		    INFTIM);
		if (err)
			goto done;
		if (n == 0)
			break;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = fetch_error(&buf[4], n - 4);
			goto done;
		}
		free(id_str);
		free(refname);
		err = got_gitproto_parse_refline(&id_str, &refname,
		    &server_capabilities, buf, n);
		if (err)
			goto done;

		if (refsz == nref + 1) {
			struct got_object_id *h, *w;

			refsz *= 2;
			h = reallocarray(have, refsz, sizeof(have[0]));
			if (h == NULL) {
				err = got_error_from_errno("reallocarray");
				goto done;
			}
			have = h;
			w = reallocarray(want, refsz, sizeof(want[0]));
			if (w == NULL) {
				err = got_error_from_errno("reallocarray");
				goto done;
			}
			want = w;
		}

		if (is_firstpkt) {
			if (chattygot && server_capabilities[0] != '\0')
				fprintf(stderr, "%s: server capabilities: %s\n",
				    getprogname(), server_capabilities);
			err = got_gitproto_match_capabilities(&my_capabilities,
			    &symrefs, server_capabilities,
			    got_capabilities, nitems(got_capabilities),
			    &algo);
			if (err)
				goto done;
			if (expected_algo != -1 && algo != expected_algo) {
				err = got_error(GOT_ERR_OBJECT_FORMAT);
				goto done;
			}

			if (chattygot)
				fprintf(stderr, "%s: my capabilities:%s\n",
				    getprogname(), my_capabilities != NULL ?
				    my_capabilities : "");

			pack_hash->algo = algo;
			err = send_object_format(ibuf, pack_hash);
			if (err)
				goto done;

			err = send_fetch_symrefs(ibuf, &symrefs);
			if (err)
				goto done;

			is_firstpkt = 0;
			if (!fetch_all_branches) {
				RB_FOREACH(pe, got_pathlist_head, &symrefs) {
					const char *name = pe->path;
					const char *symref_target = pe->data;
					if (strcmp(name, GOT_REF_HEAD) != 0)
						continue;
					default_branch = symref_target;
					break;
				}
			}
			if (default_branch)
				continue;
		}
		if (strstr(refname, "^{}")) {
			if (chattygot) {
				fprintf(stderr, "%s: ignoring %s\n",
				    getprogname(), refname);
			}
			continue;
		}
		if (default_branch == NULL &&
		    strcmp(refname, GOT_REF_HEAD) == 0) {
			default_id_str = strdup(id_str);
			if (default_id_str == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}
		if (default_branch && default_id_str == NULL &&
		    strcmp(refname, default_branch) == 0) {
			default_id_str = strdup(id_str);
			if (default_id_str == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}
		/* If no symrefs is given, go for first matching id_str */
		if (default_branch == NULL && default_id_str &&
		    strncmp(refname, "refs/heads/", 11) == 0 &&
		    strcmp(id_str, default_id_str) == 0) {
			free_default_branch = strdup(refname);
			if (free_default_branch == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
			default_branch = free_default_branch;
		}

		if (list_refs_only || strncmp(refname, "refs/tags/", 10) == 0) {
			err = fetch_ref(ibuf, have_refs, &have[nref],
			    &want[nref], refname, id_str, algo);
			if (err)
				goto done;
			nref++;
		} else if (strncmp(refname, "refs/heads/", 11) == 0) {
			if (fetch_all_branches) {
				err = fetch_ref(ibuf, have_refs, &have[nref],
				    &want[nref], refname, id_str, algo);
				if (err)
					goto done;
				nref++;
				found_branch = 1;
				continue;
			}
			RB_FOREACH(pe, got_pathlist_head, wanted_branches) {
				if (match_branch(refname, pe->path))
					break;
			}
			if (pe != NULL || (worktree_branch != NULL &&
			    match_branch(refname, worktree_branch))) {
				err = fetch_ref(ibuf, have_refs, &have[nref],
				    &want[nref], refname, id_str, algo);
				if (err)
					goto done;
				nref++;
				found_branch = 1;
			} else if (chattygot && (default_branch == NULL ||
			    strcmp(default_branch, refname) != 0)) {
				fprintf(stderr, "%s: ignoring %s\n",
				    getprogname(), refname);
			}
		} else {
			RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
				if (match_wanted_ref(refname, pe->path))
					break;
			}
			if (pe != NULL) {
				err = fetch_ref(ibuf, have_refs, &have[nref],
				    &want[nref], refname, id_str, algo);
				if (err)
					goto done;
				nref++;
			} else if (chattygot) {
				fprintf(stderr, "%s: ignoring %s\n",
				    getprogname(), refname);
			}
		}
	}

	if (list_refs_only)
		goto done;

	got_hash_init(&ctx, algo);
	idlen = got_hash_digest_length(algo);

	/*
	 * If -b was not used and either none of the requested branches
	 * (got.conf, worktree) were found or the client already has the
	 * remote HEAD symref but its target changed, fetch remote's HEAD.
	 */
	if (!no_head && default_branch && default_id_str &&
	    strncmp(default_branch, "refs/heads/", 11) == 0) {
		int remote_head_changed = 0;

		if (remote_head) {
			if (strcmp(remote_head, default_branch + 11) != 0)
				remote_head_changed = 1;
		}

		if (!found_branch || remote_head_changed) {
			err = fetch_ref(ibuf, have_refs, &have[nref],
			    &want[nref], default_branch, default_id_str, algo);
			if (err)
				goto done;
			nref++;
		}
	}

	/* Abort if we haven't found anything to fetch. */
	if (nref == 0) {
		struct got_pathlist_entry *pe;
		static char msg[PATH_MAX + 33];

		pe = RB_MIN(got_pathlist_head, wanted_branches);
		if (pe) {
			snprintf(msg, sizeof(msg),
			    "branch \"%s\" not found on server", pe->path);
			err = got_error_msg(GOT_ERR_FETCH_NO_BRANCH, msg);
			goto done;
		}

		pe = RB_MIN(got_pathlist_head, wanted_refs);
		if (pe) {
			snprintf(msg, sizeof(msg),
			    "reference \"%s\" not found on server", pe->path);
			err = got_error_msg(GOT_ERR_FETCH_NO_BRANCH, msg);
			goto done;
		}

		err = got_error(GOT_ERR_FETCH_NO_BRANCH);
		goto done;
	}

	for (i = 0; i < nref; i++) {
		if (got_object_id_cmp(&have[i], &want[i]) == 0)
			continue;
		got_object_id_hex(&want[i], hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "want %s%s\n", hashstr,
		    sent_my_capabilites || my_capabilities == NULL ?
		    "" : my_capabilities);
		if (n < 0 || (size_t)n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = got_pkt_writepkt(fd, buf, n, chattygot);
		if (err)
			goto done;
		sent_my_capabilites = 1;
		nwant++;
	}
	err = got_pkt_flushpkt(fd, chattygot);
	if (err)
		goto done;

	if (nwant == 0)
		goto done;

	RB_FOREACH(pe, got_pathlist_head, have_refs) {
		struct got_object_id *id = pe->data;
		got_object_id_hex(id, hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "have %s\n", hashstr);
		if (n < 0 || (size_t)n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = got_pkt_writepkt(fd, buf, n, chattygot);
		if (err)
			goto done;
		nhave++;
	}

	n = strlcpy(buf, "done\n", sizeof(buf));
	err = got_pkt_writepkt(fd, buf, n, chattygot);
	if (err)
		goto done;

	while (nhave > 0 && !acked) {
		struct got_object_id common_id;

		/* The server should ACK the object IDs we need. */
		err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot,
		    INFTIM);
		if (err)
			goto done;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = fetch_error(&buf[4], n - 4);
			goto done;
		}
		if (n >= 4 && strncmp(buf, "NAK\n", 4) == 0) {
			/*
			 * Server could not find a common ancestor.
			 * Perhaps it is an out-of-date mirror, or there
			 * is a repository with unrelated history.
			 */
			break;
		}
		if (n < 4 + idlen || strncmp(buf, "ACK ", 4) != 0) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		}
		if (!got_parse_object_id(&common_id, buf + 4, algo)) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "bad object ID in ACK packet from server");
			goto done;
		}
		acked++;
	}

	if (nhave == 0) {
		err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot,
		    INFTIM);
		if (err)
			goto done;
		if (n != 4 || strncmp(buf, "NAK\n", n) != 0) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		}
	}

	if (chattygot)
		fprintf(stderr, "%s: fetching...\n", getprogname());

	if (my_capabilities != NULL &&
	    strstr(my_capabilities, GOT_CAPA_SIDE_BAND_64K) != NULL)
		have_sidebands = 1;

	while (!eof) {
		ssize_t r = 0;
		int datalen = -1;

		if (have_sidebands) {
			err = got_pkt_readhdr(&datalen, fd, chattygot, INFTIM);
			if (err)
				goto done;
			if (datalen <= 0)
				break;

			/* Read sideband channel ID (one byte). */
			r = read(fd, buf, 1);
			if (r == -1) {
				err = got_error_from_errno("read");
				goto done;
			}
			if (r != 1) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "short packet");
				goto done;
			}
			if (datalen > sizeof(buf) - 5) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "bad packet length");
				goto done;
			}
			datalen--; /* sideband ID has been read */
			if (buf[0] == GOT_SIDEBAND_PACKFILE_DATA) {
				/* Read packfile data. */
				err = got_pkt_readn(&r, fd, buf, datalen,
				    INFTIM);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
			} else if (buf[0] == GOT_SIDEBAND_PROGRESS_INFO) {
				err = got_pkt_readn(&r, fd, buf, datalen,
				    INFTIM);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
				err = fetch_progress(ibuf, buf, r);
				if (err)
					goto done;
				continue;
			} else if (buf[0] == GOT_SIDEBAND_ERROR_INFO) {
				err = got_pkt_readn(&r, fd, buf, datalen,
				    INFTIM);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
				err = fetch_error(buf, r);
				goto done;
			} else if (buf[0] == 'A') {
				err = got_pkt_readn(&r, fd, buf, datalen,
				    INFTIM);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
				/*
				 * Git server responds with ACK after 'done'
				 * even though multi_ack is disabled?!?
				 */
				buf[r] = '\0';
				if (strncmp(buf, "CK ", 3) == 0)
					continue; /* ignore */
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected message from server");
				goto done;
			} else {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unknown side-band received from server");
				goto done;
			}
		} else {
			/* No sideband channel. Every byte is packfile data. */
			size_t n = 0;
			err = got_poll_read_full_timeout(fd, &n,
			    buf, sizeof buf, 1, INFTIM);
			if (err) {
				if (err->code != GOT_ERR_EOF)
					goto done;
				r = 0;
				eof = 1;
			} else
				r = n;
		}

		/*
		 * An expected checksum sits at the end of the pack file.
		 * Since we don't know the file size ahead of time we have to
		 * keep idlen bytes buffered and avoid mixing those
		 * bytes into our checksum computation until we know
		 * for sure that additional pack file data bytes
		 * follow.
		 */
		if (r < idlen) {
			if (sha1_buf_len < idlen) {
				/*
				 * If there's enough buffered + read data to
				 * fill up the buffer then shift a sufficient
				 * amount of bytes out at the front to make
				 * room, mixing those bytes into the checksum.
				 */
				if (sha1_buf_len > 0 &&
				    sha1_buf_len + r > idlen) {
					size_t nshift = MIN(sha1_buf_len + r -
					    idlen, sha1_buf_len);
					got_hash_update(&ctx, sha1_buf,
					    nshift);
					memmove(sha1_buf, sha1_buf + nshift,
					    sha1_buf_len - nshift);
					sha1_buf_len -= nshift;
				}

				/* Buffer potential checksum bytes. */
				memcpy(sha1_buf + sha1_buf_len, buf, r);
				sha1_buf_len += r;
			} else if (r > 0) {
				/*
				 * Mix in previously buffered bytes which
				 * are not part of the checksum after all.
				 */
				got_hash_update(&ctx, sha1_buf, r);

				/* Update potential checksum buffer. */
				memmove(sha1_buf, sha1_buf + r,
				    sha1_buf_len - r);
				memcpy(sha1_buf + sha1_buf_len - r, buf, r);
			}
		} else {
			/* Mix in any previously buffered bytes. */
			got_hash_update(&ctx, sha1_buf, sha1_buf_len);

			/* Mix in bytes read minus potential checksum bytes. */
			got_hash_update(&ctx, buf, r - idlen);

			/* Buffer potential checksum bytes. */
			memcpy(sha1_buf, buf + r - idlen, idlen);
			sha1_buf_len = idlen;
		}

		/* Write packfile data to temporary pack file. */
		w = write(packfd, buf, r);
		if (w == -1) {
			err = got_error_from_errno("write");
			goto done;
		}
		if (w != r) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
		packsz += w;

		/* Don't send too many progress privsep messages. */
		if (packsz > last_reported_packsz + 1024) {
			err = send_fetch_download_progress(ibuf, packsz, &rl);
			if (err)
				goto done;
			last_reported_packsz = packsz;
		}
	}
	err = send_fetch_download_progress(ibuf, packsz, NULL);
	if (err)
		goto done;

	got_hash_final_object_id(&ctx, pack_hash);
	if (sha1_buf_len != idlen ||
	    memcmp(pack_hash, sha1_buf, sha1_buf_len) != 0) {
		fprintf(stderr, "error'd due to a length mismatch? %d\n",
		    sha1_buf_len != idlen);
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "pack file checksum mismatch");
	}
done:
	got_pathlist_free(&symrefs, GOT_PATHLIST_FREE_ALL);
	free(have);
	free(want);
	free(id_str);
	free(free_default_branch);
	free(default_id_str);
	free(refname);
	free(server_capabilities);
	free(my_capabilities);
	return err;
}


int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	int fetchfd = -1, packfd = -1;
	struct got_object_id pack_hash;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_pathlist_head have_refs;
	struct got_pathlist_head wanted_branches;
	struct got_pathlist_head wanted_refs;
	struct got_imsg_fetch_request fetch_req;
	struct got_imsg_fetch_have_ref href;
	struct got_imsg_fetch_wanted_branch wbranch;
	struct got_imsg_fetch_wanted_ref wref;
	size_t datalen, i;
	struct got_pathlist_entry *new;
	char *remote_head = NULL, *worktree_branch = NULL;
#if 0
	static int attached;
	while (!attached)
		sleep (1);
#endif

	RB_INIT(&have_refs);
	RB_INIT(&wanted_branches);
	RB_INIT(&wanted_refs);

	if (imsgbuf_init(&ibuf, GOT_IMSG_FD_CHILD) == -1) {
		warn("imsgbuf_init");
		return 1;
	}
	imsgbuf_allow_fdpass(&ibuf);

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}
#endif
	err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_FETCH_REQUEST) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(fetch_req)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&fetch_req, imsg.data, sizeof(fetch_req));
	fetchfd = imsg_get_fd(&imsg);

	if (datalen != sizeof(fetch_req) +
	    fetch_req.worktree_branch_len + fetch_req.remote_head_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	if (fetch_req.worktree_branch_len != 0) {
		worktree_branch = strndup(imsg.data +
		    sizeof(fetch_req), fetch_req.worktree_branch_len);
		if (worktree_branch == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
	}

	if (fetch_req.remote_head_len != 0) {
		remote_head = strndup(imsg.data + sizeof(fetch_req) +
		    fetch_req.worktree_branch_len, fetch_req.remote_head_len);
		if (remote_head == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
	}

	imsg_free(&imsg);

	if (fetch_req.verbosity > 0)
		chattygot += fetch_req.verbosity;

	for (i = 0; i < fetch_req.n_have_refs; i++) {
		struct got_object_id *id;
		char *refname;

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			goto done;
		}
		if (imsg.hdr.type == GOT_IMSG_STOP)
			goto done;
		if (imsg.hdr.type != GOT_IMSG_FETCH_HAVE_REF) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen < sizeof(href)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		memcpy(&href, imsg.data, sizeof(href));
		if (datalen - sizeof(href) < href.name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		refname = strndup(imsg.data + sizeof(href), href.name_len);
		if (refname == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}

		id = malloc(sizeof(*id));
		if (id == NULL) {
			free(refname);
			err = got_error_from_errno("malloc");
			goto done;
		}
		memcpy(id, &href.id, sizeof(*id));
		err = got_pathlist_insert(&new, &have_refs, refname, id);
		if (err || new == NULL) {
			free(refname);
			free(id);
			if (err)
				goto done;
		}

		imsg_free(&imsg);
	}

	for (i = 0; i < fetch_req.n_wanted_branches; i++) {
		char *refname;

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			goto done;
		}
		if (imsg.hdr.type == GOT_IMSG_STOP)
			goto done;
		if (imsg.hdr.type != GOT_IMSG_FETCH_WANTED_BRANCH) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen < sizeof(wbranch)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		memcpy(&wbranch, imsg.data, sizeof(wbranch));
		if (datalen - sizeof(wbranch) < wbranch.name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		refname = strndup(imsg.data + sizeof(wbranch),
		    wbranch.name_len);
		if (refname == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}

		err = got_pathlist_insert(&new, &wanted_branches, refname, NULL);
		if (err || new == NULL) {
			free(refname);
			if (err)
				goto done;
		}

		imsg_free(&imsg);
	}

	for (i = 0; i < fetch_req.n_wanted_refs; i++) {
		char *refname;

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			goto done;
		}
		if (imsg.hdr.type == GOT_IMSG_STOP)
			goto done;
		if (imsg.hdr.type != GOT_IMSG_FETCH_WANTED_REF) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen < sizeof(wref)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		memcpy(&wref, imsg.data, sizeof(wref));
		if (datalen - sizeof(wref) < wref.name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		refname = strndup(imsg.data + sizeof(wref), wref.name_len);
		if (refname == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}

		err = got_pathlist_insert(NULL, &wanted_refs, refname, NULL);
		if (err) {
			free(refname);
			goto done;
		}

		imsg_free(&imsg);
	}

	err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_FETCH_OUTFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	packfd = imsg_get_fd(&imsg);

	err = fetch_pack(fetchfd, packfd, fetch_req.expected_algo, &pack_hash,
	    &have_refs, fetch_req.fetch_all_branches, &wanted_branches,
	    &wanted_refs, fetch_req.list_refs_only,
	    worktree_branch, remote_head, fetch_req.no_head, &ibuf);
done:
	free(worktree_branch);
	free(remote_head);
	got_pathlist_free(&have_refs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&wanted_branches, GOT_PATHLIST_FREE_PATH);
	if (fetchfd != -1 && close(fetchfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err != NULL)
		got_privsep_send_error(&ibuf, err);
	else
		err = send_fetch_done(&ibuf, &pack_hash);
	if (err != NULL) {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		exit(1);
	}

	imsgbuf_clear(&ibuf);
	exit(0);
}
