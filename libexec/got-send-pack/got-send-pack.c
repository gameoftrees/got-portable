/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <err.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <err.h>

#include "got_compat.h"
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
#include "got_lib_gitproto.h"
#include "got_lib_ratelimit.h"
#include "got_lib_poll.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_object *indexed;
static int chattygot;

static const struct got_capability got_capabilities[] = {
	{ GOT_CAPA_AGENT, "got/" GOT_VERSION_STR },
	{ GOT_CAPA_OFS_DELTA, NULL },
#if 0
	{ GOT_CAPA_SIDE_BAND_64K, NULL },
#endif
	{ GOT_CAPA_REPORT_STATUS, NULL },
	{ GOT_CAPA_DELETE_REFS, NULL },
	{ GOT_CAPA_OBJECT_FORMAT, "sha256" },
};

static const struct got_error *
send_upload_progress(struct imsgbuf *ibuf, off_t bytes,
    struct got_ratelimit *rl)
{
	const struct got_error *err = NULL;
	int elapsed = 0;

	if (rl) {
		err = got_ratelimit_check(&elapsed, rl);
		if (err || !elapsed)
			return err;
	}

	if (imsg_compose(ibuf, GOT_IMSG_SEND_UPLOAD_PROGRESS, 0, 0, -1,
	    &bytes, sizeof(bytes)) == -1)
		return got_error_from_errno(
		    "imsg_compose SEND_UPLOAD_PROGRESS");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_pack_request(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_SEND_PACK_REQUEST, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose SEND_PACK_REQUEST");
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_SEND_DONE, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose SEND_DONE");
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
recv_packfd(int *packfd, struct imsgbuf *ibuf)
{
	const struct got_error *err;
	struct imsg imsg;

	*packfd = -1;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	if (imsg.hdr.type == GOT_IMSG_STOP) {
		err = got_error(GOT_ERR_CANCELLED);
		goto done;
	}

	if (imsg.hdr.type != GOT_IMSG_SEND_PACKFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	*packfd = imsg_get_fd(&imsg);
done:
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
send_pack_file(int sendfd, int packfd, struct imsgbuf *ibuf)
{
	const struct got_error *err;
	unsigned char buf[8192];
	ssize_t r;
	off_t wtotal = 0;
	struct got_ratelimit rl;

	if (lseek(packfd, 0L, SEEK_SET) == -1)
		return got_error_from_errno("lseek");

	got_ratelimit_init(&rl, 0, 500);

	for (;;) {
		r = read(packfd, buf, sizeof(buf));
		if (r == -1)
			return got_error_from_errno("read");
		if (r == 0)
			break;
		err = got_poll_write_full(sendfd, buf, r);
		if (err)
			return NULL;
		wtotal += r;
		err = send_upload_progress(ibuf, wtotal, &rl);
		if (err)
			return err;
	}

	return send_upload_progress(ibuf, wtotal, NULL);
}

static const struct got_error *
send_error(const char *buf, size_t len)
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
	return got_error_msg(GOT_ERR_SEND_FAILED, msg);
}

static const struct got_error *
send_their_ref(struct imsgbuf *ibuf, struct got_object_id *refid,
    const char *refname)
{
	struct ibuf *wbuf;
	size_t len, reflen = strlen(refname);

	len = sizeof(struct got_imsg_send_remote_ref) + reflen;
	if (len >= MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_SEND_REMOTE_REF, 0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SEND_REMOTE_REF");

	/* Keep in sync with struct got_imsg_send_remote_ref definition! */
	if (imsg_add(wbuf, refid, sizeof(*refid)) == -1)
		return got_error_from_errno("imsg_add SEND_REMOTE_REF");
	if (imsg_add(wbuf, &reflen, sizeof(reflen)) == -1)
		return got_error_from_errno("imsg_add SEND_REMOTE_REF");
	if (imsg_add(wbuf, refname, reflen) == -1)
		return got_error_from_errno("imsg_add SEND_REMOTE_REF");

	imsg_close(ibuf, wbuf);
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_ref_status(struct imsgbuf *ibuf, const char *refname, int success,
    struct got_pathlist_head *refs, struct got_pathlist_head *delete_refs)
{
	struct ibuf *wbuf;
	size_t i, len, reflen, errmsglen = 0;
	struct got_pathlist_entry *pe;
	int ref_valid = 0;
	char *eol, *sp;
	const char *errmsg = "";

	eol = strchr(refname, '\n');
	if (eol == NULL) {
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "unexpected message from server");
	}
	*eol = '\0';

	sp = strchr(refname, ' ');
	if (sp != NULL) {
		*sp++ = '\0';
		errmsg = sp;
		errmsglen = strlen(errmsg);

		for (i = 0; i < errmsglen; ++i) {
			if (!isprint((unsigned char)errmsg[i])) {
				return got_error_msg(GOT_ERR_BAD_PACKET,
				    "non-printable error message received "
				    "from the server");
			}
		}
	}

	reflen = strlen(refname);
	if (!got_ref_name_is_valid(refname)) {
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "unexpected message from server");
	}

	RB_FOREACH(pe, got_pathlist_head, refs) {
		if (strcmp(refname, pe->path) == 0) {
			ref_valid = 1;
			break;
		}
	}
	if (!ref_valid) {
		RB_FOREACH(pe, got_pathlist_head, delete_refs) {
			if (strcmp(refname, pe->path) == 0) {
				ref_valid = 1;
				break;
			}
		}
	}
	if (!ref_valid) {
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "unexpected message from server");
	}

	len = sizeof(struct got_imsg_send_ref_status) + reflen + errmsglen;
	if (len >= MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_SEND_REF_STATUS,
	    0, 0, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SEND_REF_STATUS");

	/* Keep in sync with struct got_imsg_send_ref_status definition! */
	if (imsg_add(wbuf, &success, sizeof(success)) == -1)
		return got_error_from_errno("imsg_add SEND_REF_STATUS");
	if (imsg_add(wbuf, &reflen, sizeof(reflen)) == -1)
		return got_error_from_errno("imsg_add SEND_REF_STATUS");
	if (imsg_add(wbuf, &errmsglen, sizeof(errmsglen)) == -1)
		return got_error_from_errno("imsg_add SEND_REF_STATUS");
	if (imsg_add(wbuf, refname, reflen) == -1)
		return got_error_from_errno("imsg_add SEND_REF_STATUS");
	if (imsg_add(wbuf, errmsg, errmsglen) == -1)
		return got_error_from_errno("imsg_add SEND_REF_STATUS");

	imsg_close(ibuf, wbuf);
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
describe_refchange(int *n, int *sent_my_capabilites,
    const char *my_capabilities, char *buf, size_t bufsize,
    const char *refname, const char *old_hashstr, const char *new_hashstr)
{
	*n = snprintf(buf, bufsize, "%s %s %s",
	    old_hashstr, new_hashstr, refname);
	if (*n < 0 || (size_t)*n >= bufsize)
		return got_error(GOT_ERR_NO_SPACE);

	/*
	 * We must announce our capabilities along with the first
	 * reference. Unfortunately, the protocol requires an embedded
	 * NUL as a separator between reference name and capabilities,
	 * which we have to deal with here.
	 * It also requires a linefeed for terminating packet data.
	 */
	if (!*sent_my_capabilites && my_capabilities != NULL) {
		int m;
		if (*n >= bufsize - 1)
			return got_error(GOT_ERR_NO_SPACE);
		m = snprintf(buf + *n + 1, /* offset after '\0' */
		    bufsize - (*n + 1), "%s\n", my_capabilities);
		if (m < 0 || *n + m >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
		*n += m;
		*sent_my_capabilites = 1;
	} else {
		*n = strlcat(buf, "\n", bufsize);
		if (*n >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
	}

	return NULL;
}

static const struct got_error *
send_pack(int fd, enum got_hash_algorithm algo, struct got_pathlist_head *refs,
    struct got_pathlist_head *delete_refs, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	char buf[GOT_PKT_MAX];
	const unsigned char zero_id[GOT_HASH_DIGEST_MAXLEN] = { 0 };
	char old_hashstr[GOT_HASH_DIGEST_STRING_MAXLEN];
	char new_hashstr[GOT_HASH_DIGEST_STRING_MAXLEN];
	struct got_pathlist_head their_refs;
	int is_firstpkt = 1;
	int n, nsent = 0;
	int packfd = -1;
	char *id_str = NULL, *refname = NULL;
	struct got_object_id *id = NULL;
	char *server_capabilities = NULL, *my_capabilities = NULL;
	struct got_pathlist_entry *pe;
	int sent_my_capabilites = 0;

	RB_INIT(&their_refs);

	if (RB_EMPTY(refs) && RB_EMPTY(delete_refs))
		return got_error(GOT_ERR_SEND_EMPTY);

	while (1) {
		err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot,
		    INFTIM);
		if (err)
			goto done;
		if (n == 0)
			break;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = send_error(&buf[4], n - 4);
			goto done;
		}
		free(id_str);
		free(refname);
		err = got_gitproto_parse_refline(&id_str, &refname,
		    &server_capabilities, buf, n);
		if (err)
			goto done;
		if (is_firstpkt) {
			enum got_hash_algorithm expected_algo = algo;

			if (server_capabilities == NULL) {
				server_capabilities = strdup("");
				if (server_capabilities == NULL) {
					err = got_error_from_errno("strdup");
					goto done;
				}
			}
			if (chattygot && server_capabilities[0] != '\0')
				fprintf(stderr, "%s: server capabilities: %s\n",
				    getprogname(), server_capabilities);
			err = got_gitproto_match_capabilities(&my_capabilities,
			    NULL, server_capabilities, got_capabilities,
			    nitems(got_capabilities), &expected_algo);
			if (err)
				goto done;
			if (algo != expected_algo) {
				err = got_error(GOT_ERR_OBJECT_FORMAT);
				goto done;
			}
			if (chattygot)
				fprintf(stderr, "%s: my capabilities:%s\n",
				    getprogname(),
				    my_capabilities ? my_capabilities : "");
			is_firstpkt = 0;
		}
		if (strstr(refname, "^{}")) {
			if (chattygot) {
				fprintf(stderr, "%s: ignoring %s\n",
				    getprogname(), refname);
			}
			continue;
		}

		id = malloc(sizeof(*id));
		if (id == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		if (!got_parse_object_id(id, id_str, algo)) {
			err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
			goto done;
		}
		err = send_their_ref(ibuf, id, refname);
		if (err)
			goto done;

		err = got_pathlist_insert(&pe, &their_refs, refname, id);
		if (err || pe == NULL) {
			free(refname);
			free(id);
			if (err)
				goto done;
		}


		if (chattygot)
			fprintf(stderr, "%s: remote has %s %s\n",
			    getprogname(), refname, id_str);
		free(id_str);
		id_str = NULL;
		refname = NULL; /* do not free; owned by their_refs */
		id = NULL; /* do not free; owned by their_refs */
	}

	if (!RB_EMPTY(delete_refs)) {
		if (my_capabilities == NULL ||
		    strstr(my_capabilities, GOT_CAPA_DELETE_REFS) == NULL) {
			err = got_error(GOT_ERR_CAPA_DELETE_REFS);
			goto done;
		}
	}

	RB_FOREACH(pe, got_pathlist_head, delete_refs) {
		const char *refname = pe->path;
		struct got_pathlist_entry *their_pe;
		struct got_object_id *their_id = NULL;

		RB_FOREACH(their_pe, got_pathlist_head, &their_refs) {
			const char *their_refname = their_pe->path;
			if (got_path_cmp(refname, their_refname,
			    strlen(refname), strlen(their_refname)) == 0) {
				their_id = their_pe->data;
				break;
			}
		}
		if (their_id == NULL) {
			err = got_error_fmt(GOT_ERR_NOT_REF,
			    "%s does not exist in remote repository",
			    refname);
			goto done;
		}

		got_object_id_hex(their_id, old_hashstr,
		    sizeof(old_hashstr));
		got_hash_digest_to_str(zero_id, new_hashstr,
		    sizeof(new_hashstr), algo);
		err = describe_refchange(&n, &sent_my_capabilites,
		    my_capabilities, buf, sizeof(buf), refname,
		    old_hashstr, new_hashstr);
		if (err)
			goto done;
		err = got_pkt_writepkt(fd, buf, n, chattygot);
		if (err)
			goto done;
		if (chattygot) {
			fprintf(stderr, "%s: deleting %s %s\n",
			    getprogname(), refname, old_hashstr);
		}
		nsent++;
	}

	RB_FOREACH(pe, got_pathlist_head, refs) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		struct got_object_id *their_id = NULL;
		struct got_pathlist_entry *their_pe;

		RB_FOREACH(their_pe, got_pathlist_head, &their_refs) {
			const char *their_refname = their_pe->path;
			if (got_path_cmp(refname, their_refname,
			    strlen(refname), strlen(their_refname)) == 0) {
				their_id = their_pe->data;
				break;
			}
		}
		if (their_id) {
			if (got_object_id_cmp(id, their_id) == 0) {
				if (chattygot) {
					fprintf(stderr,
					    "%s: no change for %s\n",
					    getprogname(), refname);
				}
				continue;
			}
			got_object_id_hex(their_id, old_hashstr,
			    sizeof(old_hashstr));
		} else {
			got_hash_digest_to_str(zero_id, old_hashstr,
			    sizeof(old_hashstr), algo);
		}
		got_object_id_hex(id, new_hashstr, sizeof(new_hashstr));
		err = describe_refchange(&n, &sent_my_capabilites,
		    my_capabilities, buf, sizeof(buf), refname,
		    old_hashstr, new_hashstr);
		if (err)
			goto done;
		err = got_pkt_writepkt(fd, buf, n, chattygot);
		if (err)
			goto done;
		if (chattygot) {
			if (their_id) {
				fprintf(stderr, "%s: updating %s %s -> %s\n",
				    getprogname(), refname, old_hashstr,
				    new_hashstr);
			} else {
				fprintf(stderr, "%s: creating %s %s\n",
				    getprogname(), refname, new_hashstr);
			}
		}
		nsent++;
	}
	err = got_pkt_flushpkt(fd, chattygot);
	if (err)
		goto done;

	err = send_pack_request(ibuf);
	if (err)
		goto done;

	err = recv_packfd(&packfd, ibuf);
	if (err)
		goto done;

	if (packfd != -1) {
		err = send_pack_file(fd, packfd, ibuf);
		if (err)
			goto done;
	}

	err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot, INFTIM);
	if (err)
		goto done;
	if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
		err = send_error(&buf[4], n - 4);
		goto done;
	} else if (n < 10 || strncmp(buf, "unpack ok\n", 10) != 0) {
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "unexpected message from server");
		goto done;
	}

	while (nsent > 0) {
		err = got_pkt_readpkt(&n, fd, buf, sizeof(buf), chattygot,
		    INFTIM);
		if (err)
			goto done;
		if (n < 3) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		} else if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = send_error(&buf[4], n - 4);
			goto done;
		} else if (strncmp(buf, "ok ", 3) == 0) {
			err = send_ref_status(ibuf, buf + 3, 1,
			    refs, delete_refs);
			if (err)
				goto done;
		} else if (strncmp(buf, "ng ", 3) == 0) {
			err = send_ref_status(ibuf, buf + 3, 0,
			    refs, delete_refs);
			if (err)
				goto done;
		} else {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		}
		nsent--;
	}

	err = send_done(ibuf);
done:
	got_pathlist_free(&their_refs, GOT_PATHLIST_FREE_ALL);
	free(id_str);
	free(id);
	free(refname);
	free(server_capabilities);
	free(my_capabilities);
	return err;
}

int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	int sendfd = -1;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_pathlist_head refs;
	struct got_pathlist_head delete_refs;
	struct got_imsg_send_request send_req;
	struct got_imsg_send_ref href;
	size_t datalen, i;
#if 0
	static int attached;
	while (!attached)
		sleep (1);
#endif

	RB_INIT(&refs);
	RB_INIT(&delete_refs);

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

	/* revoke fs access */
	if (landlock_no_fs() == -1) {
		err = got_error_from_errno("landlock_no_fs");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
	if (cap_enter() == -1) {
		err = got_error_from_errno("cap_enter");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif
	if ((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_SEND_REQUEST) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(send_req)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&send_req, imsg.data, sizeof(send_req));
	sendfd = imsg_get_fd(&imsg);
	imsg_free(&imsg);

	if (send_req.verbosity > 0)
		chattygot += send_req.verbosity;

	for (i = 0; i < send_req.nrefs; i++) {
		struct got_object_id *id;
		char *refname;
		struct got_pathlist_entry *new;

		if ((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			goto done;
		}
		if (imsg.hdr.type == GOT_IMSG_STOP)
			goto done;
		if (imsg.hdr.type != GOT_IMSG_SEND_REF) {
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
		refname = malloc(href.name_len + 1);
		if (refname == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}
		memcpy(refname, imsg.data + sizeof(href), href.name_len);
		refname[href.name_len] = '\0';

		/*
		 * Prevent sending of references that won't make any
		 * sense outside the local repository's context.
		 */
		if (strncmp(refname, "refs/got/", 9) == 0 ||
		    strncmp(refname, "refs/remotes/", 13) == 0) {
			err = got_error_fmt(GOT_ERR_SEND_BAD_REF,
			    "%s", refname);
			goto done;
		}

		id = malloc(sizeof(*id));
		if (id == NULL) {
			free(refname);
			err = got_error_from_errno("malloc");
			goto done;
		}
		memcpy(id, &href.id, sizeof(*id));
		if (href.delete)
			err = got_pathlist_insert(&new, &delete_refs, refname, id);
		else
			err = got_pathlist_insert(&new, &refs, refname, id);
		if (err || new == NULL ) {
			free(refname);
			free(id);
			if (err)
				goto done;
		}

		imsg_free(&imsg);
	}

	err = send_pack(sendfd, send_req.algo, &refs, &delete_refs, &ibuf);
done:
	got_pathlist_free(&refs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&delete_refs, GOT_PATHLIST_FREE_ALL);
	if (sendfd != -1 && close(sendfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err != NULL && err->code != GOT_ERR_CANCELLED)  {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		got_privsep_send_error(&ibuf, err);
	}
	imsgbuf_clear(&ibuf);

	exit(0);
}
