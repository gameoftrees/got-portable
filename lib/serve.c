/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <poll.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_serve.h"
#include "got_path.h"
#include "got_version.h"
#include "got_reference.h"
#include "got_object.h"

#include "got_lib_pkt.h"
#include "got_lib_dial.h"
#include "got_lib_gitproto.h"
#include "got_lib_hash.h"
#include "got_lib_poll.h"

#include "gotd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/*
 * Number of seconds until we give up trying to read more
 * data from the client connection.
 */
static const int timeout = 60;

static const struct got_capability read_capabilities[] = {
	{ GOT_CAPA_AGENT, "got/" GOT_VERSION_STR },
	{ GOT_CAPA_OFS_DELTA, NULL },
	{ GOT_CAPA_SIDE_BAND_64K, NULL },
};

static const struct got_capability write_capabilities[] = {
	{ GOT_CAPA_AGENT, "got/" GOT_VERSION_STR },
	{ GOT_CAPA_OFS_DELTA, NULL },
	{ GOT_CAPA_REPORT_STATUS, NULL },
	{ GOT_CAPA_NO_THIN, NULL },
	{ GOT_CAPA_DELETE_REFS, NULL },
};

static const struct got_error *
append_read_capabilities(size_t *capalen, size_t len, const char *symrefstr,
    uint8_t *buf, size_t bufsize)
{
	struct got_capability capa[nitems(read_capabilities) + 1];
	size_t ncapa;

	memcpy(&capa, read_capabilities, sizeof(read_capabilities));
	if (symrefstr) {
		capa[nitems(read_capabilities)].key = "symref";
		capa[nitems(read_capabilities)].value = symrefstr;
		ncapa = nitems(capa);
	} else
		ncapa = nitems(read_capabilities);

	return got_gitproto_append_capabilities(capalen, buf, len,
	    bufsize, capa, ncapa);
}

static const struct got_error *
send_ref(int outfd, uint8_t *id, const char *refname, int send_capabilities,
    int client_is_reading, const char *symrefstr, int chattygot)
{
	const struct got_error *err = NULL;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char buf[GOT_PKT_MAX];
	size_t len, capalen = 0;

	if (got_sha1_digest_to_str(id, hex, sizeof(hex)) == NULL)
		return got_error(GOT_ERR_BAD_OBJ_ID);

	len = snprintf(buf, sizeof(buf), "%s %s", hex, refname);
	if (len >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	if (send_capabilities) {
		if (client_is_reading) {
			err = append_read_capabilities(&capalen, len,
			    symrefstr, buf, sizeof(buf));
		} else {
			err = got_gitproto_append_capabilities(&capalen,
			    buf, len, sizeof(buf), write_capabilities,
			    nitems(write_capabilities));
		}
		if (err)
			return err;
		len += capalen;
	}

	if (len + 1 >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);
	buf[len] = '\n';
	len++;
	buf[len] = '\0';

	return got_pkt_writepkt(outfd, buf, len, chattygot);
}

static const struct got_error *
send_zero_refs(int outfd, int client_is_reading, int chattygot)
{
	const struct got_error *err = NULL;
	const char *line = GOT_SHA1_STRING_ZERO " capabilities^{}";
	char buf[GOT_PKT_MAX];
	size_t len, capalen = 0;

	len = strlcpy(buf, line, sizeof(buf));
	if (len >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	if (client_is_reading) {
		err = got_gitproto_append_capabilities(&capalen, buf, len,
		    sizeof(buf), read_capabilities, nitems(read_capabilities));
		if (err)
			return err;
	} else {
		err = got_gitproto_append_capabilities(&capalen, buf, len,
		    sizeof(buf), write_capabilities,
		    nitems(write_capabilities));
		if (err)
			return err;
	}

	return got_pkt_writepkt(outfd, buf, len + capalen, chattygot);
}

static void
echo_error(const struct got_error *err, int outfd, int chattygot)
{
	char buf[4 + GOT_ERR_MAX_MSG_SIZE];
	size_t len;

	/*
	 * Echo the error to the client on a pkt-line.
	 * The client should then terminate its session.
	 */
	buf[0] = 'E'; buf[1] = 'R'; buf[2] = 'R'; buf[3] = ' '; buf[4] = '\0';
	len = strlcat(buf, err->msg, sizeof(buf));
	got_pkt_writepkt(outfd, buf, len, chattygot);
}

static const struct got_error *
announce_refs(int outfd, struct imsgbuf *ibuf, int client_is_reading,
    const char *repo_path, int chattygot)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	struct gotd_imsg_list_refs lsref;
	struct gotd_imsg_reflist ireflist;
	struct gotd_imsg_ref iref;
	struct gotd_imsg_symref isymref;
	size_t nrefs = 0;
	int have_nrefs = 0, sent_capabilities = 0;
	char *symrefname = NULL, *symreftarget = NULL, *symrefstr = NULL;
	char *refname = NULL;

	memset(&imsg, 0, sizeof(imsg));
	memset(&lsref, 0, sizeof(lsref));

	if (strlcpy(lsref.repo_name, repo_path, sizeof(lsref.repo_name)) >=
	    sizeof(lsref.repo_name))
		return got_error(GOT_ERR_NO_SPACE);
	lsref.client_is_reading = client_is_reading;

	if (imsg_compose(ibuf, GOTD_IMSG_LIST_REFS, 0, 0, -1,
	    &lsref, sizeof(lsref)) == -1)
		return got_error_from_errno("imsg_compose LIST_REFS");

	err = gotd_imsg_flush(ibuf);
	if (err) {
		if (err->code == GOT_ERR_EOF) {
			const struct got_error *err2;

			/* Connection closed early. Try to find out why. */
			err2 = gotd_imsg_poll_recv(&imsg, ibuf, 0);
			if (err2)
				return err;
			if (imsg.hdr.type == GOTD_IMSG_ERROR)
				err = gotd_imsg_recv_error(NULL, &imsg);
			imsg_free(&imsg);
		}
		return err;
	}

	while (!have_nrefs || nrefs > 0) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			goto done;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			goto done;
		case GOTD_IMSG_REFLIST:
			if (have_nrefs || nrefs > 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			if (datalen != sizeof(ireflist)) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			memcpy(&ireflist, imsg.data, sizeof(ireflist));
			nrefs = ireflist.nrefs;
			have_nrefs = 1;
			if (nrefs == 0)
				err = send_zero_refs(outfd, client_is_reading,
				    chattygot);
			break;
		case GOTD_IMSG_REF:
			if (!have_nrefs || nrefs == 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			if (datalen < sizeof(iref)) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			memcpy(&iref, imsg.data, sizeof(iref));
			if (datalen != sizeof(iref) + iref.name_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			refname = strndup(imsg.data + sizeof(iref),
			    iref.name_len);
			if (refname == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			err = send_ref(outfd, iref.id, refname,
			    !sent_capabilities, client_is_reading,
			    NULL, chattygot);
			free(refname);
			refname = NULL;
			if (err)
				goto done;
			sent_capabilities = 1;
			if (nrefs > 0)
				nrefs--;
			break;
		case GOTD_IMSG_SYMREF:
			if (!have_nrefs || nrefs == 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			if (datalen < sizeof(isymref)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			memcpy(&isymref, imsg.data, sizeof(isymref));
			if (datalen != sizeof(isymref) + isymref.name_len +
			    isymref.target_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}

			/*
			 * For now, we only announce one symbolic ref,
			 * as part of our capability advertisement.
			 */
			if (sent_capabilities || symrefstr != NULL ||
			    symrefname != NULL || symreftarget != NULL)
				break;

			symrefname = strndup(imsg.data + sizeof(isymref),
			    isymref.name_len);
			if (symrefname == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}

			symreftarget = strndup(
			    imsg.data + sizeof(isymref) + isymref.name_len,
			    isymref.target_len);
			if (symreftarget == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}

			if (asprintf(&symrefstr, "%s:%s", symrefname,
			    symreftarget) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = send_ref(outfd, isymref.target_id, symrefname,
			    !sent_capabilities, client_is_reading, symrefstr,
			    chattygot);
			free(refname);
			refname = NULL;
			if (err)
				goto done;
			sent_capabilities = 1;
			if (nrefs > 0)
				nrefs--;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	err = got_pkt_flushpkt(outfd, chattygot);
	if (err)
		goto done;
done:
	free(symrefstr);
	free(symrefname);
	free(symreftarget);
	return err;
}

static const struct got_error *
parse_want_line(char **common_capabilities, uint8_t *id, char *buf, size_t len)
{
	const struct got_error *err;
	char *id_str = NULL, *client_capabilities = NULL;

	err = got_gitproto_parse_want_line(&id_str,
	    &client_capabilities, buf, len);
	if (err)
		return err;

	if (!got_parse_hash_digest(id, id_str, GOT_HASH_SHA1)) {
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "want-line with bad object ID");
		goto done;
	}

	if (client_capabilities) {
		enum got_hash_algorithm algo;

		err = got_gitproto_match_capabilities(common_capabilities,
		    NULL, client_capabilities, read_capabilities,
		    nitems(read_capabilities), &algo);
		if (err)
			goto done;
	}
done:
	free(id_str);
	free(client_capabilities);
	return err;
}

static const struct got_error *
parse_have_line(uint8_t *id, char *buf, size_t len)
{
	const struct got_error *err;
	char *id_str = NULL;

	err = got_gitproto_parse_have_line(&id_str, buf, len);
	if (err)
		return err;

	if (!got_parse_hash_digest(id, id_str, GOT_HASH_SHA1)) {
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "have-line with bad object ID");
		goto done;
	}
done:
	free(id_str);
	return err;
}

static const struct got_error *
send_capability(struct got_capability *capa, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_capability icapa;
	size_t len;
	struct ibuf *wbuf;

	memset(&icapa, 0, sizeof(icapa));

	icapa.key_len = strlen(capa->key);
	len = sizeof(icapa) + icapa.key_len;
	if (capa->value) {
		icapa.value_len = strlen(capa->value);
		len += icapa.value_len;
	}

	wbuf = imsg_create(ibuf, GOTD_IMSG_CAPABILITY, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create CAPABILITY");
		return err;
	}

	if (imsg_add(wbuf, &icapa, sizeof(icapa)) == -1)
		return got_error_from_errno("imsg_add CAPABILITY");
	if (imsg_add(wbuf, capa->key, icapa.key_len) == -1)
		return got_error_from_errno("imsg_add CAPABILITY");
	if (capa->value) {
		if (imsg_add(wbuf, capa->value, icapa.value_len) == -1)
			return got_error_from_errno("imsg_add CAPABILITY");
	}

	imsg_close(ibuf, wbuf);

	return NULL;
}

static const struct got_error *
send_capabilities(int *use_sidebands, int *report_status,
    char *capabilities_str, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_capabilities icapas;
	struct got_capability *capa = NULL;
	size_t ncapa, i;

	err = got_gitproto_split_capabilities_str(&capa, &ncapa,
	    capabilities_str);
	if (err)
		return err;

	icapas.ncapabilities = ncapa;
	if (imsg_compose(ibuf, GOTD_IMSG_CAPABILITIES, 0, 0, -1,
	    &icapas, sizeof(icapas)) == -1) {
		err = got_error_from_errno("imsg_compose IMSG_CAPABILITIES");
		goto done;
	}

	for (i = 0; i < ncapa; i++) {
		err = send_capability(&capa[i], ibuf);
		if (err)
			goto done;
		if (use_sidebands &&
		    strcmp(capa[i].key, GOT_CAPA_SIDE_BAND_64K) == 0)
			*use_sidebands = 1;
		if (report_status &&
		    strcmp(capa[i].key, GOT_CAPA_REPORT_STATUS) == 0)
			*report_status = 1;
	}
done:
	free(capa);
	return err;
}

static const struct got_error *
forward_flushpkt(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOTD_IMSG_FLUSH, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose FLUSH");

	return gotd_imsg_flush(ibuf);
}

static const struct got_error *
recv_ack(struct imsg *imsg, uint8_t *expected_id)
{
	struct gotd_imsg_ack iack;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iack))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&iack, imsg->data, sizeof(iack));
	if (memcmp(iack.object_id, expected_id, SHA1_DIGEST_LENGTH) != 0)
		return got_error(GOT_ERR_BAD_OBJ_ID);

	return NULL;
}

static const struct got_error *
recv_nak(struct imsg *imsg, uint8_t *expected_id)
{
	struct gotd_imsg_ack inak;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(inak))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&inak, imsg->data, sizeof(inak));
	if (memcmp(inak.object_id, expected_id, SHA1_DIGEST_LENGTH) != 0)
		return got_error(GOT_ERR_BAD_OBJ_ID);

	return NULL;
}


static const struct got_error *
recv_want(int *use_sidebands, int outfd, struct imsgbuf *ibuf,
    char *buf, size_t len, int expect_capabilities, int chattygot)
{
	const struct got_error *err;
	struct gotd_imsg_want iwant;
	char *capabilities_str;
	int done = 0;
	struct imsg imsg;

	memset(&iwant, 0, sizeof(iwant));
	memset(&imsg, 0, sizeof(imsg));

	err = parse_want_line(&capabilities_str, iwant.object_id, buf, len);
	if (err)
		return err;

	if (capabilities_str) {
		if (!expect_capabilities) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected capability announcement received");
			goto done;
		}
		err = send_capabilities(use_sidebands, NULL, capabilities_str,
		    ibuf);
		if (err)
			goto done;

	}

	if (imsg_compose(ibuf, GOTD_IMSG_WANT, 0, 0, -1,
	    &iwant, sizeof(iwant)) == -1) {
		err = got_error_from_errno("imsg_compose WANT");
		goto done;
	}

	err = gotd_imsg_flush(ibuf);
	if (err)
		goto done;

	/*
	 * Wait for an ACK, or an error in case the desired object
	 * does not exist.
	 */
	while (!done && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			break;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_ACK:
			err = recv_ack(&imsg, iwant.object_id);
			if (err)
				break;
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}
done:
	free(capabilities_str);
	return err;
}

static const struct got_error *
send_ack(int outfd, uint8_t *id, int chattygot)
{
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char buf[GOT_PKT_MAX];
	int len;

	if (got_sha1_digest_to_str(id, hex, sizeof(hex)) == NULL)
		return got_error(GOT_ERR_BAD_OBJ_ID);

	len = snprintf(buf, sizeof(buf), "ACK %s\n", hex);
	if (len >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	return got_pkt_writepkt(outfd, buf, len, chattygot);
}

static const struct got_error *
send_nak(int outfd, int chattygot)
{
	char buf[5];
	int len;

	len = snprintf(buf, sizeof(buf), "NAK\n");
	if (len >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	return got_pkt_writepkt(outfd, buf, len, chattygot);
}

static const struct got_error *
recv_have(int *have_ack, int outfd, struct imsgbuf *ibuf, char *buf,
    size_t len, int chattygot)
{
	const struct got_error *err;
	struct gotd_imsg_have ihave;
	int done = 0;
	struct imsg imsg;

	memset(&ihave, 0, sizeof(ihave));
	memset(&imsg, 0, sizeof(imsg));

	err = parse_have_line(ihave.object_id, buf, len);
	if (err)
		return err;

	if (imsg_compose(ibuf, GOTD_IMSG_HAVE, 0, 0, -1,
	    &ihave, sizeof(ihave)) == -1)
		return got_error_from_errno("imsg_compose HAVE");

	err = gotd_imsg_flush(ibuf);
	if (err)
		return err;

	/*
	 * Wait for an ACK or a NAK, indicating whether a common
	 * commit object has been found.
	 */
	while (!done && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			return err;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_ACK:
			err = recv_ack(&imsg, ihave.object_id);
			if (err)
				break;
			if (!*have_ack) {
				err = send_ack(outfd, ihave.object_id,
				    chattygot);
				if (err)
					return err;
				*have_ack = 1;
			}
			done = 1;
			break;
		case GOTD_IMSG_NAK:
			err = recv_nak(&imsg, ihave.object_id);
			if (err)
				break;
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	return err;
}

static const struct got_error *
recv_done(int *packfd, int outfd, struct imsgbuf *ibuf, int chattygot)
{
	const struct got_error *err;
	struct imsg imsg;
	int fd;

	*packfd = -1;

	if (imsg_compose(ibuf, GOTD_IMSG_DONE, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose DONE");

	err = gotd_imsg_flush(ibuf);
	if (err)
		return err;

	while (*packfd == -1 && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_PIPE:
			fd = imsg_get_fd(&imsg);
			if (fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}
			*packfd = fd;
			if (imsg_compose(ibuf, GOTD_IMSG_PACKFILE_READY,
			    0, 0, -1, NULL, 0) == -1)
				err = got_error_from_errno("imsg_compose "
				    "PACKFILE_READY");
			err = gotd_imsg_flush(ibuf);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	return err;
}

static const struct got_error *
relay_progress_reports(struct imsgbuf *ibuf, int outfd, int chattygot)
{
	const struct got_error *err = NULL;
	int pack_starting = 0;
	struct gotd_imsg_packfile_progress iprog;
	char buf[GOT_PKT_MAX];
	struct imsg imsg;
	size_t datalen;
	int p_deltify = 0, n;
	const char *eol = "\r";

	memset(&imsg, 0, sizeof(imsg));

	while (!pack_starting && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			break;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_READY:
			eol = "\n";
			pack_starting = 1;
			/* fallthrough */
		case GOTD_IMSG_PACKFILE_PROGRESS:
			if (datalen != sizeof(iprog)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&iprog, imsg.data, sizeof(iprog));
			if (iprog.nobj_total > 0) {
				p_deltify = (iprog.nobj_deltify * 100) /
				    iprog.nobj_total;
			}
			buf[0] = GOT_SIDEBAND_PROGRESS_INFO;
			n = snprintf(&buf[1], sizeof(buf) - 1,
			    "%d commits colored, "
			    "%d objects found, "
			    "deltify %d%%%s",
			    iprog.ncolored,
			    iprog.nfound,
			    p_deltify, eol);
			if (n >= sizeof(buf) - 1)
				break;
			err = got_pkt_writepkt(outfd, buf, 1 + n, chattygot);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	return err;
}

static const struct got_error *
serve_read(int infd, int outfd, int gotd_sock, const char *repo_path,
    int chattygot)
{
	const struct got_error *err = NULL;
	char buf[GOT_PKT_MAX];
	struct imsgbuf ibuf;
	enum protostate {
		STATE_EXPECT_WANT,
		STATE_EXPECT_MORE_WANT,
		STATE_EXPECT_HAVE_OR_DONE,
		STATE_DONE,
	};
	enum protostate curstate = STATE_EXPECT_WANT;
	int have_ack = 0, use_sidebands = 0, seen_have = 0, sent_nak = 0;
	int packfd = -1;
	size_t pack_chunksize;

	if (imsgbuf_init(&ibuf, gotd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	err = announce_refs(outfd, &ibuf, 1, repo_path, chattygot);
	if (err)
		goto done;

	while (curstate != STATE_DONE) {
		int n;
		buf[0] = '\0';
		err = got_pkt_readpkt(&n, infd, buf, sizeof(buf), chattygot,
		    timeout);
		if (err)
			goto done;
		if (n == 0) {
			if (curstate != STATE_EXPECT_WANT &&
			    curstate != STATE_EXPECT_MORE_WANT &&
			    curstate != STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected flush packet received");
				goto done;
			}

			if (curstate == STATE_EXPECT_WANT) {
				ssize_t r;
				/*
				 * If the client does not want to fetch
				 * anything we should receive a flush
				 * packet followed by EOF.
				 */
				r = read(infd, buf, sizeof(buf));
				if (r == -1) {
					err = got_error_from_errno("read");
					goto done;
				}
				if (r == 0) /* EOF */
					goto done;

				/* Zero-length field followed by payload. */
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected flush packet received");
				goto done;
			}

			if (curstate == STATE_EXPECT_WANT ||
			    curstate == STATE_EXPECT_MORE_WANT ||
			    curstate == STATE_EXPECT_HAVE_OR_DONE) {
				err = forward_flushpkt(&ibuf);
				if (err)
					goto done;
			}
			if (curstate == STATE_EXPECT_HAVE_OR_DONE &&
			    !have_ack) {
				err = send_nak(outfd, chattygot);
				if (err)
					goto done;
				sent_nak = 1;
			}
			if (curstate == STATE_EXPECT_MORE_WANT)
				curstate = STATE_EXPECT_HAVE_OR_DONE;
		} else if (n >= 5 && strncmp(buf, "want ", 5) == 0) {
			if (curstate != STATE_EXPECT_WANT &&
			    curstate != STATE_EXPECT_MORE_WANT) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected 'want' packet");
				goto done;
			}
			err = recv_want(&use_sidebands, outfd, &ibuf, buf, n,
			    curstate == STATE_EXPECT_WANT ? 1 : 0, chattygot);
			if (err)
				goto done;
			if (curstate == STATE_EXPECT_WANT)
				curstate = STATE_EXPECT_MORE_WANT;
		} else if (n >= 5 && strncmp(buf, "have ", 5) == 0) {
			if (curstate != STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected 'have' packet");
				goto done;
			}
			err = recv_have(&have_ack, outfd, &ibuf,
			    buf, n, chattygot);
			if (err)
				goto done;
			seen_have = 1;
		} else if (n == 5 && strncmp(buf, "done\n", 5) == 0) {
			if (curstate != STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected 'done' packet");
				goto done;
			}
			err = recv_done(&packfd, outfd, &ibuf, chattygot);
			if (err)
				goto done;
			curstate = STATE_DONE;
			break;
		} else {
			err = got_error(GOT_ERR_BAD_PACKET);
			goto done;
		}
	}

	if (!seen_have || (!have_ack && !sent_nak)) {
		err = send_nak(outfd, chattygot);
		if (err)
			goto done;
	}

	if (use_sidebands) {
		err = relay_progress_reports(&ibuf, outfd, chattygot);
		if (err)
			goto done;
		pack_chunksize = GOT_SIDEBAND_64K_PACKFILE_DATA_MAX;
	} else
		pack_chunksize = sizeof(buf);

	for (;;) {
		ssize_t r;

		r = read(packfd, use_sidebands ? &buf[1] : buf,
		    pack_chunksize);
		if (r == -1) {
			err = got_error_from_errno("read");
			break;
		} else if (r == 0) {
			err = got_pkt_flushpkt(outfd, chattygot);
			break;
		}

		if (use_sidebands) {
			buf[0] = GOT_SIDEBAND_PACKFILE_DATA;
			err = got_pkt_writepkt(outfd, buf, 1 + r, chattygot);
			if (err)
				break;
		} else {
			err = got_poll_write_full(outfd, buf, r);
			if (err) {
				if (err->code == GOT_ERR_EOF)
					err = NULL;
				break;
			}
		}
	}
done:
	imsgbuf_clear(&ibuf);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err)
		echo_error(err, outfd, chattygot);
	return err;
}

static const struct got_error *
parse_ref_update_line(char **common_capabilities, char **refname,
    uint8_t *old_id, uint8_t *new_id, char *buf, size_t len)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL;
	char *client_capabilities = NULL;

	*refname = NULL;

	err = got_gitproto_parse_ref_update_line(&old_id_str, &new_id_str,
	    refname, &client_capabilities, buf, len);
	if (err)
		return err;

	if (!got_parse_hash_digest(old_id, old_id_str, GOT_HASH_SHA1) ||
	    !got_parse_hash_digest(new_id, new_id_str, GOT_HASH_SHA1)) {
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "ref-update with bad object ID");
		goto done;
	}
	if (!got_ref_name_is_valid(*refname)) {
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "ref-update with bad reference name");
		goto done;
	}

	if (client_capabilities) {
		enum got_hash_algorithm algo;

		err = got_gitproto_match_capabilities(common_capabilities,
		    NULL, client_capabilities, write_capabilities,
		    nitems(write_capabilities), &algo);
		if (err)
			goto done;
	}
done:
	free(old_id_str);
	free(new_id_str);
	free(client_capabilities);
	if (err) {
		free(*refname);
		*refname = NULL;
	}
	return err;
}

static const struct got_error *
recv_ref_update(int *report_status, int outfd, struct imsgbuf *ibuf,
    char *buf, size_t len, int expect_capabilities, int chattygot)
{
	const struct got_error *err;
	struct gotd_imsg_ref_update iref;
	struct ibuf *wbuf;
	char *capabilities_str = NULL, *refname = NULL;
	int done = 0;
	struct imsg imsg;

	memset(&iref, 0, sizeof(iref));
	memset(&imsg, 0, sizeof(imsg));

	err = parse_ref_update_line(&capabilities_str, &refname,
	    iref.old_id, iref.new_id, buf, len);
	if (err)
		return err;

	if (capabilities_str) {
		if (!expect_capabilities) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected capability announcement received");
			goto done;
		}
		err = send_capabilities(NULL, report_status, capabilities_str,
		    ibuf);
		if (err)
			goto done;
	}

	iref.name_len = strlen(refname);
	len = sizeof(iref) + iref.name_len;
	wbuf = imsg_create(ibuf, GOTD_IMSG_REF_UPDATE, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF_UPDATE");
		goto done;
	}

	if (imsg_add(wbuf, &iref, sizeof(iref)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");
	if (imsg_add(wbuf, refname, iref.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");
	imsg_close(ibuf, wbuf);

	err = gotd_imsg_flush(ibuf);
	if (err)
		goto done;

	/* Wait for ACK or an error. */
	while (!done && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, ibuf, 0);
		if (err)
			break;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_ACK:
			err = recv_ack(&imsg, iref.new_id);
			if (err)
				break;
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}
done:
	free(capabilities_str);
	free(refname);
	return err;
}

static const struct got_error *
recv_packfile(struct imsg *imsg, struct imsgbuf *ibuf, int infd)
{
	const struct got_error *err = NULL;
	size_t datalen;
	int packfd;
	char buf[GOT_PKT_MAX];
	int pack_done = 0;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	packfd = imsg_get_fd(imsg);
	if (packfd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsg_compose(ibuf, GOTD_IMSG_PACKFILE_READY,
	    0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose PACKFILE_READY");

	err = gotd_imsg_flush(ibuf);
	if (err)
		return err;

	while (!pack_done) {
		ssize_t r = 0;

		err = got_poll_fd(infd, POLLIN, 1);
		if (err) {
			if (err->code != GOT_ERR_TIMEOUT)
				break;
			err = NULL;
		} else {
			r = read(infd, buf, sizeof(buf));
			if (r == -1) {
				err = got_error_from_errno("read");
				break;
			}
			if (r == 0) {
				/*
				 * Git clients hang up their side of the
				 * connection after sending the pack file.
				 */
				err = NULL;
				pack_done = 1;
				break;
			}
		}

		if (r == 0) {
			/* Detect gotd(8) closing the pack pipe when done. */
			err = got_poll_fd(packfd, 0, 1);
			if (err) {
				if (err->code != GOT_ERR_TIMEOUT &&
				    err->code != GOT_ERR_EOF)
					break;
				if (err->code == GOT_ERR_EOF)
					pack_done = 1;
				err = NULL;
			}
		} else {
			/* Write pack data and/or detect pipe being closed. */
			err = got_poll_write_full(packfd, buf, r);
			if (err) {
				if (err->code == GOT_ERR_EOF)
					err = NULL;
				break;
			}
		}
	}

	close(packfd);
	return err;
}

static const struct got_error *
report_unpack_status(struct imsg *imsg, int outfd, int chattygot)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_packfile_status istatus;
	char buf[GOT_PKT_MAX];
	size_t datalen, len;
	char *reason = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(istatus))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&istatus, imsg->data, sizeof(istatus));
	if (datalen != sizeof(istatus) + istatus.reason_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	reason = strndup(imsg->data + sizeof(istatus), istatus.reason_len);
	if (reason == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

	if (err == NULL)
		len = snprintf(buf, sizeof(buf), "unpack ok\n");
	else
		len = snprintf(buf, sizeof(buf), "unpack %s\n", reason);
	if (len >= sizeof(buf)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	err = got_pkt_writepkt(outfd, buf, len, chattygot);
done:
	free(reason);
	return err;
}

static const struct got_error *
recv_ref_update_ok(struct imsg *imsg, int outfd, int chattygot)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_ref_update_ok iok;
	size_t datalen, len;
	char buf[GOT_PKT_MAX];
	char *refname = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iok))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iok, imsg->data, sizeof(iok));
	if (datalen != sizeof(iok) + iok.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&iok, imsg->data, sizeof(iok));

	refname = strndup(imsg->data + sizeof(iok), iok.name_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	len = snprintf(buf, sizeof(buf), "ok %s\n", refname);
	if (len >= sizeof(buf)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	err = got_pkt_writepkt(outfd, buf, len, chattygot);
done:
	free(refname);
	return err;
}

static const struct got_error *
recv_ref_update_ng(struct imsg *imsg, int outfd, int chattygot)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_ref_update_ng ing;
	size_t datalen, len;
	char buf[GOT_PKT_MAX];
	char *refname = NULL, *reason = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ing))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ing, imsg->data, sizeof(ing));
	if (datalen != sizeof(ing) + ing.name_len + ing.reason_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ing, imsg->data, sizeof(ing));

	refname = strndup(imsg->data + sizeof(ing), ing.name_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	reason = strndup(imsg->data + sizeof(ing) + ing.name_len,
	    ing.reason_len);
	if (reason == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

	len = snprintf(buf, sizeof(buf), "ng %s %s\n", refname, reason);
	if (len >= sizeof(buf)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	err = got_pkt_writepkt(outfd, buf, len, chattygot);
done:
	free(refname);
	free(reason);
	return err;
}

static const struct got_error *
serve_write(int infd, int outfd, int gotd_sock, const char *repo_path,
    int chattygot)
{
	const struct got_error *err = NULL;
	char buf[GOT_PKT_MAX];
	struct imsgbuf ibuf;
	enum protostate {
		STATE_EXPECT_REF_UPDATE,
		STATE_EXPECT_MORE_REF_UPDATES,
		STATE_EXPECT_PACKFILE,
		STATE_PACKFILE_RECEIVED,
		STATE_REFS_UPDATED,
	};
	enum protostate curstate = STATE_EXPECT_REF_UPDATE;
	struct imsg imsg;
	int report_status = 0;

	if (imsgbuf_init(&ibuf, gotd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&ibuf);

	memset(&imsg, 0, sizeof(imsg));

	err = announce_refs(outfd, &ibuf, 0, repo_path, chattygot);
	if (err)
		goto done;

	while (curstate != STATE_EXPECT_PACKFILE) {
		int n;
		buf[0] = '\0';
		err = got_pkt_readpkt(&n, infd, buf, sizeof(buf), chattygot,
		    timeout);
		if (err)
			goto done;
		if (n == 0) {
			if (curstate == STATE_EXPECT_REF_UPDATE) {
				/* The client will not send us anything. */
				goto done;
			} else if (curstate != STATE_EXPECT_MORE_REF_UPDATES) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected flush packet received");
				goto done;
			}
			err = forward_flushpkt(&ibuf);
			if (err)
				goto done;
			curstate = STATE_EXPECT_PACKFILE;
		} else if (n >= (SHA1_DIGEST_STRING_LENGTH * 2) + 2) {
			if (curstate != STATE_EXPECT_REF_UPDATE &&
			    curstate != STATE_EXPECT_MORE_REF_UPDATES) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unexpected ref-update packet");
				goto done;
			}
			if (curstate == STATE_EXPECT_REF_UPDATE) {
				err = recv_ref_update(&report_status,
				    outfd, &ibuf, buf, n, 1, chattygot);
			} else {
				err = recv_ref_update(NULL, outfd, &ibuf,
				    buf, n, 0, chattygot);
			}
			if (err)
				goto done;
			curstate = STATE_EXPECT_MORE_REF_UPDATES;
		} else {
			err = got_error(GOT_ERR_BAD_PACKET);
			goto done;
		}
	}

	while (curstate != STATE_PACKFILE_RECEIVED) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err)
			goto done;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			goto done;
		case GOTD_IMSG_PACKFILE_PIPE:
			err = recv_packfile(&imsg, &ibuf, infd);
			if (err) {
				if (err->code != GOT_ERR_EOF)
					goto done;
				/*
				 * EOF is reported when the client hangs up,
				 * which can happen with Git clients.
				 * The socket should stay half-open so we
				 * can still send our reports if requested.
				 */
				err = NULL;
			}
			curstate = STATE_PACKFILE_RECEIVED;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
		if (err)
			goto done;
	}

	while (curstate != STATE_REFS_UPDATED && err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err)
			break;
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_STATUS:
			if (!report_status)
				break;
			err = report_unpack_status(&imsg, outfd, chattygot);
			break;
		case GOTD_IMSG_REF_UPDATE_OK:
			if (!report_status)
				break;
			err = recv_ref_update_ok(&imsg, outfd, chattygot);
			break;
		case GOTD_IMSG_REF_UPDATE_NG:
			if (!report_status)
				break;
			err = recv_ref_update_ng(&imsg, outfd, chattygot);
			break;
		case GOTD_IMSG_REFS_UPDATED:
			curstate = STATE_REFS_UPDATED;
			err = got_pkt_flushpkt(outfd, chattygot);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}
done:
	imsgbuf_clear(&ibuf);
	if (err)
		echo_error(err, outfd, chattygot);
	return err;
}

const struct got_error *
got_serve(int infd, int outfd, const char *command, const char *repo_path,
    int gotd_sock, int chattygot)
{
	const struct got_error *err = NULL;

	if (strcmp(command, GOT_DIAL_CMD_FETCH) == 0)
		err = serve_read(infd, outfd, gotd_sock, repo_path, chattygot);
	else if (strcmp(command, GOT_DIAL_CMD_SEND) == 0)
		err = serve_write(infd, outfd, gotd_sock, repo_path,
		    chattygot);
	else
		err = got_error(GOT_ERR_BAD_PACKET);

	return err;
}
