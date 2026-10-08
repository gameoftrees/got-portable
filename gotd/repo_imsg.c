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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <event.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <imsg.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_hash.h"

#include "gotd.h"
#include "log.h"

void
gotd_imsg_send_ack(struct got_object_id *id, struct imsgbuf *ibuf,
    uint32_t peerid, pid_t pid)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_ack iack;
	char hex[GOT_HASH_DIGEST_STRING_MAXLEN];

	if (log_getverbose() > 0 &&
	    got_object_id_hex(id, hex, sizeof(hex)))
		log_debug("sending ACK for %s", hex);

	memset(&iack, 0, sizeof(iack));
	memcpy(iack.object_id, id->hash, got_hash_digest_length(id->algo));
	iack.algo = id->algo;

	if (imsg_compose(ibuf, GOTD_IMSG_ACK, peerid, pid, -1,
	    &iack, sizeof(iack)) == -1) {
		err = got_error_from_errno("imsg_compose ACK");
		goto done;
	}

	err = gotd_imsg_flush(ibuf);
done:
	if (err)
		log_warnx("sending ACK: %s", err->msg);
}

void
gotd_imsg_send_nak(struct got_object_id *id, struct imsgbuf *ibuf,
    uint32_t peerid, pid_t pid)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_nak inak;
	char hex[GOT_HASH_DIGEST_STRING_MAXLEN];

	if (log_getverbose() > 0 &&
	    got_object_id_hex(id, hex, sizeof(hex)))
		log_debug("sending NAK for %s", hex);

	memset(&inak, 0, sizeof(inak));
	memcpy(inak.object_id, id->hash, got_hash_digest_length(id->algo));
	inak.algo = id->algo;

	if (imsg_compose(ibuf, GOTD_IMSG_NAK, peerid, pid, -1,
	    &inak, sizeof(inak)) == -1) {
		err = got_error_from_errno("imsg_compose NAK");
		goto done;
	}

	err = gotd_imsg_flush(ibuf);
done:
	if (err)
		log_warnx("sending NAK: %s", err->msg);
}
