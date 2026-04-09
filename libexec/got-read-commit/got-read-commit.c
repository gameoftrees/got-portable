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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <err.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_qid.h"
#include "got_lib_privsep.h"

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	size_t datalen;

	signal(SIGINT, catch_sigint);

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

	for (;;) {
		struct imsg imsg;
		struct got_commit_object *commit = NULL;
		struct got_object_id expected_id;
		int fd = -1;

		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP) {
			imsg_free(&imsg);
			break;
		}

		if (imsg.hdr.type != GOT_IMSG_COMMIT_REQUEST) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != sizeof(expected_id)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		memcpy(&expected_id, imsg.data, sizeof(expected_id));

		fd = imsg_get_fd(&imsg);
		if (fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}

		err = got_object_read_commit(&commit, fd, &expected_id, 0);
		if (err)
			goto done;

		err = got_privsep_send_commit(&ibuf, commit);
		got_object_commit_close(commit);
done:
		if (fd != -1 && close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		imsg_free(&imsg);
		if (err)
			break;
	}

	if (err) {
		if (!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	imsgbuf_clear(&ibuf);
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
