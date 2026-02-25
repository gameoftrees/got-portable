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
#include "got_lib_privsep.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"
#define GOT_OBJ_TAG_TAG		"tag"

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
send_raw_obj(struct imsgbuf *ibuf, struct got_object *obj,
    struct got_object_id *expected_id,
    int fd, int outfd)
{
	const struct got_error *err = NULL;
	uint8_t *data = NULL;
	off_t size;
	size_t hdrlen;

	if (lseek(fd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	err = got_object_read_raw(&data, &size, &hdrlen,
	    GOT_PRIVSEP_INLINE_BLOB_DATA_MAX, outfd, expected_id, fd);
	if (err)
		goto done;

	err = got_privsep_send_raw_obj(ibuf, size, hdrlen, 0, data);
done:
	free(data);
	if (close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct imsg imsg;
	struct imsgbuf ibuf;
	size_t datalen;
	struct got_object_id expected_id;

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
		int fd = -1, outfd = -1, finished = 0;

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
			finished = 1;
			goto done;
		}

		if (imsg.hdr.type != GOT_IMSG_OBJECT_REQUEST &&
		    imsg.hdr.type != GOT_IMSG_RAW_OBJECT_REQUEST) {
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

		err = got_object_read_header(&obj, fd);
		if (err)
			goto done;

		if (imsg.hdr.type == GOT_IMSG_RAW_OBJECT_REQUEST) {
			struct imsg imsg_outfd;

			err = got_privsep_recv_imsg(&imsg_outfd, &ibuf, 0);
			if (err) {
				if (imsg_outfd.hdr.len == 0)
					err = NULL;
				goto done;
			}

			if (imsg_outfd.hdr.type == GOT_IMSG_STOP) {
				imsg_free(&imsg_outfd);
				goto done;
			}

			if (imsg_outfd.hdr.type != GOT_IMSG_RAW_OBJECT_OUTFD) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				imsg_free(&imsg_outfd);
				goto done;
			}

			datalen = imsg_outfd.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				imsg_free(&imsg_outfd);
				goto done;
			}
			outfd = imsg_get_fd(&imsg_outfd);
			if (outfd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				imsg_free(&imsg_outfd);
				goto done;
			}
			err = send_raw_obj(&ibuf, obj, &expected_id,
			    fd, outfd);
			fd = -1; /* fd is owned by send_raw_obj() */
			if (close(outfd) == -1 && err == NULL)
				err = got_error_from_errno("close");
			imsg_free(&imsg_outfd);
			if (err)
				goto done;
		} else
			err = got_privsep_send_obj(&ibuf, obj);
done:
		if (fd != -1 && close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		imsg_free(&imsg);
		if (obj) {
			got_object_close(obj);
			obj = NULL;
		}
		if (err || finished)
			break;
	}

	if (err) {
		if(!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	imsgbuf_clear(&ibuf);
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
