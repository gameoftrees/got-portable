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

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <poll.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "got_lib_poll.h"

#include "gotsysd.h"

const struct got_error *
gotsysd_imsg_recv_error(uint32_t *client_id, struct imsg *imsg)
{
	struct gotsysd_imsg_error ierr;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ierr))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ierr, imsg->data, sizeof(ierr));

	if (client_id)
		*client_id = ierr.client_id;

	if (ierr.code == GOT_ERR_ERRNO)
		errno = ierr.errno_code;

	return got_error_msg(ierr.code, ierr.msg);
}

const struct got_error *
gotsysd_imsg_flush(struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;

	while (imsgbuf_queuelen(ibuf) > 0) {
		err = got_poll_fd(ibuf->fd, POLLOUT, INFTIM);
		if (err)
			break;

		if (imsgbuf_write(ibuf) == -1) {
			err = got_error_from_errno("imsgbuf_write");
			break;
		}
	}

	return err;
}

static const struct got_error *
gotsysd_imsg_recv(struct imsg *imsg, struct imsgbuf *ibuf, size_t min_datalen)
{
	ssize_t n;

	n = imsgbuf_get(ibuf, imsg);
	if (n == -1)
		return got_error_from_errno("imsgbuf_get");

	if (n == 0) {
		n = imsgbuf_read(ibuf);
		if (n == -1)
			return got_error_from_errno("imsgbuf_read");
		if (n == 0)
			return got_error(GOT_ERR_EOF);
		n = imsgbuf_get(ibuf, imsg);
		if (n == -1)
			return got_error_from_errno("imsgbuf_get");
		if (n == 0)
			return got_error(GOT_ERR_PRIVSEP_READ);
	}

	if (imsg->hdr.len < IMSG_HEADER_SIZE + min_datalen)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	return NULL;
}

const struct got_error *
gotsysd_imsg_poll_recv(struct imsg *imsg, struct imsgbuf *ibuf,
    size_t min_datalen)
{
	const struct got_error *err = NULL;

	for (;;) {
		err = gotsysd_imsg_recv(imsg, ibuf, min_datalen);
		if (err == NULL || err->code != GOT_ERR_PRIVSEP_READ)
			return err;

		err = got_poll_fd(ibuf->fd, POLLIN, INFTIM);
		if (err)
			break;
	}

	return err;
}

int
gotsysd_imsg_send_error(struct imsgbuf *ibuf, uint32_t peerid,
    uint32_t client_id, const struct got_error *err)
{
	const struct got_error *flush_err;
	struct gotsysd_imsg_error ierr;
	int ret;

	ierr.code = err->code;
	if (err->code == GOT_ERR_ERRNO)
		ierr.errno_code = errno;
	else
		ierr.errno_code = 0;
	ierr.client_id = client_id;
	strlcpy(ierr.msg, err->msg, sizeof(ierr.msg));

	ret = imsg_compose(ibuf, GOTSYSD_IMSG_ERROR, peerid, getpid(), -1,
	    &ierr, sizeof(ierr));
	if (ret == -1)
		return -1;

	flush_err = gotsysd_imsg_flush(ibuf);
	if (flush_err)
		return -1;

	return 0;
}

int
gotsysd_imsg_send_error_event(struct gotsysd_imsgev *iev, uint32_t peerid,
    uint32_t client_id, const struct got_error *err)
{
	struct gotsysd_imsg_error ierr;
	int ret;

	ierr.code = err->code;
	if (err->code == GOT_ERR_ERRNO)
		ierr.errno_code = errno;
	else
		ierr.errno_code = 0;
	ierr.client_id = client_id;
	strlcpy(ierr.msg, err->msg, sizeof(ierr.msg));

	ret = gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_ERROR, peerid, -1,
	    &ierr, sizeof(ierr));
	if (ret == -1)
		return -1;

	return 0;
}

void
gotsysd_imsg_event_add(struct gotsysd_imsgev *iev)
{
	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf))
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
gotsysd_imsg_compose_event(struct gotsysd_imsgev *iev, uint16_t type,
    uint32_t peerid, int fd, void *data, uint16_t datalen)
{
	int ret;

	ret = imsg_compose(&iev->ibuf, type, peerid, getpid(), fd,
	    data, datalen);
	if (ret != -1)
		gotsysd_imsg_event_add(iev);

	return ret;
}

int
gotsysd_imsg_forward(struct gotsysd_imsgev *iev, struct imsg *imsg, int fd)
{
	return gotsysd_imsg_compose_event(iev, imsg->hdr.type, imsg->hdr.peerid,
	    fd, imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
}
