/*
 * Copyright (c) 2022, 2025 Stefan Sperling <stsp@openbsd.org>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_poll.h"

#include "gotd.h"

static const struct got_error *
gotd_imsg_recv(struct imsg *imsg, struct imsgbuf *ibuf, size_t min_datalen)
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
gotd_imsg_poll_recv(struct imsg *imsg, struct imsgbuf *ibuf, size_t min_datalen)
{
	const struct got_error *err = NULL;

	for (;;) {
		err = gotd_imsg_recv(imsg, ibuf, min_datalen);
		if (err == NULL || err->code != GOT_ERR_PRIVSEP_READ)
			return err;

		err = got_poll_fd(ibuf->fd, POLLIN, INFTIM);
		if (err)
			break;
	}

	return err;
}

int
gotd_imsg_send_error_event(struct gotd_imsgev *iev, uint32_t peerid,
    uint32_t client_id, const struct got_error *err)
{
	struct gotd_imsg_error ierr;
	int ret;

	ierr.code = err->code;
	if (err->code == GOT_ERR_ERRNO)
		ierr.errno_code = errno;
	else
		ierr.errno_code = 0;
	ierr.client_id = client_id;
	strlcpy(ierr.msg, err->msg, sizeof(ierr.msg));

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_ERROR, peerid, -1,
	    &ierr, sizeof(ierr));
	if (ret == -1)
		return -1;

	return 0;
}

int
gotd_imsg_forward(struct gotd_imsgev *iev, struct imsg *imsg, int fd)
{
	return gotd_imsg_compose_event(iev, imsg->hdr.type, imsg->hdr.peerid,
	    fd, imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
}

const struct got_error *
gotd_imsg_recv_pathlist(size_t *npaths, struct imsg *imsg)
{
	struct gotd_imsg_pathlist ilist;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ilist))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ilist, imsg->data, sizeof(ilist));

	if (ilist.nelem == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	*npaths = ilist.nelem;
	return NULL;
}

const struct got_error *
gotd_imsg_recv_pathlist_elem(struct imsg *imsg, struct got_pathlist_head *paths)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_pathlist_elem ielem;
	size_t datalen;
	char *path;
	struct got_pathlist_entry *pe;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ielem))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ielem, imsg->data, sizeof(ielem));

	if (datalen != sizeof(ielem) + ielem.path_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	path = strndup(imsg->data + sizeof(ielem), ielem.path_len);
	if (path == NULL)
		return got_error_from_errno("strndup");

	err = got_pathlist_insert(&pe, paths, path, NULL);
	if (err || pe == NULL)
		free(path);
	return err;
}

void
gotd_free_notification_target(struct gotd_notification_target *target)
{
	if (target == NULL)
		return;

	switch (target->type) {
	case GOTD_NOTIFICATION_VIA_EMAIL:
		free(target->conf.email.sender);
		free(target->conf.email.recipient);
		free(target->conf.email.responder);
		free(target->conf.email.hostname);
		free(target->conf.email.port);
		break;
	case GOTD_NOTIFICATION_VIA_HTTP:
		free(target->conf.http.hostname);
		free(target->conf.http.port);
		free(target->conf.http.path);
		free(target->conf.http.auth);
		free(target->conf.http.hmac);
		break;
	default:
		break;
	}

	free(target);
}

const struct got_error *
gotd_imsg_recv_notification_target_email(char **repo_name,
    struct gotd_notification_target **new_target, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_notitfication_target_email itarget;
	struct gotd_notification_target *target;
	size_t datalen;

	if (repo_name)
		*repo_name = NULL;
	*new_target = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(itarget))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&itarget, imsg->data, sizeof(itarget));

	if (datalen != sizeof(itarget) + itarget.sender_len +
	    itarget.recipient_len + itarget.responder_len +
	    itarget.hostname_len + itarget.port_len + itarget.repo_name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (itarget.sender_len == 0 || itarget.recipient_len == 0 ||
	    itarget.repo_name_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	target = calloc(1, sizeof(*target));
	if (target == NULL)
		return got_error_from_errno("calloc");

	target->type = GOTD_NOTIFICATION_VIA_EMAIL;

	if (itarget.sender_len) {
		target->conf.email.sender = strndup(imsg->data +
		    sizeof(itarget), itarget.sender_len);
		if (target->conf.email.sender == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.sender) != itarget.sender_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	target->conf.email.recipient = strndup(imsg->data + sizeof(itarget) +
	    itarget.sender_len, itarget.recipient_len);
	if (target->conf.email.recipient == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.email.recipient) != itarget.recipient_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	
	if (itarget.responder_len) {
		target->conf.email.responder = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len + itarget.recipient_len,
		    itarget.responder_len);
		if (target->conf.email.responder == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.responder) !=
		    itarget.responder_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.hostname_len) {
		target->conf.email.hostname = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len,
		    itarget.hostname_len);
		if (target->conf.email.hostname == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.hostname) !=
		    itarget.hostname_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.port_len) {
		target->conf.email.port = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len +
		    itarget.hostname_len, itarget.port_len);
		if (target->conf.email.port == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.port) != itarget.port_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (repo_name) {
		*repo_name = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len +
		    itarget.hostname_len + itarget.port_len,
		    itarget.repo_name_len);
		if (*repo_name == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(*repo_name) != itarget.repo_name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			free(*repo_name);
			*repo_name = NULL;
			goto done;
		}
	}

	*new_target = target;
done:
	if (err)
		gotd_free_notification_target(target);
	return err;
}

const struct got_error *
gotd_imsg_recv_notification_target_http(char **repo_name,
    struct gotd_notification_target **new_target, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_notitfication_target_http itarget;
	struct gotd_notification_target *target;
	size_t datalen;

	if (repo_name)
		*repo_name = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(itarget))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&itarget, imsg->data, sizeof(itarget));

	if (datalen != sizeof(itarget) + itarget.hostname_len +
	    itarget.port_len + itarget.path_len + itarget.auth_len +
	    itarget.hmac_len + itarget.repo_name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (itarget.hostname_len == 0 || itarget.port_len == 0 ||
	    itarget.path_len == 0 || itarget.repo_name_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	target = calloc(1, sizeof(*target));
	if (target == NULL)
		return got_error_from_errno("calloc");

	target->type = GOTD_NOTIFICATION_VIA_HTTP;

	target->conf.http.tls = itarget.tls;

	target->conf.http.hostname = strndup(imsg->data +
	    sizeof(itarget), itarget.hostname_len);
	if (target->conf.http.hostname == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.hostname) != itarget.hostname_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	target->conf.http.port = strndup(imsg->data + sizeof(itarget) +
	    itarget.hostname_len, itarget.port_len);
	if (target->conf.http.port == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.port) != itarget.port_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	
	target->conf.http.path = strndup(imsg->data +
	    sizeof(itarget) + itarget.hostname_len + itarget.port_len,
	    itarget.path_len);
	if (target->conf.http.path == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.path) != itarget.path_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	if (itarget.auth_len) {
		target->conf.http.auth = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len,
		    itarget.auth_len);
		if (target->conf.http.auth == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.http.auth) != itarget.auth_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.hmac_len) {
		target->conf.http.hmac = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len +
		    itarget.auth_len, itarget.hmac_len);
		if (target->conf.http.hmac == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.http.hmac) != itarget.hmac_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (repo_name) {
		*repo_name = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len +
		    itarget.auth_len + itarget.hmac_len,
		    itarget.repo_name_len);
		if (*repo_name == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(*repo_name) != itarget.repo_name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			free(*repo_name);
			*repo_name = NULL;
			goto done;
		}
	}
		
	*new_target = target;
done:
	if (err)
		gotd_free_notification_target(target);
	return err;
}
