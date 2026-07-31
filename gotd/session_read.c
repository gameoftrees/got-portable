/*
 * Copyright (c) 2022, 2023 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_opentemp.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"
#include "got_lib_gitproto.h"

#include "gotd.h"
#include "log.h"
#include "session_read.h"

enum gotd_session_read_state {
	GOTD_STATE_EXPECT_LIST_REFS,
	GOTD_STATE_EXPECT_CAPABILITIES,
	GOTD_STATE_EXPECT_WANT,
	GOTD_STATE_EXPECT_HAVE_OR_DONE,
	GOTD_STATE_DONE,
};

static struct gotd_session_read {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
	struct gotd_imsgev parent_iev;
	struct gotd_imsgev notifier_iev;
	struct timeval request_timeout;
	enum gotd_session_read_state state;
	struct gotd_imsgev repo_child_iev;
	int repo_child_packfd;
} gotd_session;

static struct gotd_session_client {
	struct gotd_client_capability	*capabilities;
	size_t				 ncapa_alloc;
	size_t				 ncapabilities;
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	struct gotd_imsgev		 iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	char				*username;
	char				*packfile_path;
	char				*packidx_path;
	int				 nref_updates;
	int				 accept_flush_pkt;
	int				 flush_disconnect;
} gotd_session_client;

static void session_read_shutdown(void);

static void
disconnect(struct gotd_session_client *client)
{
	log_debug("uid %d: disconnecting", client->euid);

	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_DISCONNECT, GOTD_PROC_SESSION_READ, -1, NULL, 0) == -1)
		log_warn("imsg compose DISCONNECT");

	imsgbuf_clear(&gotd_session.repo_child_iev.ibuf);
	event_del(&gotd_session.repo_child_iev.ev);
	evtimer_del(&client->tmo);
	close(client->fd);
	if (client->delta_cache_fd != -1)
		close(client->delta_cache_fd);
	if (client->packfile_path) {
		if (unlink(client->packfile_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packfile_path);
		free(client->packfile_path);
	}
	if (client->packidx_path) {
		if (unlink(client->packidx_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packidx_path);
		free(client->packidx_path);
	}
	free(client->capabilities);

	session_read_shutdown();
}

static void
disconnect_on_error(struct gotd_session_client *client,
    const struct got_error *err)
{
	struct imsgbuf ibuf;

	if (err->code != GOT_ERR_EOF) {
		log_warnx("uid %d: %s", client->euid, err->msg);
		if (imsgbuf_init(&ibuf, client->fd) == -1) {
			log_warn("imsgbuf_init");
		} else {
			gotd_imsg_send_error(&ibuf, 0,
			    GOTD_PROC_SESSION_READ, err);
			imsgbuf_clear(&ibuf);
		}
	}

	disconnect(client);
}

static void
gotd_request_timeout(int fd, short events, void *arg)
{
	struct gotd_session_client *client = arg;

	log_warnx("disconnecting uid %d due to timeout", client->euid);
	disconnect(client);
}

static void
session_read_sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		session_read_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static const struct got_error *
recv_packfile_done(struct imsg *imsg)
{
	size_t datalen;

	log_debug("packfile-done received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	return NULL;
}

static void
session_dispatch_repo_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;

		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_DONE:
			do_disconnect = 1;
			err = recv_packfile_done(&imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else {
			if (err)
				log_warnx("uid %d: %s", client->euid, err->msg);
		}
		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static const struct got_error *
recv_capabilities(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capabilities icapas;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(icapas))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapas, imsg->data, sizeof(icapas));

	client->ncapa_alloc = icapas.ncapabilities;
	client->capabilities = calloc(client->ncapa_alloc,
	    sizeof(*client->capabilities));
	if (client->capabilities == NULL) {
		client->ncapa_alloc = 0;
		return got_error_from_errno("calloc");
	}

	log_debug("expecting %zu capabilities from uid %d",
	    client->ncapa_alloc, client->euid);
	return NULL;
}

static const struct got_error *
recv_capability(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capability icapa;
	struct gotd_client_capability *capa;
	size_t datalen;
	char *key, *value = NULL;

	if (client->capabilities == NULL ||
	    client->ncapabilities >= client->ncapa_alloc) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "unexpected capability received");
	}

	memset(&icapa, 0, sizeof(icapa));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(icapa))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapa, imsg->data, sizeof(icapa));

	if (datalen != sizeof(icapa) + icapa.key_len + icapa.value_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	key = strndup(imsg->data + sizeof(icapa), icapa.key_len);
	if (key == NULL)
		return got_error_from_errno("strndup");
	if (icapa.value_len > 0) {
		value = strndup(imsg->data + sizeof(icapa) + icapa.key_len,
		    icapa.value_len);
		if (value == NULL) {
			free(key);
			return got_error_from_errno("strndup");
		}
	}

	capa = &client->capabilities[client->ncapabilities++];
	capa->key = key;
	capa->value = value;

	if (value)
		log_debug("uid %d: capability %s=%s", client->euid, key, value);
	else
		log_debug("uid %d: capability %s", client->euid, key);

	return NULL;
}

static const struct got_error *
forward_want(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_want ireq;
	struct gotd_imsg_want iwant;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	memset(&iwant, 0, sizeof(iwant));
	memcpy(iwant.object_id, ireq.object_id, SHA1_DIGEST_LENGTH);

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_WANT, GOTD_PROC_SESSION_READ, -1,
	    &iwant, sizeof(iwant)) == -1)
		return got_error_from_errno("imsg compose WANT");

	return NULL;
}

static const struct got_error *
forward_have(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_have ireq;
	struct gotd_imsg_have ihave;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	memset(&ihave, 0, sizeof(ihave));
	memcpy(ihave.object_id, ireq.object_id, SHA1_DIGEST_LENGTH);

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_HAVE, GOTD_PROC_SESSION_READ, -1,
	    &ihave, sizeof(ihave)) == -1)
		return got_error_from_errno("imsg compose HAVE");

	return NULL;
}

static int
client_has_capability(struct gotd_session_client *client, const char *capastr)
{
	struct gotd_client_capability *capa;
	size_t i;

	if (client->ncapabilities == 0)
		return 0;

	for (i = 0; i < client->ncapabilities; i++) {
		capa = &client->capabilities[i];
		if (strcmp(capa->key, capastr) == 0)
			return 1;
	}

	return 0;
}

static const struct got_error *
send_packfile(struct gotd_session_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_send_packfile ipack;
	int pipe[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	memset(&ipack, 0, sizeof(ipack));

	if (client_has_capability(client, GOT_CAPA_SIDE_BAND_64K))
		ipack.report_progress = 1;

	client->delta_cache_fd = got_opentempfd();
	if (client->delta_cache_fd == -1)
		return got_error_from_errno("got_opentempfd");

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_SEND_PACKFILE, GOTD_PROC_GOTD, client->delta_cache_fd,
	    &ipack, sizeof(ipack)) == -1) {
		err = got_error_from_errno("imsg compose SEND_PACKFILE");
		close(pipe[0]);
		close(pipe[1]);
		close(client->delta_cache_fd);
		client->delta_cache_fd = -1;
		return err;
	}

	/*
	 * Send pack data pipe end 0 to gotsh(1) (expects just an fd, no data).
	 *
	 * We will forward the other pipe end to the repo_read process only
	 * once we have confirmation that gotsh(1) has received its end.
	 * It is important that we send a pipe end to gotsh(1) before the
	 * repo_read process starts sending pack progress messages via imsg
	 * to prevent spurious "unexpected privsep message" errors from gotsh.
	 */
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_PACKFILE_PIPE, GOTD_PROC_GOTD, pipe[0], NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	gotd_session.repo_child_packfd = pipe[1];
	return NULL;
}

static void
session_dispatch_client(int fd, short events, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
	const struct got_error *err = NULL;
	struct imsg imsg;
	ssize_t n;

	if (events & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err) {
			disconnect_on_error(client, err);
			return;
		}

		if (client->flush_disconnect) {
			disconnect(client);
			return;
		}
	}

	if (events & EV_READ) {
		n = imsgbuf_read(ibuf);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_read");
			disconnect_on_error(client, err);
			return;
		}
		if (n == 0) {
			 err = got_error(GOT_ERR_EOF);
			 disconnect_on_error(client, err);
			 return;
		}
	}

	while (err == NULL) {
		n = imsgbuf_get(ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_get");
			break;
		}
		if (n == 0)
			break;

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
		case GOTD_IMSG_CAPABILITIES:
			if (gotd_session.state !=
			    GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capabilities received");
				break;
			}
			log_debug("receiving capabilities from uid %d",
			    client->euid);
			err = recv_capabilities(client, &imsg);
			break;
		case GOTD_IMSG_CAPABILITY:
			if (gotd_session.state != GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capability received");
				break;
			}
			err = recv_capability(client, &imsg);
			if (err || client->ncapabilities < client->ncapa_alloc)
				break;
			gotd_session.state = GOTD_STATE_EXPECT_WANT;
			client->accept_flush_pkt = 1;
			log_debug("uid %d: expecting want-lines", client->euid);
			break;
		case GOTD_IMSG_WANT:
			if (gotd_session.state != GOTD_STATE_EXPECT_WANT) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected want-line received");
				break;
			}
			log_debug("received want-line from uid %d",
			    client->euid);
			client->accept_flush_pkt = 1;
			err = forward_want(client, &imsg);
			break;
		case GOTD_IMSG_HAVE:
			if (gotd_session.state !=
			    GOTD_STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected have-line received");
				break;
			}
			log_debug("received have-line from uid %d",
			    client->euid);
			err = forward_have(client, &imsg);
			if (err)
				break;
			client->accept_flush_pkt = 1;
			break;
		case GOTD_IMSG_FLUSH:
			if (gotd_session.state != GOTD_STATE_EXPECT_WANT &&
			    gotd_session.state !=
			    GOTD_STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			if (!client->accept_flush_pkt) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}

			/*
			 * Accept just one flush packet at a time.
			 * Future client state transitions will set this flag
			 * again if another flush packet is expected.
			 */
			client->accept_flush_pkt = 0;

			log_debug("received flush-pkt from uid %d",
			    client->euid);
			if (gotd_session.state == GOTD_STATE_EXPECT_WANT) {
				gotd_session.state =
				    GOTD_STATE_EXPECT_HAVE_OR_DONE;
				log_debug("uid %d: expecting have-lines "
				    "or 'done'", client->euid);
			} else if (gotd_session.state ==
			    GOTD_STATE_EXPECT_HAVE_OR_DONE) {
				client->accept_flush_pkt = 1;
				log_debug("uid %d: expecting more have-lines "
				    "or 'done'", client->euid);
			} else if (gotd_session.state !=
			    GOTD_STATE_EXPECT_HAVE_OR_DONE) {
				/* should not happen, see above */
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected client state");
				break;
			}
			break;
		case GOTD_IMSG_DONE:
			if (gotd_session.state !=
			    GOTD_STATE_EXPECT_HAVE_OR_DONE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			log_debug("received 'done' from uid %d", client->euid);
			gotd_session.state = GOTD_STATE_DONE;
			client->accept_flush_pkt = 1;
			err = send_packfile(client);
			break;
		case GOTD_IMSG_PACKFILE_READY:
			if (gotd_session.repo_child_packfd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			/*
			 * gotsh(1) has received its send of the pack pipe.
			 * Send pack pipe end 1 to repo child process.
			 */
			if (gotd_imsg_compose_event(
			    &gotd_session.repo_child_iev,
			    GOTD_IMSG_PACKFILE_PIPE, GOTD_PROC_GOTD,
			    gotd_session.repo_child_packfd, NULL, 0) == -1) {
				err = got_error_from_errno("imsg compose "
				    "PACKFILE_PIPE");
			} else
				gotd_session.repo_child_packfd = -1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err) {
		if (err->code != GOT_ERR_EOF)
			disconnect_on_error(client, err);
	} else {
		gotd_imsg_event_add(iev);
		evtimer_add(&client->tmo, &gotd_session.request_timeout);
	}
}

static const struct got_error *
list_refs_request(void)
{
	static const struct got_error *err;
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsgev *iev = &gotd_session.repo_child_iev;
	int fd;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_LIST_REFS_INTERNAL,
	    GOTD_PROC_SESSION_READ, fd, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose LIST_REFS_INTERNAL");
		close(fd);
		return err;
	}

	gotd_session.state = GOTD_STATE_EXPECT_CAPABILITIES;
	log_debug("uid %d: expecting capabilities", client->euid);
	return NULL;
}

static const struct got_error *
recv_connect(struct imsg *imsg)
{
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsg_connect iconnect;
	size_t datalen;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iconnect, imsg->data, sizeof(iconnect));
	if (iconnect.username_len == 0 ||
	    datalen != sizeof(iconnect) + iconnect.username_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	client->euid = iconnect.euid;
	client->egid = iconnect.egid;
	client->fd = imsg_get_fd(imsg);
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	client->username = strndup(imsg->data + sizeof(iconnect),
	    iconnect.username_len);
	if (client->username == NULL)
		return got_error_from_errno("strndup");

	if (imsgbuf_init(&client->iev.ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&client->iev.ibuf);
	client->iev.handler = session_dispatch_client;
	client->iev.events = EV_READ;
	client->iev.handler_arg = NULL;
	event_set(&client->iev.ev, client->iev.ibuf.fd, EV_READ,
	    session_dispatch_client, &client->iev);
	gotd_imsg_event_add(&client->iev);
	evtimer_set(&client->tmo, gotd_request_timeout, client);
	evtimer_add(&client->tmo, &gotd_session.request_timeout);

	return NULL;
}

static const struct got_error *
recv_repo_child(struct imsg *imsg)
{
	struct gotd_imsg_connect_repo_child ichild;
	struct gotd_session_client *client = &gotd_session_client;
	size_t datalen;
	int fd;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	/* We should already have received a pipe to the listener. */
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ichild))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ichild, imsg->data, sizeof(ichild));

	if (ichild.proc_id != GOTD_PROC_REPO_READ)
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad child process type");

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (imsgbuf_init(&gotd_session.repo_child_iev.ibuf, fd)) {
		close(fd);
		return got_error_from_errno("imsgbuf_init");
	}
	imsgbuf_allow_fdpass(&gotd_session.repo_child_iev.ibuf);
	gotd_session.repo_child_iev.handler = session_dispatch_repo_child;
	gotd_session.repo_child_iev.events = EV_READ;
	gotd_session.repo_child_iev.handler_arg = NULL;
	event_set(&gotd_session.repo_child_iev.ev,
	    gotd_session.repo_child_iev.ibuf.fd, EV_READ,
	    session_dispatch_repo_child, &gotd_session.repo_child_iev);
	gotd_imsg_event_add(&gotd_session.repo_child_iev);

	/* The "recvfd" pledge promise is no longer needed. */
	if (pledge("stdio rpath wpath cpath sendfd fattr flock", NULL) == -1)
		fatal("pledge");

	return NULL;
}

static void
session_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0, do_list_refs = 0;

		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_CONNECT:
			err = recv_connect(&imsg);
			break;
		case GOTD_IMSG_DISCONNECT:
			do_disconnect = 1;
			break;
		case GOTD_IMSG_REQUEST_TIMEOUT:
			if (imsg_get_data(&imsg, &gotd_session.request_timeout,
			    sizeof(gotd_session.request_timeout)) == -1)
				err = got_error_from_errno("imsg_get_data");
			break;
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_repo_child(&imsg);
			if (err)
				break;
			do_list_refs = 1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else if (do_list_refs)
			err = list_refs_request();

		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
session_read_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds)
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	gotd_session.title = title;
	gotd_session.pid = getpid();
	gotd_session.pack_fds = pack_fds;
	gotd_session.temp_fds = temp_fds;
	gotd_session.request_timeout.tv_sec = GOTD_DEFAULT_REQUEST_TIMEOUT;
	gotd_session.request_timeout.tv_usec = 0;
	gotd_session.repo_child_packfd = -1;

	if (imsgbuf_init(&gotd_session.notifier_iev.ibuf, -1) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&gotd_session.notifier_iev.ibuf);

	err = got_repo_open(&gotd_session.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(gotd_session.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}
	if (got_repo_get_object_format(gotd_session.repo) != GOT_HASH_SHA1) {
		err = got_error_msg(GOT_ERR_NOT_IMPL,
		    "sha256 object IDs unsupported in network protocol");
		goto done;
	}

	got_repo_temp_fds_set(gotd_session.repo, temp_fds);

	signal_set(&evsigint, SIGINT, session_read_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, session_read_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, session_read_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, session_read_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	gotd_session.state = GOTD_STATE_EXPECT_LIST_REFS;

	gotd_session_client.fd = -1;
	gotd_session_client.nref_updates = -1;
	gotd_session_client.delta_cache_fd = -1;
	gotd_session_client.accept_flush_pkt = 1;

	if (imsgbuf_init(&gotd_session.parent_iev.ibuf, GOTD_FILENO_MSG_PIPE)
	    == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&gotd_session.parent_iev.ibuf);
	gotd_session.parent_iev.handler = session_dispatch;
	gotd_session.parent_iev.events = EV_READ;
	gotd_session.parent_iev.handler_arg = NULL;
	event_set(&gotd_session.parent_iev.ev, gotd_session.parent_iev.ibuf.fd,
	    EV_READ, session_dispatch, &gotd_session.parent_iev);
	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_CLIENT_SESSION_READY, GOTD_PROC_SESSION_READ,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CLIENT_SESSION_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	session_read_shutdown();
}

static void
session_read_shutdown(void)
{
	log_debug("%s: shutting down", gotd_session.title);

	if (gotd_session.repo)
		got_repo_close(gotd_session.repo);
	got_repo_pack_fds_close(gotd_session.pack_fds);
	got_repo_temp_fds_close(gotd_session.temp_fds);
	free(gotd_session_client.username);
	if (gotd_session.repo_child_packfd != -1)
		close(gotd_session.repo_child_packfd);
	exit(0);
}
