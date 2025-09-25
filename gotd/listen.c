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
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <siphash.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "gotd.h"
#include "log.h"
#include "listen.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gotd_listen_client {
	STAILQ_ENTRY(gotd_listen_client)	 entry;
	uint32_t			 id;
	int				 fd;
	uid_t				 euid;
};
STAILQ_HEAD(gotd_listen_clients, gotd_listen_client);

static struct gotd_listen_clients gotd_listen_clients[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
static volatile int listen_client_cnt;
static int inflight;
static int listener_halted;

struct gotd_uid_connection_counter {
	STAILQ_ENTRY(gotd_uid_connection_counter) entry;
	uid_t euid;
	int nconnections;
};
STAILQ_HEAD(gotd_client_uids, gotd_uid_connection_counter);
static struct gotd_client_uids gotd_client_uids[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY uid_hash_key;

static struct {
	pid_t pid;
	const char *title;
	int fd;
	struct gotd_imsgev iev;
	struct gotd_imsgev parent_iev;
	struct event pause_ev;
	struct gotd_uid_connection_limit *connection_limits;
	size_t nconnection_limits;
	size_t nconnection_limits_received;
} gotd_listen;

static int inflight;

static void listen_shutdown(void);

static void
listen_sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		break;
	case SIGUSR1:
		break;
	case SIGTERM:
	case SIGINT:
		listen_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static void
clients_init(void)
{
	uint64_t slot;

	arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));

	for (slot = 0; slot < nitems(gotd_listen_clients); slot++)
		STAILQ_INIT(&gotd_listen_clients[slot]);
}

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct gotd_listen_client *client)
{
	uint64_t slot = client_hash(client->id) % nitems(gotd_listen_clients);
	STAILQ_INSERT_HEAD(&gotd_listen_clients[slot], client, entry);
	listen_client_cnt++;
}

static struct gotd_listen_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct gotd_listen_client *c;

	slot = client_hash(client_id) % nitems(gotd_listen_clients);
	STAILQ_FOREACH(c, &gotd_listen_clients[slot], entry) {
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

static uint32_t
get_client_id(void)
{
	int duplicate = 0;
	uint32_t id;

	do {
		id = arc4random();
		duplicate = (find_client(id) != NULL);
	} while (duplicate || id == 0);

	return id;
}

static uint64_t
uid_hash(uid_t euid)
{
	return SipHash24(&uid_hash_key, &euid, sizeof(euid));
}

static void
add_uid_connection_counter(struct gotd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotd_client_uids);
	STAILQ_INSERT_HEAD(&gotd_client_uids[slot], counter, entry);
}

static void
remove_uid_connection_counter(struct gotd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotd_client_uids);
	STAILQ_REMOVE(&gotd_client_uids[slot], counter,
	    gotd_uid_connection_counter, entry);
}

static struct gotd_uid_connection_counter *
find_uid_connection_counter(uid_t euid)
{
	uint64_t slot;
	struct gotd_uid_connection_counter *c;

	slot = uid_hash(euid) % nitems(gotd_client_uids);
	STAILQ_FOREACH(c, &gotd_client_uids[slot], entry) {
		if (c->euid == euid)
			return c;
	}

	return NULL;
}

static const struct got_error *
disconnect(struct gotd_listen_client *client)
{
	struct gotd_uid_connection_counter *counter;
	uint64_t slot;
	int client_fd;

	log_debug("client on fd %d disconnecting", client->fd);

	slot = client_hash(client->id) % nitems(gotd_listen_clients);
	STAILQ_REMOVE(&gotd_listen_clients[slot], client,
	    gotd_listen_client, entry);

	counter = find_uid_connection_counter(client->euid);
	if (counter) {
		if (counter->nconnections > 0)
			counter->nconnections--;
		if (counter->nconnections == 0) {
			remove_uid_connection_counter(counter);
			free(counter);
		}
	}

	client_fd = client->fd;
	free(client);
	inflight--;
	listen_client_cnt--;
	if (close(client_fd) == -1)
		return got_error_from_errno("close");

	if (listener_halted && listen_client_cnt == 0)
		listen_shutdown();

	return NULL;
}

static int
accept_reserve(int fd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve +
	    ((*counter + 1) * GOTD_FD_NEEDED) >= getdtablesize()) {
		log_debug("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}

	if ((ret = accept4(fd, addr, addrlen,
	    SOCK_NONBLOCK | SOCK_CLOEXEC)) > -1) {
		(*counter)++;
	}

	return ret;
}

static void
gotd_accept_paused(int fd, short event, void *arg)
{
	event_add(&gotd_listen.iev.ev, NULL);
}

static void
gotd_accept(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct sockaddr_storage ss;
	struct timeval backoff;
	socklen_t len;
	int s = -1;
	struct gotd_listen_client *client = NULL;
	struct gotd_uid_connection_counter *counter = NULL;
	struct gotd_imsg_connect iconn;
	uid_t euid;
	gid_t egid;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (event_add(&iev->ev, NULL) == -1) {
		log_warn("event_add");
		return;
	}
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	/* Other backoff conditions apart from EMFILE/ENFILE? */
	s = accept_reserve(fd, (struct sockaddr *)&ss, &len, GOTD_FD_RESERVE,
	    &inflight);
	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&iev->ev);
			evtimer_add(&gotd_listen.pause_ev, &backoff);
			return;
		default:
			log_warn("accept");

			/* Prevent endless looping on errors. */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (listen_client_cnt >= GOTD_MAXCLIENTS)
		goto err;

	if (getpeereid(s, &euid, &egid) == -1) {
		log_warn("getpeerid");
		goto err;
	}

	counter = find_uid_connection_counter(euid);
	if (counter == NULL) {
		counter = calloc(1, sizeof(*counter));
		if (counter == NULL) {
			log_warn("%s: calloc", __func__);
			goto err;
		}
		counter->euid = euid;
		counter->nconnections = 1;
		add_uid_connection_counter(counter);
	} else {
		int max_connections = GOTD_MAX_CONN_PER_UID;
		struct gotd_uid_connection_limit *limit;

		limit = gotd_find_uid_connection_limit(
		    gotd_listen.connection_limits,
		    gotd_listen.nconnection_limits, euid);
		if (limit)
			max_connections = limit->max_connections;

		if (counter->nconnections >= max_connections) {
			const struct got_error *error;
			struct imsgbuf ibuf;

			log_warnx("maximum connections exceeded for uid %d",
			    euid);

			/* Report error to client and close connection. */
			if (imsgbuf_init(&ibuf, s) == -1) {
				log_warn("imsgbuf_init");
				goto err;
			}
			error = got_error(GOT_ERR_CONNECTION_LIMIT);
			if (gotd_imsg_send_error(&ibuf, GOTD_PROC_LISTEN,
			    0, error) == -1)
				log_warn("imsg send error");
			goto err;
		}
		counter->nconnections++;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		log_warn("%s: calloc", __func__);
		goto err;
	}
	client->id = get_client_id();
	client->fd = s;
	client->euid = euid;
	s = -1;
	add_client(client);
	log_debug("%s: new client connected on fd %d uid %d gid %d", __func__,
	    client->fd, euid, egid);

	memset(&iconn, 0, sizeof(iconn));
	iconn.client_id = client->id;
	iconn.euid = euid;
	iconn.egid = egid;
	s = dup(client->fd);
	if (s == -1) {
		log_warn("%s: dup", __func__);
		goto err;
	}
	if (gotd_imsg_compose_event(&gotd_listen.parent_iev,
	    GOTD_IMSG_CONNECT, GOTD_PROC_LISTEN, s,
	    &iconn, sizeof(iconn)) == -1) {
		log_warn("imsg compose CONNECT");
		goto err;
	}

	return;
err:
	inflight--;
	if (client)
		disconnect(client);
	if (s != -1)
		close(s);
}

static const struct got_error *
recv_listen_socket(struct imsg *imsg)
{
	struct gotd_imsg_listen_socket isocket;
	size_t datalen;

	if (gotd_listen.fd != -1 ||
	    gotd_listen.nconnection_limits_received != 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(isocket))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&isocket, imsg->data, sizeof(isocket));

	gotd_listen.fd = imsg_get_fd(imsg);
	if (gotd_listen.fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

#ifndef PROFILE
	/* The "recvfd" promise is no longer needed. */
	if (pledge("stdio sendfd unix", NULL) == -1)
		fatal("pledge");
#endif

	gotd_listen.nconnection_limits = isocket.nconnection_limits;
	gotd_listen.nconnection_limits_received = 0;

	if (gotd_listen.nconnection_limits > 0) {
		gotd_listen.connection_limits =
		    calloc(gotd_listen.nconnection_limits,
		        sizeof(gotd_listen.connection_limits[0]));
		if (gotd_listen.connection_limits == NULL)
			return got_error_from_errno("calloc");
	}

	return NULL;
}

static const struct got_error *
recv_connection_limit(struct imsg *imsg)
{
	struct gotd_uid_connection_limit *limit;
	size_t datalen, idx;

	if (gotd_listen.nconnection_limits == 0 ||
	    gotd_listen.nconnection_limits_received >=
	    gotd_listen.nconnection_limits)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(*limit))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	idx = gotd_listen.nconnection_limits_received;
	limit = &gotd_listen.connection_limits[idx];
	memcpy(limit, imsg->data, sizeof(*limit));
	gotd_listen.nconnection_limits_received++;

	return NULL;
}

static void
start_listening(void)
{
	struct gotd_imsgev *iev;

	iev = &gotd_listen.iev;
	if (imsgbuf_init(&iev->ibuf, gotd_listen.fd) == -1)
		fatal("imsgbuf_init");
	iev->handler = gotd_accept;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, gotd_listen.fd, EV_READ | EV_PERSIST,
	    gotd_accept, iev);
	if (event_add(&iev->ev, NULL))
		fatalx("event add");
	evtimer_set(&gotd_listen.pause_ev, gotd_accept_paused, NULL);

	log_debug("listening for client connections");
}

static const struct got_error *
recv_disconnect(struct imsg *imsg)
{
	struct gotd_imsg_disconnect idisconnect;
	size_t datalen;
	struct gotd_listen_client *client = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(idisconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&idisconnect, imsg->data, sizeof(idisconnect));

	log_debug("client disconnecting");

	client = find_client(idisconnect.client_id);
	if (client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	return disconnect(client);
}

static void
listen_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_LISTEN_SOCKET:
			err = recv_listen_socket(&imsg);
			if (err)
				break;
			if (gotd_listen.nconnection_limits == 0)
				start_listening();
			break;
		case GOTD_IMSG_CONNECTION_LIMIT:
			err = recv_connection_limit(&imsg);
			if (err)
				break;
			if (gotd_listen.nconnection_limits ==
			    gotd_listen.nconnection_limits_received)
				start_listening();
			break;
		case GOTD_IMSG_DISCONNECT:
			err = recv_disconnect(&imsg);
			if (err)
				log_warnx("disconnect: %s", err->msg);
			break;
		case GOTD_IMSG_HALT: {
			uint32_t reload_client_id;
			struct gotd_listen_client *client;

			event_del(&gotd_listen.iev.ev);
			evtimer_del(&gotd_listen.pause_ev);
			listener_halted = 1;
			log_debug("gotd reloading; stopped listening for "
			    "connections");

			if (imsg_get_data(&imsg, &reload_client_id,
			    sizeof(reload_client_id)) == -1) {
				err = got_error_from_errno("imsg-get_data");
				break;
			}
			client = find_client(reload_client_id);
			if (client)
				disconnect(client);
			break;
		}
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		if (!listener_halted)
			event_loopexit(NULL);
	}
}

void
listen_main(const char *title)
{
	struct gotd_imsgev *iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	clients_init();
	arc4random_buf(&uid_hash_key, sizeof(uid_hash_key));

	gotd_listen.title = title;
	gotd_listen.pid = getpid();
	gotd_listen.fd = -1;
	gotd_listen.connection_limits = NULL;
	gotd_listen.nconnection_limits = 0;
	gotd_listen.nconnection_limits_received = 0;

	signal_set(&evsigint, SIGINT, listen_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, listen_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, listen_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, listen_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	iev = &gotd_listen.parent_iev;
	if (imsgbuf_init(&iev->ibuf, GOTD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = listen_dispatch;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ, listen_dispatch, iev);

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_LISTENER_READY,
	    GOTD_PROC_GOTD, -1, NULL, 0) == -1)
		fatal("imsg compose LISTENER_READY");

	event_dispatch();

	listen_shutdown();
}

static void
listen_shutdown(void)
{
	log_debug("%s: shutting down", gotd_listen.title);

	free(gotd_listen.connection_limits);
	if (gotd_listen.fd != -1)
		close(gotd_listen.fd);

	exit(0);
}
