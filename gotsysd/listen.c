/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
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
#include "got_path.h"
#include "got_object.h"

#include "gotsysd.h"
#include "log.h"
#include "listen.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gotsysd_listen_client {
	STAILQ_ENTRY(gotsysd_listen_client)	 entry;
	uint32_t			 id;
	int				 fd;
	uid_t				 euid;
};
STAILQ_HEAD(gotsysd_listen_clients, gotsysd_listen_client);

static struct gotsysd_listen_clients
    gotsysd_listen_clients[GOTSYSD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
static volatile int listen_client_cnt;
static int inflight;

struct gotsysd_uid_connection_counter {
	STAILQ_ENTRY(gotsysd_uid_connection_counter) entry;
	uid_t euid;
	int nconnections;
};
STAILQ_HEAD(gotsysd_client_uids, gotsysd_uid_connection_counter);
static struct gotsysd_client_uids
    gotsysd_client_uids[GOTSYSD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY uid_hash_key;

static struct {
	pid_t pid;
	const char *title;
	int fd;
	struct gotsysd_imsgev iev;
	struct gotsysd_imsgev pause;
} gotsysd_listen;

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

	for (slot = 0; slot < nitems(gotsysd_listen_clients); slot++)
		STAILQ_INIT(&gotsysd_listen_clients[slot]);
}

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct gotsysd_listen_client *client)
{
	uint64_t slot = client_hash(client->id) %
	    nitems(gotsysd_listen_clients);
	STAILQ_INSERT_HEAD(&gotsysd_listen_clients[slot], client, entry);
	listen_client_cnt++;
}

static struct gotsysd_listen_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct gotsysd_listen_client *c;

	slot = client_hash(client_id) % nitems(gotsysd_listen_clients);
	STAILQ_FOREACH(c, &gotsysd_listen_clients[slot], entry) {
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
add_uid_connection_counter(struct gotsysd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotsysd_client_uids);
	STAILQ_INSERT_HEAD(&gotsysd_client_uids[slot], counter, entry);
}

static void
remove_uid_connection_counter(struct gotsysd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotsysd_client_uids);
	STAILQ_REMOVE(&gotsysd_client_uids[slot], counter,
	    gotsysd_uid_connection_counter, entry);
}

static struct gotsysd_uid_connection_counter *
find_uid_connection_counter(uid_t euid)
{
	uint64_t slot;
	struct gotsysd_uid_connection_counter *c;

	slot = uid_hash(euid) % nitems(gotsysd_client_uids);
	STAILQ_FOREACH(c, &gotsysd_client_uids[slot], entry) {
		if (c->euid == euid)
			return c;
	}

	return NULL;
}

static const struct got_error *
disconnect(struct gotsysd_listen_client *client)
{
	struct gotsysd_uid_connection_counter *counter;
	uint64_t slot;
	int client_fd;

	log_debug("client on fd %d disconnecting", client->fd);

	slot = client_hash(client->id) % nitems(gotsysd_listen_clients);
	STAILQ_REMOVE(&gotsysd_listen_clients[slot], client,
	    gotsysd_listen_client, entry);

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

	return NULL;
}

static int
accept_reserve(int fd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve +
	    ((*counter + 1) * GOTSYSD_FD_NEEDED) >= getdtablesize()) {
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
gotsysd_accept_paused(int fd, short event, void *arg)
{
	event_add(&gotsysd_listen.iev.ev, NULL);
}

static void
gotsysd_accept(int fd, short event, void *arg)
{
	struct gotsysd_imsgev *iev = arg;
	struct sockaddr_storage ss;
	struct timeval backoff;
	socklen_t len;
	int s = -1;
	struct gotsysd_listen_client *client = NULL;
	struct gotsysd_uid_connection_counter *counter = NULL;
	struct gotsysd_imsg_connect iconn;
	uid_t euid;
	gid_t egid;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (event_add(&gotsysd_listen.iev.ev, NULL) == -1) {
		log_warn("event_add");
		return;
	}
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	/* Other backoff conditions apart from EMFILE/ENFILE? */
	s = accept_reserve(fd, (struct sockaddr *)&ss, &len, GOTSYSD_FD_RESERVE,
	    &inflight);
	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&gotsysd_listen.iev.ev);
			evtimer_add(&gotsysd_listen.pause.ev, &backoff);
			return;
		default:
			log_warn("accept");
			return;
		}
	}

	if (listen_client_cnt >= GOTSYSD_MAXCLIENTS)
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
		if (counter->nconnections >= GOTSYSD_MAX_CONN_PER_UID) {
			log_warnx("maximum connections exceeded for uid %d",
			    euid);
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
	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_CONNECT,
	    GOTSYSD_PROC_LISTEN, s, &iconn, sizeof(iconn)) == -1) {
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
recv_disconnect(struct imsg *imsg)
{
	struct gotsysd_imsg_disconnect idisconnect;
	size_t datalen;
	struct gotsysd_listen_client *client = NULL;

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
	struct gotsysd_imsgev *iev = arg;
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
		err = gotsysd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_DISCONNECT:
			err = recv_disconnect(&imsg);
			if (err)
				log_warnx("disconnect: %s", err->msg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
listen_main(const char *title, int gotsysd_socket)
{
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	clients_init();
	arc4random_buf(&uid_hash_key, sizeof(uid_hash_key));

	gotsysd_listen.title = title;
	gotsysd_listen.pid = getpid();
	gotsysd_listen.fd = gotsysd_socket;

	signal_set(&evsigint, SIGINT, listen_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, listen_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, listen_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, listen_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev.ibuf);
	iev.handler = listen_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, listen_dispatch, &iev);
	if (event_add(&iev.ev, NULL) == -1)
		fatalx("event add");

	event_set(&gotsysd_listen.iev.ev, gotsysd_listen.fd,
	    EV_READ | EV_PERSIST, gotsysd_accept, &iev);
	if (event_add(&gotsysd_listen.iev.ev, NULL))
		fatalx("event add");
	evtimer_set(&gotsysd_listen.pause.ev, gotsysd_accept_paused, NULL);

	event_dispatch();

	listen_shutdown();
}

static void
listen_shutdown(void)
{
	log_debug("%s: shutting down", gotsysd_listen.title);

	if (gotsysd_listen.fd != -1)
		close(gotsysd_listen.fd);

	exit(0);
}
