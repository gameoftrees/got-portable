/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <siphash.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"
#include "tmpl.h"

#define SOCKS_BACKLOG 5
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))

static volatile int client_cnt;

static struct timeval	timeout = { TIMEOUT_DEFAULT, 0 };

static void	 sockets_sighdlr(int, short, void *);
static void	 sockets_shutdown(void);
static void	 sockets_launch(struct gotwebd *);

static void	 sockets_dispatch_main(int, short, void *);
static int	 sockets_unix_socket_listen(struct gotwebd *, struct socket *, uid_t, gid_t);
static int	 sockets_create_socket(struct address *);
static int	 sockets_accept_reserve(int, struct sockaddr *, socklen_t *,
		    int, volatile int *);

int cgi_inflight = 0;

/* Request hash table needs some spare room to avoid collisions. */
struct requestlist requests[GOTWEBD_MAXCLIENTS * 4];
static SIPHASH_KEY requests_hash_key;

static void
requests_init(void)
{
	int i;

	arc4random_buf(&requests_hash_key, sizeof(requests_hash_key));

	for (i = 0; i < nitems(requests); i++)
		TAILQ_INIT(&requests[i]);
}

static uint64_t
request_hash(uint32_t request_id)
{
	return SipHash24(&requests_hash_key, &request_id, sizeof(request_id));
}

static void
add_request(struct request *c)
{
	uint64_t slot = request_hash(c->request_id) % nitems(requests);
	TAILQ_INSERT_HEAD(&requests[slot], c, entry);
	client_cnt++;
}

static void
del_request(struct request *c)
{
	uint64_t slot = request_hash(c->request_id) % nitems(requests);
	TAILQ_REMOVE(&requests[slot], c, entry);
	client_cnt--;
}

static struct request *
find_request(uint32_t request_id)
{
	uint64_t slot;
	struct request *c;

	slot = request_hash(request_id) % nitems(requests);
	TAILQ_FOREACH(c, &requests[slot], entry) {
		if (c->request_id == request_id)
			return c;
	}

	return NULL;
}

static void
cleanup_request(struct request *c)
{
	struct gotwebd *env = gotwebd_env;

	cgi_inflight--;

	if (c->worker_idx != -1) {
		if (env->worker_load[c->worker_idx] <= 0)
			fatalx("request in flight on worker with zero load");
		env->worker_load[c->worker_idx]--;
	}

	del_request(c);

	event_add(&c->sock->ev, NULL);

	if (evtimer_initialized(&c->tmo))
		evtimer_del(&c->tmo);
	if (event_initialized(&c->ev))
		event_del(&c->ev);
	if (c->fd != -1)
		close(c->fd);
	free(c->buf);
	free(c);
}

static void
request_timeout(int fd, short events, void *arg)
{
	struct request *c = arg;

	log_warnx("request %u has timed out", c->request_id);
	cleanup_request(c);
}

static void
requests_purge(void)
{
	uint64_t slot;
	struct request *c;

	for (slot = 0; slot < nitems(requests); slot++) {
		while (!TAILQ_EMPTY(&requests[slot])) {
			c = TAILQ_FIRST(&requests[slot]);
			cleanup_request(c);
		}
	}
}

static uint32_t
get_request_id(void)
{
	int duplicate = 0;
	uint32_t id;

	do {
		id = arc4random();
		duplicate = (find_request(id) != NULL);
	} while (duplicate || id == 0);

	return id;
}

static void
request_done(struct request *c)
{
	/*
	 * If we have not yet handed the client off to gotweb.c we
	 * must send an FCGI end record ourselves.
	 */
	if (c->client_status < CLIENT_REQUEST)
		fcgi_create_end_record(c);

	cleanup_request(c);
}

void
sockets(struct gotwebd *env, int fd)
{
	struct event	 sighup, sigint, sigusr1, sigchld, sigterm;
	struct event_base *evb;

	requests_init();

	evb = event_init();

	sockets_rlimit(-1);

	env->iev_parent = calloc(1, sizeof(*env->iev_parent));
	if (env->iev_parent == NULL)
		fatal("calloc");
	if (imsgbuf_init(&env->iev_parent->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&env->iev_parent->ibuf);
	env->iev_parent->handler = sockets_dispatch_main;
	env->iev_parent->data = env->iev_parent;
	event_set(&env->iev_parent->ev, fd, EV_READ, sockets_dispatch_main,
	    env->iev_parent);
	event_add(&env->iev_parent->ev, NULL);

	if (env->prefork <= 0)
		fatalx("invalid prefork count: %d", env->prefork);
	env->iev_auth = calloc(env->prefork, sizeof(*env->iev_auth));
	if (env->iev_auth == NULL)
		fatal("calloc");
	env->auth_pending = env->prefork;

	signal(SIGPIPE, SIG_IGN);

	signal_set(&sighup, SIGHUP, sockets_sighdlr, env);
	signal_add(&sighup, NULL);
	signal_set(&sigint, SIGINT, sockets_sighdlr, env);
	signal_add(&sigint, NULL);
	signal_set(&sigusr1, SIGUSR1, sockets_sighdlr, env);
	signal_add(&sigusr1, NULL);
	signal_set(&sigchld, SIGCHLD, sockets_sighdlr, env);
	signal_add(&sigchld, NULL);
	signal_set(&sigterm, SIGTERM, sockets_sighdlr, env);
	signal_add(&sigterm, NULL);

#ifndef PROFILE
	if (pledge("stdio inet unix recvfd sendfd", NULL) == -1)
		fatal("pledge");
#endif

	event_dispatch();
	event_base_free(evb);
	sockets_shutdown();
}

void
sockets_parse_sockets(struct gotwebd *env)
{
	struct address *a;
	struct socket *new_sock = NULL;
	int sock_id = 1;

	TAILQ_FOREACH(a, &env->addresses, entry) {
		new_sock = sockets_conf_new_socket(sock_id, a);
		if (new_sock) {
			sock_id++;
			TAILQ_INSERT_TAIL(&env->sockets,
			    new_sock, entry);
		}
	}
}

struct socket *
sockets_conf_new_socket(int id, struct address *a)
{
	struct socket *sock;
	struct address *acp;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatalx("%s: calloc", __func__);

	sock->conf.id = id;
	sock->fd = -1;
	sock->conf.af_type = a->ss.ss_family;

	if (a->ss.ss_family == AF_UNIX) {
		struct sockaddr_un *sun;

		sun = (struct sockaddr_un *)&a->ss;
		if (strlcpy(sock->conf.unix_socket_name, sun->sun_path,
		    sizeof(sock->conf.unix_socket_name)) >=
		    sizeof(sock->conf.unix_socket_name))
			fatalx("unix socket path too long: %s", sun->sun_path);
	}

	sock->conf.fcgi_socket_port = a->port;

	acp = &sock->conf.addr;

	memcpy(&acp->ss, &a->ss, sizeof(acp->ss));
	acp->slen = a->slen;
	acp->ai_family = a->ai_family;
	acp->ai_socktype = a->ai_socktype;
	acp->ai_protocol = a->ai_protocol;
	acp->port = a->port;
	if (*a->ifname != '\0') {
		if (strlcpy(acp->ifname, a->ifname,
		    sizeof(acp->ifname)) >= sizeof(acp->ifname)) {
			fatalx("%s: interface name truncated",
			    __func__);
		}
	}

	return (sock);
}

static void
sockets_launch(struct gotwebd *env)
{
	struct socket *sock;
	const char *sockname;
	int i, have_unix = 0, have_inet = 0;

	if (env->iev_fcgi == NULL)
		fatalx("fcgi process not connected");
	if (env->auth_pending != 0)
		fatal("auth process not connected");

	TAILQ_FOREACH(sock, &gotwebd_env->sockets, entry) {
		if (sock->conf.af_type == AF_UNIX) {
			have_unix = 1;
			sockname = sock->conf.unix_socket_name;
		} else {
			have_inet = 1;
			sockname = sock->conf.addr.ifname;
		}

		log_info("%s: configuring socket %s %d (%d)", __func__,
		    sockname, sock->conf.id, sock->fd);

		if (listen(sock->fd, SOCKS_BACKLOG) == -1)
			fatal("cannot listen on %s", sockname);

		event_set(&sock->ev, sock->fd, EV_READ | EV_PERSIST,
		    sockets_socket_accept, sock);

		if (event_add(&sock->ev, NULL))
			fatalx("event add sock");

		evtimer_set(&sock->pause, sockets_socket_accept, sock);

		log_info("%s: running socket listener %d", __func__,
		    sock->conf.id);
	}

#ifndef PROFILE
	if (have_unix && have_inet) {
		if (pledge("stdio inet unix sendfd", NULL) == -1)
			fatal("pledge");
	} else if (have_unix) {
		if (pledge("stdio unix sendfd", NULL) == -1)
			fatal("pledge");
	} else if (have_inet) {
		if (pledge("stdio inet sendfd", NULL) == -1)
			fatal("pledge");
	}
#endif
	event_add(&env->iev_fcgi->ev, NULL);
	for (i = 0; i < env->prefork; i++)
		event_add(&env->iev_auth[i].ev, NULL);
}

static void
abort_request(struct imsg *imsg)
{
	struct request *c;
	uint32_t request_id;

	if (imsg_get_data(imsg, &request_id, sizeof(request_id)) == -1) {
		log_warn("imsg_get_data");
		return;
	}

	c = find_request(request_id);
	if (c == NULL)
		return;

	request_done(c);
}

static void
server_dispatch_auth(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1)
			fatal("imsgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTWEBD_IMSG_REQ_ABORT:
			abort_request(&imsg);
			break;
		default:
			fatalx("%s: unknown imsg type %d", __func__,
			    imsg.hdr.type);
		}

		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static void
recv_auth_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->auth_pending <= 0) {
		log_warn("all auth pipes already received");
		return;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid auth pipe fd");

	iev = &env->iev_auth[env->auth_pending - 1];
	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	imsgbuf_set_maxsize(&iev->ibuf, sizeof(struct request));

	iev->handler = server_dispatch_auth;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, server_dispatch_auth, iev);
	imsg_event_add(iev);

	env->auth_pending--;
}

static struct imsgev *
select_worker(struct request *c)
{
	struct gotwebd *env = gotwebd_env;
	int i, least_busy_worker_idx, min_load;

	min_load = env->worker_load[0];
	least_busy_worker_idx = 0;
	for (i = 1; i < env->prefork; i++) {
		if (env->worker_load[i] > min_load) 
			continue;

		min_load = env->worker_load[i];
		least_busy_worker_idx = i;
	}

	log_debug("dispatching request %u to gotweb %d",
	    c->request_id, least_busy_worker_idx);

	c->worker_idx = least_busy_worker_idx;
	return &env->iev_auth[least_busy_worker_idx];
}

static int
process_request(struct request *c)
{
	struct gotwebd *env = gotwebd_env;
	struct gotwebd_fcgi_params *params = &c->fcgi_params;
	struct querystring *qs = &params->qs;
	struct imsgev *iev_auth;
	int ret, i;
	struct request ic;

	/* Fill in defaults for unspecified parameters where needed. */
	if (qs->action == NO_ACTION)
		qs->action = INDEX;
	if (qs->index_page == -1)
		qs->index_page = 0;
	if (qs->headref[0] == '\0') {
		if (strlcpy(qs->headref, GOT_REF_HEAD, sizeof(qs->headref)) >=
		    sizeof(qs->headref)) {
			log_warnx("head reference buffer too small");
			return -1;
		}
	}
	if (params->server_name[0] == '\0') {
		struct server *srv = TAILQ_FIRST(&env->servers);

		if (strlcpy(params->server_name, srv->name,
		    sizeof(params->server_name)) >=
		    sizeof(params->server_name)) {
			log_warnx("server name buffer too small");
			return -1;
		}
	}

	memcpy(&ic, c, sizeof(ic));

	/* Don't leak pointers from our address space to another process. */
	ic.sock = NULL;
	ic.srv = NULL;
	ic.t = NULL;
	ic.tp = NULL;
	ic.buf = NULL;
	ic.outbuf = NULL;

	/* Other process will use its own set of temp files. */
	for (i = 0; i < nitems(c->priv_fd); i++)
		ic.priv_fd[i] = -1;
	ic.fd = -1;

	iev_auth = select_worker(c);
	ret = imsg_compose_event(iev_auth, GOTWEBD_IMSG_REQ_PROCESS,
	    GOTWEBD_PROC_SOCKETS, -1, c->fd, &ic, sizeof(ic));
	if (ret == -1) {
		log_warn("imsg_compose_event");
		c->worker_idx = -1;
		return -1;
	}

	c->fd = -1;
	event_del(&c->ev);
	c->client_status = CLIENT_REQUEST;
	env->worker_load[c->worker_idx]++;
	return 0;
}

static void
recv_parsed_params(struct imsg *imsg)
{
	struct gotwebd_fcgi_params params, *p;
	struct request *c;

	if (imsg_get_data(imsg, &params, sizeof(params)) == -1) {
		log_warn("imsg_get_data");
		return;
	}

	c = find_request(params.request_id);
	if (c == NULL)
		return;

	if (c->client_status > CLIENT_FCGI_STDIN)
		return;

	if (c->client_status < CLIENT_FCGI_PARAMS)
		goto fail;

	p = &c->fcgi_params;

	if (params.qs.action != NO_ACTION)
		p->qs.action = params.qs.action;

	if (params.qs.commit[0] &&
	    strlcpy(p->qs.commit, params.qs.commit,
	    sizeof(p->qs.commit)) >= sizeof(p->qs.commit)) {
		log_warnx("commit ID too long");
		goto fail;
	}

	if (params.qs.file[0] &&
	    strlcpy(p->qs.file, params.qs.file,
	    sizeof(p->qs.file)) >= sizeof(p->qs.file)) {
		log_warnx("file path too long");
		goto fail;
	}

	if (params.qs.folder[0] &&
	    strlcpy(p->qs.folder, params.qs.folder,
	    sizeof(p->qs.folder)) >= sizeof(p->qs.folder)) {
		log_warnx("folder path too long");
		goto fail;
	}

	if (params.qs.headref[0] &&
	    strlcpy(p->qs.headref, params.qs.headref,
	    sizeof(p->qs.headref)) >= sizeof(p->qs.headref)) {
		log_warnx("headref too long");
		goto fail;
	}

	if (params.qs.index_page != -1)
		p->qs.index_page = params.qs.index_page;

	if (params.qs.path[0] &&
	    strlcpy(p->qs.path, params.qs.path,
	    sizeof(p->qs.path)) >= sizeof(p->qs.path)) {
		log_warnx("path path too long");
		goto fail;
	}

	if (params.qs.login[0] != '\0' &&
	    strlcpy(p->qs.login, params.qs.login,
	    sizeof(p->qs.login)) >= sizeof(p->qs.login)) {
		log_warnx("login token too long");
		goto fail;
	}

	if (params.document_uri[0] != '\0' &&
	    strlcpy(p->document_uri, params.document_uri,
	    sizeof(p->document_uri)) >= sizeof(p->document_uri)) {
		log_warnx("document uri too long");
		goto fail;
	}

	if (params.server_name[0] != '\0' &&
	    strlcpy(p->server_name, params.server_name,
	    sizeof(p->server_name)) >= sizeof(p->server_name)) {
		log_warnx("server name too long");
		goto fail;
	}

	if (params.auth_cookie[0] != '\0' &&
	    strlcpy(p->auth_cookie, params.auth_cookie,
	    sizeof(p->auth_cookie)) >= sizeof(p->auth_cookie)) {
		log_warnx("auth cookie too long");
		goto fail;
	}

	if (params.https && !p->https)
		p->https = 1;

	c->nparams_parsed++;

	if (c->client_status == CLIENT_FCGI_STDIN &&
	    c->nparams_parsed >= c->nparams) {
		if (process_request(c) == -1)
			goto fail;
	}

	return;
fail:
	request_done(c);
}

static void
server_dispatch_fcgi(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1)
			fatal("imsgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTWEBD_IMSG_FCGI_PARAMS:
			recv_parsed_params(&imsg);
			break;
		case GOTWEBD_IMSG_REQ_ABORT:
			abort_request(&imsg);
			break;
		default:
			fatalx("%s: unknown imsg type %d", __func__,
			    imsg.hdr.type);
		}

		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static void
recv_fcgi_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->iev_fcgi != NULL) {
		log_warn("fcgi pipe already received");
		return;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid fcgi pipe fd");

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	imsgbuf_set_maxsize(&iev->ibuf, sizeof(struct gotwebd_fcgi_record));

	iev->handler = server_dispatch_fcgi;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, server_dispatch_fcgi, iev);
	imsg_event_add(iev);

	env->iev_fcgi = iev;
}

static void
sockets_dispatch_main(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct gotwebd		*env = gotwebd_env;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1)
			fatal("imsgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTWEBD_IMSG_CFG_SRV:
			config_getserver(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_SOCK:
			config_getsock(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_DONE:
			config_getcfg(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_PIPE:
			if (env->iev_fcgi == NULL)
				recv_fcgi_pipe(env, &imsg);
			else
				recv_auth_pipe(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_START:
			sockets_launch(env);
			break;
		default:
			fatalx("%s: unknown imsg type %d", __func__,
			    imsg.hdr.type);
		}

		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static void
sockets_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGCHLD:
		break;
	case SIGINT:
	case SIGTERM:
		sockets_shutdown();
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static void
sockets_shutdown(void)
{
	int i;

	requests_purge();

	/* clean servers */
	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);
		free(srv);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->addresses)) {
		struct address *h;

		h = TAILQ_FIRST(&gotwebd_env->addresses);
		TAILQ_REMOVE(&gotwebd_env->addresses, h, entry);
		free(h);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->sockets)) {
		struct socket *sock;

		sock = TAILQ_FIRST(&gotwebd_env->sockets);
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		free(sock);
	}

	imsgbuf_clear(&gotwebd_env->iev_parent->ibuf);
	free(gotwebd_env->iev_parent);

	imsgbuf_clear(&gotwebd_env->iev_fcgi->ibuf);
	free(gotwebd_env->iev_fcgi);

	for (i = 0; i < gotwebd_env->prefork; i++)
		imsgbuf_clear(&gotwebd_env->iev_auth[i].ibuf);
	free(gotwebd_env->iev_auth);
	free(gotwebd_env->worker_load);
	free(gotwebd_env);

	exit(0);
}

int
sockets_privinit(struct gotwebd *env, struct socket *sock, uid_t uid, gid_t gid)
{
	if (sock->conf.af_type == AF_UNIX) {
		log_info("%s: initializing unix socket %s", __func__,
		    sock->conf.unix_socket_name);
		sock->fd = sockets_unix_socket_listen(env, sock, uid, gid);
		if (sock->fd == -1)
			return -1;
	}

	if (sock->conf.af_type == AF_INET || sock->conf.af_type == AF_INET6) {
		log_info("%s: initializing %s FCGI socket on port %d",
		    __func__, sock->conf.af_type == AF_INET ? "inet" : "inet6",
		    sock->conf.fcgi_socket_port);
		sock->fd = sockets_create_socket(&sock->conf.addr);
		if (sock->fd == -1)
			return -1;
	}

	return 0;
}

static int
sockets_unix_socket_listen(struct gotwebd *env, struct socket *sock,
    uid_t uid, gid_t gid)
{
	int u_fd = -1;
	mode_t old_umask, mode;

	u_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK| SOCK_CLOEXEC, 0);
	if (u_fd == -1) {
		log_warn("%s: socket", __func__);
		return -1;
	}

	if (unlink(sock->conf.unix_socket_name) == -1) {
		if (errno != ENOENT) {
			log_warn("%s: unlink %s", __func__,
			    sock->conf.unix_socket_name);
			close(u_fd);
			return -1;
		}
	}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP;

	if (bind(u_fd, (struct sockaddr *)&sock->conf.addr.ss,
	    sock->conf.addr.slen) == -1) {
		log_warn("%s: bind: %s", __func__, sock->conf.unix_socket_name);
		close(u_fd);
		(void)umask(old_umask);
		return -1;
	}

	(void)umask(old_umask);

	if (chmod(sock->conf.unix_socket_name, mode) == -1) {
		log_warn("%s: chmod", __func__);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	if (chown(sock->conf.unix_socket_name, uid, gid) == -1) {
		log_warn("%s: chown", __func__);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	return u_fd;
}

static int
sockets_create_socket(struct address *a)
{
	int fd = -1, o_val = 1, flags;

	fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd == -1)
		return -1;

	log_debug("%s: opened socket (%d) for %s", __func__,
	    fd, a->ifname);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o_val,
	    sizeof(int)) == -1) {
		log_warn("%s: setsockopt error", __func__);
		close(fd);
		return -1;
	}

	/* non-blocking */
	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		log_warn("%s: could not enable non-blocking I/O", __func__);
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&a->ss, a->slen) == -1) {
		close(fd);
		log_warn("%s: can't bind to port %d", __func__, a->port);
		return -1;
	}

	return (fd);
}

static int
sockets_accept_reserve(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve + *counter + 1 >= getdtablesize()) {
		log_warnx("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}

	if ((ret = accept4(sockfd, addr, addrlen,
	    SOCK_NONBLOCK | SOCK_CLOEXEC)) > -1) {
		(*counter)++;
		log_debug("inflight incremented, now %d", *counter);
	}

	return ret;
}

static int
parse_params(struct request *c, uint8_t *record, size_t record_len)
{
	struct gotwebd *env = gotwebd_env;
	struct gotwebd_fcgi_record rec;
	int ret;

	memset(&rec, 0, sizeof(rec));

	memcpy(rec.record, record, record_len);
	rec.record_len = record_len;
	rec.request_id = c->request_id;

	ret = imsg_compose_event(env->iev_fcgi,
	    GOTWEBD_IMSG_FCGI_PARSE_PARAMS,
	    GOTWEBD_PROC_SOCKETS, -1, -1, &rec, sizeof(rec));
	if (ret == -1)
		log_warn("imsg_compose_event");

	return ret;
}

static void
read_fcgi_records(int fd, short events, void *arg)
{
	struct request *c = arg;
	ssize_t n;
	struct fcgi_record_header h;
	size_t record_len;

	n = read(fd, c->buf + c->buf_len, FCGI_RECORD_SIZE - c->buf_len);

	switch (n) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			goto more;
		default:
			goto fail;
		}
		break;
	case 0:
		if (c->client_status < CLIENT_FCGI_STDIN) {
			log_warnx("client %u closed connection too early",
			    c->request_id);
			goto fail;
		}
		return;
	default:
		break;
	}

	c->buf_len += n;

	while (c->buf_len >= sizeof(h)) {
		memcpy(&h, c->buf, sizeof(h));

		record_len = sizeof(h) + ntohs(h.content_len) + h.padding_len;
		if (record_len > FCGI_RECORD_SIZE) {
			log_warnx("FGI record length too large");
			goto fail;
		}

		if (c->buf_len < record_len)
			goto more;

		switch (h.type) {
		case FCGI_BEGIN_REQUEST:
			if (c->client_status >= CLIENT_FCGI_BEGIN) {
				log_warnx("unexpected FCGI_BEGIN_REQUEST");
				goto fail;
			}

			if (ntohs(h.content_len) !=
			    sizeof(struct fcgi_begin_request_body)) {
				log_warnx("wrong begin request size %u != %zu",
				    ntohs(h.content_len),
				    sizeof(struct fcgi_begin_request_body));
				goto fail;
			}

			/* XXX -- FCGI_CANT_MPX_CONN */
			c->client_status = CLIENT_FCGI_BEGIN;
			c->id = ntohs(h.id);
			break;
		case FCGI_PARAMS:
			if (c->client_status < CLIENT_FCGI_BEGIN) {
				log_warnx("FCGI_PARAMS without "
				    "FCGI_BEGIN_REQUEST");
				goto fail;
			}
			if (c->client_status > CLIENT_FCGI_PARAMS) {
				log_warnx("FCGI_PARAMS after FCGI_STDIN");
				goto fail;
			}

			if (c->id != ntohs(h.id)) {
				log_warnx("unexpected ID in FCGI header");
				goto fail;
			}

			c->client_status = CLIENT_FCGI_PARAMS;
			c->nparams++;

			if (parse_params(c, c->buf, record_len) == -1)
				goto fail;
			break;
		case FCGI_ABORT_REQUEST:
			log_warnx("received FCGI_ABORT_REQUEST from client");
			request_done(c);
			return;
		case FCGI_STDIN:
			if (c->client_status < CLIENT_FCGI_BEGIN) {
				log_warnx("FCGI_STDIN without "
				    "FCGI_BEGIN_REQUEST");
				goto fail;
			}

			if (c->client_status < CLIENT_FCGI_PARAMS) {
				log_warnx("FCGI_STDIN without FCGI_PARAMS");
				goto fail;
			}

			if (c->id != ntohs(h.id)) {
				log_warnx("unexpected ID in FCGI header");
				goto fail;
			}

			c->client_status = CLIENT_FCGI_STDIN;
			if (c->nparams_parsed >= c->nparams) {
				if (process_request(c) == -1)
					goto fail;
			}
			break;
		default:
			log_warn("unexpected FCGI type %u", h.type);
			goto fail;
		}

		/* drop the parsed record */
		c->buf_len -= record_len;
		memmove(c->buf, c->buf + record_len, c->buf_len);
	}
more:
	if (c->client_status < CLIENT_REQUEST)
		event_add(&c->ev, NULL);
	return;
fail:
	request_done(c);
}

void
sockets_socket_accept(int fd, short event, void *arg)
{
	struct socket *sock = (struct socket *)arg;
	struct sockaddr_storage ss;
	struct timeval backoff;
	struct request *c = NULL;
	uint8_t *buf = NULL;
	socklen_t len;
	int s;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (event & EV_TIMEOUT) {
		event_add(&sock->ev, NULL);
		return;
	}

	len = sizeof(ss);

	s = sockets_accept_reserve(fd, (struct sockaddr *)&ss, &len,
	    FD_RESERVE, &cgi_inflight);

	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			event_add(&sock->ev, NULL);
			return;
		case EMFILE:
		case ENFILE:
			log_warn("accept");
			event_del(&sock->ev);
			evtimer_add(&sock->pause, &backoff);
			return;
		default:
			log_warn("%s: accept", __func__);
		}
	}

	if (client_cnt > GOTWEBD_MAXCLIENTS) {
		cgi_inflight--;
		close(s);
		if (c != NULL)
			free(c);
		event_add(&sock->ev, NULL);
		return;
	}

	c = calloc(1, sizeof(struct request));
	if (c == NULL) {
		log_warn("%s: calloc", __func__);
		close(s);
		cgi_inflight--;
		event_add(&sock->ev, NULL);
		return;
	}

	buf = calloc(1, FCGI_RECORD_SIZE);
	if (buf == NULL) {
		log_warn("%s: calloc", __func__);
		close(s);
		cgi_inflight--;
		free(c);
		event_add(&sock->ev, NULL);
		return;
	}

	fcgi_init_querystring(&c->fcgi_params.qs);
	c->buf = buf;
	c->fd = s;
	c->sock = sock;
	memcpy(c->priv_fd, gotwebd_env->priv_fd, sizeof(c->priv_fd));
	c->sock_id = sock->conf.id;
	c->buf_len = 0;
	c->client_status = CLIENT_CONNECT;
	c->request_id = get_request_id();
	c->worker_idx = -1;

	event_set(&c->ev, s, EV_READ, read_fcgi_records, c);
	event_add(&c->ev, NULL);

	evtimer_set(&c->tmo, request_timeout, c);
	evtimer_add(&c->tmo, &timeout);

	add_request(c);
}

void
sockets_rlimit(int maxfd)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to get resource limit", __func__);
	log_info("%s: max open files %llu", __func__,
	    (unsigned long long)rl.rlim_max);

	/*
	 * Allow the maximum number of open file descriptors for this
	 * login class (which should be the class "daemon" by default).
	 */
	if (maxfd == -1)
		rl.rlim_cur = rl.rlim_max;
	else
		rl.rlim_cur = MAXIMUM(rl.rlim_max, (rlim_t)maxfd);
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to set resource limit", __func__);
}
