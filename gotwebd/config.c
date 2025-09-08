/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <event.h>
#include <fcntl.h>
#include <util.h>
#include <errno.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>

#include "got_opentemp.h"
#include "got_reference.h"
#include "got_object.h"

#include "gotwebd.h"
#include "log.h"

int
config_init(struct gotwebd *env)
{
	int i;

	strlcpy(env->httpd_chroot, D_HTTPD_CHROOT, sizeof(env->httpd_chroot));

	env->prefork = GOTWEBD_NUMPROC;
	TAILQ_INIT(&env->servers);
	TAILQ_INIT(&env->sockets);
	TAILQ_INIT(&env->addresses);

	for (i = 0; i < PRIV_FDS__MAX; i++)
		env->priv_fd[i] = -1;

	for (i = 0; i < GOTWEB_PACK_NUM_TEMPFILES; i++)
		env->pack_fds[i] = -1;

	return 0;
}

int
config_getcfg(struct gotwebd *env, struct imsg *imsg)
{
	/* nothing to do but tell gotwebd configuration is done */
	if (sockets_compose_main(env, GOTWEBD_IMSG_CFG_DONE, NULL, 0) == -1)
		fatal("sockets_compose_main GOTWEBD_IMSG_CFG_DONE");
	return 0;
}

int
config_getserver(struct gotwebd *env, struct imsg *imsg)
{
	struct server *srv;
	uint8_t *p = imsg->data;

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		fatalx("%s: calloc", __func__);

	if (IMSG_DATA_SIZE(imsg) != sizeof(*srv))
		fatalx("%s: wrong size", __func__);

	memcpy(srv, p, sizeof(*srv));

	/* log server info */
	log_debug("%s: server=%s", __func__, srv->name);

	TAILQ_INSERT_TAIL(&env->servers, srv, entry);

	return 0;
}

int
config_setsock(struct gotwebd *env, struct socket *sock, uid_t uid, gid_t gid)
{
	/* open listening sockets */
	if (sockets_privinit(env, sock, uid, gid) == -1)
		return -1;

	if (main_compose_sockets(env, GOTWEBD_IMSG_CFG_SOCK, sock->fd,
	    &sock->conf, sizeof(sock->conf)) == -1)
		fatal("main_compose_sockets GOTWEBD_IMSG_CFG_SOCK");

	if (main_compose_gotweb(env, GOTWEBD_IMSG_CFG_SOCK, sock->fd,
	    &sock->conf, sizeof(sock->conf)) == -1)
		fatal("main_compose_gotweb GOTWEBD_IMSG_CFG_SOCK");

	return 0;
}

int
config_getsock(struct gotwebd *env, struct imsg *imsg)
{
	struct socket *sock = NULL;
	struct socket_conf sock_conf;
	uint8_t *p = imsg->data;

	if (IMSG_DATA_SIZE(imsg) != sizeof(sock_conf))
		fatalx("%s: wrong size", __func__);

	memcpy(&sock_conf, p, sizeof(sock_conf));

	if (IMSG_DATA_SIZE(imsg) != sizeof(sock_conf)) {
		log_warnx("%s: imsg size error", __func__);
		return 1;
	}

	/* create a new socket */
	if ((sock = calloc(1, sizeof(*sock))) == NULL) {
		return 1;
	}

	memcpy(&sock->conf, &sock_conf, sizeof(sock->conf));
	sock->fd = imsg_get_fd(imsg);

	TAILQ_INSERT_TAIL(&env->sockets, sock, entry);

	/* log new socket info */
	log_debug("%s: id=%d af_type=%s socket_path=%s",
	    __func__, sock->conf.id,
	    sock->conf.af_type == AF_UNIX ? "unix" :
	    (sock->conf.af_type == AF_INET ? "inet" :
	    (sock->conf.af_type == AF_INET6 ? "inet6" : "unknown")),
	    *sock->conf.unix_socket_name != '\0' ?
	    sock->conf.unix_socket_name : "none");

	return 0;
}

int
config_setfd(struct gotwebd *env)
{
	int i, j, fd;

	log_info("%s: Allocating %d file descriptors",
	    __func__, PRIV_FDS__MAX + GOTWEB_PACK_NUM_TEMPFILES);

	for (i = 0; i < PRIV_FDS__MAX + GOTWEB_PACK_NUM_TEMPFILES; i++) {
		for (j = 0; j < env->prefork; j++) {
			fd = got_opentempfd();
			if (fd == -1)
				fatal("got_opentemp");
			if (imsg_compose_event(&env->iev_gotweb[j],
			    GOTWEBD_IMSG_CFG_FD, 0, -1, fd, NULL, 0) == -1)
				fatal("imsg_compose_event GOTWEBD_IMSG_CFG_FD");

			if (imsgbuf_flush(&env->iev_gotweb[j].ibuf) == -1)
				fatal("imsgbuf_flush");
			imsg_event_add(&env->iev_gotweb[j]);
		}
	}

	return 0;
}

int
config_getfd(struct gotwebd *env, struct imsg *imsg)
{
	int i;

	if (imsg_get_len(imsg) != 0)
		fatalx("%s: wrong size", __func__);

	for (i = 0; i < nitems(env->priv_fd); ++i) {
		if (env->priv_fd[i] == -1) {
			env->priv_fd[i] = imsg_get_fd(imsg);
			log_debug("%s: assigning priv_fd %d",
			    __func__, env->priv_fd[i]);
			return 0;
		}
	}

	for (i = 0; i < nitems(env->pack_fds); ++i) {
		if (env->pack_fds[i] == -1) {
			env->pack_fds[i] = imsg_get_fd(imsg);
			log_debug("%s: assigning pack_fd %d",
			    __func__, env->pack_fds[i]);
			return 0;
		}
	}

	return 1;
}
