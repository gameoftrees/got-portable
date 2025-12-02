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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
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
#include <errno.h>
#include <imsg.h>

#include "got_opentemp.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"
#include "got_error.h"

#include "gotwebd.h"
#include "log.h"

int
config_init(struct gotwebd *env)
{
	int i;

	strlcpy(env->httpd_chroot, D_HTTPD_CHROOT, sizeof(env->httpd_chroot));
	strlcpy(env->htdocs_path, D_HTDOCS_PATH, sizeof(env->htdocs_path));
	strlcpy(env->gotweb_url_root, "/", sizeof(env->gotweb_url_root));

	env->prefork = GOTWEBD_NUMPROC;
	TAILQ_INIT(&env->servers);
	TAILQ_INIT(&env->sockets);
	TAILQ_INIT(&env->addresses);
	STAILQ_INIT(&env->access_rules);

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
		fatal("sockets_compose_main IMSG_CFG_DONE");
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
	STAILQ_INIT(&srv->access_rules);
	TAILQ_INIT(&srv->repos);
	RB_INIT(&srv->websites);

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
		fatal("main_compose_sockets IMSG_CFG_SOCK");

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

void
config_set_access_rules(struct imsgev *iev,
    struct gotwebd_access_rule_list *rules)
{
	struct gotwebd_access_rule *rule;

	STAILQ_FOREACH(rule, rules, entry) {
		if (imsg_compose_event(iev, GOTWEBD_IMSG_CFG_ACCESS_RULE,
		    0, -1, -1, rule, sizeof(*rule)) == -1)
			fatal("imsg_compose_event "
			    "GOTWEBD_IMSG_CFG_ACCESS_RULE");
	}
}

void
config_get_access_rule(struct gotwebd_access_rule_list *rules,
    struct imsg *imsg)
{
	struct gotwebd_access_rule *rule;
	size_t len;

	rule = calloc(1, sizeof(*rule));
	if (rule == NULL)
		fatal("malloc");

	if (imsg_get_data(imsg, rule, sizeof(*rule)))
		fatalx("%s: invalid CFG_ACCESS_RULE message", __func__);
	
	switch (rule->access) {
	case GOTWEBD_ACCESS_DENIED:
	case GOTWEBD_ACCESS_PERMITTED:
		break;
	default:
		fatalx("%s: invalid CFG_ACCESS_RULE message", __func__);
	}

	len = strnlen(rule->identifier, sizeof(rule->identifier));
	if (len == 0 || len >= sizeof(rule->identifier))
		fatalx("%s: invalid CFG_ACCESS_RULE message", __func__);

	STAILQ_INSERT_TAIL(rules, rule, entry);
}

void
config_free_access_rules(struct gotwebd_access_rule_list *rules)
{
	struct gotwebd_access_rule *rule;

	while (!STAILQ_EMPTY(rules)) {
		rule = STAILQ_FIRST(rules);
		STAILQ_REMOVE(rules, rule, gotwebd_access_rule, entry);
		free(rule);
	}
}

void
config_free_repos(struct gotwebd_repolist *repos)
{
	struct gotwebd_repo *repo;

	while (!TAILQ_EMPTY(repos)) {
		repo = TAILQ_FIRST(repos);
		TAILQ_REMOVE(repos, repo, entry);
		config_free_access_rules(&repo->access_rules);
		free(repo);
	}
}

void
config_set_repository(struct imsgev *iev, struct gotwebd_repo *repo)
{
	if (imsg_compose_event(iev,
	    GOTWEBD_IMSG_CFG_REPO, 0, -1, -1, repo, sizeof(*repo)) == -1)
		fatal("imsg_compose_event GOTWEBD_IMSG_CFG_REPO");
}

void
config_get_repository(struct gotwebd_repolist *repos, struct imsg *imsg)
{
	struct gotwebd_repo *repo;
	size_t len;

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		fatal("malloc");

	if (imsg_get_data(imsg, repo, sizeof(*repo)))
		fatalx("%s: invalid CFG_REPO message", __func__);
	
	switch (repo->auth_config) {
	case GOTWEBD_AUTH_DISABLED:
	case GOTWEBD_AUTH_SECURE:
	case GOTWEBD_AUTH_INSECURE:
		break;
	default:
		fatalx("%s: invalid CFG_REPO message", __func__);
	}

	len = strnlen(repo->name, sizeof(repo->name));
	if (len == 0 || len >= sizeof(repo->name))
		fatalx("%s: invalid CFG_REPO message", __func__);

	if (strchr(repo->name, '/') != NULL) {
		fatalx("repository names must not contain slashes: %s",
		    repo->name);
	}

	if (strchr(repo->name, '\n') != NULL) {
		fatalx("repository names must not contain linefeeds: %s",
		    repo->name);
	}

	STAILQ_INIT(&repo->access_rules);

	TAILQ_INSERT_TAIL(repos, repo, entry);
}

void
config_free_websites(struct got_pathlist_head *websites)
{
	got_pathlist_free(websites, GOT_PATHLIST_FREE_DATA);
}

void
config_set_website(struct imsgev *iev, struct website *website)
{
	if (imsg_compose_event(iev,
	    GOTWEBD_IMSG_CFG_WEBSITE, 0, -1, -1,
	    website, sizeof(*website)) == -1)
		fatal("imsg_compose_event GOTWEBD_IMSG_CFG_WEBSITE");
}

void
config_get_website(struct got_pathlist_head *websites, struct imsg *imsg)
{
	const struct got_error *error;
	struct website *site;
	struct got_pathlist_entry *new;
	size_t len;

	site = calloc(1, sizeof(*site));
	if (site == NULL)
		fatal("malloc");

	if (imsg_get_data(imsg, site, sizeof(*site)))
		fatalx("%s: invalid CFG_WEBSITE message", __func__);
	
	len = strnlen(site->repo_name, sizeof(site->repo_name));
	if (len == 0 || len >= sizeof(site->repo_name))
		fatalx("%s: invalid CFG_WEBSITE message", __func__);

	if (strchr(site->repo_name, '/') != NULL) {
		fatalx("repository names must not contain slashes: %s",
		    site->repo_name);
	}

	if (strchr(site->repo_name, '\n') != NULL) {
		fatalx("repository names must not contain linefeeds: %s",
		    site->repo_name);
	}

	if (strchr(site->url_path, '\n') != NULL) {
		fatalx("URL paths must not contain linefeeds: %s",
		    site->url_path);
	}

	if (!got_path_is_absolute(site->url_path)) {
		fatalx("URL paths must be absolute paths: %s",
		    site->url_path);
	}

	error = got_pathlist_insert(&new, websites, site->url_path, site);
	if (error)
		fatalx("%s: %s", __func__, error->msg);
	if (new == NULL)
		fatalx("%s: duplicate web site '%s'", __func__, site->url_path);
}
