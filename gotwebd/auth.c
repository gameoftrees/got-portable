/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2025 Omar Polo <op@openbsd.org>
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"
#include "tmpl.h"

static char login_token_secret[32];
static char auth_token_secret[32];

static void
auth_shutdown(void)
{
	struct gotwebd *env = gotwebd_env;

	imsgbuf_clear(&env->iev_parent->ibuf);
	imsgbuf_clear(&env->iev_sockets->ibuf);
	imsgbuf_clear(&env->iev_gotweb->ibuf);

	free(env->iev_parent);
	free(env->iev_sockets);
	free(env->iev_gotweb);

	config_free_access_rules(&gotwebd_env->access_rules);

	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);

		config_free_access_rules(&srv->access_rules);
		config_free_repos(&srv->repos);
		config_free_websites(&srv->websites);
		free(srv);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->sockets)) {
		struct socket *sock;

		sock = TAILQ_FIRST(&gotwebd_env->sockets);
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		free(sock);
	}

	free(env);

	exit(0);
}

static void
auth_sighdlr(int sig, short event, void *arg)
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
	case SIGTERM:
		/* continue until the parent exits */
		break;
	case SIGINT:
		auth_shutdown();
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match_identifier(const char *identifier, gid_t *groups, int ngroups,
    uid_t euid, gid_t egid)
{
	int i;

	if (identifier[0] == ':') {
		gid_t rgid;
		if (parsegid(identifier + 1, &rgid) == -1)
			return 0;
		if (rgid == egid)
			return 1;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else if (uidcheck(identifier, euid) != 0)
		return 0;

	return 1;
}

static enum gotwebd_access
auth_check(const char **identifier, uid_t uid,
    struct gotwebd_access_rule_list *rules)
{
	struct gotwebd_access_rule *rule;
	enum gotwebd_access access = GOTWEBD_ACCESS_NO_MATCH;
	struct passwd *pw;
	gid_t groups[NGROUPS_MAX];
	int ngroups = NGROUPS_MAX;
	gid_t gid;

	if (identifier)
		*identifier = NULL;

	pw = getpwuid(uid);
	if (pw == NULL)
		return GOTWEBD_ACCESS_DENIED;

	gid = pw->pw_gid;

	if (getgrouplist(pw->pw_name, gid, groups, &ngroups) == -1)
		log_warnx("group membership list truncated");

	STAILQ_FOREACH(rule, rules, entry) {
		if (!match_identifier(rule->identifier, groups, ngroups,
		    uid, gid))
			continue;

		access = rule->access;
		if (identifier)
			*identifier = rule->identifier;
	}

	return access;
}

static void
auth_launch(struct gotwebd *env)
{
	if (env->iev_sockets == NULL)
		fatal("sockets process not connected");
	if (env->iev_gotweb == NULL)
		fatal("gotweb process not connected");

	event_add(&env->iev_sockets->ev, NULL);
	event_add(&env->iev_gotweb->ev, NULL);
}

static void
render_error(struct request *c, const struct got_error *error)
{
	int status;

	log_warnx("%s", error->msg);

	c->t->error = error;

	if (error->code == GOT_ERR_NOT_FOUND)
		status = 404;
	else if (error->code == GOT_ERR_LOGIN_FAILED)
		status = 401;
	else
		status = 400;

	if (gotweb_reply(c, status, "text/html", NULL) == -1)
		return;
	gotweb_render_page(c->tp, gotweb_render_error);
}

static void
abort_request(uint32_t request_id)
{
	if (imsg_compose_event(gotwebd_env->iev_sockets, GOTWEBD_IMSG_REQ_ABORT,
	    GOTWEBD_PROC_GOTWEB, -1, -1, &request_id, sizeof(request_id)) == -1)
		log_warn("imsg_compose_event");
}

static void
forward_request(struct request *c)
{
	struct gotwebd *env = gotwebd_env;
	const struct got_error *error;
	int ret;

	ret = imsg_compose_event(env->iev_gotweb, GOTWEBD_IMSG_REQ_PROCESS,
	    GOTWEBD_PROC_AUTH, -1, c->fd, c, sizeof(*c));
	if (ret == -1) {
		error = got_error_set_errno(ret, "could not forward request "
		    "to gotweb process");
		render_error(c, error);
		return;
	}

	c->fd = -1;
}

static void
do_login(struct request *c)
{
	const struct got_error *error = NULL;
	struct gotwebd *env = gotwebd_env;
	uid_t uid;
	struct server *srv;
	char *hostname = NULL;
	char *token = NULL;
	const char *identifier = NULL;
	const time_t validity = 24 * 60 * 60; /* 1 day */
	struct gotweb_url url;
	struct gotwebd_repo *repo;

	int r;

	if (login_check_token(&uid, &hostname, c->fcgi_params.qs.login,
	    login_token_secret, sizeof(login_token_secret), "login") == -1) {
		error = got_error(GOT_ERR_LOGIN_FAILED);
		goto err;
	}

	/*
	 * The www user ID represents the case where no authentication
	 * occurred. This user must not be allowed to log in.
	 */
	if (uid == env->www_uid) {
		error = got_error(GOT_ERR_LOGIN_FAILED);
		goto err;
	}

	c->client_uid = uid;
	if (strcmp(hostname, c->fcgi_params.server_name) != 0) {
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "wrong server name in login token");
		goto err;
	}

	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL) {
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "invalid server name for login");
		goto err;
	}

	TAILQ_FOREACH(repo, &srv->repos, entry) {
		switch (auth_check(&identifier, uid, &repo->access_rules)) {
		case GOTWEBD_ACCESS_PERMITTED:
			goto logged_in;
		case GOTWEBD_ACCESS_DENIED:
		case GOTWEBD_ACCESS_NO_MATCH:
			break;
		default:
			error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
			     "access check error for uid %u\n", uid);
			goto err;
		}
	}

	switch (auth_check(&identifier, uid, &srv->access_rules)) {
	case GOTWEBD_ACCESS_PERMITTED:
		goto logged_in;
	case GOTWEBD_ACCESS_DENIED:
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "permission denied");
		goto err;
	case GOTWEBD_ACCESS_NO_MATCH:
		break;
	default:
		error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
		     "access check error for uid %u\n", uid);
		goto err;
	}

	switch (auth_check(&identifier, uid, &env->access_rules)) {
	case GOTWEBD_ACCESS_PERMITTED:
		break;
	case GOTWEBD_ACCESS_DENIED:
	case GOTWEBD_ACCESS_NO_MATCH:
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "permission denied");
		goto err;
	default:
		error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
		     "access check error for uid %u\n", uid);
		goto err;
	}

logged_in:
	if (gotwebd_env->gotwebd_verbose > 0) {
		log_info("successful login of uid %u as %s for server \"%s\"",
		    uid, identifier, hostname);
	}

	/*
	 * Generate a long-lasting token for the browser cookie.
	 * TODO: make validity configurable?
	 */
	token = login_gen_token(uid, hostname, validity,
	    auth_token_secret, sizeof(auth_token_secret),
	    "authentication");
	if (token == NULL) {
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "failed to generate authentication cookie");
		goto err;
	}

	r = tp_writef(c->tp, "Set-Cookie: gwdauth=%s;"
	    " SameSite=Strict;%s Path=%s; HttpOnly; Max-Age=%llu\r\n", token,
	    env->auth_config == GOTWEBD_AUTH_SECURE ? " Secure;" : "",
	    srv->gotweb_url_root, validity);
	explicit_bzero(token, strlen(token));
	free(token);
	if (r == -1) {
		error = got_error_from_errno("tp_writef");
		goto err;
	}

	memset(&url, 0, sizeof(url));
	url.action = INDEX;
	gotweb_reply(c, 307, "text/html", &url);
	return;

err:
	free(hostname);
	hostname = NULL;

	log_warnx("%s: %s", __func__, error->msg);
	c->t->error = error;
	if (error->code == GOT_ERR_LOGIN_FAILED) {
		if (gotweb_reply(c, 401, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_unauthorized);
	} else {
		if (gotweb_reply(c, 400, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_error);
	}
}

static void
do_logout(struct request *c)
{
	const struct got_error *error = NULL;
	struct gotwebd *env = gotwebd_env;
	uid_t uid;
	struct server *srv;
	char *hostname = NULL;
	const char *identifier = NULL;
	struct gotweb_url url;

	int r;

	if (login_check_token(&uid, &hostname, c->fcgi_params.auth_cookie,
	    auth_token_secret, sizeof(auth_token_secret),
	    "authentication") == -1) {
		error = got_error(GOT_ERR_LOGOUT_FAILED);
		goto err;
	}

	/*
	 * The www user ID represents the case where no authentication
	 * occurred. This user must not be allowed to log in.
	 */
	if (uid == env->www_uid) {
		error = got_error(GOT_ERR_LOGOUT_FAILED);
		goto err;
	}

	c->client_uid = uid;
	if (strcmp(hostname, c->fcgi_params.server_name) != 0) {
		error = got_error_msg(GOT_ERR_LOGOUT_FAILED,
		    "wrong server name in authentication cookie");
		goto err;
	}

	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL) {
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "invalid server name for logout");
		goto err;
	}

	if (gotwebd_env->gotwebd_verbose > 0) {
		log_info("logging out uid %u as %s for server \"%s\"",
		    uid, identifier, hostname);
	}

	/* Ask the browser to delete the authentication cookie.  */
	r = tp_writef(c->tp, "Set-Cookie: gwdauth=invalid;"
	    " SameSite=Strict;%s Path=%s; HttpOnly; Max-Age=-1\r\n",
	    env->auth_config == GOTWEBD_AUTH_SECURE ? " Secure;" : "",
	    srv->gotweb_url_root);
	if (r == -1) {
		error = got_error_from_errno("tp_writef");
		goto err;
	}

	memset(&url, 0, sizeof(url));
	url.action = INDEX;
	gotweb_reply(c, 307, "text/html", &url);
	return;

err:
	free(hostname);
	hostname = NULL;

	log_warnx("%s: %s", __func__, error->msg);
	c->t->error = error;
	if (gotweb_reply(c, 400, "text/html", NULL) == -1)
		return;
	gotweb_render_page(c->tp, gotweb_render_error);
}

static const struct got_error *
login_error_hint(struct request *c)
{
	struct server *srv;
	char msg[512];
	int ret;

	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL || srv->login_hint_user[0] == '\0')
		return got_error(GOT_ERR_LOGIN_FAILED);

	ret = snprintf(msg, sizeof(msg),
	    "Log in by running: ssh %s%s%s%s@%s \"weblogin %s\"",
	    srv->login_hint_port[0] ? " -p " : "",
	    srv->login_hint_port[0] ? srv->login_hint_port : "",
	    srv->login_hint_port[0] ? " " : "",
	    srv->login_hint_user, srv->name, srv->name);
	if (ret == -1 || (size_t)ret >= sizeof(msg))
		return got_error(GOT_ERR_LOGIN_FAILED);

	return got_error_msg(GOT_ERR_LOGIN_FAILED, msg);
}

static void
process_request(struct request *c)
{
	const struct got_error *error = NULL;
	struct gotwebd *env = gotwebd_env;
	uid_t uid;
	struct server *srv;
	struct website *site;
	struct gotwebd_repo *repo = NULL;
	enum gotwebd_auth_config auth_config;
	struct gotwebd_access_rule_list *access_rules = NULL;
	char *hostname = NULL;
	const char *identifier = NULL;
	char *request_path = NULL;
	int is_repository_request = 0;

	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL) {
		log_warnx("request for unknown server name");
		error = got_error(GOT_ERR_BAD_QUERYSTRING);
		goto done;
	}

	error = gotweb_route_request(&is_repository_request, &site,
	    &request_path, c);
	if (error)
		goto done;

	/*
	 * Static gotwebd assets (images, CSS, ...) are not protected
	 * by authentication.
	 */
	if (is_repository_request && !got_path_is_root_dir(request_path)) {
		forward_request(c);
		free(request_path);
		return;
	}

	free(request_path);
	request_path = NULL;

	auth_config = srv->auth_config;

	if (c->fcgi_params.qs.path[0] != '\0')
		repo = gotweb_get_repository(srv, c->fcgi_params.qs.path);

	if (repo) {
		auth_config = repo->auth_config;
		access_rules = &repo->access_rules;
	} else if (site) {
		auth_config = site->auth_config;
		access_rules = &site->access_rules;

		/* Ignore the querystring while serving web sites. */
		fcgi_init_querystring(&c->fcgi_params.qs);
	}

	switch (auth_config) {
	case GOTWEBD_AUTH_SECURE:
	case GOTWEBD_AUTH_INSECURE:
		break;
	case GOTWEBD_AUTH_DISABLED:
		forward_request(c);
		return;
	default:
		fatalx("bad auth_config %d", env->auth_config);
	}

	if (login_check_token(&uid, &hostname, c->fcgi_params.auth_cookie,
	    auth_token_secret, sizeof(auth_token_secret),
	    "authentication") == -1) {
		error = login_error_hint(c);
		goto done;
	}

	/*
	 * The www user ID represents the case where no authentication
	 * occurred. This user is not allowed in authentication cookies.
	 */
	if (uid == env->www_uid) {
		error = login_error_hint(c);
		goto done;
	}

	c->client_uid = uid;
	if (strcmp(hostname, c->fcgi_params.server_name) != 0) {
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "bad server name in login token");
		goto done;
	}

	if (access_rules) {
		switch (auth_check(&identifier, uid, access_rules)) {
		case GOTWEBD_ACCESS_DENIED:
			error = got_error_msg(GOT_ERR_LOGIN_FAILED,
			    "permission denied");
			goto done;
		case GOTWEBD_ACCESS_PERMITTED:
			goto permitted;
		case GOTWEBD_ACCESS_NO_MATCH:
			break;
		default:
			error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
			    "access check error for uid %u\n", uid);
			goto done;
		}
	} else if (c->fcgi_params.qs.action == INDEX) {
		int have_public_repo = 0;

		/*
		 * The index page may contain a mix of repositories we have
		 * access to and/or for which authentication is disabled.
		 */
		TAILQ_FOREACH(repo, &srv->repos, entry) {
			if (repo->auth_config == GOTWEBD_AUTH_DISABLED)
				have_public_repo = -1;

			switch (auth_check(&identifier, uid,
			    &repo->access_rules)) {
			case GOTWEBD_ACCESS_PERMITTED:
				goto permitted;
			case GOTWEBD_ACCESS_DENIED:
			case GOTWEBD_ACCESS_NO_MATCH:
				break;
			default:
				error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
				     "access check error for uid %u\n", uid);
				goto done;
			}
		}

		/* We have access to public repositories only. */
		if (have_public_repo) {
			identifier = "";
			goto permitted;
		}
	}

	switch (auth_check(&identifier, uid, &srv->access_rules)) {
	case GOTWEBD_ACCESS_DENIED:
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "permission denied");
		goto done;
	case GOTWEBD_ACCESS_PERMITTED:
		goto permitted;
	case GOTWEBD_ACCESS_NO_MATCH:
		break;
	default:
		error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
		    "access check error for uid %u\n", uid);
		goto done;
	}

	switch (auth_check(&identifier, uid, &env->access_rules)) {
	case GOTWEBD_ACCESS_DENIED:
	case GOTWEBD_ACCESS_NO_MATCH:
		error = got_error_msg(GOT_ERR_LOGIN_FAILED,
		    "permission denied");
		goto done;
	case GOTWEBD_ACCESS_PERMITTED:
		goto permitted;
	default:
		error = got_error_fmt(GOT_ERR_LOGIN_FAILED,
		    "access check error for uid %u\n", uid);
		goto done;
	}

permitted:
	/*
	 * At this point, identifier should either be the empty string (if
	 * the request is allowed because authentication is partly disabled),
	 * or a user or group name.
	 */
	if (identifier == NULL)
		fatalx("have no known user identifier");

	if (strlcpy(c->access_identifier, identifier,
	    sizeof(c->access_identifier)) >= sizeof(c->access_identifier)) {
		error = got_error_msg(GOT_ERR_NO_SPACE,
		    "identifier too long");
		goto done;
	}

	if (gotwebd_env->gotwebd_verbose > 0) {
		log_info("authenticated UID %u as %s for server \"%s\"",
		    uid, identifier, hostname);
	}
done:
	free(hostname);
	free(request_path);
	if (error)
		render_error(c, error);
	else
		forward_request(c);
}

static struct request *
recv_request(struct imsg *imsg)
{
	const struct got_error *error = NULL;
	struct request *c;
	struct server *srv;
	size_t datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	int fd = -1;
	uint8_t *outbuf = NULL;

	if (datalen != sizeof(*c)) {
		log_warnx("bad request size received over imsg");
		return NULL;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1) {
		log_warnx("no client file descriptor");
		return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		log_warn("calloc");
		return NULL;
	}

	outbuf = calloc(1, GOTWEBD_CACHESIZE);
	if (outbuf == NULL) {
		log_warn("calloc");
		free(c);
		return NULL;
	}

	memcpy(c, imsg->data, sizeof(*c));

	/* Non-NULL pointers, if any, are not from our address space. */
	c->sock = NULL;
	c->srv = NULL;
	c->t = NULL;
	c->tp = NULL;
	c->buf = NULL;
	c->outbuf = outbuf;

	memset(&c->ev, 0, sizeof(c->ev));
	memset(&c->tmo, 0, sizeof(c->tmo));

	/* Use our own temporary file descriptors. */
	memcpy(c->priv_fd, gotwebd_env->priv_fd, sizeof(c->priv_fd));

	c->fd = fd;

	c->client_uid = gotwebd_env->www_uid;

	c->tp = template(c, fcgi_write, c->outbuf, GOTWEBD_CACHESIZE);
	if (c->tp == NULL) {
		log_warn("gotweb init template");
		fcgi_cleanup_request(c);
		return NULL;
	}

	/* init the transport */
	error = gotweb_init_transport(&c->t);
	if (error) {
		log_warnx("gotweb init transport: %s", error->msg);
		fcgi_cleanup_request(c);
		return NULL;
	}

	/* querystring */
	c->t->qs = &c->fcgi_params.qs;

	/* get the gotwebd server */
	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL) {
		log_warnx("server '%s' not found", c->fcgi_params.server_name);
		fcgi_cleanup_request(c);
		return NULL;
	}
	c->srv = srv;

	return c;
}

static void
auth_dispatch_sockets(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	struct request		*c;
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
		case GOTWEBD_IMSG_REQ_PROCESS:
			c = recv_request(&imsg);
			if (c == NULL)
				break;

			if (c->fcgi_params.qs.login[0] != '\0')
				do_login(c);
			else if (c->fcgi_params.qs.logout)
				do_logout(c);
			else
				process_request(c);

			/*
			 * If we have not forwarded the request to the gotweb
			 * process we must flush and clean up ourselves.
			 */
			if (c->fd != -1) {
				uint32_t request_id = c->request_id;

				if (template_flush(c->tp) == -1) {
					log_warn("request %u flush",
					    c->request_id);
				}
				fcgi_create_end_record(c);
				abort_request(request_id);
			}
			fcgi_cleanup_request(c);
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
recv_sockets_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->iev_sockets != NULL)
		fatalx("sockets process already connected");

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid login pipe fd");

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	imsgbuf_set_maxsize(&iev->ibuf, sizeof(struct request));

	iev->handler = auth_dispatch_sockets;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, auth_dispatch_sockets, iev);
	imsg_event_add(iev);

	env->iev_sockets = iev;
}

static void
auth_dispatch_gotweb(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_REQ_ABORT: {
			uint32_t request_id;

			if (imsg_get_data(&imsg, &request_id,
			    sizeof(request_id)) == -1)
				fatalx("invalid REQ_ABORT msg");

			abort_request(request_id);
			break;
		}
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
recv_gotweb_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->iev_gotweb != NULL)
		fatalx("gotweb process already connected");

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid login pipe fd");

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	imsgbuf_set_maxsize(&iev->ibuf, sizeof(struct request));

	iev->handler = auth_dispatch_gotweb;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, auth_dispatch_gotweb, iev);
	imsg_event_add(iev);

	env->iev_gotweb = iev;
}

static void
auth_dispatch_main(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct gotwebd		*env = gotwebd_env;
	struct server		*srv;
	struct gotwebd_repo	*repo;
	struct got_pathlist_entry *pe;
	struct website		*site;
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
		case GOTWEBD_IMSG_CFG_ACCESS_RULE:
			if (TAILQ_EMPTY(&env->servers)) {
				/* global access rule */
				config_get_access_rule(&env->access_rules,
				    &imsg);
			} else {
				srv = TAILQ_LAST(&env->servers, serverlist);
				if (TAILQ_EMPTY(&srv->repos)) {
					if (RB_EMPTY(&srv->websites)) {
						/* per-server access rule */
						config_get_access_rule(
						    &srv->access_rules, &imsg);
					} else {
						pe = RB_MAX(got_pathlist_head,
						    &srv->websites);
						site = pe->data;
						/* per-website access rule */
						config_get_access_rule(
						    &site->access_rules, &imsg);
					}
				} else {
					/* per-repository access rule */
					repo = TAILQ_LAST(&srv->repos,
					    gotwebd_repolist);
					config_get_access_rule(
					    &repo->access_rules, &imsg);
				}
			}
			break;
		case GOTWEBD_IMSG_CFG_SRV:
			config_getserver(gotwebd_env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_REPO:
			if (TAILQ_EMPTY(&env->servers))
				fatalx("%s: unexpected CFG_REPO msg", __func__);
			srv = TAILQ_LAST(&env->servers, serverlist);
			config_get_repository(&srv->repos, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_WEBSITE:
			if (TAILQ_EMPTY(&env->servers)) {
				fatalx("%s: unexpected CFG_WEBSITE msg",
				    __func__);
			}
			srv = TAILQ_LAST(&env->servers, serverlist);
			config_get_website(&srv->websites, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_PIPE:
			if (env->iev_sockets == NULL)
				recv_sockets_pipe(env, &imsg);
			else
				recv_gotweb_pipe(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_START:
			auth_launch(env);
			break;
		case GOTWEBD_IMSG_LOGIN_SECRET:
			if (imsg_get_data(&imsg, login_token_secret,
			    sizeof(login_token_secret)) == -1)
				fatalx("invalid LOGIN_SECRET msg");
			break;
		case GOTWEBD_IMSG_AUTH_SECRET:
			if (imsg_get_data(&imsg, auth_token_secret,
			    sizeof(auth_token_secret)) == -1)
				fatalx("invalid AUTH_SECRET msg");
			break;
		case GOTWEBD_IMSG_AUTH_CONF:
			if (imsg_get_data(&imsg, &env->auth_config,
			    sizeof(env->auth_config)) == -1)
				fatalx("invalid AUTH_CONF msg");
			break;
		case GOTWEBD_IMSG_WWW_UID:
			if (imsg_get_data(&imsg, &env->www_uid,
			    sizeof(env->www_uid)) == -1)
				fatalx("invalid WWW_UID msg");
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

void
gotwebd_auth(struct gotwebd *env, int fd)
{
	struct event	 sighup, sigint, sigusr1, sigchld, sigterm;
	struct event_base *evb;

	evb = event_init();

	if ((env->iev_parent = malloc(sizeof(*env->iev_parent))) == NULL)
		fatal("malloc");
	if (imsgbuf_init(&env->iev_parent->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&env->iev_parent->ibuf);
	env->iev_parent->handler = auth_dispatch_main;
	env->iev_parent->data = env->iev_parent;
	event_set(&env->iev_parent->ev, fd, EV_READ, auth_dispatch_main,
	    env->iev_parent);
	event_add(&env->iev_parent->ev, NULL);

	signal(SIGPIPE, SIG_IGN);

	signal_set(&sighup, SIGHUP, auth_sighdlr, env);
	signal_add(&sighup, NULL);
	signal_set(&sigint, SIGINT, auth_sighdlr, env);
	signal_add(&sigint, NULL);
	signal_set(&sigusr1, SIGUSR1, auth_sighdlr, env);
	signal_add(&sigusr1, NULL);
	signal_set(&sigchld, SIGCHLD, auth_sighdlr, env);
	signal_add(&sigchld, NULL);
	signal_set(&sigterm, SIGTERM, auth_sighdlr, env);
	signal_add(&sigterm, NULL);

#ifndef PROFILE
	if (pledge("stdio getpw recvfd sendfd", NULL) == -1)
		fatal("pledge");
#endif
	event_dispatch();
	event_base_free(evb);
	auth_shutdown();
}
