/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2025 Omar Polo <op@openbsd.org>
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

#include <sys/queue.h>
#include <sys/stat.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <signal.h>
#include <siphash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"

#define LOGIN_SOCKET_BACKLOG 4

struct gotwebd_login_client {
	int fd;
	int cmd_done;
	uid_t euid;
	struct bufferevent *bev;
};

static volatile int client_cnt;
static int inflight;
static volatile int stopping;

static char login_token_secret[32];

/*
 * The token format is:
 *
 *    "v2\0"[random/64bit][issued at/64bit][expire/64bit][uid/64bit][host]"\0"
 *
 * Padded with additional \0 to a length divisible by 4, and then
 * followed by the HMAC-SHA256 of it, all encoded in base64.
 */

/* checks whether the token's signature matches, i.e. if it looks good. */
int
login_check_token(uid_t *euid, char **hostname,
    const char *token, const char *secret, size_t secret_len,
    const char *purpose)
{
	time_t	 now;
	uint64_t random, issued, expire, uid;
	uint8_t *data;
	int	 len;
	char	 hmac[32], exp[32];
	unsigned int explen;
	size_t	used = 0;

	/*
	 * We get called in several processes which should all have
	 * a copy of the same secret.
	 */
	if (secret_len != sizeof(login_token_secret))
		fatalx("%s token secret length mismatch", purpose);

	/* xxx check for overflow */
	len = (strlen(token) / 4) * 3;

	data = malloc(len);
	if (data == NULL)
		return -1;

	len = EVP_DecodeBlock(data, token, strlen(token));
	if (len == -1) {
		free(data);
		return -1;
	}

	/* Trim padding. */
	while (len > 0 && (len % 4) != 0)
		len--;

	if (len < 28 + 32) { /* min length assuming empty hostname */
		log_warnx("%s token too short: %d", purpose, len);
		free(data);
		return -1;
	}

	if (memcmp(data, "v2", 3) != 0) {
		log_warnx("unknown %s token format version", purpose);
		free(data);
		return -1;
	}
	used = 3;

	if (HMAC(EVP_sha256(), secret, secret_len, data, len - 32,
	    exp, &explen) == NULL) {
		log_warnx("HMAC computation failed\n");
		free(data);
		return -1;
	}

	if (explen != 32) {
		log_warnx("unexpected HMAC length: %u\n", explen);
		free(data);
		return -1;
	}

	memcpy(hmac, data + len - explen, explen);

	if (memcmp(hmac, exp, explen) != 0) {
		log_warnx("HMAC check failed\n");
		free(data);
		return -1;
	}

	memcpy(&random, data + used, sizeof(random));
	used += sizeof(random);

	memcpy(&issued, data + used, sizeof(issued));
	used += sizeof(issued);

	memcpy(&expire, data + used, sizeof(expire));
	used += sizeof(expire);

	memcpy(&uid, data + used, sizeof(uid));
	used += sizeof(uid);

	now = time(NULL);
	if (expire < now) {
		log_warnx("uid %llu: %s token has expired\n", uid, purpose);
		free(data);
		return -1;
	}

	if (euid)
		*euid = (uid_t)uid;

	if (hostname) {
		if (used < len - explen) {
			*hostname = strndup(data + used,
			    len - explen - used);
			if (*hostname == NULL) {
				log_warn("strndup");
				free(data);
				return -1;
			}
		} else {
			*hostname = strdup("");
			if (*hostname == NULL) {
				log_warn("strdup");
				free(data);
				return -1;
			}
		}
	}
		
	free(data);
	return 0;
}

char *
login_gen_token(uint64_t uid, const char *hostname, time_t validity,
    const char *secret, size_t secret_len, const char *purpose)
{
	BIO		*bmem, *b64;
	BUF_MEM		*bufm;
	char		 hmac[EVP_MAX_MD_SIZE];
	char		*enc;
	FILE		*fp;
	char		*tok;
	time_t		 now;
	uint64_t	 random, issued, expire;
	size_t		 siz, hlen, pad;
	unsigned int	 hmaclen;	/* openssl... */

	/*
	 * We get called in several processes which should all have
	 * a copy of the same secret.
	 */
	if (secret_len != sizeof(login_token_secret))
		fatalx("%s token secret length mismatch", purpose);

	now = time(NULL);
	arc4random_buf(&random, sizeof(random));
	issued = (uint64_t)now;
	expire = issued + validity;

	fp = open_memstream(&tok, &siz);
	if (fp == NULL)
		return NULL;

	/* include NUL */
	hlen = strlen(hostname) + 1;

	if (fwrite("v2", 1, 3, fp) != 3 ||
	    fwrite(&random, 1, 8, fp) != 8 ||
	    fwrite(&issued, 1, 8, fp) != 8 ||
	    fwrite(&expire, 1, 8, fp) != 8 ||
	    fwrite(&uid, 1, 8, fp) != 8 ||
	    fwrite(hostname, 1, hlen, fp) != hlen) {
		fclose(fp);
		free(tok);
		return NULL;
	}

	/* Pad hostname with trailing NULs for base64 encoding. */
	pad = 0;
	while (((3 + 8 + 8 + 8 + hlen + pad) % 4) != 0) {
		if (fwrite("", 1, 1, fp) != 1) {
			fclose(fp);
			free(tok);
			return NULL;
		}
		pad++;
	}

	if (fclose(fp) == EOF) {
		free(tok);
		return NULL;
	}

	/* Base64 encoder expects a length divisible by 4. */
	if ((siz % 4) != 0)
		fatalx("generated %s token with bad size %zu", purpose, siz);

	if (siz > INT_MAX) {
		/*
		 * can't really happen, isn't it?  yet, openssl
		 * sometimes likes to take ints so I'd prefer to
		 * assert.
		 */
		free(tok);
		return NULL;
	}

	if (HMAC(EVP_sha256(), secret, secret_len, tok, siz,
	    hmac, &hmaclen) == NULL) {
		free(tok);
		return NULL;
	}

	bmem = BIO_new(BIO_s_mem());
	if (bmem == NULL) {
		free(tok);
		return NULL;
	}

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		BIO_free(bmem);
		free(tok);
		return NULL;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	b64 = BIO_push(b64, bmem);

	if (BIO_write(b64, tok, siz) != (int)siz ||
	    BIO_write(b64, hmac, hmaclen) != hmaclen ||
	    BIO_flush(b64) <= 0) {
		free(tok);
		BIO_free_all(b64);
		return NULL;
	}

	BIO_get_mem_ptr(b64, &bufm);
	enc = strndup(bufm->data, bufm->length);

	free(tok);
	BIO_free_all(b64);

	if (login_check_token(NULL, NULL, enc, secret, secret_len,
	    purpose) == -1)
		fatalx("generated %s token that won't pass validation",
		    purpose);

	return enc;
}

static int
login_socket_listen(struct gotwebd *env, struct socket *sock,
    uid_t uid, gid_t gid)
{
	int u_fd = -1;
	mode_t old_umask, mode;
	int sock_flags = SOCK_STREAM | SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif
	u_fd = socket(AF_UNIX, sock_flags, 0);
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
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

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

	if (listen(u_fd, LOGIN_SOCKET_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return -1;
	}

	return u_fd;
}

int
login_privinit(struct gotwebd *env, uid_t uid, gid_t gid)
{
	struct socket *sock = env->login_sock;

	if (sock == NULL)
		fatalx("no login socket configured");

	log_info("initializing login socket %s",
	    sock->conf.unix_socket_name);

	sock->fd = login_socket_listen(env, sock, uid, gid);
	if (sock->fd == -1)
		return -1;

	return 0;
}

static void
login_shutdown(void)
{
	struct gotwebd *env = gotwebd_env;

	imsgbuf_clear(&env->iev_parent->ibuf);
	free(env->iev_parent);
	if (env->iev_gotsh) {
		imsgbuf_clear(&env->iev_gotsh->ibuf);
		free(env->iev_gotsh);
	}

	config_free_access_rules(&env->access_rules);

	while (!TAILQ_EMPTY(&gotwebd_env->sockets)) {
		struct socket *sock;

		sock = TAILQ_FIRST(&gotwebd_env->sockets);
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		free(sock);
	}
	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);

		config_free_access_rules(&srv->access_rules);
		config_free_repos(&srv->repos);
		free(srv);
	}
	free(env);

	exit(0);
}

static void
login_stop(void)
{
	struct gotwebd *env = gotwebd_env;

	stopping = 1;

	if (env->iev_gotsh) {
		evtimer_del(&env->login_pause_ev);
		event_del(&env->iev_gotsh->ev);
		close(env->iev_gotsh->ibuf.fd);
		env->iev_gotsh->ibuf.fd = -1;
		imsgbuf_clear(&env->iev_gotsh->ibuf);
	}
}

static void
login_sighdlr(int sig, short event, void *arg)
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
		login_stop();
		break;
	case SIGINT:
		login_shutdown();
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static int
accept_reserve(int fd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve + *counter + 1 >= getdtablesize()) {
		log_debug("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}

/* TA:  This needs fixing upstream. */
#ifdef __APPLE__
	ret = accept(fd, addr, addrlen);
#else
	ret = accept4(fd, addr, addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif
	if (ret > -1) {
		(*counter)++;
	}

	return ret;
}

static void
client_err(struct bufferevent *bev, short error, void *d)
{
	struct gotwebd_login_client *client = d;

	log_debug("closing connection with client fd=%d; error=%d",
	    client->fd, error);

	bufferevent_free(client->bev);
	close(client->fd);
	free(client);

	inflight--;
	client_cnt--;
}

static void
client_read(struct bufferevent *bev, void *d)
{
	struct gotwebd_login_client *client = d;
	struct evbuffer *in = EVBUFFER_INPUT(bev);
	struct evbuffer *out = EVBUFFER_OUTPUT(bev);
	char *line, *cmd, *code;
	size_t linelen;
	const char *hostname, *path = NULL;

	if (client->cmd_done) {
		log_warnx("%s: client sent data even though login command "
		    "has already completed", __func__);
		client_err(bev, EVBUFFER_READ, client);
		return;
	}

	line = evbuffer_readln(in, &linelen, EVBUFFER_EOL_LF);
	if (line == NULL) {
		/*
		 * there is no line yet to read.  however, error if we
		 * have too much data buffered without a newline
		 * character.
		 */
		if (EVBUFFER_LENGTH(in) > LINE_MAX)
			client_err(bev, EVBUFFER_READ, client);
		return;
	}

	cmd = line;
	if (strncmp(cmd, "login", 5) == 0) {
		struct server *srv = NULL;

		cmd += 5;
		cmd += strspn(cmd, " \t");
		hostname = cmd;
		if (hostname[0] == '\0') {
			/*
			 * In a multi-server setup we do not want to leak our
			 * first server's hostname to random people. But if
			 * we only have a single server, we'll expose it.
			 */
			srv = TAILQ_FIRST(&gotwebd_env->servers);
			if (TAILQ_NEXT(srv, entry) == NULL)
				hostname = srv->name;
			else {
				log_warnx("%s: no hostname provided for "
				    "weblogin", __func__);
				client_err(bev, EVBUFFER_READ, client);
				return;
			}
		} else {
			/* Match hostname against available servers. */
			TAILQ_FOREACH(srv, &gotwebd_env->servers, entry) {
				if (strcmp(srv->name, hostname) == 0)
					break;
			}

			if (srv == NULL) {
				log_warnx("%s: bad hostname for weblogin: %s",
				    __func__, hostname);
				client_err(bev, EVBUFFER_READ, client);
				return;
			}
		}

		code = login_gen_token(client->euid, hostname,
		    GOTWEBD_LOGIN_TIMEOUT,
		    login_token_secret, sizeof(login_token_secret), "login");
		if (code == NULL) {
			log_warn("%s: login_gen_token failed", __func__);
			client_err(bev, EVBUFFER_READ, client);
			return;
		}

		if (srv->gotweb_url_root[0] != '\0' &&
		    !got_path_is_root_dir(srv->gotweb_url_root))
			path = srv->gotweb_url_root;

		if (evbuffer_add_printf(out, "ok https://%s%s/?login=%s\n",
		    hostname, path ? path : "", code) == -1) {
			log_warnx("%s: evbuffer_add_printf failed", __func__);
			client_err(bev, EVBUFFER_READ, client);
			free(code);
			return;
		}
		free(code);

		client->cmd_done = 1;
		bufferevent_enable(client->bev, EV_READ|EV_WRITE);
		return;
	}

	if (evbuffer_add_printf(out, "err unknown command\n") == -1) {
		log_warnx("%s: evbuffer_add_printf failed", __func__);
		client_err(bev, EVBUFFER_READ, client);
		return;
	}

	client->cmd_done = 1;
	return;
}

static void
client_write(struct bufferevent *bev, void *d)
{
	struct gotwebd_login_client *client = d;
	struct evbuffer *out = EVBUFFER_OUTPUT(bev);

	if (client->cmd_done && EVBUFFER_LENGTH(out) == 0) {
		/* reply sent */
		client_err(bev, EVBUFFER_WRITE, client);
		return;
	}
}

static void
login_accept(int fd, short event, void *arg)
{
	struct imsgev *iev = arg;
	struct gotwebd *env = gotwebd_env;
	struct sockaddr_storage ss;
	struct timeval backoff;
	socklen_t len;
	int s = -1;
	struct gotwebd_login_client *client = NULL;
	uid_t euid;
	gid_t egid;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (!stopping && event_add(&iev->ev, NULL) == -1) {
		log_warn("event_add");
		return;
	}
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	/* Other backoff conditions apart from EMFILE/ENFILE? */
	s = accept_reserve(fd, (struct sockaddr *)&ss, &len, FD_RESERVE,
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
			if (!stopping)
				evtimer_add(&env->login_pause_ev, &backoff);
			return;
		default:
			log_warn("accept");
			return;
		}
	}

	if (client_cnt >= GOTWEBD_MAXCLIENTS)
		goto err;

	if (getpeereid(s, &euid, &egid) == -1) {
		log_warn("getpeerid");
		goto err;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		log_warn("%s: calloc", __func__);
		goto err;
	}
	client->fd = s;
	client->euid = euid;
	s = -1;

	client->bev = bufferevent_new(client->fd, client_read, client_write,
	    client_err, client);
	if (client->bev == NULL) {
		log_warn("%s: bufferevent_new failed", __func__);
		goto err;
	}
	bufferevent_enable(client->bev, EV_READ|EV_WRITE);

	/*
	 * undocumented; but these are seconds.  10s should be plenty
	 * for both receiving a request and sending the reply.
	 */
	bufferevent_settimeout(client->bev, 10, 10);

	log_debug("%s: new client connected on fd %d uid %d gid %d", __func__,
	    client->fd, euid, egid);
	client_cnt++;
	return;
err:
	inflight--;
	if (client) {
		if (client->bev != NULL)
			bufferevent_free(client->bev);
		close(client->fd);
		free(client);
	}
	if (s != -1)
		close(s);
}

static void
get_login_sock(struct gotwebd *env, struct imsg *imsg)
{
	const struct got_error *err;
	struct imsgev *iev;
	int fd;

	if (env->iev_gotsh != NULL) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		fatalx("%s", err->msg);
	}

	if (IMSG_DATA_SIZE(imsg) != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		fatalx("%s", err->msg);
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		fatalx("%s", err->msg);
	}

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");

	iev->handler = login_accept;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, login_accept, iev);
	imsg_event_add(iev);

	env->iev_gotsh = iev;
}

static void
login_launch(struct gotwebd *env)
{
#ifndef PROFILE
	if (pledge("stdio unix", NULL) == -1)
		fatal("pledge");
#endif
	event_add(&env->iev_gotsh->ev, NULL);
}

static void
login_dispatch_main(int fd, short event, void *arg)
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
			get_login_sock(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_START:
			login_launch(env);
			break;
		case GOTWEBD_IMSG_CTL_STOP:
			login_stop();
			break;
		case GOTWEBD_IMSG_LOGIN_SECRET:
			if (imsg_get_data(&imsg, login_token_secret,
			    sizeof(login_token_secret)) == -1)
				fatalx("invalid LOGIN_SECRET msg");
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
accept_paused(int fd, short event, void *arg)
{
	struct gotwebd *env = gotwebd_env;

	if (!stopping)
		event_add(&env->iev_gotsh->ev, NULL);
}

void
gotwebd_login(struct gotwebd *env, int fd)
{
	struct event	 sighup, sigint, sigusr1, sigchld, sigterm;
	struct event_base *evb;

	evb = event_init();

	if ((env->iev_parent = malloc(sizeof(*env->iev_parent))) == NULL)
		fatal("malloc");
	if (imsgbuf_init(&env->iev_parent->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&env->iev_parent->ibuf);
	env->iev_parent->handler = login_dispatch_main;
	env->iev_parent->data = env->iev_parent;
	event_set(&env->iev_parent->ev, fd, EV_READ, login_dispatch_main,
	    env->iev_parent);
	event_add(&env->iev_parent->ev, NULL);
	evtimer_set(&env->login_pause_ev, accept_paused, NULL);

	signal(SIGPIPE, SIG_IGN);

	signal_set(&sighup, SIGHUP, login_sighdlr, env);
	signal_add(&sighup, NULL);
	signal_set(&sigint, SIGINT, login_sighdlr, env);
	signal_add(&sigint, NULL);
	signal_set(&sigusr1, SIGUSR1, login_sighdlr, env);
	signal_add(&sigusr1, NULL);
	signal_set(&sigchld, SIGCHLD, login_sighdlr, env);
	signal_add(&sigchld, NULL);
	signal_set(&sigterm, SIGTERM, login_sighdlr, env);
	signal_add(&sigterm, NULL);

#ifndef PROFILE
	if (pledge("stdio recvfd unix", NULL) == -1)
		fatal("pledge");
#endif

	event_dispatch();
	event_base_free(evb);
	login_shutdown();
}

