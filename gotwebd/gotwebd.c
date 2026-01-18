/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <util.h>

#include "got_opentemp.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"

__dead void usage(void);

int	 main(int, char **);
int	 gotwebd_configure(struct gotwebd *, uid_t, gid_t);
void	 gotwebd_configure_done(struct gotwebd *);
void	 gotwebd_sighdlr(int sig, short event, void *arg);
void	 gotwebd_shutdown(void);
void	 gotwebd_dispatch_server(int, short, void *);
void	 gotwebd_dispatch_fcgi(int, short, void *);
void	 gotwebd_dispatch_login(int, short, void *);
void	 gotwebd_dispatch_auth(int, short, void *);
void	 gotwebd_dispatch_gotweb(int, short, void *);

struct gotwebd	*gotwebd_env;

static volatile int client_cnt;
static volatile int stopping;

void
imsg_event_add(struct imsgev *iev)
{
	if (iev->handler == NULL) {
		imsgbuf_flush(&iev->ibuf);
		return;
	}

	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf))
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev->data);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, const void *data, size_t datalen)
{
	int ret;

	ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data, datalen);
	if (ret == -1)
		return (ret);
	imsg_event_add(iev);
	return (ret);
}

static int
send_imsg(struct imsgev *iev, uint32_t type, int fd, const void *data,
    uint16_t len)
{
	int	 ret, d = -1;

	if (fd != -1 && (d = dup(fd)) == -1)
		goto err;

	ret = imsg_compose_event(iev, type, 0, -1, d, data, len);
	if (ret == -1)
		goto err;

	if (d != -1) {
		d = -1;
		/* Flush imsg to prevent fd exhaustion. 'd' will be closed. */
		if (imsgbuf_flush(&iev->ibuf) == -1)
			goto err;
		imsg_event_add(iev);
	}

	return 0;
err:
	if (d != -1)
		close(d);
	return -1;
}

int
main_compose_sockets(struct gotwebd *env, uint32_t type, int fd,
    const void *data, uint16_t len)
{
	return send_imsg(env->iev_sockets, type, fd, data, len);
}

int
main_compose_login(struct gotwebd *env, uint32_t type, int fd,
    const void *data, uint16_t len)
{
	return send_imsg(env->iev_login, type, fd, data, len);
}

int
main_compose_gotweb(struct gotwebd *env, uint32_t type, int fd,
    const void *data, uint16_t len)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < env->prefork; i++) {
		ret = send_imsg(&env->iev_gotweb[i], type, fd, data, len);
		if (ret)
			break;
	}

	return ret;
}

int
main_compose_auth(struct gotwebd *env, uint32_t type, int fd,
    const void *data, uint16_t len)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < env->prefork; i++) {
		ret = send_imsg(&env->iev_auth[i], type, fd, data, len);
		if (ret)
			break;
	}

	return ret;
}

int
sockets_compose_main(struct gotwebd *env, uint32_t type, const void *d,
    uint16_t len)
{
	return (imsg_compose_event(env->iev_parent, type, 0, -1, -1, d, len));
}

 void
gotwebd_dispatch_login(int fd, short event, void *arg)
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
gotwebd_dispatch_server(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_CFG_DONE:
			gotwebd_configure_done(env);
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
gotwebd_dispatch_fcgi(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_CFG_DONE:
			gotwebd_configure_done(env);
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
gotwebd_dispatch_auth(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_CFG_DONE:
			gotwebd_configure_done(env);
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
gotwebd_dispatch_gotweb(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_CFG_DONE:
			gotwebd_configure_done(env);
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
control_socket_destroy(void)
{
	struct gotwebd *env = gotwebd_env;

	if (env->iev_control == NULL)
		return;

	event_del(&env->iev_control->ev);
	imsgbuf_clear(&env->iev_control->ibuf);
	if (env->iev_control->ibuf.fd != -1)
		close(env->iev_control->ibuf.fd);

	free(env->iev_control);
	env->iev_control = NULL;

	free(env->control_sock);
	env->control_sock = NULL;
}

static void
gotwebd_stop(void)
{
	if (main_compose_sockets(gotwebd_env, GOTWEBD_IMSG_CTL_STOP,
	    -1, NULL, 0) == -1)
		fatal("send_imsg GOTWEBD_IMSG_CTL_STOP");

	if (main_compose_login(gotwebd_env, GOTWEBD_IMSG_CTL_STOP,
	    -1, NULL, 0) == -1)
		fatal("send_imsg GOTWEBD_IMSG_CTL_STOP");

	control_socket_destroy();
	stopping = 1;
}

void
gotwebd_sighdlr(int sig, short event, void *arg)
{
	/* struct privsep	*ps = arg; */

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
	case SIGTERM:
		if (stopping)
			break;
		gotwebd_stop();
		break;
	case SIGINT:
		gotwebd_shutdown();
		exit(0);
		/* NOTREACHED */
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static void
spawn_process(struct gotwebd *env, const char *argv0, struct imsgev *iev,
    enum gotwebd_proc_type proc_type, const char *username,
    const char *www_user, void (*handler)(int, short, void *))
{
	const char	*argv[10];
	int		 argc = 0;
	int		 p[2];
	pid_t		 pid;
	char		 usernames[_PW_NAME_LEN * 2 + 1 + 1];
	int		 ret;

	ret = snprintf(usernames, sizeof(usernames), "%s:%s",
	    username, www_user);
	if (ret == -1)
		fatal("snprintf");
	if ((size_t)ret >= sizeof(usernames))
		fatalx("usernames too long");

	if (socketpair(AF_UNIX,
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, PF_UNSPEC, p) == -1)
		fatal("socketpair");

	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:		/* child */
		break;
	default:	/* parent */
		close(p[0]);
		if (imsgbuf_init(&iev->ibuf, p[1]) == -1)
			fatal("imsgbuf_init");
		imsgbuf_allow_fdpass(&iev->ibuf);
		iev->handler = handler;
		iev->data = iev;
		event_set(&iev->ev, p[1], EV_READ, handler, iev);
		event_add(&iev->ev, NULL);
		return;
	}

	close(p[1]);

	argv[argc++] = argv0;
	if (proc_type == GOTWEBD_PROC_SOCKETS) {
		char *s;

		argv[argc++] = "-S";
		argv[argc++] = usernames;
		if (asprintf(&s, "-S%d", env->prefork) == -1)
			fatal("asprintf");
		argv[argc++] = s;
	} else if (proc_type == GOTWEBD_PROC_LOGIN) {
		argv[argc++] = "-L";
		argv[argc++] = usernames;
	} else if (proc_type == GOTWEBD_PROC_FCGI) {
		argv[argc++] = "-F";
		argv[argc++] = usernames;
	} else if (proc_type == GOTWEBD_PROC_AUTH) {
		argv[argc++] = "-A";
		argv[argc++] = usernames;
	} else if (proc_type == GOTWEBD_PROC_GOTWEB) {
		argv[argc++] = "-G";
		argv[argc++] = usernames;
	}
	if (strcmp(env->gotwebd_conffile, GOTWEBD_CONF) != 0) {
		argv[argc++] = "-f";
		argv[argc++] = env->gotwebd_conffile;
	}
	if (env->gotwebd_debug)
		argv[argc++] = "-d";
	if (env->gotwebd_verbose > 0)
		argv[argc++] = "-v";
	if (env->gotwebd_verbose > 1)
		argv[argc++] = "-v";
	argv[argc] = NULL;

	if (p[0] != GOTWEBD_SOCK_FILENO) {
		if (dup2(p[0], GOTWEBD_SOCK_FILENO) == -1)
			fatal("dup2");
	} else if (fcntl(p[0], F_SETFD, 0) == -1)
		fatal("fcntl");

	/* obnoxious cast */
	execvp(argv0, (char * const *)argv);
	fatal("execvp %s", argv0);
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-D macro=value] [-f file]\n",
	    getprogname());
	exit(1);
}

static void
get_usernames(const char **gotwebd_username, const char **www_username,
    char *optarg)
{
	static char usernames[_PW_NAME_LEN * 2 + 1 + 1];
	char *colon;

	if (strlcpy(usernames, optarg, sizeof(usernames)) >=
	    sizeof(usernames))
		fatalx("usernames too long");

	colon = strchr(usernames, ':');
	if (colon == NULL)
		fatalx("bad username option parameter");
	*colon = '\0';

	*gotwebd_username = &usernames[0];
	*www_username = colon + 1;
}

static int
control_socket_listen(struct gotwebd *env, struct socket *sock,
    uid_t uid, gid_t gid)
{
	int u_fd = -1;
	mode_t old_umask, mode;

	u_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK| SOCK_CLOEXEC, 0);
	if (u_fd == -1) {
		log_warn("socket");
		return -1;
	}

	if (unlink(sock->conf.unix_socket_name) == -1) {
		if (errno != ENOENT) {
			log_warn("unlink %s", sock->conf.unix_socket_name);
			close(u_fd);
			return -1;
		}
	}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

	if (bind(u_fd, (struct sockaddr *)&sock->conf.addr.ss,
	    sock->conf.addr.slen) == -1) {
		log_warn("bind: %s", sock->conf.unix_socket_name);
		close(u_fd);
		(void)umask(old_umask);
		return -1;
	}

	(void)umask(old_umask);

	if (chmod(sock->conf.unix_socket_name, mode) == -1) {
		log_warn("chmod: %s", sock->conf.unix_socket_name);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	if (chown(sock->conf.unix_socket_name, uid, gid) == -1) {
		log_warn("chown: %s", sock->conf.unix_socket_name);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	if (listen(u_fd, 1) == -1) {
		log_warn("listen: %s", sock->conf.unix_socket_name);
		return -1;
	}

	return u_fd;
}

struct gotwebd_control_client {
	int fd;
	struct imsgev iev;
	struct event tmo;
};

static void
disconnect(struct gotwebd_control_client *client)
{
	if (client->fd != -1)
		close(client->fd);
	free(client);
	client_cnt--;
}

static void
control_timeout(int fd, short events, void *arg)
{
	struct gotwebd_control_client *client = arg;

	log_debug("disconnecting control socket due to timeout");

	disconnect(client);
}

static void
send_info(struct gotwebd_control_client *client)
{
	struct gotwebd_imsg_info info;

	info.pid = getpid();
	info.verbosity = gotwebd_env->gotwebd_verbose;

	if (imsg_compose_event(&client->iev, GOTWEBD_IMSG_CTL_INFO, 0,
	    getpid(), -1, &info, sizeof(info)) == -1)
		log_warn("imsg compose INFO");
}

static void
control_request(int fd, short event, void *arg)
{
	struct gotwebd_control_client *client = arg;
	struct imsg imsg;
	ssize_t n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&client->iev.ibuf) == -1) {
			log_warn("imsgbuf_write");
			disconnect(client);
			return;
		}

		if (stopping) {
			disconnect(client);
			return;
		}
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&client->iev.ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			disconnect(client);
			return;
		}
	}

	for (;;) {
		n = imsg_get(&client->iev.ibuf, &imsg);
		if (n == -1) {
			disconnect(client);
			return;
		}

		if (n == 0)
			break;

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
		case GOTWEBD_IMSG_CTL_INFO:
			send_info(client);
			break;
		case GOTWEBD_IMSG_CTL_STOP:
			if (!stopping)
				gotwebd_stop();
			disconnect(client);
			imsg_free(&imsg);
			return;
		default:
			log_warnx("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	imsg_event_add(&client->iev);
}

static void
control_accept(int fd, short event, void *arg)
{
	struct imsgev *iev = arg;
	struct gotwebd *env = gotwebd_env;
	struct sockaddr_storage ss;
	struct timeval backoff;
	socklen_t len;
	int s = -1;
	struct gotwebd_control_client *client = NULL;
	uid_t euid;
	gid_t egid;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (stopping)
		return;

	if (event_add(&iev->ev, NULL) == -1) {
		log_warn("event_add");
		return;
	}
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	s = accept4(fd, (struct sockaddr *)&ss, &len, 
	    SOCK_NONBLOCK | SOCK_CLOEXEC);
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
				evtimer_add(&env->control_pause_ev, &backoff);
			return;
		default:
			log_warn("accept");
			return;
		}
	}

	if (client_cnt >= 1)
		goto err;

	if (getpeereid(s, &euid, &egid) == -1) {
		log_warn("getpeerid");
		goto err;
	}

	if (euid != 0) {
		log_warnx("control connection from UID %d denied", euid);
		goto err;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		log_warn("%s: calloc", __func__);
		goto err;
	}
	client->fd = s;
	s = -1;

	client->iev.handler = control_request;
	client->iev.events = EV_READ;
	client->iev.data = client;

	imsgbuf_init(&client->iev.ibuf, client->fd);
	event_set(&client->iev.ev, client->fd, EV_READ, control_request,
	    client);
	imsg_event_add(&client->iev);

	evtimer_set(&client->tmo, control_timeout, client);

	log_debug("%s: control connection on fd %d uid %d gid %d", __func__,
	    client->fd, euid, egid);
	client_cnt++;
	return;
err:
	if (client) {
		close(client->fd);
		free(client);
	}
	if (s != -1)
		close(s);
}

static void
accept_paused(int fd, short event, void *arg)
{
	struct gotwebd *env = gotwebd_env;

	if (!stopping)
		event_add(&env->iev_control->ev, NULL);
}

static void
control_socket_init(struct gotwebd *env, uid_t uid, gid_t gid)
{
	struct imsgev *iev;
	int fd;

	log_info("initializing control socket %s",
	    env->control_sock->conf.unix_socket_name);

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	fd = control_socket_listen(env, env->control_sock, uid, gid);
	if (fd == -1)
		exit(1);

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");

	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, control_accept, iev);
	event_add(&iev->ev, NULL);
	evtimer_set(&env->control_pause_ev, accept_paused, NULL);

	env->iev_control = iev;
}

int
main(int argc, char **argv)
{
	struct event		 sigint, sigterm, sighup, sigpipe, sigusr1;
	struct event_base	*evb;
	struct gotwebd		*env;
	struct passwd		*pw;
	int			 ch, i, gotwebd_ngroups = NGROUPS_MAX;
	int			 no_action = 0;
	int			 proc_type = GOTWEBD_PROC_PARENT;
	const char		*conffile = GOTWEBD_CONF;
	const char		*gotwebd_username = GOTWEBD_DEFAULT_USER;
	const char		*www_username = GOTWEBD_WWW_USER;
	gid_t			 gotwebd_groups[NGROUPS_MAX];
	gid_t			 www_gid;
	const char		*argv0, *errstr;

	if ((argv0 = argv[0]) == NULL)
		argv0 = "gotwebd";

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);

	env = calloc(1, sizeof(*env));
	if (env == NULL)
		fatal("%s: calloc", __func__);
	config_init(env);

	while ((ch = getopt(argc, argv, "A:D:dG:f:F:L:nS:vW:")) != -1) {
		switch (ch) {
		case 'A':
			proc_type = GOTWEBD_PROC_AUTH;
			get_usernames(&gotwebd_username, &www_username, optarg);
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			env->gotwebd_debug = 1;
			break;
		case 'G':
			proc_type = GOTWEBD_PROC_GOTWEB;
			get_usernames(&gotwebd_username, &www_username, optarg);
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'F':
			proc_type = GOTWEBD_PROC_FCGI;
			get_usernames(&gotwebd_username, &www_username, optarg);
			break;
		case 'L':
			proc_type = GOTWEBD_PROC_LOGIN;
			get_usernames(&gotwebd_username, &www_username, optarg);
			break;
		case 'n':
			no_action = 1;
			break;
		case 'S':
			proc_type = GOTWEBD_PROC_SOCKETS;
			i = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr) {
				get_usernames(&gotwebd_username,
				    &www_username, optarg);
			} else
				env->prefork = i;
			break;
		case 'v':
			if (env->gotwebd_verbose < 3)
				env->gotwebd_verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	if (argc > 0)
		usage();

	gotwebd_env = env;
	env->gotwebd_conffile = conffile;

	if (proc_type == GOTWEBD_PROC_PARENT) {
		if (parse_config(env->gotwebd_conffile, env) == -1)
			exit(1);

		if (no_action) {
			fprintf(stderr, "configuration OK\n");
			exit(0);
		}

		if (env->user)
			gotwebd_username = env->user;
		if (env->www_user)
			www_username = env->www_user;
	}

	if (proc_type == GOTWEBD_PROC_SOCKETS) {
		env->worker_load = calloc(env->prefork,
		    sizeof(env->worker_load[0]));
		if (env->worker_load == NULL)
			fatal("calloc");
	}

	pw = getpwnam(www_username);
	if (pw == NULL)
		fatalx("unknown user %s", www_username);
	env->www_uid = pw->pw_uid;
	www_gid = pw->pw_gid;
	if (pw->pw_uid == 0 || pw->pw_gid == 0) {
		warnx("warning: detected www user \"root\" in gotwebd.conf; "
		    "running a web server with UID/GID 0 is dangerous");
	}

	pw = getpwnam(gotwebd_username);
	if (pw == NULL)
		fatalx("unknown user %s", gotwebd_username);
	if (pw->pw_uid == 0 || pw->pw_gid == 0) {
		fatalx("refusing to start up with user \"root\" set "
		    "in gotwebd.conf; running gotwebd with UID/GID 0 "
		    "is dangerous");
	}
	if (getgrouplist(gotwebd_username, pw->pw_gid, gotwebd_groups,
	    &gotwebd_ngroups) == -1)
		fatalx("too many groups for user %s", gotwebd_username);

	/* check for root privileges */
	if (geteuid())
		fatalx("need root privileges to start up");

	log_init(env->gotwebd_debug, LOG_DAEMON);
	log_setverbose(env->gotwebd_verbose);

	switch (proc_type) {
	case GOTWEBD_PROC_LOGIN:
		setproctitle("login");
		log_procinit("login");

		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		gotwebd_login(env, GOTWEBD_SOCK_FILENO);
		return 1;
	case GOTWEBD_PROC_SOCKETS:
		setproctitle("sockets");
		log_procinit("sockets");

		if (chroot(env->httpd_chroot) == -1)
			fatal("chroot %s", env->httpd_chroot);
		if (chdir("/") == -1)
			fatal("chdir /");

		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		sockets(env, GOTWEBD_SOCK_FILENO);
		return 1;
	case GOTWEBD_PROC_FCGI:
		setproctitle("fcgi");
		log_procinit("fcgi");

		if (chroot(env->httpd_chroot) == -1)
			fatal("chroot %s", env->httpd_chroot);
		if (chdir("/") == -1)
			fatal("chdir /");

		if (setgroups(gotwebd_ngroups, gotwebd_groups) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		gotwebd_fcgi(env, GOTWEBD_SOCK_FILENO);
		return 1;
	case GOTWEBD_PROC_AUTH:
		setproctitle("auth");
		log_procinit("auth");

		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		gotwebd_auth(env, GOTWEBD_SOCK_FILENO);
		return 1;
	case GOTWEBD_PROC_GOTWEB:
		setproctitle("gotweb");
		log_procinit("gotweb");

		if (setgroups(gotwebd_ngroups, gotwebd_groups) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		gotweb(env, GOTWEBD_SOCK_FILENO);
		return 1;
	default:
		break;
	}

	if (!env->gotwebd_debug && daemon(1, 0) == -1)
		fatal("daemon");

	evb = event_init();

	control_socket_init(env, pw->pw_uid, pw->pw_gid);

	env->iev_sockets = calloc(1, sizeof(*env->iev_sockets));
	if (env->iev_sockets == NULL)
		fatal("calloc");

	env->iev_login = calloc(1, sizeof(*env->iev_login));
	if (env->iev_login == NULL)
		fatal("calloc");

	env->iev_fcgi = calloc(1, sizeof(*env->iev_fcgi));
	if (env->iev_fcgi == NULL)
		fatal("calloc");

	env->iev_auth = calloc(env->prefork, sizeof(*env->iev_auth));
	if (env->iev_auth == NULL)
		fatal("calloc");

	env->iev_gotweb = calloc(env->prefork, sizeof(*env->iev_gotweb));
	if (env->iev_gotweb == NULL)
		fatal("calloc");

	spawn_process(env, argv0, env->iev_sockets,
	    GOTWEBD_PROC_SOCKETS, gotwebd_username, www_username,
	    gotwebd_dispatch_server);

	spawn_process(env, argv0, env->iev_login, GOTWEBD_PROC_LOGIN,
	    gotwebd_username, www_username, gotwebd_dispatch_login);

	spawn_process(env, argv0, env->iev_fcgi,
	    GOTWEBD_PROC_FCGI, gotwebd_username, www_username,
	    gotwebd_dispatch_fcgi);

	for (i = 0; i < env->prefork; ++i) {
		spawn_process(env, argv0, &env->iev_auth[i],
		    GOTWEBD_PROC_AUTH, gotwebd_username, www_username,
		    gotwebd_dispatch_auth);
		spawn_process(env, argv0, &env->iev_gotweb[i],
		    GOTWEBD_PROC_GOTWEB, gotwebd_username, www_username,
		    gotwebd_dispatch_gotweb);
	}

	if (chdir("/") == -1)
		fatal("chdir /");

	log_procinit("gotwebd");

	log_info("%s startup", getprogname());

	signal_set(&sigint, SIGINT, gotwebd_sighdlr, env);
	signal_set(&sigterm, SIGTERM, gotwebd_sighdlr, env);
	signal_set(&sighup, SIGHUP, gotwebd_sighdlr, env);
	signal_set(&sigpipe, SIGPIPE, gotwebd_sighdlr, env);
	signal_set(&sigusr1, SIGUSR1, gotwebd_sighdlr, env);

	signal_add(&sigint, NULL);
	signal_add(&sigterm, NULL);
	signal_add(&sighup, NULL);
	signal_add(&sigpipe, NULL);
	signal_add(&sigusr1, NULL);

	if (gotwebd_configure(env, pw->pw_uid, www_gid) == -1)
		fatalx("configuration failed");

	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("failed to drop privileges");

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		err(1, "gmon.out");
#endif

	if (unveil(GOTWEBD_CONF, "r") == -1)
		err(1, "unveil");

	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

#ifndef PROFILE
	if (pledge("stdio unix", NULL) == -1)
		err(1, "pledge");
#endif

	event_dispatch();

	gotwebd_shutdown();

	event_base_free(evb);

	return (0);
}

static void
connect_children(struct gotwebd *env)
{
	struct imsgev *iev_gotweb, *iev_auth;
	int pipe[2];
	int i;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe) == -1)
		fatal("socketpair");

	if (main_compose_sockets(env, GOTWEBD_IMSG_CTL_PIPE, pipe[0], NULL, 0))
		fatal("main_compose_sockets");

	if (send_imsg(env->iev_fcgi, GOTWEBD_IMSG_CTL_PIPE, pipe[1], NULL, 0))
		fatal("send_imsg");

	for (i = 0; i < env->prefork; i++) {
		iev_gotweb = &env->iev_gotweb[i];
		iev_auth = &env->iev_auth[i];

		if (socketpair(AF_UNIX,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    PF_UNSPEC, pipe) == -1)
			fatal("socketpair");

		if (main_compose_sockets(env, GOTWEBD_IMSG_CTL_PIPE,
		    pipe[0], NULL, 0))
			fatal("send_imsg");

		if (send_imsg(iev_auth, GOTWEBD_IMSG_CTL_PIPE,
		    pipe[1], NULL, 0))
			fatal("send_imsg");

		if (socketpair(AF_UNIX,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    PF_UNSPEC, pipe) == -1)
			fatal("socketpair");

		if (send_imsg(iev_auth, GOTWEBD_IMSG_CTL_PIPE,
		    pipe[0], NULL, 0))
			fatal("send_imsg");

		if (send_imsg(iev_gotweb, GOTWEBD_IMSG_CTL_PIPE,
		    pipe[1], NULL, 0))
			fatal("send_imsg");
	}
}

int
gotwebd_configure(struct gotwebd *env, uid_t uid, gid_t gid)
{
	struct server *srv;
	struct socket *sock;
	struct gotwebd_repo *repo;
	struct got_pathlist_entry *pe;
	struct media_type *mt;
	char secret[32];
	int i;

	/* gotweb need to reload its config. */
	env->gotweb_pending = env->prefork;
	env->auth_pending = env->prefork;

	/* send global access rules */
	for (i = 0; i < env->prefork; ++i) {
		config_set_access_rules(&env->iev_auth[i],
		    &env->access_rules);
		config_set_access_rules(&env->iev_gotweb[i],
		    &env->access_rules);
	}

	/* send the mime mapping */
	RB_FOREACH(mt, mediatypes, &env->mediatypes) {
		if (main_compose_gotweb(env, GOTWEBD_IMSG_CFG_MEDIA_TYPE,
		    -1, mt, sizeof(*mt)) == -1)
			fatal("send_imsg GOTWEBD_IMSG_CFG_MEDIA_TYPE");
	}

	/* send our gotweb servers */
	TAILQ_FOREACH(srv, &env->servers, entry) {
		if (main_compose_sockets(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("send_imsg GOTWEBD_IMSG_CFG_SRV");
		if (main_compose_auth(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("main_compose_gotweb GOTWEBD_IMSG_CFG_SRV");
		if (main_compose_gotweb(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("main_compose_gotweb GOTWEBD_IMSG_CFG_SRV");
		if (main_compose_login(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("main_compose_gotweb GOTWEBD_IMSG_CFG_SRV");

		/* send per-server access rules */
		for (i = 0; i < env->prefork; ++i) {
			config_set_access_rules(&env->iev_auth[i],
			    &srv->access_rules);
			config_set_access_rules(&env->iev_gotweb[i],
			    &srv->access_rules);
		}

		/* send web sites and per-site access rules */
		RB_FOREACH(pe, got_pathlist_head, &srv->websites) {
			struct website *site = pe->data;

			for (i = 0; i < env->prefork; i++) {
				config_set_website(&env->iev_auth[i], site);
				config_set_website(&env->iev_gotweb[i], site);

				config_set_access_rules(&env->iev_auth[i],
				    &site->access_rules);
				config_set_access_rules(&env->iev_gotweb[i],
				    &site->access_rules);
			}
		}

		/* send repositories and per-repository access rules */
		TAILQ_FOREACH(repo, &srv->repos, entry) {
			for (i = 0; i < env->prefork; i++) {
				config_set_repository(&env->iev_auth[i],
				    repo);
				config_set_repository(&env->iev_gotweb[i],
				    repo);

				config_set_access_rules(&env->iev_auth[i],
				    &repo->access_rules);
				config_set_access_rules(&env->iev_gotweb[i],
				    &repo->access_rules);
			}
		}

		for (i = 0; i < env->prefork; i++) {
			if (imsgbuf_flush(&env->iev_auth[i].ibuf) == -1)
				fatal("imsgbuf_flush");
			imsg_event_add(&env->iev_auth[i]);

			if (imsgbuf_flush(&env->iev_gotweb[i].ibuf) == -1)
				fatal("imsgbuf_flush");
			imsg_event_add(&env->iev_gotweb[i]);
		}
	}

	/* send our sockets */
	TAILQ_FOREACH(sock, &env->sockets, entry) {
		if (config_setsock(env, sock, uid, gid) == -1)
			fatalx("%s: send socket error", __func__);
	}

	/* send the temp files */
	if (config_setfd(env) == -1)
		fatalx("%s: send priv_fd error", __func__);

	/* Connect servers and gotwebs. */
	connect_children(env);

	if (main_compose_auth(env, GOTWEBD_IMSG_AUTH_CONF, -1,
	    &env->auth_config, sizeof(env->auth_config)) == -1)
		fatal("send_imsg GOTWEB_IMSG_AUTH_CONF");
	if (main_compose_gotweb(env, GOTWEBD_IMSG_AUTH_CONF, -1,
	    &env->auth_config, sizeof(env->auth_config)) == -1)
		fatal("main_compose_gotweb GOTWEB_IMSG_AUTH_CONF");

	if (main_compose_auth(env, GOTWEBD_IMSG_WWW_UID, -1,
	    &env->www_uid, sizeof(env->www_uid)) == -1)
		fatal("main_compose_auth GOTWEB_IMSG_WWW_UID");
	if (main_compose_gotweb(env, GOTWEBD_IMSG_WWW_UID, -1,
	    &env->www_uid, sizeof(env->www_uid)) == -1)
		fatal("main_compose_gotweb GOTWEB_IMSG_WWW_UID");

	arc4random_buf(secret, sizeof(secret));

	if (main_compose_login(env, GOTWEBD_IMSG_LOGIN_SECRET, -1,
	    secret, sizeof(secret)) == -1)
		fatal("main_compose_login GOTWEB_IMSG_LOGIN_SECRET");
	if (main_compose_auth(env, GOTWEBD_IMSG_LOGIN_SECRET, -1,
	    secret, sizeof(secret)) == -1)
		fatal("main_compose_auth GOTWEB_IMSG_LOGIN_SECRET");

	arc4random_buf(secret, sizeof(secret));

	if (main_compose_auth(env, GOTWEBD_IMSG_AUTH_SECRET, -1,
	    secret, sizeof(secret)) == -1)
		fatal("main_compose_auth GOTWEB_IMSG_AUTH_SECRET");

	explicit_bzero(secret, sizeof(secret));

	if (login_privinit(env, uid, gid) == -1)
		fatalx("cannot open authentication socket");

	if (main_compose_login(env, GOTWEBD_IMSG_CFG_SOCK, env->login_sock->fd,
	    NULL, 0) == -1)
		fatal("main_compose_login GOTWEBD_IMSG_CFG_SOCK");

	if (main_compose_sockets(env, GOTWEBD_IMSG_CFG_DONE, -1,
	    NULL, 0) == -1)
		fatal("send_imsg GOTWEBD_IMSG_CFG_DONE");

	return (0);
}

void
gotwebd_configure_done(struct gotwebd *env)
{
	if (main_compose_sockets(env, GOTWEBD_IMSG_CTL_START,
	    -1, NULL, 0) == -1)
		fatal("send_imsg GOTWEBD_IMSG_CTL_START");

	if (env->gotweb_pending > 0) {
		env->gotweb_pending--;
		if (env->gotweb_pending == 0 &&
		    main_compose_gotweb(env, GOTWEBD_IMSG_CTL_START,
		        -1, NULL, 0) == -1)
			fatal("main_compose_gotweb GOTWEBD_IMSG_CTL_START");
	}

	if (env->auth_pending > 0) {
		env->auth_pending--;
		if (env->auth_pending == 0 &&
		    main_compose_auth(env, GOTWEBD_IMSG_CTL_START,
		        -1, NULL, 0) == -1)
			fatal("main_compose_auth GOTWEBD_IMSG_CTL_START");
	}

	if (main_compose_login(env, GOTWEBD_IMSG_CTL_START,
	    -1, NULL, 0) == -1)
		fatal("send_imsg GOTWEBD_IMSG_CTL_START");
}

void
gotwebd_shutdown(void)
{
	struct gotwebd	*env = gotwebd_env;
	pid_t		 pid;
	int		 i, status;

	media_purge(&gotwebd_env->mediatypes);

	event_del(&env->iev_login->ev);
	imsgbuf_clear(&env->iev_login->ibuf);
	close(env->iev_login->ibuf.fd);
	env->iev_login->ibuf.fd = -1;
	free(env->iev_login);

	event_del(&env->iev_sockets->ev);
	imsgbuf_clear(&env->iev_sockets->ibuf);
	close(env->iev_sockets->ibuf.fd);
	env->iev_sockets->ibuf.fd = -1;
	free(env->iev_sockets);

	event_del(&env->iev_fcgi->ev);
	imsgbuf_clear(&env->iev_fcgi->ibuf);
	close(env->iev_fcgi->ibuf.fd);
	env->iev_fcgi->ibuf.fd = -1;
	free(env->iev_fcgi);

	for (i = 0; i < env->prefork; ++i) {
		event_del(&env->iev_auth[i].ev);
		imsgbuf_clear(&env->iev_auth[i].ibuf);
		close(env->iev_auth[i].ibuf.fd);
		env->iev_auth[i].ibuf.fd = -1;

		event_del(&env->iev_gotweb[i].ev);
		imsgbuf_clear(&env->iev_gotweb[i].ibuf);
		close(env->iev_gotweb[i].ibuf.fd);
		env->iev_gotweb[i].ibuf.fd = -1;
	}
	free(env->iev_auth);
	free(env->iev_gotweb);

	free(env->login_sock);

	control_socket_destroy();

	do {
		pid = waitpid(WAIT_ANY, &status, 0);
		if (pid <= 0)
			continue;

		if (WIFSIGNALED(status))
			log_warnx("lost child: pid %u terminated; signal %d",
			    pid, WTERMSIG(status));
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			log_warnx("lost child: pid %u exited abnormally",
			    pid);
	} while (pid != -1 || (pid == -1 && errno == EINTR));

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
	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);
		free(srv);
	}
	free(gotwebd_env);

	log_warnx("gotwebd terminating");
}
