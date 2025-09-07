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
void	 gotwebd_dispatch_gotweb(int, short, void *);

struct gotwebd	*gotwebd_env;

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
sockets_compose_main(struct gotwebd *env, uint32_t type, const void *d,
    uint16_t len)
{
	return (imsg_compose_event(env->iev_parent, type, 0, -1, -1, d, len));
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
	case SIGINT:
		gotwebd_shutdown();
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static void
spawn_process(struct gotwebd *env, const char *argv0, struct imsgev *iev,
    enum gotwebd_proc_type proc_type, const char *username,
    void (*handler)(int, short, void *))
{
	const char	*argv[10];
	int		 argc = 0;
	int		 p[2];
	pid_t		 pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
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
	if (proc_type == GOTWEBD_PROC_SERVER) {
		char *s;

		argv[argc++] = "-S";
		argv[argc++] = username;
		if (asprintf(&s, "-S%d", env->prefork) == -1)
			fatal("asprintf");
		argv[argc++] = s;
	} else if (proc_type == GOTWEBD_PROC_FCGI) {
		argv[argc++] = "-F";
		argv[argc++] = username;
	} else if (proc_type == GOTWEBD_PROC_GOTWEB) {
		char *s;

		argv[argc++] = "-G";
		argv[argc++] = username;
		if (asprintf(&s, "-G%d", env->server_cnt) == -1)
			fatal("asprintf");
		argv[argc++] = s;
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

	while ((ch = getopt(argc, argv, "D:dG:f:F:nS:vW:")) != -1) {
		switch (ch) {
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
			i = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr)
				gotwebd_username = optarg;
			else
				env->server_cnt = i;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'F':
			proc_type = GOTWEBD_PROC_FCGI;
			gotwebd_username = optarg;
			break;
		case 'n':
			no_action = 1;
			break;
		case 'S':
			proc_type = GOTWEBD_PROC_SERVER;
			i = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr)
				gotwebd_username = optarg;
			else
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

	if (proc_type == GOTWEBD_PROC_SERVER) {
		env->worker_load = calloc(env->prefork,
		    sizeof(env->worker_load[0]));
		if (env->worker_load == NULL)
			fatal("calloc");
	}

	pw = getpwnam(www_username);
	if (pw == NULL)
		fatalx("unknown user %s", www_username);
	www_gid = pw->pw_gid;

	pw = getpwnam(gotwebd_username);
	if (pw == NULL)
		fatalx("unknown user %s", gotwebd_username);
	if (getgrouplist(gotwebd_username, pw->pw_gid, gotwebd_groups,
	    &gotwebd_ngroups) == -1)
		fatalx("too many groups for user %s", gotwebd_username);

	/* check for root privileges */
	if (geteuid())
		fatalx("need root privileges");

	log_init(env->gotwebd_debug, LOG_DAEMON);
	log_setverbose(env->gotwebd_verbose);

	switch (proc_type) {
	case GOTWEBD_PROC_SERVER:
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

	env->iev_sockets = calloc(1, sizeof(*env->iev_sockets));
	if (env->iev_sockets == NULL)
		fatal("calloc");

	env->iev_fcgi = calloc(1, sizeof(*env->iev_fcgi));
	if (env->iev_fcgi == NULL)
		fatal("calloc");

	env->iev_gotweb = calloc(env->prefork, sizeof(*env->iev_gotweb));
	if (env->iev_gotweb == NULL)
		fatal("calloc");

	spawn_process(env, argv0, env->iev_sockets,
	    GOTWEBD_PROC_SERVER, gotwebd_username,
	    gotwebd_dispatch_server);

	spawn_process(env, argv0, env->iev_fcgi,
	    GOTWEBD_PROC_FCGI, gotwebd_username,
	    gotwebd_dispatch_fcgi);

	for (i = 0; i < env->prefork; ++i) {
		spawn_process(env, argv0, &env->iev_gotweb[i],
		    GOTWEBD_PROC_GOTWEB, gotwebd_username,
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
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	event_dispatch();
	event_base_free(evb);

	log_debug("%s gotwebd exiting", getprogname());

	return (0);
}

static void
connect_children(struct gotwebd *env)
{
	struct imsgev *iev_gotweb;
	int pipe[2];
	int i;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
		fatal("socketpair");

	if (main_compose_sockets(env, GOTWEBD_IMSG_CTL_PIPE, pipe[0], NULL, 0))
		fatal("main_compose_sockets");

	if (send_imsg(env->iev_fcgi, GOTWEBD_IMSG_CTL_PIPE, pipe[1], NULL, 0))
		fatal("send_imsg");

	for (i = 0; i < env->prefork; i++) {
		iev_gotweb = &env->iev_gotweb[i];

		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
			fatal("socketpair");

		if (main_compose_sockets(env, GOTWEBD_IMSG_CTL_PIPE,
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

	/* gotweb need to reload its config. */
	env->gotweb_pending = env->prefork;

	/* send our gotweb servers */
	TAILQ_FOREACH(srv, &env->servers, entry) {
		if (main_compose_sockets(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("send_imsg GOTWEBD_IMSG_CFG_SRV");
		if (main_compose_gotweb(env, GOTWEBD_IMSG_CFG_SRV,
		    -1, srv, sizeof(*srv)) == -1)
			fatal("main_compose_gotweb GOTWEBD_IMSG_CFG_SRV");
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
			fatal("main_compose_sockets GOTWEBD_IMSG_CTL_START");
	}
}

void
gotwebd_shutdown(void)
{
	struct gotwebd	*env = gotwebd_env;
	pid_t		 pid;
	int		 i, status;

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
		event_del(&env->iev_gotweb[i].ev);
		imsgbuf_clear(&env->iev_gotweb[i].ibuf);
		close(env->iev_gotweb[i].ibuf.fd);
		env->iev_gotweb[i].ibuf.fd = -1;
	}
	free(env->iev_gotweb);

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
	exit(0);
}
