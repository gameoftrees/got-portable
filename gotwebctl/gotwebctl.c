/*
 * Copyright (c) 2026 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_version.h"
#include "got_path.h"
#include "got_reference.h"

#include "media.h"
#include "gotwebd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigpipe_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigpipe(int signo)
{
	sigpipe_received = 1;
}

struct gotwebctl_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[], int);
	void		(*cmd_usage)(int);
};

__dead static void	usage(int, int);

__dead static void	usage_info(int);
__dead static void	usage_stop(int);

static const struct got_error*		cmd_info(int, char *[], int);
static const struct got_error*		cmd_stop(int, char *[], int);

static const struct gotwebctl_cmd gotwebctl_commands[] = {
	{ "info",	cmd_info,	usage_info },
	{ "stop",	cmd_stop,	usage_stop },
};

__dead static void
usage_info(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s info\n", getprogname());
	exit(status);
}

static const struct got_error *
show_info(struct imsg *imsg)
{
	struct gotwebd_imsg_info info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("gotwebd PID: %d\n", info.pid);
	printf("verbosity: %d\n", info.verbosity);
	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[], int gotwebd_sock)
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	struct imsg imsg;
	ssize_t n;
	int done = 0;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if (imsgbuf_init(&ibuf, gotwebd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOTWEBD_IMSG_CTL_INFO, 0, 0, -1,
	    NULL, 0) == -1) {
		imsgbuf_clear(&ibuf);
		return got_error_from_errno("imsg_compose INFO");
	}

	if (imsgbuf_flush(&ibuf) == -1) {
		imsgbuf_clear(&ibuf);

		if (errno == EPIPE) {
			return got_error_fmt(GOT_ERR_EOF,
			    "gotwebd control socket");
		}

		return got_error_from_errno("imsgbuf_flush");
	}

	while (!done && err == NULL) {
		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		n = imsgbuf_read(&ibuf);
		if (n == -1) {
			if  (errno != EAGAIN) {
				err = got_error_from_errno("imsgbuf_read");
				break;
			}
				
			sleep(1);
			continue;
		}
		if (n == 0)
			break;

		n = imsg_get(&ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsg_get");
			break;
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case GOTWEBD_IMSG_CTL_INFO:
			err = show_info(&imsg);
			done = 1;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	imsgbuf_clear(&ibuf);
	return err;
}

__dead static void
usage_stop(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s stop\n", getprogname());
	exit(status);
}

static const struct got_error *
cmd_stop(int argc, char *argv[], int gotwebd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;
	ssize_t n;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if (imsgbuf_init(&ibuf, gotwebd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOTWEBD_IMSG_CTL_STOP, 0, 0, -1,
	    NULL, 0) == -1) {
		imsgbuf_clear(&ibuf);
		return got_error_from_errno("imsg_compose STOP");
	}

	if (imsgbuf_flush(&ibuf) == -1) {
		imsgbuf_clear(&ibuf);

		if (errno == EPIPE) {
			return got_error_fmt(GOT_ERR_EOF,
			    "gotwebd control socket");
		}

		return got_error_from_errno("imsgbuf_flush");
	}

	for (;;) {
		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		n = imsg_get(&ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsg_get");
			break;
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	imsgbuf_clear(&ibuf);
	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotwebctl_commands); i++) {
		const struct gotwebctl_cmd *cmd = &gotwebctl_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-hV] [-f path] command [arg ...]\n",
	    getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

static int
connect_gotwebd(const char *socket_path)
{
	int gotwebd_sock = -1;
	struct sockaddr_un sun;

	if (unveil(socket_path, "w") != 0)
		err(1, "unveil %s", socket_path);

	if ((gotwebd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "gotd socket path too long");
	if (connect(gotwebd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", socket_path);

	return gotwebd_sock;
}

int
main(int argc, char *argv[])
{
	const struct gotwebctl_cmd *cmd;
	int gotwebd_sock = -1, i;
	int ch;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};
	const char *socket_path = GOTWEBD_CONTROL_SOCKET;

	setlocale(LC_CTYPE, "");

#ifndef PROFILE
	if (pledge("stdio rpath unix unveil", NULL) == -1)
		err(1, "pledge");
#endif
	while ((ch = getopt_long(argc, argv, "+hf:V", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
			break;
		case 'f':
			socket_path = optarg;
			break;
		case 'V':
			Vflag = 1;
			break;
		default:
			usage(hflag, 1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	optind = 1;
	optreset = 1;

	if (Vflag) {
		got_version_print_str();
		return 0;
	}

	if (argc <= 0)
		usage(hflag, hflag ? 0 : 1);

	signal(SIGINT, catch_sigint);
	signal(SIGPIPE, catch_sigpipe);

	for (i = 0; i < nitems(gotwebctl_commands); i++) {
		const struct got_error *error;

		cmd = &gotwebctl_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage(0);
#ifdef PROFILE
		if (unveil("gmon.out", "rwc") != 0)
			err(1, "unveil", "gmon.out");
#endif
		gotwebd_sock = connect_gotwebd(socket_path);
		if (gotwebd_sock == -1)
			return 1;
		error = cmd->cmd_main(argc, argv, gotwebd_sock);
		close(gotwebd_sock);
		if (error && error->msg[0] != '\0') {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}
