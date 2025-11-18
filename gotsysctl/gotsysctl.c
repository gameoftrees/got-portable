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

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <locale.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <vis.h>

#include "got_error.h"
#include "got_version.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"

#include "got_lib_poll.h"

#include "gotsysd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

struct gotsysctl_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[], int);
	void		(*cmd_usage)(int);
};

__dead static void	usage(int, int);

__dead static void	usage_info(int);

static const struct got_error*		cmd_info(int, char *[], int);

static const struct gotsysctl_cmd gotsysctl_commands[] = {
	{ "info",	cmd_info,	usage_info },
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
	const struct got_error *err = NULL;
	struct gotsysd_imsg_info info;
	size_t datalen;
	char *repo_dir_safe = NULL, *commit_id_str = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	info.repository_directory[sizeof(info.repository_directory) - 1] = '\0';

	if (info.commit_id.algo == GOT_HASH_SHA1 ||
	    info.commit_id.algo == GOT_HASH_SHA256) {
		err = got_object_id_str(&commit_id_str, &info.commit_id);
		if (err)
			return err;
	}

	if (stravis(&repo_dir_safe, info.repository_directory,
	    VIS_SAFE) == -1)
		return got_error_from_errno("stravis");

	printf("gotsysd PID: %d\n", info.pid);
	printf("verbosity: %d\n", info.verbosity);
	printf("repository directory: %s\n", repo_dir_safe);
	printf("UID range: %u-%u\n", info.uid_start, info.uid_end);
	printf("gotsys.conf commit: %s\n",
	    commit_id_str ? commit_id_str : "unknown");

	free(repo_dir_safe);
	free(commit_id_str);
	return NULL;
}

static const struct got_error *
apply_unveil_none(void)
{
	if (unveil("/", "") == -1)
		return got_error_from_errno("unveil");

	if (unveil(NULL, NULL) == -1)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[], int gotsysd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;

	err = apply_unveil_none();
	if (err)
		return err;
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if (imsgbuf_init(&ibuf, gotsysd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOTSYSD_IMSG_CMD_INFO, 0, 0, -1,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose INFO");
		goto done;
	}

	err = gotsysd_imsg_flush(&ibuf);
	if (err)
		goto done;

	err = gotsysd_imsg_poll_recv(&imsg, &ibuf, 0);
	if (err)
		goto done;

	switch (imsg.hdr.type) {
	case GOTSYSD_IMSG_ERROR:
		err = gotsysd_imsg_recv_error(NULL, &imsg);
		break;
	case GOTSYSD_IMSG_INFO:
		err = show_info(&imsg);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
done:
	imsgbuf_clear(&ibuf);
	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotsysctl_commands); i++) {
		const struct gotsysctl_cmd *cmd = &gotsysctl_commands[i];
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
connect_gotsysd(const char *socket_path)
{
	int gotsysd_sock = -1;
	struct sockaddr_un sun;

	if ((gotsysd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "gotsysd socket path too long");
	if (connect(gotsysd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", socket_path);

	return gotsysd_sock;
}

int
main(int argc, char *argv[])
{
	const struct gotsysctl_cmd *cmd;
	int gotsysd_sock = -1, i;
	int ch;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};
	const char *socket_path = GOTSYSD_UNIX_SOCKET;

	setlocale(LC_CTYPE, "");

	signal(SIGINT, catch_sigint);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unix unveil", NULL) == -1)
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

	for (i = 0; i < nitems(gotsysctl_commands); i++) {
		const struct got_error *error;

		cmd = &gotsysctl_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage(0);

		gotsysd_sock = connect_gotsysd(socket_path);
		if (gotsysd_sock == -1)
			return 1;
		error = cmd->cmd_main(argc, argv, gotsysd_sock);
		close(gotsysd_sock);
		if (error) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}
