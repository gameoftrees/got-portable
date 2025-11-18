/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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
#include <sha1.h>
#include <sha2.h>
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

#include "got_lib_gitproto.h"

#include "gotd.h"
#include "secrets.h"
#include "log.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define GOTCTL_CMD_INFO "info"
#define GOTCTL_CMD_STOP "stop"

struct gotctl_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[], int);
	void		(*cmd_usage)(int);
};

__dead static void	usage(int, int);

__dead static void	usage_info(int);
__dead static void	usage_stop(int);
__dead static void	usage_reload(int);

static const struct got_error*		cmd_info(int, char *[], int);
static const struct got_error*		cmd_stop(int, char *[], int);
static const struct got_error*		cmd_reload(int, char *[], int);

static const struct gotctl_cmd gotctl_commands[] = {
	{ "info",	cmd_info,	usage_info },
	{ "stop",	cmd_stop,	usage_stop },
	{ "reload",	cmd_reload,	usage_reload },
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
	struct gotd_imsg_info info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("gotd PID: %d\n", info.pid);
	printf("verbosity: %d\n", info.verbosity);
	printf("number of repositories: %d\n", info.nrepos);
	printf("number of connected clients: %d\n", info.nclients);
	return NULL;
}

static const struct got_error *
show_repo_info(struct imsg *imsg)
{
	struct gotd_imsg_info_repo info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("repository \"%s\", path %s\n", info.repo_name, info.repo_path);
	return NULL;
}

static char *
get_datestr(time_t *time, char *datebuf)
{
	struct tm mytm, *tm;
	char *p, *s;

	tm = localtime_r(time, &mytm);
	if (tm == NULL)
		return NULL;
	s = asctime_r(tm, datebuf);
	if (s == NULL)
		return NULL;
	p = strchr(s, '\n');
	if (p)
		*p = '\0';
	return s;
}

static const struct got_error *
show_client_info(struct imsg *imsg)
{
	struct gotd_imsg_info_client info;
	size_t datalen;
	char *datestr;
	char datebuf[26];

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	datestr = get_datestr(&info.time_connected, datebuf);

	printf("client UID %d, GID %d, ", info.euid, info.egid);
	if (info.session_child_pid)
		printf("session PID %ld, ", (long)info.session_child_pid);
	if (info.repo_child_pid)
		printf("repo PID %ld, ", (long)info.repo_child_pid);
	if (info.is_writing) {
		printf("writing to repository \"%s\"%s%s\n", info.repo_name,
		    datestr ? " since " : "",
		    datestr ? datestr : "");
	} else {
		printf("reading from repository \"%s\"%s%s\n", info.repo_name,
		    datestr ? " since " : "",
		    datestr ? datestr : "");
	}

	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[], int gotd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if (imsgbuf_init(&ibuf, gotd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOTD_IMSG_INFO, 0, 0, -1, NULL, 0) == -1) {
		imsgbuf_clear(&ibuf);
		return got_error_from_errno("imsg_compose INFO");
	}

	err = gotd_imsg_flush(&ibuf);
	while (err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_EOF)
				err = NULL;
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_INFO:
			err = show_info(&imsg);
			break;
		case GOTD_IMSG_INFO_REPO:
			err = show_repo_info(&imsg);
			break;
		case GOTD_IMSG_INFO_CLIENT:
			err = show_client_info(&imsg);
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
cmd_stop(int argc, char *argv[], int gotd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if (imsgbuf_init(&ibuf, gotd_sock) == -1)
		return got_error_from_errno("imsgbuf_init");

	if (imsg_compose(&ibuf, GOTD_IMSG_STOP, 0, 0, -1, NULL, 0) == -1) {
		imsgbuf_clear(&ibuf);
		return got_error_from_errno("imsg_compose STOP");
	}

	err = gotd_imsg_flush(&ibuf);
	while (err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_EOF)
				err = NULL;
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
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
usage_reload(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s reload [-c config-file] [-s secrets]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
check_file_secrecy(int fd, const char *fname)
{
	struct stat st;

	if (fstat(fd, &st))
		return got_error_from_errno2("stat", fname);

	if (st.st_uid != 0) {
		return got_error_fmt(GOT_ERR_UID,
		    "secrets file %s must be owned by root", fname);
	}

	if (st.st_gid != 0) {
		return got_error_fmt(GOT_ERR_GID,
		    "secrets file %s must be owned by group wheel/root",
		    fname);
	}

	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		return got_error_fmt(GOT_ERR_GID,
		    "secrets file %s must not be group writable or world "
		    "readable/writable", fname);
	}

	return NULL;
}

static const struct got_error *
cmd_reload(int argc, char *argv[], int gotd_sock)
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	struct gotd gotd;
	struct gotd_secrets *secrets = NULL;
	struct imsg imsg;
	char *confpath = NULL, *secretspath = NULL;
	int ch, conf_fd = -1, secrets_fd = -1;
	int no_action = 0;

	log_init(1, LOG_DAEMON); /* log to stderr . */

#ifndef PROFILE
	if (pledge("stdio rpath sendfd unveil", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	while ((ch = getopt(argc, argv, "c:ns:")) != -1) {
		switch (ch) {
		case 'c':
			if (unveil(optarg, "r") != 0)
				return got_error_from_errno("unveil");
			confpath = realpath(optarg, NULL);
			if (confpath == NULL) {
				return got_error_from_errno2("realpath",
				    optarg);
			}
			break;
		case 'n':
			no_action = 1;
			break;
		case 's':
			if (unveil(optarg, "r") != 0)
				return got_error_from_errno("unveil");
			secretspath = realpath(optarg, NULL);
			if (secretspath == NULL) {
				return got_error_from_errno2("realpath",
				    optarg);
			}
			break;
		default:
			usage_reload(1);
			/* NOTREACHED */
		}
	}

	if (confpath == NULL) {
		confpath = strdup(GOTD_CONF_PATH);
		if (confpath == NULL)
			return got_error_from_errno("strdup");
	}

	if (unveil(confpath, "r") != 0)
		return got_error_from_errno("unveil");

	if (unveil(secretspath ? secretspath : GOTD_SECRETS_PATH, "r") != 0)
		return got_error_from_errno("unveil");

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	secrets_fd = open(secretspath ? secretspath : GOTD_SECRETS_PATH,
	    O_RDONLY | O_NOFOLLOW);
	if (secrets_fd == -1) {
		if (secretspath != NULL || errno != ENOENT) {
			return got_error_from_errno2("open",
			    secretspath ? secretspath : GOTD_SECRETS_PATH);
		}
	} else if (secretspath == NULL) {
		secretspath = strdup(GOTD_SECRETS_PATH);
		if (secretspath == NULL)
			return got_error_from_errno("strdup");
	}

	conf_fd = open(confpath, O_RDONLY | O_NOFOLLOW);
	if (conf_fd == -1)
		return got_error_from_errno2("open", confpath);

	if (secrets_fd != -1) {
		int fd;
		FILE *fp;

		err = check_file_secrecy(secrets_fd, secretspath);
		if (err)
			goto done;

		fd = dup(secrets_fd);
		if (fd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}

		fp = fdopen(fd, "r");
		if (fp == NULL) {
			err = got_error_from_errno2("fdopen", secretspath);
			close(fd);
			goto done;
		}
		err = gotd_secrets_parse(secretspath, fp, &secrets);
		fclose(fp);
		if (err) {
			err = got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "failed to parse secrets file %s: %s",
			    secretspath, err->msg);
			goto done;
		}
	}

	if (gotd_parse_config(confpath, conf_fd, GOTD_PROC_GOTCTL,
	    secrets, &gotd) != 0) {
		/* Errors were already printed. Silence this one. */
		err = got_error_msg(GOT_ERR_PARSE_CONFIG, "");
		goto done;
	}

	if (no_action) {
		fprintf(stderr, "configuration OK\n");
		goto done;
	}

#ifndef PROFILE
	if (pledge("stdio sendfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (secrets_fd != -1 && lseek(secrets_fd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", secretspath);
		goto done;
	}
	if (lseek(conf_fd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", confpath);
		goto done;
	}

	if (imsgbuf_init(&ibuf, gotd_sock) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&ibuf);

	if (secrets_fd != -1) {
		if (imsg_compose(&ibuf, GOTD_IMSG_RELOAD_SECRETS, 0, 0,
		    secrets_fd, secretspath ? secretspath : GOTD_SECRETS_PATH,
		    secretspath ?
		    strlen(secretspath) : strlen(GOTD_SECRETS_PATH)) == -1) {
			err = got_error_from_errno("imsg_compose "
			    "RELOAD_SECRETS");
			imsgbuf_clear(&ibuf);
			goto done;
		}
		secrets_fd = -1;
	} else {
		if (imsg_compose(&ibuf, GOTD_IMSG_RELOAD_SECRETS, 0, 0, -1,
		    NULL, 0) == -1) {
			err = got_error_from_errno("imsg_compose "
			    "RELOAD_SECRETS");
			imsgbuf_clear(&ibuf);
			goto done;
		}
	}

	if (imsg_compose(&ibuf, GOTD_IMSG_RELOAD, 0, 0, conf_fd,
	    confpath, strlen(confpath)) == -1) {
		err = got_error_from_errno("imsg_compose RELOAD");
		imsgbuf_clear(&ibuf);
		goto done;

	}
	conf_fd = -1;

	err = gotd_imsg_flush(&ibuf);
	if (err)
		goto done;
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	while (err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_EOF)
				err = NULL;
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	imsgbuf_clear(&ibuf);
done:
	free(confpath);
	free(secretspath);
	if (conf_fd != -1 && close(conf_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (secrets_fd != -1 && close(secrets_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotctl_commands); i++) {
		const struct gotctl_cmd *cmd = &gotctl_commands[i];
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
connect_gotd(const char *socket_path)
{
	int gotd_sock = -1;
	struct sockaddr_un sun;

	if (unveil(socket_path, "w") != 0)
		err(1, "unveil %s", socket_path);

	if ((gotd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "gotd socket path too long");
	if (connect(gotd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", socket_path);

#ifndef PROFILE
	if (pledge("stdio rpath sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif
	return gotd_sock;
}

int
main(int argc, char *argv[])
{
	const struct gotctl_cmd *cmd;
	int gotd_sock = -1, i;
	int ch;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};
	const char *socket_path = GOTD_UNIX_SOCKET;

	setlocale(LC_CTYPE, "");

#ifndef PROFILE
	if (pledge("stdio rpath unix sendfd unveil", NULL) == -1)
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

	for (i = 0; i < nitems(gotctl_commands); i++) {
		const struct got_error *error;

		cmd = &gotctl_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage(0);
#ifdef PROFILE
		if (unveil("gmon.out", "rwc") != 0)
			err(1, "unveil", "gmon.out");
#endif
		gotd_sock = connect_gotd(socket_path);
		if (gotd_sock == -1)
			return 1;
		error = cmd->cmd_main(argc, argv, gotd_sock);
		close(gotd_sock);
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
