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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "got_error.h"
#include "got_version.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"

#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "gotsysd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gotsys_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(int);
};

__dead static void	usage(int, int);

__dead static void	usage_apply(int);
__dead static void	usage_check(int);

static const struct got_error*		cmd_apply(int, char *[]);
static const struct got_error*		cmd_check(int, char *[]);

static const struct gotsys_cmd gotsys_commands[] = {
	{ "apply",	cmd_apply,	usage_apply },
	{ "check",	cmd_check,	usage_check },
};

static const struct got_error *
unveil_repo(const char *repo_path)
{
#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (unveil(repo_path, "r") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
cat_blob(struct got_object_id *id, struct got_repository *repo, int fd,
    FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object *blob;

	err = got_object_open_as_blob(&blob, repo, id, 8192, fd);
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, outfile, blob);
done:
	if (blob)
		got_object_blob_close(blob);
	return err;
}

static const struct got_error *
read_gotsysconf(struct got_object_id **commit_id, struct got_repository *repo,
    const char *commit_id_str, const char *filename, int tmpfd, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_object_id *id = NULL;
	struct got_commit_object *commit = NULL;
	int obj_type;

	TAILQ_INIT(&refs);

	*commit_id = NULL;

	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	err = got_repo_match_object_id(commit_id, NULL,
	    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (err)
		goto done;

	err = got_object_open_as_commit(&commit, repo, *commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&id, repo, commit, filename);
	if (err)
		goto done;

	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		err = got_error_path(filename, GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = cat_blob(id, repo, tmpfd, outfile);
done:
	if (commit)
		got_object_commit_close(commit);
	got_ref_list_free(&refs);
	if (err) {
		free(*commit_id);
		*commit_id = NULL;
	}
	free(id);
	return err;
}


__dead static void
usage_apply(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s apply [-f socket] [-r repository] "
	    "[-c commit] [-w] [filename]\n", getprogname());
	exit(status);
}

static const struct got_error *
connect_gotsysd(int *gotsysd_sock, const char *socket_path)
{
	const struct got_error *err = NULL;
	struct sockaddr_un sun;

	*gotsysd_sock = -1;

	if ((*gotsysd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return got_error_from_errno("socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		err = got_error_msg(GOT_ERR_NO_SPACE,
		    "gotsysd socket path too long");
		goto done;
	}

	if (connect(*gotsysd_sock, (struct sockaddr *)&sun,
	    sizeof(sun)) == -1) {
		err = got_error_from_errno2("connect", socket_path);
		goto done;
	}
done:
	if (err) {
		close(*gotsysd_sock);
		*gotsysd_sock = -1;
	}
	return err;
}

static const struct got_error *
recv_error(struct imsg *imsg)
{
	struct gotsysd_imsg_error ierr;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ierr))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ierr, imsg->data, sizeof(ierr));

	if (ierr.code == GOT_ERR_ERRNO)
		errno = ierr.errno_code;

	return got_error_msg(ierr.code, ierr.msg);
}

static const struct got_error *
cmd_apply(int argc, char *argv[])
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_repository *repo = NULL;
	char *repo_path = NULL;
	const char *commit_id_str = GOT_REF_HEAD;
	const char *filename = GOTSYSD_SYSCONF_FILENAME;
	const char *socket_path = GOTSYSD_UNIX_SOCKET;
	struct got_commit_object *commit = NULL;
	int ch, ret, fd = -1, sysconf_fd = -1, gotsysd_sock = -1, wait = 0;
	FILE *sysconf_file = NULL;
	struct got_object_id *commit_id = NULL;
	struct gotsysd_imsg_cmd_sysconf sysconf_cmd;
	int *pack_fds = NULL;
	ssize_t n;

	memset(&ibuf, 0, sizeof(ibuf));

	while ((ch = getopt(argc, argv, "f:c:r:w")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'f':
			socket_path = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL) {
				err = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'w':
			wait = 1;
			break;
		default:
			usage_apply(1);
			/* NOTREACHED */
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage_apply(1);

	filename = (argc == 1 ? argv[0] : GOTSYSD_SYSCONF_FILENAME);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath sendfd unix unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	err = connect_gotsysd(&gotsysd_sock, socket_path);
	if (err)
		goto done;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath sendfd unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	fd = got_opentempfd();
	if (fd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	sysconf_file = got_opentemp();
	if (sysconf_file == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	err = got_repo_pack_fds_open(&pack_fds);
	if (err != NULL)
		goto done;
#ifndef PROFILE
	if (pledge("stdio rpath sendfd unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (repo_path == NULL) {
		repo_path = strdup(GOTSYSD_REPOSITORIES_PATH "/"
		    GOTSYS_SYSTEM_REPOSITORY_NAME ".git");
		if (repo_path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	err = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (err != NULL)
		goto done;

	err = unveil_repo(got_repo_get_path(repo));
	if (err)
		goto done;

	err = read_gotsysconf(&commit_id, repo, commit_id_str, filename, fd,
	    sysconf_file);
	if (err)
		goto done;
#ifndef PROFILE
	if (pledge("stdio sendfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (imsgbuf_init(&ibuf, gotsysd_sock) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&ibuf);

	sysconf_fd = dup(fileno(sysconf_file));
	if (sysconf_fd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	memset(&sysconf_cmd, 9, sizeof(sysconf_cmd));
	memcpy(&sysconf_cmd.commit_id, commit_id,
	    sizeof(sysconf_cmd.commit_id));
	ret = imsg_compose(&ibuf, GOTSYSD_IMSG_CMD_SYSCONF, 0, getpid(),
	    sysconf_fd, &sysconf_cmd, sizeof(sysconf_cmd));
	if (ret == -1) {
		err = got_error_from_errno("imsg_compose");
		goto done;
	}
	sysconf_fd = -1;

	ret = imsgbuf_flush(&ibuf);
	if (ret == -1) {
		err = got_error_from_errno("imsgbuf_flush");
		goto done;
	}
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	do {
		n = imsgbuf_read(&ibuf);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_read");
			goto done;
		}
		if (n == 0) {
			err = got_error(GOT_ERR_EOF);
			goto done;
		}

		n = imsg_get(&ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsg_get");
			goto done;
		}
		if (n == 0) {
			err = got_error(GOT_ERR_PRIVSEP_READ);
			goto done;
		}

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_ERROR:
			err = recv_error(&imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_STARTED:
			break;
		case GOTSYSD_IMSG_SYSCONF_SUCCESS:
			printf("sysconf success\n");
			wait = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_FAILURE:
			err = got_error_fmt(GOT_ERR_ON_SERVER_SIDE,
			    "sysconf failure");
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	} while (err == NULL && wait);
done:
	imsgbuf_clear(&ibuf);
	free(repo_path);
	if (commit)
		got_object_commit_close(commit);
	free(commit_id);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (err == NULL)
			err = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (err == NULL)
			err = pack_err;
	}
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (sysconf_file && fclose(sysconf_file) == EOF && err == NULL)
		err = got_error_from_errno("close");
	if (sysconf_fd != -1 && close(sysconf_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");

	return err;
}

__dead static void
usage_check(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s check [-q] [-f file]\n", getprogname());
	exit(status);
}

static const struct got_error *
unveil_none(void)
{
	if (unveil("/", "") != 0)
		return got_error_from_errno("unveil");

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
unveil_conf(const char *config_file)
{
#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (config_file) {
		if (unveil(config_file, "r") != 0)
			return got_error_from_errno2("unveil", config_file);
	}

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
cmd_check(int argc, char *argv[])
{
	const struct got_error *err;
	int ch, fd = -1, quiet = 0;
	char *configfile = NULL;
	struct gotsys_conf gotsysconf;
	struct stat sb;

	gotsys_conf_init(&gotsysconf);

	while ((ch = getopt(argc, argv, "f:q")) != -1) {
		switch (ch) {
		case 'q':
			quiet = 1;
			break;
		case 'f':
			if (strcmp(optarg, "-") == 0) {
				fd = STDIN_FILENO;
				configfile = strdup("stdin");
				if (configfile == NULL)
					return got_error_from_errno("strdup");
				break;
			}
			configfile = realpath(optarg, NULL);
			if (configfile == NULL) {
				return got_error_from_errno2("realpath",
				    optarg);
			}
			got_path_strip_trailing_slashes(configfile);
			break;
		default:
			usage_check(1);
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage_check(1);

	if (fd != STDIN_FILENO && configfile == NULL) {
		configfile = strdup(GOTSYSD_SYSCONF_FILENAME);
		if (configfile == NULL)
			return got_error_from_errno("strdup");
	}

#ifndef PROFILE
	if (pledge("stdio rpath unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (fd == STDIN_FILENO) {
		err = unveil_none();
		if (err)
			goto done;
	} else {
		err = unveil_conf(configfile);
		if (err)
			goto done;

		fd = open(configfile, O_RDONLY);
		if (fd == -1) {
			err = got_error_from_errno2("open", configfile);
			goto done;
		}
	}

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (fd != STDIN_FILENO) {
		if (fstat(fd, &sb) == -1) {
			err = got_error_from_errno2("fstat", configfile);
			goto done;
		}
		if (!S_ISREG(sb.st_mode)) {
			err = got_error_fmt(GOT_ERR_BAD_PATH,
			    "%s is not a regular file", configfile);
			goto done;
		}
	}

	err = gotsys_conf_parse(configfile, &gotsysconf, &fd);
	if (err)
		goto done;

	if (!quiet)
		printf("configuration OK\n");
done:
	if (fd != -1 && fd != STDIN_FILENO && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", configfile);
	free(configfile);
	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotsys_commands); i++) {
		const struct gotsys_cmd *cmd = &gotsys_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-hV] command [arg ...]\n", getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

int
main(int argc, char *argv[])
{
	const struct gotsys_cmd *cmd;
	int ch, i;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};

	setlocale(LC_CTYPE, "");

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unix sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt_long(argc, argv, "+hV", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
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

	for (i = 0; i < nitems(gotsys_commands); i++) {
		const struct got_error *error;

		cmd = &gotsys_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage(0);

		error = cmd->cmd_main(argc, argv);
		if (error) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			fflush(stderr);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	fflush(stderr);
	return 1;
}
