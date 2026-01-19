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
#include <sys/signal.h>
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
#include <poll.h>
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

#include "got_lib_poll.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"
#include "gotd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const char *commit_id_str = GOT_REF_HEAD;
static const char *socket_path = GOTSYSD_UNIX_SOCKET;
static char *gotsys_repo_path;

static void
sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		break;
	case SIGUSR1:
		break;
	case SIGTERM:
	case SIGINT:
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

static const struct got_error *
connect_gotsysd(int *gotsysd_sock)
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
    int tmpfd, FILE *outfile)
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

	err = got_object_id_by_path(&id, repo, commit,
	    GOTSYSD_SYSCONF_FILENAME);
	if (err)
		goto done;

	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		err = got_error_path(GOTSYSD_SYSCONF_FILENAME,
		    GOT_ERR_OBJ_TYPE);
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

static const struct got_error *
gotsys_apply(struct gotd_imsgev *iev)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_repository *repo = NULL;
	struct got_commit_object *commit = NULL;
	int ret, fd = -1, sysconf_fd = -1, gotsysd_sock = -1;
	FILE *sysconf_file = NULL;
	struct got_object_id *commit_id = NULL;
	struct gotsysd_imsg_cmd_sysconf sysconf_cmd;
	int *pack_fds = NULL;
	ssize_t n;

	memset(&ibuf, 0, sizeof(ibuf));

	err = connect_gotsysd(&gotsysd_sock);
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
	if (gotsys_repo_path == NULL) {
		gotsys_repo_path = strdup(GOTSYSD_REPOSITORIES_PATH "/"
		    GOTSYS_SYSTEM_REPOSITORY_NAME ".git");
		if (gotsys_repo_path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	err = got_repo_open(&repo, gotsys_repo_path, NULL, pack_fds);
	if (err != NULL)
		goto done;

	err = unveil_repo(got_repo_get_path(repo));
	if (err)
		goto done;

	err = read_gotsysconf(&commit_id, repo, fd, sysconf_file);
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
		err = gotd_imsg_recv_error(NULL, &imsg);
		break;
	case GOTSYSD_IMSG_SYSCONF_STARTED:
		ret = gotd_imsg_compose_event(iev, GOTD_IMSG_SYSCONF_STARTED,
		    0, 1, NULL, 0);
		if (ret == -1) {
			err = got_error_from_errno("imsg_compose "
			    "SYSCONF_STARTED");
			goto done;
		}
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);
done:
	imsgbuf_clear(&ibuf);
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

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	static int flush_and_exit;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto fatal;
		}

		if (flush_and_exit) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	while (err == NULL && !flush_and_exit) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_GOTSYS_APPLY:
			err = gotsys_apply(iev);
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotd_imsg_send_error(&iev->ibuf, 0, 0, err);
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct gotd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	int ch;
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif
	iev.ibuf.fd = -1;

	while ((ch = getopt(argc, argv, "f:c:r:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'f':
			socket_path = optarg;
			break;
		case 'r':
			gotsys_repo_path = realpath(optarg, NULL);
			if (gotsys_repo_path == NULL) {
				err = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			got_path_strip_trailing_slashes(gotsys_repo_path);
			break;
		default:
			err = got_error_fmt(GOT_ERR_NOT_IMPL, "-%c option", ch);
			goto done;
		}
	}

	argc -= optind;
	argv += optind;

	event_init();

	signal_set(&evsigint, SIGINT, sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}

	if (pledge("stdio rpath wpath cpath sendfd unix unveil",
	    NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);
	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_GOTSYS_READY, 0, -1,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose");
		goto done;
	}

	event_dispatch();
done:
	if (close(GOTD_FILENO_MSG_PIPE) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err && iev.ibuf.fd != -1)
		gotd_imsg_send_error(&iev.ibuf, 0, 0, err);
	imsgbuf_clear(&iev.ibuf);
	if (iev.ibuf.fd != -1)
		close(iev.ibuf.fd);
	return err ? 1 : 0;
}
