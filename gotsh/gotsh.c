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

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_serve.h"
#include "got_path.h"
#include "got_reference.h"

#include "got_lib_dial.h"
#include "got_lib_poll.h"

#include "media.h"
#include "gotd.h"
#include "gotwebd.h"

static int chattygot;

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s -c '%s|%s repository-path'\n",
	    getprogname(), GOT_DIAL_CMD_SEND, GOT_DIAL_CMD_FETCH);
	fprintf(stderr, "       %s -c 'weblogin [hostname]'\n", getprogname());
	exit(1);
}

static const struct got_error *
apply_unveil(const char *unix_socket_path)
{
#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (unveil(unix_socket_path, "w") != 0)
		return got_error_from_errno2("unveil", unix_socket_path);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

/* Read session URL from gotwebd's auth socket and send it to the client. */
static const struct got_error *
weblogin(FILE *out, int sock, const char *hostname)
{
	const struct got_error *err = NULL;
	FILE *fp;
	int ret;
	char *line = NULL;
	size_t linesize;
	ssize_t linelen;

	fp = fdopen(sock, "w+");
	if (fp == NULL)
		return got_error_from_errno("fdopen");

	ret = fprintf(fp, "login%s%s\n", hostname != NULL ? " " : "",
	    hostname != NULL ? hostname : "");
	if (ret < 0) {
		err = got_error_from_errno("fprintf");
		goto done;
	}

	/*
	 * gotwebd will return "ok URL", likewise terminated by \n,
	 * or might return an arbitrary error message + \n.
	 * We don't know how long this line will be, so keep reading
	 * in chunks until we have read all of it.
	 * For forward compatibilty, ignore any trailing lines received.
	 */
	linelen = getline(&line, &linesize, fp);
	if (linelen == -1) {
		err = got_error(GOT_ERR_EOF);
		if (ferror(fp))
			err = got_error_from_errno("getline");
		goto done;
	}

	if (strncmp(line, "ok ", 3) == 0) {
		fprintf(out, "Login successful.  Please visit the following "
		    "URL within the next %d minutes: %s\n",
		    GOTWEBD_LOGIN_TIMEOUT / 60, line + 3);
		goto done;
	}

	if (strncmp(line, "err ", 4) == 0) {
		err = got_error_fmt(GOT_ERR_LOGIN_FAILED, "%s", line + 4);
		goto done;
	}

	err = got_error(GOT_ERR_UNKNOWN_COMMAND);
done:
	if (line != NULL)
		free(line);
	if (fp != NULL && fclose(fp) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}


static const struct got_error *
parse_weblogin_command(char **hostname, char *cmd)
{
	size_t len, cmdlen;

	*hostname = NULL;

	len = strlen(cmd);

	while (len > 0 && isspace(cmd[len - 1]))
		cmd[--len] = '\0';

	if (len == 0)
		return got_error(GOT_ERR_BAD_PACKET);

	if (len >= strlen(GOTWEBD_LOGIN_CMD) &&
	    strncmp(cmd, GOTWEBD_LOGIN_CMD, strlen(GOTWEBD_LOGIN_CMD)) == 0)
		cmdlen = strlen(GOTWEBD_LOGIN_CMD);
	else
		return got_error(GOT_ERR_BAD_PACKET);

	/* The hostname parameter is optional. */
	if (len == cmdlen)
		return NULL;

	if (len <= cmdlen + 1 || cmd[cmdlen] != ' ')
		return got_error(GOT_ERR_BAD_PACKET);

	if (memchr(&cmd[cmdlen + 1], '\0', len - cmdlen) == NULL)
		return got_error(GOT_ERR_BAD_PACKET);

	/* Forbid linefeeds in hostnames. We use \n as internal terminator. */
	if (memchr(&cmd[cmdlen + 1], '\n', len - cmdlen) != NULL)
		return got_error(GOT_ERR_BAD_PACKET);

	*hostname = strdup(&cmd[cmdlen + 1]);
	if (*hostname == NULL)
		return got_error_from_errno("strdup");

	/* Deny an empty hostname. */
	if ((*hostname)[0] == '\0') {
		free(*hostname);
		*hostname = NULL;
		return got_error(GOT_ERR_BAD_PACKET);
	}

	/* Deny overlong hostnames ,*/
	if (len - cmdlen > _POSIX_HOST_NAME_MAX)
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "hostname length exceeds %d bytes", _POSIX_HOST_NAME_MAX);

	/*
	 * TODO: More hostname verification? In any case, the provided
	 * value will have to match a string obtained from gotwebd.conf.
	 */

	return NULL;
}

int
main(int argc, char *argv[])
{
	const struct got_error *error;
	const char *unix_socket_path;
	int sock = -1;
	struct sockaddr_un	 sun;
	char *gitcmd = NULL, *command = NULL, *repo_path = NULL;
	char *hostname = NULL;
	int do_weblogin = 0;

#ifndef PROFILE
	if (pledge("stdio recvfd unix unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (strcmp(argv[0], GOTWEBD_LOGIN_CMD) == 0) {
		if (argc != 1 && argc != 2)
			usage();
		unix_socket_path = getenv("GOTWEBD_LOGIN_SOCKET");
		if (unix_socket_path == NULL)
			unix_socket_path = GOTWEBD_LOGIN_SOCKET;
		error = apply_unveil(unix_socket_path);
		if (error)
			goto done;
		if (argc == 2) {
			hostname = strdup(argv[1]);
			if (hostname == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
		do_weblogin = 1;
	} else if (strcmp(argv[0], GOT_DIAL_CMD_SEND) == 0 ||
	    strcmp(argv[0], GOT_DIAL_CMD_FETCH) == 0) {
		if (argc != 2)
			usage();
		unix_socket_path = getenv("GOTD_UNIX_SOCKET");
		if (unix_socket_path == NULL)
			unix_socket_path = GOTD_UNIX_SOCKET;
		error = apply_unveil(unix_socket_path);
		if (error)
			goto done;
		if (asprintf(&gitcmd, "%s %s", argv[0], argv[1]) == -1)
			err(1, "asprintf");
		error = got_dial_parse_command(&command, &repo_path, gitcmd);
		if (error) {
			if (error->code == GOT_ERR_BAD_PACKET)
				usage();
			goto done;
		}
	} else if (argc == 3 && strcmp(argv[1], "-c") == 0) {
		if (strncmp(argv[2], GOTWEBD_LOGIN_CMD,
		    strlen(GOTWEBD_LOGIN_CMD)) == 0) {
			unix_socket_path = getenv("GOTWEBD_LOGIN_SOCKET");
			if (unix_socket_path == NULL)
				unix_socket_path = GOTWEBD_LOGIN_SOCKET;
			error = apply_unveil(unix_socket_path);
			if (error)
				goto done;
			error = parse_weblogin_command(&hostname, argv[2]);
			if (error) {
				if (error->code == GOT_ERR_BAD_PACKET)
					usage();
				goto done;
			}
			do_weblogin = 1;
		} else {
			unix_socket_path = getenv("GOTD_UNIX_SOCKET");
			if (unix_socket_path == NULL)
				unix_socket_path = GOTD_UNIX_SOCKET;
			error = apply_unveil(unix_socket_path);
			if (error)
				goto done;
			error = got_dial_parse_command(&command, &repo_path,
			    argv[2]);
			if (error) {
				if (error->code == GOT_ERR_BAD_PACKET)
					usage();
				goto done;
			}
		}
	} else
		usage();

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, unix_socket_path,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path))
		errx(1, "gotd socket path too long");
	if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", unix_socket_path);

	if (do_weblogin) {
#ifndef PROFILE
		if (pledge("stdio", NULL) == -1)
			err(1, "pledge");
#endif
		error = weblogin(stdout, sock, hostname);
	} else {
#ifndef PROFILE
		if (pledge("stdio recvfd", NULL) == -1)
			err(1, "pledge");
#endif
		error = got_serve(STDIN_FILENO, STDOUT_FILENO, command,
		    repo_path, sock, chattygot);
	}
done:
	free(gitcmd);
	free(command);
	free(repo_path);
	free(hostname);
	if (sock != -1)
		close(sock);
	if (error) {
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
		return 1;
	}

	return 0;
}
