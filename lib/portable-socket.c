/*
 * Copyright (c) 2026 Thomas Adam <thomas@xteddy.org>
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

#if defined(__APPLE__)

/*
 * We need to undefine these macros so we can call the real system calls.
 * got_compat.h defines them to point to these functions.
 */
#undef socket
#undef socketpair

int
got_socket_compat(int domain, int type, int proto)
{
	int fd, fl;
	int st = SOCK_NONBLOCK | SOCK_CLOEXEC;

	if ((fd = socket(domain, (type & ~st), proto)) == -1)
		return -1;

	if (type & SOCK_CLOEXEC) {
		fl = fcntl(fd, F_GETFD);
		if (fl == -1 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == -1) {
			close(fd);
			return -1;
		}
	}

	if (type & SOCK_NONBLOCK) {
		fl = fcntl(fd, F_GETFL);
		if (fl == -1 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

int
got_socketpair_compat(int domain, int type, int proto, int *sv)
{
	int i, fl;
	int st = SOCK_NONBLOCK | SOCK_CLOEXEC;

	if (socketpair(domain, (type & ~st), proto, sv) == -1)
		return -1;

	if (type & SOCK_CLOEXEC) {
		for (i = 0; i < 2; i++) {
			fl = fcntl(sv[i], F_GETFD);
			if (fl == -1 || fcntl(sv[i], F_SETFD, fl | FD_CLOEXEC) == -1) {
				close(sv[0]);
				close(sv[1]);
				return -1;
			}
		}
	}

	if (type & SOCK_NONBLOCK) {
		for (i = 0; i < 2; i++) {
			fl = fcntl(sv[i], F_GETFL);
			if (fl == -1 || fcntl(sv[i], F_SETFL, fl | O_NONBLOCK) == -1) {
				close(sv[0]);
				close(sv[1]);
				return -1;
			}
		}
	}

	return 0;
}
#endif
