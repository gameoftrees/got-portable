/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
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

#define GOT_FETCH_DEFAULT_REMOTE_NAME	"origin"

/*
 * Attempt to open a connection to a server using the provided protocol
 * scheme, hostname port number (as a string) and server-side path.
 * A jumphost can be specified which will be passed to ssh(1) via -J.
 * An identity file can be specified which will be passed to ssh(1) via -i.
 * A verbosity level can be specified; it currently controls the amount
 * of -v options passed to ssh(1). If the level is -1 ssh(1) will be run
 * with the -q option.
 *
 * If successful return an open file descriptor for the connection which can
 * be passed to other functions below, and must be disposed of with close(2).
 *
 * If an ssh(1) process was started return its PID as well, in which case
 * the caller should eventually send SIGTERM to the procress and wait for
 * the process to exit with waitpid(2). Otherwise, return PID -1.
 */
const struct got_error *got_fetch_connect(pid_t *, int *, const char *,
    const char *, const char *, const char *, const char *, const char *, int);

/* A callback function which gets invoked with progress information to print. */
typedef const struct got_error *(*got_fetch_progress_cb)(void *,
    const char *, off_t, struct got_object_id *, int, int, int, int);

/*
 * Attempt to fetch a packfile from a server. This pack file will contain
 * objects which that are not yet contained in the provided repository.
 * Return the hash of the packfile (in form of an object ID) and lists of
 * references and symbolic references learned from the server.
 * The expected object ID format is either from got_repo_get_object_format(),
 * or can be passed as -1 to discover the server's object iD hash format
 * when cloning a fresh repository.
 */
const struct got_error *got_fetch_pack(struct got_object_id **,
	struct got_pathlist_head *, struct got_pathlist_head *, const char *,
	int, int, struct got_pathlist_head *, struct got_pathlist_head *,
	int, int, int, int, struct got_repository *, const char *, const char *,
	int, got_fetch_progress_cb, void *);
