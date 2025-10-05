/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 1997 Todd C. Miller <millert@openbsd.org>
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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <paths.h>

#include "got_error.h"
#include "got_path.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

int
got_path_is_absolute(const char *path)
{
	return path[0] == '/';
}

/* based on canonpath() from kern_pledge.c */
const struct got_error *
got_canonpath(const char *input, char *buf, size_t bufsize)
{
	const char *p;
	char *q;

	/* can't canon relative paths, don't bother */
	if (!got_path_is_absolute(input)) {
		if (strlcpy(buf, input, bufsize) >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
		return NULL;
	}

	p = input;
	q = buf;
	while (*p && (q - buf < bufsize)) {
		if (p[0] == '/' && (p[1] == '/' || p[1] == '\0')) {
			p += 1;

		} else if (p[0] == '/' && p[1] == '.' &&
		    (p[2] == '/' || p[2] == '\0')) {
			p += 2;

		} else if (p[0] == '/' && p[1] == '.' && p[2] == '.' &&
		    (p[3] == '/' || p[3] == '\0')) {
			p += 3;
			if (q != buf)	/* "/../" at start of buf */
				while (*--q != '/')
					continue;

		} else {
			*q++ = *p++;
		}
	}
	if ((*p == '\0') && (q - buf < bufsize)) {
		*q = 0;
		return NULL;
	} else
		return got_error(GOT_ERR_NO_SPACE);
}

const struct got_error *
got_path_skip_common_ancestor(char **child, const char *parent_abspath,
    const char *abspath)
{
	const struct got_error *err = NULL;
	size_t len_parent, len, bufsize;

	*child = NULL;

	len_parent = strlen(parent_abspath);
	len = strlen(abspath);
	if (len_parent >= len)
		return got_error_path(abspath, GOT_ERR_BAD_PATH);
	if (strncmp(parent_abspath, abspath, len_parent) != 0)
		return got_error_path(abspath, GOT_ERR_BAD_PATH);
	if (!got_path_is_root_dir(parent_abspath) && abspath[len_parent] != '/')
		return got_error_path(abspath, GOT_ERR_BAD_PATH);
	while (abspath[len_parent] == '/')
		abspath++;
	bufsize = len - len_parent + 1;
	*child = malloc(bufsize);
	if (*child == NULL)
		return got_error_from_errno("malloc");
	if (strlcpy(*child, abspath + len_parent, bufsize) >= bufsize) {
		err = got_error(GOT_ERR_NO_SPACE);
		free(*child);
		*child = NULL;
		return err;
	}
	return NULL;
}

const struct got_error *
got_path_strip(char **out, const char *path, int n)
{
	const char *p, *c;

	p = path;
	*out = NULL;

	while (n > 0 && (c = strchr(p, '/')) != NULL) {
		p = c + 1;
		n--;
	}

	if (n > 0)
		return got_error_fmt(GOT_ERR_BAD_PATH,
		    "can't strip %d path-components from %s", n, path);

	if ((*out = strdup(p)) == NULL)
		return got_error_from_errno("strdup");
	return NULL;
}

int
got_path_is_root_dir(const char *path)
{
	while (*path == '/')
		path++;
	return (*path == '\0');
}

int
got_path_is_child(const char *child, const char *parent, size_t parent_len)
{
	if (parent_len == 0 || got_path_is_root_dir(parent))
		return 1;

	if (strncmp(parent, child, parent_len) != 0)
		return 0;
	if (child[parent_len] != '/')
		return 0;

	return 1;
}

int
got_path_cmp(const char *path1, const char *path2, size_t len1, size_t len2)
{
	size_t min_len;
	size_t i = 0;

	/* Leading directory separators are insignificant. */
	while (path1[0] == '/') {
		path1++;
		len1--;
	}
	while (path2[0] == '/') {
		path2++;
		len2--;
	}

	min_len = MIN(len1, len2);

	/* Skip over common prefix. */
	while (i < min_len && path1[i] == path2[i])
		i++;

	/* Are the paths exactly equal (besides path separators)? */
	if (len1 == len2 && i >= min_len)
		return 0;

	/* Skip over redundant trailing path separators. */
	while (path1[i] == '/' && path1[i + 1] == '/')
		path1++;
	while (path2[i] == '/' && path2[i + 1] == '/')
		path2++;

	/* Trailing path separators are insignificant. */
	if (path1[i] == '/' && path1[i + 1] == '\0' && path2[i] == '\0')
		return 0;
	if (path2[i] == '/' && path2[i + 1] == '\0' && path1[i] == '\0')
		return 0;

	/* Order children in subdirectories directly after their parents. */
	if (path1[i] == '/' && path2[i] == '\0')
		return 1;
	if (path2[i] == '/' && path1[i] == '\0')
		return -1;
	if (path1[i] == '/' && path2[i] != '\0')
		return -1;
	if (path2[i] == '/' && path1[i] != '\0')
		return 1;

	/* Next character following the common prefix determines order. */
	return (unsigned char)path1[i] < (unsigned char)path2[i] ? -1 : 1;
}

int
got_pathlist_cmp(const struct got_pathlist_entry *p1,
    const struct got_pathlist_entry *p2)
{
	return got_path_cmp(p1->path, p2->path, p1->path_len, p2->path_len);
}

const struct got_error *
got_pathlist_insert(struct got_pathlist_entry **inserted,
    struct got_pathlist_head *pathlist, const char *path, void *data)
{
	struct got_pathlist_entry *new;
	size_t path_len = strlen(path);

	if (inserted)
		*inserted = NULL;
	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");
	new->path = path;
	new->path_len = path_len;
	new->data = data;
	if (RB_INSERT(got_pathlist_head, pathlist, new)) {
		free(new);
		new = NULL;
	}
	if (inserted)
		*inserted = new;
	return NULL;
}

void
got_pathlist_free(struct got_pathlist_head *pathlist, int freemask)
{
	struct got_pathlist_entry *pe, *temp;

	RB_FOREACH_SAFE(pe, got_pathlist_head, pathlist, temp) {
		if (freemask & GOT_PATHLIST_FREE_PATH) {
			free((char *)pe->path);
			pe->path = NULL;
		}
		if (freemask & GOT_PATHLIST_FREE_DATA) {
			free(pe->data);
			pe->data = NULL;
		}
		RB_REMOVE(got_pathlist_head, pathlist, pe);
		free(pe);
	}
}

static const struct got_error *
make_parent_dirs(const char *abspath)
{
	const struct got_error *err = NULL;
	char *parent;

	err = got_path_dirname(&parent, abspath);
	if (err)
		return err;

	if (mkdir(parent, GOT_DEFAULT_DIR_MODE) == -1) {
		if (errno == ENOENT) {
			err = make_parent_dirs(parent);
			if (err)
				goto done;
			if (mkdir(parent, GOT_DEFAULT_DIR_MODE) == -1) {
				err = got_error_from_errno2("mkdir", parent);
				goto done;
			}
		} else
			err = got_error_from_errno2("mkdir", parent);
	}
done:
	free(parent);
	return err;
}

const struct got_error *
got_path_mkdir(const char *abspath)
{
	const struct got_error *err = NULL;

	if (mkdir(abspath, GOT_DEFAULT_DIR_MODE) == -1) {
		if (errno == ENOENT) {
			err = make_parent_dirs(abspath);
			if (err)
				goto done;
			if (mkdir(abspath, GOT_DEFAULT_DIR_MODE) == -1)
				err = got_error_from_errno2("mkdir", abspath);
		} else
			err = got_error_from_errno2("mkdir", abspath);
	}

done:
	return err;
}

int
got_path_dir_is_empty(const char *dir)
{
	DIR *d;
	struct dirent *dent;
	int empty = 1;

	d = opendir(dir);
	if (d == NULL)
		return 1;

	while ((dent = readdir(d)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		empty = 0;
		break;
	}

	closedir(d);
	return empty;
}

const struct got_error *
got_path_dirname(char **parent, const char *path)
{
	char buf[PATH_MAX];
	char *p;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	p = dirname(buf);
	if (p == NULL)
		return got_error_from_errno2("dirname", path);

	if (p[0] == '.' && p[1] == '\0')
		return got_error_path(path, GOT_ERR_BAD_PATH);

	*parent = strdup(p);
	if (*parent == NULL)
		return got_error_from_errno("strdup");

	return NULL;
}

const struct got_error *
got_path_dirent_type(int *type, const char *path_parent, struct dirent *dent)
{
	const struct got_error *err = NULL;
	char *path_child;
	struct stat sb;

	if (dent->d_type != DT_UNKNOWN) {
		*type = dent->d_type;
		return NULL;
	}

	*type = DT_UNKNOWN;

	/*
	 * This is a fallback to accommodate filesystems which do not
	 * provide directory entry type information. DT_UNKNOWN directory
	 * entries occur on NFS mounts without "readdir plus" RPC.
	 */

	if (asprintf(&path_child, "%s/%s", path_parent, dent->d_name) == -1)
		return got_error_from_errno("asprintf");

	if (lstat(path_child, &sb) == -1) {
		err = got_error_from_errno2("lstat", path_child);
		goto done;
	}

	if (S_ISFIFO(sb.st_mode))
		*type = DT_FIFO;
	else if (S_ISCHR(sb.st_mode))
		*type = DT_CHR;
	else if (S_ISDIR(sb.st_mode))
		*type = DT_DIR;
	else if (S_ISBLK(sb.st_mode))
		*type = DT_BLK;
	else if (S_ISLNK(sb.st_mode))
		*type = DT_LNK;
	else if (S_ISREG(sb.st_mode))
		*type = DT_REG;
	else if (S_ISSOCK(sb.st_mode))
		*type = DT_SOCK;
done:
	free(path_child);
	return err;
}

const struct got_error *
got_path_basename(char **s, const char *path)
{
	char buf[PATH_MAX];
	char *base;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	base = basename(buf);
	if (base == NULL)
		return got_error_from_errno2("basename", path);

	*s = strdup(base);
	if (*s == NULL)
		return got_error_from_errno("strdup");

	return NULL;
}

void
got_path_strip_trailing_slashes(char *path)
{
	size_t x;

	x = strlen(path);
	while (x-- > 0 && path[x] == '/')
		path[x] = '\0';
}

/* based on findprog() from usr.bin/which/which.c */
const struct got_error *
got_path_find_prog(char **filename, const char *prog)
{
	const struct got_error *err = NULL;
	const char *path;
	char *p;
	int len;
	struct stat sbuf;
	char *pathcpy, *dup = NULL;

	*filename = NULL;

	path = getenv("PATH");
	if (path == NULL)
		path = _PATH_DEFPATH;

	/* Special case if prog contains '/' */
	if (strchr(prog, '/')) {
		if ((stat(prog, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(prog, X_OK) == 0) {
			*filename = strdup(prog);
			if (*filename == NULL)
				return got_error_from_errno("strdup");
		}
		return NULL;
	}

	if ((dup = strdup(path)) == NULL)
		return got_error_from_errno("strdup");
	pathcpy = dup;

	while ((p = strsep(&pathcpy, ":")) != NULL) {
		const char *d;

		len = strlen(p);
		while (len > 0 && p[len-1] == '/')
			p[--len] = '\0';	/* strip trailing '/' */

		d = p;
		if (*d == '\0')
			d = ".";

		if (asprintf(filename, "%s/%s", d, prog) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}
		if ((stat(*filename, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(*filename, X_OK) == 0)
			break;
		free(*filename);
		*filename = NULL;
	}
	free(dup);
	return err;
}

const struct got_error *
got_path_create_file(const char *path, const char *content)
{
	const struct got_error *err = NULL;
	int fd = -1;

	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
	    GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		err = got_error_from_errno2("open", path);
		goto done;
	}

	if (content) {
		int len = dprintf(fd, "%s\n", content);
		if (len != strlen(content) + 1) {
			err = got_error_from_errno("dprintf");
			goto done;
		}
	}

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

const struct got_error *
got_path_move_file(const char *oldpath, const char *newpath)
{
	const struct got_error *err;

	if (rename(oldpath, newpath) != -1)
		return NULL;

	if (errno != ENOENT)
		return got_error_from_errno3("rename", oldpath, newpath);

	err = make_parent_dirs(newpath);
	if (err)
		return err;

	if (rename(oldpath, newpath) == -1)
		return got_error_from_errno3("rename", oldpath, newpath);

	return NULL;
}

RB_GENERATE(got_pathlist_head, got_pathlist_entry, entry, got_pathlist_cmp);
