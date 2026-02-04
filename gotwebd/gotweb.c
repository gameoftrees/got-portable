/*
 * Copyright (c) 2016, 2019, 2020-2022 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"
#include "tmpl.h"

static int gotweb_render_index(struct template *);
static const struct got_error *gotweb_load_got_path(struct repo_dir **,
    const char *, struct request *, struct website *);
static const struct got_error *gotweb_load_file(char **, const char *,
    const char *, int);
static const struct got_error *gotweb_get_repo_description(char **,
    struct server *, const char *, int);
static const struct got_error *gotweb_get_clone_url(char **, struct server *,
    const char *, int);

static void gotweb_free_repo_dir(struct repo_dir *);

int
gotweb_reply(struct request *c, int status, const char *ctype,
    struct gotweb_url *location)
{
	const char	*csp;

	if (status != 200 && tp_writef(c->tp, "Status: %d\r\n", status) == -1)
		return -1;

	if (location) {
		if (tp_writes(c->tp, "Location: ") == -1 ||
		    gotweb_render_absolute_url(c, location) == -1 ||
		    tp_writes(c->tp, "\r\n") == -1)
			return -1;
	}

	csp = "Content-Security-Policy: default-src 'self'; "
	    "script-src 'self'; object-src 'none';\r\n";
	if (tp_writes(c->tp, csp) == -1)
		return -1;

	if (ctype && tp_writef(c->tp, "Content-Type: %s\r\n", ctype) == -1)
		return -1;

	return tp_writes(c->tp, "\r\n");
}

static int
gotweb_reply_file(struct request *c, const char *ctype, const char *file,
    const char *suffix)
{
	int r;

	r = tp_writef(c->tp, "Content-Disposition: attachment; "
	    "filename=%s%s\r\n", file, suffix ? suffix : "");
	if (r == -1)
		return -1;
	return gotweb_reply(c, 200, ctype, NULL);
}

static struct socket *
gotweb_get_socket(int sock_id)
{
	struct socket *sock;

	TAILQ_FOREACH(sock, &gotwebd_env->sockets, entry) {
		if (sock->conf.id == sock_id)
			return sock;
	}

	return NULL;
}

static void
cleanup_request(struct request *c)
{
	uint32_t request_id = c->request_id;

	fcgi_cleanup_request(c);

	if (imsg_compose_event(gotwebd_env->iev_auth, GOTWEBD_IMSG_REQ_ABORT,
	    GOTWEBD_PROC_GOTWEB, -1, -1, &request_id, sizeof(request_id)) == -1)
		log_warn("imsg_compose_event");
}

static struct request *
recv_request(struct imsg *imsg)
{
	const struct got_error *error;
	struct request *c;
	struct server *srv;
	size_t datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	int fd = -1;
	uint8_t *outbuf = NULL;

	if (datalen != sizeof(*c)) {
		log_warnx("bad request size received over imsg");
		return NULL;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1) {
		log_warnx("no client file descriptor");
		return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		log_warn("calloc");
		return NULL;
	}

	outbuf = calloc(1, GOTWEBD_CACHESIZE);
	if (outbuf == NULL) {
		log_warn("calloc");
		free(c);
		return NULL;
	}

	memcpy(c, imsg->data, sizeof(*c));

	/* Non-NULL pointers, if any, are not from our address space. */
	c->sock = NULL;
	c->srv = NULL;
	c->t = NULL;
	c->tp = NULL;
	c->buf = NULL;
	c->outbuf = outbuf;

	memset(&c->ev, 0, sizeof(c->ev));
	memset(&c->tmo, 0, sizeof(c->tmo));

	/* Use our own temporary file descriptors. */
	memcpy(c->priv_fd, gotwebd_env->priv_fd, sizeof(c->priv_fd));

	c->fd = fd;

	c->tp = template(c, fcgi_write, c->outbuf, GOTWEBD_CACHESIZE);
	if (c->tp == NULL) {
		log_warn("gotweb init template");
		cleanup_request(c);
		return NULL;
	}

	c->sock = gotweb_get_socket(c->sock_id);
	if (c->sock == NULL) {
		log_warn("socket id '%d' not found", c->sock_id);
		cleanup_request(c);
		return NULL;
	}

	/* init the transport */
	error = gotweb_init_transport(&c->t);
	if (error) {
		log_warnx("gotweb init transport: %s", error->msg);
		cleanup_request(c);
		return NULL;
	}

	/* get the gotwebd server */
	srv = gotweb_get_server(c->fcgi_params.server_name);
	if (srv == NULL) {
		log_warnx("server '%s' not found", c->fcgi_params.server_name);
		cleanup_request(c);
		return NULL;
	}
	c->srv = srv;

	return c;
}

void
gotweb_log_request(struct request *c)
{
	struct gotwebd_fcgi_params *p = &c->fcgi_params;
	struct querystring *qs = &p->qs;
	char *server_name = NULL;
	char *document_uri = NULL;
	const char *action_name = NULL;

	if (gotwebd_env->gotwebd_verbose == 0)
		return;

	if (p->server_name[0] &&
	    stravis(&server_name, p->server_name, VIS_SAFE) == -1) {
		log_warn("stravis");
		server_name = NULL;
	}

	if (p->document_uri[0] &&
	    stravis(&document_uri, p->document_uri, VIS_SAFE) == -1) {
		log_warn("stravis");
		document_uri = NULL;
	}

	action_name = gotweb_action_name(qs->action);
	log_info("processing request: server='%s' action='%s' "
	    "commit='%s', file='%s', folder='%s', headref='%s' "
	    "index_page=%d path='%s' document_uri='%s'",
	    server_name ? server_name : "",
	    action_name ? action_name : "",
	    qs->commit,
	    qs->file,
	    qs->folder,
	    qs->headref,
	    qs->index_page,
	    qs->path,
	    document_uri ? document_uri : "");

	free(server_name);
	free(document_uri);
}

const struct got_error *
gotweb_serve_htdocs(struct request *c, const char *request_path)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;;
	struct media_type *m;
	char *ondisk_path = NULL;
	int n, fd = -1;
	char mime_type[MEDIA_STRMAX] = "application/octet-stream";

	if (asprintf(&ondisk_path, "%s/%s/%s", gotwebd_env->httpd_chroot,
	    srv->htdocs_path, request_path) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	fd = open(ondisk_path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT || errno == ENOTDIR)
			error = got_error(GOT_ERR_NOT_FOUND);
		else
			error = got_error_from_errno_fmt("open: %s");
		goto done;
	}

	m = media_find(&gotwebd_env->mediatypes, ondisk_path);
	if (m != NULL) {
		n = snprintf(mime_type, sizeof(mime_type), "%s/%s",
		    m->media_type, m->media_subtype);
		if (n < 0 || (size_t)n >= sizeof(mime_type)) {
			error = got_error(GOT_ERR_RANGE);
			goto done;
		}
	}

	if (gotweb_reply(c, 200, mime_type, NULL) == -1) {
		error = got_error(GOT_ERR_IO);
		goto done;
	}

	if (template_flush(c->tp) == -1) {
		error = got_error(GOT_ERR_IO);
		goto done;
	}

	for (;;) {
		uint8_t buf[BUF];
		ssize_t r;

		r = read(fd, buf, sizeof(buf));
		if (r == -1) {
			error = got_error_from_errno("read");
			goto done;
		}
		if (r == 0)
			break;
	
		if (fcgi_write(c, buf, r) == -1) {
			error = got_error(GOT_ERR_IO);
			goto done;
		}
	}
done:
	if (fd != -1 && close(fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	free(ondisk_path);
	return error;
}

static const struct got_error *
serve_blob(int *response_code, struct request *c, struct got_repository *repo,
    struct got_object_id *obj_id, const char *basename)
{
	const struct got_error *error = NULL;
	struct got_blob_object *blob = NULL;
	struct media_type *m;
	int binary, n;
	char mime_type[MEDIA_STRMAX] = "application/octet-stream";

	c->t->fd = dup(c->priv_fd[BLOB_FD_1]);
	if (c->t->fd == -1) {
		error = got_error_from_errno("dup");
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, BUF, c->t->fd);
	if (error)
		goto done;

	error = got_object_blob_is_binary(&binary, blob);
	if (error)
		goto done;

	if (binary) {
		if (gotweb_reply_file(c, mime_type, basename, NULL) == -1) {
			error = got_error(GOT_ERR_IO);
			*response_code = 500;
			goto done;
		}
	} else {
		m = media_find(&gotwebd_env->mediatypes, basename);
		if (m != NULL) {
			n = snprintf(mime_type, sizeof(mime_type), "%s/%s",
			    m->media_type, m->media_subtype);
			if (n < 0 || (size_t)n >= sizeof(mime_type)) {
				error = got_error_msg(GOT_ERR_RANGE,
				    "media type snprintf");
				goto done;
			}
		}

		if (gotweb_reply(c, 200, mime_type, NULL) == -1) {
			error = got_error(GOT_ERR_IO);
			*response_code = 500;
			goto done;
		}
	}

	if (template_flush(c->tp) == -1) {
		error = got_error(GOT_ERR_IO);
		*response_code = 500;
		goto done;
	}

	for (;;) {
		const uint8_t *buf;
		size_t len;

		error = got_object_blob_read_block(&len, blob);
		if (error)
			goto done;
		if (len == 0)
			break;

		buf = got_object_blob_get_read_buf(blob);
		if (fcgi_write(c, buf, len) == -1) {
			error = got_error(GOT_ERR_IO);
			*response_code = 500;
			goto done;
		}
	}

done:
	if (blob)
		got_object_blob_close(blob);
	return error;
}

static int
gotweb_serve_website(struct request *c, struct website *site,
    struct repo_dir *repo_dir, const char *request_path)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct gotwebd_fcgi_params *p = &c->fcgi_params;
	struct got_repository *repo = t->repo;
	char *refname = NULL;
	struct got_reference *ref = NULL;
	struct got_object_id *id = NULL, *obj_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	char *basename = NULL;
	int response_code = 404;
	char *in_repo_child = NULL, *in_repo_path = NULL;
	int obj_type;

	if (got_path_is_root_dir(request_path)) {
		in_repo_child = strdup(request_path);
		if (in_repo_child == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		if (got_path_is_root_dir(site->url_path)) {
			in_repo_child = strdup(request_path);
			if (in_repo_child == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		} else if (got_path_cmp(site->url_path, request_path,
		    strlen(site->url_path), strlen(request_path)) == 0) {
			in_repo_child = strdup("/");
			if (in_repo_child == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			error = got_path_skip_common_ancestor(&in_repo_child,
			   site->url_path, request_path);
			if (error)
				goto done;
		}
	}

	if (site->path[0] != '\0') {
		char *s = in_repo_child;

		while (*s == '/')
			s++;

		if (asprintf(&in_repo_path, "%s/%s", site->path, s) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		got_path_strip_trailing_slashes(in_repo_path);
	} else {
		in_repo_path = in_repo_child;
		in_repo_child = NULL;
	}

	if (site->branch_name[0] != 0) {
		const char *branch = site->branch_name;

		if (strncmp("refs/heads/", branch, 11) != 0) {
			if (asprintf(&refname, "refs/heads/%s", branch) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		} else {
			refname = strdup(branch);
			if (refname == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}

	} else {
		refname = strdup(GOT_REF_HEAD);
		if (refname == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_ref_open(&ref, repo, refname, 0);
	if (error)
		goto done;

	error = got_ref_resolve(&id, repo, ref);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, id);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit, in_repo_path);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_path_basename(&basename, in_repo_path);
		if (error)
			goto done;
		error = serve_blob(&response_code, c, repo, obj_id,
		    basename);
		if (error)
			goto done;
		break;
	case GOT_OBJ_TYPE_TREE: {
		struct got_tree_entry *te;
		int nentries, i;
		const char *name;
		mode_t mode;

		error = got_object_open_as_tree(&tree, repo, obj_id);
		if (error)
			goto done;
		nentries = got_object_tree_get_nentries(tree);

		for (i = 0; i < nentries; i++) {
			struct gotweb_url url = {
				.index_page = -1,
				.action = -1,
			};

			te = got_object_tree_get_entry(tree, i);

			name = got_tree_entry_get_name(te);
			mode = got_tree_entry_get_mode(te);
			if (!S_ISREG(mode) ||
			    strcasecmp(name, "index.html") != 0)
				continue;

			/* XXX gotweb_reply uses request struct field */
			got_path_strip_trailing_slashes(p->document_uri);
			if (strlcat(p->document_uri, "/index.html",
			    sizeof(p->document_uri)) >=
			    sizeof(p->document_uri)) {
				error = got_error(GOT_ERR_NO_SPACE);
				goto done;
			}

			if (gotweb_reply(c, 302, NULL, &url) == -1) {
				error = got_error(GOT_ERR_IO);
				goto done;
			}
			break;
		}
		break;
	}
	default:
		error = got_error(GOT_ERR_NOT_FOUND);
		goto done;
	}
done:
	free(in_repo_child);
	free(in_repo_path);
	free(refname);
	free(basename);
	free(id);
	free(obj_id);
	if (ref)
		got_ref_close(ref);
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);

	if (error) {
		char *safe_path = NULL;

		if (stravis(&safe_path, request_path, VIS_SAFE) == -1) {
			log_warn("stravis");
			safe_path = NULL;
		}
		log_warnx("%s: %s: %d: %s", __func__,
		    safe_path ? safe_path : "?", response_code, error->msg);
		free(safe_path);

		if (response_code == 404)
			c->t->error = got_error(GOT_ERR_NOT_FOUND);
		else
			c->t->error = error;

		if (gotweb_reply(c, response_code, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_error);
	}

	return 0;
}

const struct got_error *
gotweb_route_request(int *is_repository_request, struct website **site,
	char **request_path, struct request *c)
{
	const struct got_error *error = NULL;
	struct gotwebd_fcgi_params *p = &c->fcgi_params;
	struct server *srv = c->srv;;
	char *child_path = NULL;

	*is_repository_request = 0;
	*site = NULL;
	*request_path = NULL;

	if (got_path_cmp(srv->full_repos_url_path, p->document_uri,
	    strlen(srv->full_repos_url_path),
	    strlen(p->document_uri)) == 0) {
		/* 
		 * Requesting / in repository url path space.
		 * We will be rendering Git repository data.
		 */
		*request_path = strdup("/");
		if (*request_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		*is_repository_request = 1;
	} else if (got_path_is_child(p->document_uri,
	    srv->full_repos_url_path, strlen(srv->full_repos_url_path))) {
		/*
		 * Requesting something within repository url path space.
		 * We will be returning a static asset for a repository page.
		 */
		error = got_path_skip_common_ancestor(&child_path,
		    srv->full_repos_url_path, p->document_uri);
		if (error)
			goto done;
		*is_repository_request = 1;

		if (asprintf(request_path, "/%s", child_path) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
	} else if (got_path_is_child(p->document_uri,
	    srv->gotweb_url_root, strlen(srv->gotweb_url_root))) {
		/*
		 * Requesting something outside repository url path space.
		 * This will result in a 404 error unless the request is
		 * matched by a website.
		 */
		if (got_path_is_root_dir(p->document_uri)) {
			*request_path = strdup("/");
			if (*request_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			error = got_path_skip_common_ancestor(&child_path,
			    srv->gotweb_url_root, p->document_uri);
			if (error)
				goto done;
			if (asprintf(request_path, "/%s", child_path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
	} else {
		/*
		 * Requesting something outside gotweb url path space.
		 * This will result in a 404 error.
		 */
		*request_path = strdup(p->document_uri);
		if (*request_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (!got_path_is_root_dir(*request_path))
		got_path_strip_trailing_slashes(*request_path);

	*site = gotweb_get_website(srv, *request_path);

	/*
	 * If the target of the request is ambiguous, the longer path wins.
	 */
	if (*is_repository_request && *site) {
		if (got_path_cmp(srv->repos_url_path, (*site)->url_path,
		    strlen(srv->repos_url_path),
		    strlen((*site)->url_path)) <= 0)
			*is_repository_request = 0;
		else
			*site = NULL;
	}
done:
	free(child_path);
	if (error) {
		free(*request_path);
		*request_path = NULL;
		*site = NULL;
	}

	return error;
}

int
gotweb_process_request(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;;
	struct website *site;
	struct querystring *qs = NULL;
	struct repo_dir *repo_dir = NULL;
	struct repo_commit *commit;
	const char *rss_ctype = "application/rss+xml;charset=utf-8";
	const uint8_t *buf;
	size_t len;
	int r, binary = 0;
	char *request_path = NULL;
	int is_repository_request = 0;

	/* querystring */
	qs = &c->fcgi_params.qs;
	c->t->qs = qs;

	gotweb_log_request(c);

	error = gotweb_route_request(&is_repository_request, &site,
	    &request_path, c);
	if (error)
		goto err;

	if (is_repository_request && !got_path_is_root_dir(request_path)) {
		error = gotweb_serve_htdocs(c, request_path);
		if (error)
			goto err;

		free(request_path);
		return 0;
	}

	if (site) {
		error = gotweb_load_got_path(&repo_dir, site->repo_name, c,
		    site);
		c->t->repo_dir = repo_dir;
		if (error)
			goto err;

		r = gotweb_serve_website(c, site, repo_dir, request_path);
		free(request_path);
		return r;
	}

	free(request_path);
	request_path = NULL;

	/*
	 * certain actions require a commit id in the querystring. this stops
	 * bad actors from exploiting this by manually manipulating the
	 * querystring.
	 */

	if (qs->action == BLAME || qs->action == BLOB ||
	    qs->action == BLOBRAW || qs->action == DIFF ||
	    qs->action == PATCH) {
		if (qs->commit[0] == '\0') {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}
	}

	if (qs->action != INDEX) {
		if (qs->path[0] == '\0') {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}

		error = gotweb_load_got_path(&repo_dir, qs->path, c, NULL);
		c->t->repo_dir = repo_dir;
		if (error)
			goto err;
	}

	if (qs->action == BLOBRAW || qs->action == BLOB) {
		if (qs->folder[0] == '\0' || qs->file[0] == '\0') {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}

		error = got_get_repo_commits(c, 1);
		if (error)
			goto err;

		error = got_open_blob_for_output(&c->t->blob, &c->t->fd,
		    &binary, c, qs->folder, qs->file, qs->commit);
		if (error)
			goto err;
	}

	switch (qs->action) {
	case BLAME:
		if (qs->folder[0] == '\0' || qs->file[0] == '\0') {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_blame);
	case BLOB:
		if (binary) {
			struct gotweb_url url = {
				.index_page = -1,
				.action = BLOBRAW,
				.path = qs->path[0] ? qs->path : NULL,
				.commit = qs->commit[0] ? qs->commit : NULL,
				.folder = qs->folder[0] ? qs->folder : NULL,
				.file = qs->file[0] ? qs->file : NULL,
			};

			return gotweb_reply(c, 302, NULL, &url);
		}

		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_blob);
	case BLOBRAW:
		if (binary)
			r = gotweb_reply_file(c, "application/octet-stream",
			    qs->file, NULL);
		else
			r = gotweb_reply(c, 200, "text/plain", NULL);
		if (r == -1)
			return -1;
		if (template_flush(c->tp) == -1)
			return -1;

		for (;;) {
			error = got_object_blob_read_block(&len, c->t->blob);
			if (error)
				break;
			if (len == 0)
				break;
			buf = got_object_blob_get_read_buf(c->t->blob);
			if (fcgi_write(c, buf, len) == -1)
				return -1;
		}
		return 0;
	case BRIEFS:
		error = got_get_repo_commits(c, srv->max_commits_display);
		if (error)
			goto err;
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_briefs);
	case COMMITS:
		error = got_get_repo_commits(c, srv->max_commits_display);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_commits);
	case DIFF:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		error = got_open_diff_for_output(&c->t->fp, c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_diff);
	case INDEX:
		c->t->nrepos = scandir(srv->repos_path, &c->t->repos, NULL,
		    alphasort);
		if (c->t->nrepos == -1) {
			c->t->repos = NULL;
			error = got_error_from_errno2("scandir",
			    srv->repos_path);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_index);
	case PATCH:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		error = got_open_diff_for_output(&c->t->fp, c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/plain", NULL) == -1)
			return -1;
		return gotweb_render_patch(c->tp);
	case RSS:
		error = got_get_repo_tags(c, D_MAXSLCOMMDISP);
		if (error)
			goto err;
		if (gotweb_reply_file(c, rss_ctype, repo_dir->name, ".rss")
		    == -1)
			return -1;
		return gotweb_render_rss(c->tp);
	case SUMMARY:
		error = got_ref_list(&c->t->refs, c->t->repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
		if (error) {
			log_warnx("%s: got_ref_list: %s", __func__,
			    error->msg);
			goto err;
		}
		error = got_get_repo_commits(c, srv->summary_commits_display);
		if (error)
			goto err;
		qs->action = TAGS;
		error = got_get_repo_tags(c, srv->summary_tags_display);
		if (error) {
			log_warnx("%s: got_get_repo_tags: %s", __func__,
			    error->msg);
			goto err;
		}
		qs->action = SUMMARY;
		commit = TAILQ_FIRST(&c->t->repo_commits);
		if (commit && qs->commit[0] == '\0') {
			if (strlcpy(qs->commit, commit->commit_id,
			    sizeof(qs->commit)) >= sizeof(qs->commit)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "commit ID too long");
				log_warn("%s: %s", __func__, error->msg);
				goto err;
			}
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_summary);
	case TAG:
		error = got_get_repo_tags(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (TAILQ_EMPTY(&c->t->repo_tags)) {
			error = got_error_msg(GOT_ERR_BAD_OBJ_ID,
			    "bad commit id");
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_tag);
	case TAGS:
		error = got_get_repo_tags(c, srv->max_commits_display);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_tags);
	case TREE:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return -1;
		return gotweb_render_page(c->tp, gotweb_render_tree);
	case ERR:
	default:
		error = got_error(GOT_ERR_BAD_QUERYSTRING);
	}

err:
	free(request_path);
	c->t->error = error;
	if (error->code == GOT_ERR_NOT_FOUND) {
		if (gotweb_reply(c, 404, "text/html", NULL) == -1)
			return -1;
	} else {
		if (gotweb_reply(c, 400, "text/html", NULL) == -1)
			return -1;
	}

	return gotweb_render_page(c->tp, gotweb_render_error);
}

struct server *
gotweb_get_server(const char *server_name)
{
	struct server *srv;

	/* check against the server name first */
	if (*server_name != '\0')
		TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
			if (strcmp(srv->name, server_name) == 0)
				return srv;

	/* otherwise, use the first server */
	return TAILQ_FIRST(&gotwebd_env->servers);
};

struct website *
gotweb_get_website(struct server *srv, const char *url_path)
{
	struct got_pathlist_entry *pe;
	size_t url_path_len = strlen(url_path);
	struct website *site = NULL;

	if (RB_EMPTY(&srv->websites))
		return NULL;

	/*
	 * Parent paths are sorted before children so we can match the
	 * provided URL path against the most specific web site URL path
	 * by walking the list backwards.
	 */
	pe = RB_MAX(got_pathlist_head, &srv->websites);
	while (pe) {
		if (got_path_cmp(url_path, pe->path,
		    url_path_len, pe->path_len) == 0 ||
		    got_path_is_child(url_path, pe->path, pe->path_len)) {
			site = pe->data;
			break;
		}

		pe = RB_PREV(got_pathlist_head, &srv->websites, pe);
	}

	return site;
}

const struct got_error *
gotweb_init_transport(struct transport **t)
{
	const struct got_error *error = NULL;

	*t = calloc(1, sizeof(**t));
	if (*t == NULL)
		return got_error_from_errno2(__func__, "calloc");

	TAILQ_INIT(&(*t)->repo_commits);
	TAILQ_INIT(&(*t)->repo_tags);
	TAILQ_INIT(&(*t)->refs);

	(*t)->fd = -1;

	return error;
}

struct gotwebd_repo *
gotweb_get_repository(struct server *server, const char *name)
{
	struct gotwebd_repo *repo;

	TAILQ_FOREACH(repo, &server->repos, entry) {
		if (strncmp(repo->name, name, strlen(repo->name)) != 0)
			continue;
	
		if (strlen(name) == strlen(repo->name))
			return repo;

		if (strlen(name) != strlen(repo->name) + 4)
			continue;

		if (strcmp(name + strlen(repo->name), ".git") == 0)
			return repo;
	}

	return NULL;
}

void
gotweb_free_repo_tag(struct repo_tag *rt)
{
	if (rt != NULL) {
		free(rt->commit_id);
		free(rt->tag_name);
		free(rt->tag_commit);
		free(rt->commit_msg);
		free(rt->tagger);
	}
	free(rt);
}

void
gotweb_free_repo_commit(struct repo_commit *rc)
{
	if (rc != NULL) {
		free(rc->path);
		free(rc->refs_str);
		free(rc->commit_id);
		free(rc->parent_id);
		free(rc->tree_id);
		free(rc->author);
		free(rc->committer);
		free(rc->commit_msg);
	}
	free(rc);
}

static void
gotweb_free_repo_dir(struct repo_dir *repo_dir)
{
	if (repo_dir != NULL) {
		free(repo_dir->name);
		free(repo_dir->owner);
		free(repo_dir->description);
		free(repo_dir->url);
		free(repo_dir->path);
	}
	free(repo_dir);
}

void
gotweb_free_transport(struct transport *t)
{
	const struct got_error *err;
	struct repo_commit *rc = NULL, *trc = NULL;
	struct repo_tag *rt = NULL, *trt = NULL;
	int i;

	got_ref_list_free(&t->refs);
	TAILQ_FOREACH_SAFE(rc, &t->repo_commits, entry, trc) {
		TAILQ_REMOVE(&t->repo_commits, rc, entry);
		gotweb_free_repo_commit(rc);
	}
	TAILQ_FOREACH_SAFE(rt, &t->repo_tags, entry, trt) {
		TAILQ_REMOVE(&t->repo_tags, rt, entry);
		gotweb_free_repo_tag(rt);
	}
	gotweb_free_repo_dir(t->repo_dir);
	t->qs = NULL;
	free(t->more_id);
	free(t->tags_more_id);
	if (t->blob)
		got_object_blob_close(t->blob);
	if (t->fp) {
		err = got_gotweb_closefile(t->fp);
		if (err)
			log_warnx("%s: got_gotweb_closefile failure: %s",
			    __func__, err->msg);
	}
	if (t->fd != -1 && close(t->fd) == -1)
		log_warn("%s: close", __func__);
	if (t->repos) {
		for (i = 0; i < t->nrepos; ++i)
			free(t->repos[i]);
		free(t->repos);
	}
	if (t->repo)
		got_repo_close(t->repo);
	free(t);
}

void
gotweb_index_navs(struct request *c, struct gotweb_url *prev, int *have_prev,
    struct gotweb_url *next, int *have_next)
{
	struct transport *t = c->t;
	const struct querystring *qs = t->qs;
	struct server *srv = c->srv;

	*have_prev = *have_next = 0;

	if (qs->index_page > 0) {
		*have_prev = 1;
		*prev = (struct gotweb_url){
			.action = -1,
			.index_page = qs->index_page - 1,
		};
	}
	if (t->next_disp == srv->max_repos_display &&
	    t->repos_total != (qs->index_page + 1) *
	    srv->max_repos_display) {
		*have_next = 1;
		*next = (struct gotweb_url){
			.action = -1,
			.index_page = qs->index_page + 1,
		};
	}
}

static int
gotweb_render_index(struct template *tp)
{
	const struct got_error *error = NULL;
	struct request *c = tp->tp_arg;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	const struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = NULL;
	struct dirent **sd_dent = t->repos;
	unsigned int d_i, d_disp = 0;
	unsigned int d_skipped = 0;
	int type, r;

	if (gotweb_render_repo_table_hdr(c->tp) == -1)
		return -1;

	for (d_i = 0; d_i < t->nrepos; d_i++) {
		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0) {
			d_skipped++;
			continue;
		}

		error = got_path_dirent_type(&type, srv->repos_path,
		    sd_dent[d_i]);
		if (error)
			continue;
		if (type != DT_DIR) {
			d_skipped++;
			continue;
		}

		if (qs->index_page > 0 && (qs->index_page *
		    srv->max_repos_display) > t->prev_disp) {
			t->prev_disp++;
			continue;
		}

		error = gotweb_load_got_path(&repo_dir, sd_dent[d_i]->d_name,
		    c, NULL);
		if (error) {
			if (error->code != GOT_ERR_NOT_GIT_REPO)
				log_warnx("%s: %s: %s", __func__,
				    sd_dent[d_i]->d_name, error->msg);
			gotweb_free_repo_dir(repo_dir);
			repo_dir = NULL;
			d_skipped++;
			continue;
		}

		d_disp++;
		t->prev_disp++;

		r = gotweb_render_repo_fragment(c->tp, repo_dir);
		gotweb_free_repo_dir(repo_dir);
		repo_dir = NULL;
		got_repo_close(t->repo);
		t->repo = NULL;
		if (r == -1)
			return -1;

		t->next_disp++;
		if (d_disp == srv->max_repos_display)
			break;
	}
	t->repos_total = t->nrepos - d_skipped;

	if (srv->max_repos_display == 0 ||
	    t->repos_total <= srv->max_repos_display)
		return 0;

	if (gotweb_render_navs(c->tp) == -1)
		return -1;

	return 0;
}

static inline int
should_urlencode(int c)
{
	if (c <= ' ' || c >= 127)
		return 1;

	switch (c) {
		/* gen-delim */
	case ':':
	case '/':
	case '?':
	case '#':
	case '[':
	case ']':
	case '@':
		/* sub-delims */
	case '!':
	case '$':
	case '&':
	case '\'':
	case '(':
	case ')':
	case '*':
	case '+':
	case ',':
	case ';':
	case '=':
		/* needed because the URLs are embedded into the HTML */
	case '\"':
		return 1;
	default:
		return 0;
	}
}

static char *
gotweb_urlencode(const char *str)
{
	const char *s;
	char *escaped;
	size_t i, len;
	int a, b;

	len = 0;
	for (s = str; *s; ++s) {
		len++;
		if (should_urlencode(*s))
			len += 2;
	}

	escaped = calloc(1, len + 1);
	if (escaped == NULL)
		return NULL;

	i = 0;
	for (s = str; *s; ++s) {
		if (should_urlencode(*s)) {
			a = (*s & 0xF0) >> 4;
			b = (*s & 0x0F);

			escaped[i++] = '%';
			escaped[i++] = a <= 9 ? ('0' + a) : ('7' + a);
			escaped[i++] = b <= 9 ? ('0' + b) : ('7' + b);
		} else
			escaped[i++] = *s;
	}

	return escaped;
}

const char *
gotweb_action_name(int action)
{
	switch (action) {
	case NO_ACTION:
		return "no action";
	case BLAME:
		return "blame";
	case BLOB:
		return "blob";
	case BLOBRAW:
		return "blobraw";
	case BRIEFS:
		return "briefs";
	case COMMITS:
		return "commits";
	case DIFF:
		return "diff";
	case ERR:
		return "err";
	case INDEX:
		return "index";
	case PATCH:
		return "patch";
	case SUMMARY:
		return "summary";
	case TAG:
		return "tag";
	case TAGS:
		return "tags";
	case TREE:
		return "tree";
	case RSS:
		return "rss";
	default:
		return NULL;
	}
}

int
gotweb_render_url(struct request *c, struct gotweb_url *url)
{
	const char *sep = "?", *action;
	char *tmp;
	int r;

	action = gotweb_action_name(url->action);
	if (action != NULL) {
		if (tp_writef(c->tp, "?action=%s", action) == -1)
			return -1;
		sep = "&";
	}

	if (url->commit) {
		if (tp_writef(c->tp, "%scommit=%s", sep, url->commit) == -1)
			return -1;
		sep = "&";
	}

	if (url->file) {
		tmp = gotweb_urlencode(url->file);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sfile=%s", sep, tmp);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->folder) {
		if (got_path_is_root_dir(url->folder))
			tmp = NULL;
		else {
			tmp = gotweb_urlencode(url->folder);
			if (tmp == NULL)
				return -1;
		}
		r = tp_writef(c->tp, "%sfolder=%s", sep, tmp ? tmp : "");
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->headref) {
		tmp = gotweb_urlencode(url->headref);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sheadref=%s", sep, url->headref);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->index_page != -1) {
		if (tp_writef(c->tp, "%sindex_page=%d", sep,
		    url->index_page) == -1)
			return -1;
		sep = "&";
	}

	if (url->path) {
		tmp = gotweb_urlencode(url->path);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%spath=%s", sep, tmp);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	return 0;
}

int
gotweb_render_absolute_url(struct request *c, struct gotweb_url *url)
{
	struct template	*tp = c->tp;
	struct gotwebd_fcgi_params *p = &c->fcgi_params;
	const char	*proto = p->https ? "https" : "http";

	if (tp_writes(tp, proto) == -1 ||
	    tp_writes(tp, "://") == -1 ||
	    tp_htmlescape(tp, p->server_name) == -1 ||
	    tp_htmlescape(tp, p->document_uri) == -1)
		return -1;

	return gotweb_render_url(c, url);
}

/* 
 * Ensure that a path sent in the request will not escape from the given
 * parent directory. This matters for got-portable where we are not
 * necessarily running in chroot and cannot be protected by unveil(2).
 */
static const struct got_error *
validate_path(const char *path, const char *parent_path,
    const char *orig_path)
{
	const struct got_error *error = NULL;
	char *abspath;

	abspath = realpath(path, NULL);
	if (abspath == NULL) {
		/* Paths which cannot be resolved are safe. */
		if (errno == ENOENT || errno == EACCES || errno == ENOTDIR)
			return NULL;
		return got_error_from_errno("realpath");
	}

	if (!got_path_is_child(abspath, parent_path, strlen(parent_path)))
		error = got_error_path(orig_path, GOT_ERR_NOT_GIT_REPO);

	free(abspath);
	return error;
}

static enum gotwebd_access
auth_check(struct request *c, struct gotwebd_access_rule_list *rules)
{
	struct gotwebd *env = gotwebd_env;
	enum gotwebd_access access = GOTWEBD_ACCESS_NO_MATCH;
	struct gotwebd_access_rule *rule;

	/*
	 * The www user ID implies that no user authentication occurred.
	 * But authentication is enabled so we must deny this request.
	 */
	if (c->client_uid == env->www_uid)
		return GOTWEBD_ACCESS_DENIED;

	/*
	 * We cannot access /etc/passwd in this process so we cannot
	 * verify the client's user ID ourselves here.
	 * Match rules against the access identifier which has already
	 * passed authentication in the auth process.
	 */
	STAILQ_FOREACH(rule, rules, entry) {
		if (strcmp(rule->identifier, c->access_identifier) == 0)
			access = rule->access;
	}

	return access;
}

static const struct got_error *
gotweb_load_got_path(struct repo_dir **rp, const char *dir,
    struct request *c, struct website *site)
{
	const struct got_error *error = NULL;
	struct gotwebd *env = gotwebd_env;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct repo_dir *repo_dir;
	DIR *dt;
	char *dir_test;
	struct gotwebd_repo *repo;
	enum gotwebd_auth_config auth_config = 0;
	struct gotwebd_access_rule_list *access_rules = NULL;
	enum gotwebd_access access = GOTWEBD_ACCESS_DENIED;
	int repo_is_hidden = 0;

	*rp = calloc(1, sizeof(**rp));
	if (*rp == NULL)
		return got_error_from_errno("calloc");
	repo_dir = *rp;

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, dir,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

	error = validate_path(dir_test, srv->repos_path, dir);
	if (error) {
		free(dir_test);
		return error;
	}

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
		if (asprintf(&dir_test, "%s/%s", srv->repos_path, dir) == -1)
			return got_error_from_errno("asprintf");
		dt = opendir(dir_test);
		if (dt == NULL) {
			free(dir_test);
			if (asprintf(&dir_test, "%s/%s%s", srv->repos_path,
			    dir, GOTWEB_GIT_DIR) == -1)
				return got_error_from_errno("asprintf");
			dt = opendir(dir_test);
			if (dt == NULL) {
				free(dir_test);
				return got_error_path(dir,
				    GOT_ERR_NOT_GIT_REPO);
			}
		}
	}

	repo_dir->path = dir_test;
	dir_test = NULL;

	error = got_path_basename(&repo_dir->name, repo_dir->path);
	if (error)
		goto err;

	repo = gotweb_get_repository(srv, repo_dir->name);
	if (repo || site) {
		if (site) {
			auth_config = site->auth_config;
			access_rules = &site->access_rules;
		} else {
			repo_is_hidden = repo->hidden;
			auth_config = repo->auth_config;
			access_rules = &repo->access_rules;
		}

		switch (auth_config) {
		case GOTWEBD_AUTH_DISABLED:
			access = GOTWEBD_ACCESS_PERMITTED;
			break;
		case GOTWEBD_AUTH_SECURE:
		case GOTWEBD_AUTH_INSECURE:
			access = auth_check(c, access_rules);
			if (access == GOTWEBD_ACCESS_NO_MATCH)
				access = auth_check(c, &srv->access_rules);
			if (access == GOTWEBD_ACCESS_NO_MATCH)
				access = auth_check(c, &env->access_rules);
			if (access == GOTWEBD_ACCESS_NO_MATCH)
				access = GOTWEBD_ACCESS_DENIED;
			break;
		}
	} else {
		repo_is_hidden = srv->hide_repositories;
		auth_config = srv->auth_config;
		switch (auth_config) {
		case GOTWEBD_AUTH_DISABLED:
			access = GOTWEBD_ACCESS_PERMITTED;
			break;
		case GOTWEBD_AUTH_SECURE:
		case GOTWEBD_AUTH_INSECURE:
			access = auth_check(c, &srv->access_rules);
			if (access == GOTWEBD_ACCESS_NO_MATCH)
				access = auth_check(c, &env->access_rules);
			if (access == GOTWEBD_ACCESS_NO_MATCH)
				access = GOTWEBD_ACCESS_DENIED;
			break;
		}
	}

	if (access != GOTWEBD_ACCESS_PERMITTED &&
	    access != GOTWEBD_ACCESS_DENIED)
		fatalx("invalid access check result %d", access);

	if (access != GOTWEBD_ACCESS_PERMITTED) {
		error = got_error_path(repo_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto err;
	}

	if (site == NULL) {
		if (repo_is_hidden) {
			error = got_error_path(repo_dir->name,
			    GOT_ERR_NOT_GIT_REPO);
			goto err;
		}

		if (srv->respect_exportok && faccessat(dirfd(dt),
		    "git-daemon-export-ok", F_OK, 0) == -1) {
			error = got_error_path(repo_dir->name,
			    GOT_ERR_NOT_GIT_REPO);
			goto err;
		}
	}

	error = got_repo_open(&t->repo, repo_dir->path, NULL,
	    gotwebd_env->pack_fds);
	if (error)
		goto err;
	if (repo && repo->description[0] != '\0') {
		repo_dir->description = strdup(repo->description);
		if (repo_dir->description == NULL) {
			error = got_error_from_errno("strdup");
			goto err;
		}
	} else {
		error = gotweb_get_repo_description(&repo_dir->description,
		    srv, repo_dir->path, dirfd(dt));
		if (error)
			goto err;
	}
	if (srv->show_repo_owner) {
		error = gotweb_load_file(&repo_dir->owner, repo_dir->path,
		    "owner", dirfd(dt));
		if (error)
			goto err;
		if (repo_dir->owner == NULL) {
			error = got_get_repo_owner(&repo_dir->owner, c);
			if (error)
				goto err;
		}
	}
	if (srv->show_repo_age) {
		error = got_get_repo_age(&repo_dir->age, c, NULL);
		if (error)
			goto err;
	}
	error = gotweb_get_clone_url(&repo_dir->url, srv, repo_dir->path,
	    dirfd(dt));
err:
	free(dir_test);
	if (dt != NULL && closedir(dt) == EOF && error == NULL)
		error = got_error_from_errno("closedir");
	if (error && t->repo) {
		got_repo_close(t->repo);
		t->repo = NULL;
	}
	return error;
}

static const struct got_error *
gotweb_load_file(char **str, const char *dir, const char *file, int dirfd)
{
	const struct got_error *error = NULL;
	struct stat sb;
	off_t len;
	int fd;

	*str = NULL;

	fd = openat(dirfd, file, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT || errno == EACCES)
			return NULL;
		return got_error_from_errno_fmt("openat %s/%s", dir, file);
	}

	if (fstat(fd, &sb) == -1) {
		error = got_error_from_errno_fmt("fstat %s/%s", dir, file);
		goto done;
	}

	len = sb.st_size;
	if (len > GOTWEBD_MAXDESCRSZ - 1)
		len = GOTWEBD_MAXDESCRSZ - 1;

	*str = calloc(len + 1, 1);
	if (*str == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	if (read(fd, *str, len) == -1)
		error = got_error_from_errno("read");
 done:
	if (fd != -1 && close(fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	return error;
}

static const struct got_error *
gotweb_get_repo_description(char **description, struct server *srv,
    const char *dirpath, int dir)
{
	*description = NULL;
	if (srv->show_repo_description == 0)
		return NULL;

	return gotweb_load_file(description, dirpath, "description", dir);
}

static const struct got_error *
gotweb_get_clone_url(char **url, struct server *srv, const char *dirpath,
    int dir)
{
	*url = NULL;
	if (srv->show_repo_cloneurl == 0)
		return NULL;

	return gotweb_load_file(url, dirpath, "cloneurl", dir);
}

int
gotweb_render_age(struct template *tp, time_t committer_time)
{
	struct request *c = tp->tp_arg;
	long long diff_time;
	const char *years = "years ago", *months = "months ago";
	const char *weeks = "weeks ago", *days = "days ago";
	const char *hours = "hours ago",  *minutes = "minutes ago";
	const char *seconds = "seconds ago", *now = "right now";

	diff_time = time(NULL) - committer_time;
	if (diff_time > 60 * 60 * 24 * 365 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / 365), years) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * (365 / 12) * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / (365 / 12)),
		    months) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * 7 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / 7), weeks) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24), days) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60), hours) == -1)
			return -1;
	} else if (diff_time > 60 * 2) {
		if (tp_writef(c->tp, "%lld %s", (diff_time / 60),
		    minutes) == -1)
			return -1;
	} else if (diff_time > 2) {
		if (tp_writef(c->tp, "%lld %s", diff_time,
		    seconds) == -1)
			return -1;
	} else {
		if (tp_writes(tp, now) == -1)
			return -1;
	}
	return 0;
}

static void
gotweb_shutdown(void)
{
	imsgbuf_clear(&gotwebd_env->iev_parent->ibuf);
	free(gotwebd_env->iev_parent);

	imsgbuf_clear(&gotwebd_env->iev_auth->ibuf);
	free(gotwebd_env->iev_auth);

	media_purge(&gotwebd_env->mediatypes);

	config_free_access_rules(&gotwebd_env->access_rules);

	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);

		config_free_access_rules(&srv->access_rules);
		config_free_repos(&srv->repos);
		config_free_websites(&srv->websites);
		free(srv);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->sockets)) {
		struct socket *sock;

		sock = TAILQ_FIRST(&gotwebd_env->sockets);
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		free(sock);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->addresses)) {
		struct address *h;

		h = TAILQ_FIRST(&gotwebd_env->addresses);
		TAILQ_REMOVE(&gotwebd_env->addresses, h, entry);
		free(h);
	}

	free(gotwebd_env);

	exit(0);
}

static void
gotweb_sighdlr(int sig, short event, void *arg)
{
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
	case SIGCHLD:
		break;
	case SIGTERM:
		/* continue until the parent exits */
		break;
	case SIGINT:
		gotweb_shutdown();
		break;
	default:
		log_warn("unhandled signal %d", sig);
	}
}

static void
unveil_htdocs_path(const char *htdocs_path)
{
	struct gotwebd *env = gotwebd_env;
	char path[PATH_MAX];
	int ret;

	while (htdocs_path[0] == '/')
		htdocs_path++;

	ret = snprintf(path, sizeof(path), "%s/%s",
	    env->httpd_chroot, htdocs_path);
	if (ret == -1)
		fatal("snprintf");
	if ((size_t)ret >= sizeof(path)) {
		fatalx("htdocs path too long, exceeds %zd bytes: %s",
		    sizeof(path) - strlen(env->httpd_chroot) - 1,
		    htdocs_path);
	}

	if (unveil(path, "r") == -1)
		fatal("unveil %s", path);
}

static void
gotweb_launch(struct gotwebd *env)
{
	struct server *srv;
	const struct got_error *error;

	if (env->iev_auth == NULL)
		fatal("auth process not connected");

#ifndef PROFILE
	if (pledge("stdio rpath recvfd sendfd proc exec unveil", NULL) == -1)
		fatal("pledge");
#endif

	unveil_htdocs_path(env->htdocs_path);

	TAILQ_FOREACH(srv, &gotwebd_env->servers, entry) {
		if (unveil(srv->repos_path, "r") == -1)
			fatal("unveil %s", srv->repos_path);

		if (got_path_cmp(env->htdocs_path, srv->htdocs_path, 
		    strlen(env->htdocs_path), strlen(srv->htdocs_path)) != 0)
			unveil_htdocs_path(srv->htdocs_path);
	}

	error = got_privsep_unveil_exec_helpers();
	if (error)
		fatalx("%s", error->msg);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	event_add(&env->iev_auth->ev, NULL);
}

static void
gotweb_dispatch_server(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct request		*c;
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
		case GOTWEBD_IMSG_REQ_PROCESS:
			c = recv_request(&imsg);
			if (c) {
				int request_id = c->request_id;
				if (gotweb_process_request(c) == -1) {
					log_warnx("request %u failed",
					    request_id);
				 } else {
					if (template_flush(c->tp) == -1) {
						log_warn("request %u flush",
						    request_id);
					}
				}

				fcgi_create_end_record(c);
				cleanup_request(c);
			}
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

static void
recv_auth_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->iev_auth != NULL)
		fatalx("auth process already connected");

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid auth pipe fd");

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");
	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);

	iev->handler = gotweb_dispatch_server;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, gotweb_dispatch_server, iev);
	imsg_event_add(iev);

	env->iev_auth = iev;
}

static void
gotweb_dispatch_main(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct gotwebd		*env = gotwebd_env;
	struct server		*srv;
	struct gotwebd_repo	*repo;
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
		case GOTWEBD_IMSG_CFG_ACCESS_RULE:
			if (TAILQ_EMPTY(&env->servers)) {
				/* global access rule */
				config_get_access_rule(&env->access_rules,
				    &imsg);
			} else {
				srv = TAILQ_LAST(&env->servers, serverlist);
				if (TAILQ_EMPTY(&srv->repos)) {
					/* per-server access rule */
					config_get_access_rule(
					    &srv->access_rules, &imsg);
				} else {
					/* per-repository access rule */
					repo = TAILQ_LAST(&srv->repos,
					    gotwebd_repolist);
					config_get_access_rule(
					    &repo->access_rules, &imsg);
				}
			}
			break;
		case GOTWEBD_IMSG_CFG_MEDIA_TYPE:
			config_getmediatype(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_SRV:
			config_getserver(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_REPO:
			if (TAILQ_EMPTY(&env->servers))
				fatalx("%s: unexpected CFG_REPO msg", __func__);
			srv = TAILQ_LAST(&env->servers, serverlist);
			config_get_repository(&srv->repos, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_WEBSITE:
			if (TAILQ_EMPTY(&env->servers)) {
				fatalx("%s: unexpected CFG_WEBSITE msg",
				    __func__);
			}
			srv = TAILQ_LAST(&env->servers, serverlist);
			config_get_website(&srv->websites, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_FD:
			config_getfd(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_SOCK:
			config_getsock(env, &imsg);
			break;
		case GOTWEBD_IMSG_CFG_DONE:
			config_getcfg(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_PIPE:
			recv_auth_pipe(env, &imsg);
			break;
		case GOTWEBD_IMSG_AUTH_CONF:
			if (imsg_get_data(&imsg, &env->auth_config,
			    sizeof(env->auth_config)) == -1)
				fatalx("%s: invalid AUTH_CONF msg", __func__);
			break;
		case GOTWEBD_IMSG_WWW_UID:
			if (imsg_get_data(&imsg, &env->www_uid,
			    sizeof(env->www_uid)) == -1)
				fatalx("%s: invalid WWW_UID msg", __func__);
			break;
		case GOTWEBD_IMSG_CTL_START:
			gotweb_launch(env);
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
gotweb(struct gotwebd *env, int fd)
{
	struct event	 sighup, sigint, sigusr1, sigchld, sigterm;
	struct event_base *evb;

	evb = event_init();

	sockets_rlimit(-1);

	env->iev_parent = calloc(1, sizeof(*env->iev_parent));
	if (env->iev_parent == NULL)
		fatal("calloc");
	if (imsgbuf_init(&env->iev_parent->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&env->iev_parent->ibuf);
	env->iev_parent->handler = gotweb_dispatch_main;
	env->iev_parent->data = env->iev_parent;
	event_set(&env->iev_parent->ev, fd, EV_READ, gotweb_dispatch_main,
	    env->iev_parent);
	event_add(&env->iev_parent->ev, NULL);

	signal(SIGPIPE, SIG_IGN);

	signal_set(&sighup, SIGHUP, gotweb_sighdlr, env);
	signal_add(&sighup, NULL);
	signal_set(&sigint, SIGINT, gotweb_sighdlr, env);
	signal_add(&sigint, NULL);
	signal_set(&sigusr1, SIGUSR1, gotweb_sighdlr, env);
	signal_add(&sigusr1, NULL);
	signal_set(&sigchld, SIGCHLD, gotweb_sighdlr, env);
	signal_add(&sigchld, NULL);
	signal_set(&sigterm, SIGTERM, gotweb_sighdlr, env);
	signal_add(&sigterm, NULL);

#ifndef PROFILE
	if (pledge("stdio rpath recvfd sendfd proc exec unveil", NULL) == -1)
		fatal("pledge");
#endif
	event_dispatch();
	event_base_free(evb);
	gotweb_shutdown();
}
