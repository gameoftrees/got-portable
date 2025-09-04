/*
 * Copyright (c) 2016, 2019, 2020-2022 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
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

#include "gotwebd.h"
#include "log.h"
#include "tmpl.h"

static const struct querystring_keys querystring_keys[] = {
	{ "action",		ACTION },
	{ "commit",		COMMIT },
	{ "file",		RFILE },
	{ "folder",		FOLDER },
	{ "headref",		HEADREF },
	{ "index_page",		INDEX_PAGE },
	{ "path",		PATH },
};

static const struct action_keys action_keys[] = {
	{ "blame",	BLAME },
	{ "blob",	BLOB },
	{ "blobraw",	BLOBRAW },
	{ "briefs",	BRIEFS },
	{ "commits",	COMMITS },
	{ "diff",	DIFF },
	{ "error",	ERR },
	{ "index",	INDEX },
	{ "patch",	PATCH },
	{ "summary",	SUMMARY },
	{ "tag",	TAG },
	{ "tags",	TAGS },
	{ "tree",	TREE },
	{ "rss",	RSS },
};

static const struct got_error *gotweb_init_querystring(struct querystring **);
static const struct got_error *gotweb_parse_querystring(struct querystring *,
    char *);
static const struct got_error *gotweb_assign_querystring(struct querystring *,
    char *, char *);
static int gotweb_render_index(struct template *);
static const struct got_error *gotweb_load_got_path(struct repo_dir **,
    const char *, struct request *);
static const struct got_error *gotweb_load_file(char **, const char *,
    const char *, int);
static const struct got_error *gotweb_get_repo_description(char **,
    struct server *, const char *, int);
static const struct got_error *gotweb_get_clone_url(char **, struct server *,
    const char *, int);

static void gotweb_free_querystring(struct querystring *);
static void gotweb_free_repo_dir(struct repo_dir *);

struct server *gotweb_get_server(const char *);

static int
gotweb_reply(struct request *c, int status, const char *ctype,
    struct gotweb_url *location)
{
	const char	*csp;

	if (status != 200 && tp_writef(c->tp, "Status: %d\r\n", status) == -1)
		return -1;

	if (location) {
		if (tp_writes(c->tp, "Location: ") == -1 ||
		    gotweb_render_url(c, location) == -1 ||
		    tp_writes(c->tp, "\r\n") == -1)
			return -1;
	}

	csp = "Content-Security-Policy: default-src 'self'; "
	    "script-src 'none'; object-src 'none';\r\n";
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

	if (imsg_compose_event(gotwebd_env->iev_server, GOTWEBD_IMSG_REQ_ABORT,
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

int
gotweb_process_request(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;;
	struct querystring *qs = NULL;
	struct repo_dir *repo_dir = NULL;
	struct repo_commit *commit;
	const char *rss_ctype = "application/rss+xml;charset=utf-8";
	const uint8_t *buf;
	size_t len;
	int r, binary = 0;

	/* parse our querystring */
	error = gotweb_init_querystring(&qs);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}
	c->t->qs = qs;
	error = gotweb_parse_querystring(qs, c->fcgi_params.querystring);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}

	/* Log the request. */
	if (gotwebd_env->gotwebd_verbose > 0) {
		struct gotwebd_fcgi_params *p = &c->fcgi_params;
		char *server_name = NULL;
		char *querystring = NULL;
		char *document_uri = NULL;

		if (p->server_name[0] &&
		    stravis(&server_name, p->server_name, VIS_SAFE) == -1) {
			log_warn("stravis");
			server_name = NULL;
		}
		if (p->querystring[0] &&
		    stravis(&querystring, p->querystring, VIS_SAFE) == -1) {
			log_warn("stravis");
			querystring = NULL;
		}
		if (p->document_uri[0] &&
		    stravis(&document_uri, p->document_uri, VIS_SAFE) == -1) {
			log_warn("stravis");
			document_uri = NULL;
		}

		log_info("processing request: server='%s' query='%s' "
		    "document_uri='%s'",
		    server_name ? server_name : "",
		    querystring ? querystring : "",
		    document_uri ? document_uri : "");
		free(server_name);
		free(querystring);
		free(document_uri);
	}

	/*
	 * certain actions require a commit id in the querystring. this stops
	 * bad actors from exploiting this by manually manipulating the
	 * querystring.
	 */

	if (qs->action == BLAME || qs->action == BLOB ||
	    qs->action == BLOBRAW || qs->action == DIFF ||
	    qs->action == PATCH) {
		if (qs->commit == NULL) {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}
	}

	if (qs->action != INDEX) {
		if (qs->path == NULL) {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}

		error = gotweb_load_got_path(&repo_dir, qs->path, c);
		c->t->repo_dir = repo_dir;
		if (error)
			goto err;
	}

	if (qs->action == BLOBRAW || qs->action == BLOB) {
		if (qs->folder == NULL || qs->file == NULL) {
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
		if (qs->folder == NULL || qs->file == NULL) {
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
				.path = qs->path,
				.commit = qs->commit,
				.folder = qs->folder,
				.file = qs->file,
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
		if (commit && qs->commit == NULL) {
			qs->commit = strdup(commit->commit_id);
			if (qs->commit == NULL) {
				error = got_error_from_errno("strdup");
				log_warn("%s: strdup", __func__);
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
	c->t->error = error;
	if (gotweb_reply(c, 400, "text/html", NULL) == -1)
		return -1;
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

static const struct got_error *
gotweb_init_querystring(struct querystring **qs)
{
	const struct got_error *error = NULL;

	*qs = calloc(1, sizeof(**qs));
	if (*qs == NULL)
		return got_error_from_errno2(__func__, "calloc");

	(*qs)->headref = strdup("HEAD");
	if ((*qs)->headref == NULL) {
		free(*qs);
		*qs = NULL;
		return got_error_from_errno2(__func__, "strdup");
	}

	(*qs)->action = INDEX;

	return error;
}

static const struct got_error *
gotweb_parse_querystring(struct querystring *qs, char *qst)
{
	const struct got_error *error = NULL;
	char *tok1 = NULL, *tok1_pair = NULL, *tok1_end = NULL;
	char *tok2 = NULL, *tok2_pair = NULL, *tok2_end = NULL;

	if (qst == NULL)
		return error;

	tok1 = strdup(qst);
	if (tok1 == NULL)
		return got_error_from_errno2(__func__, "strdup");

	tok1_pair = tok1;
	tok1_end = tok1;

	while (tok1_pair != NULL) {
		strsep(&tok1_end, "&");

		tok2 = strdup(tok1_pair);
		if (tok2 == NULL) {
			free(tok1);
			return got_error_from_errno2(__func__, "strdup");
		}

		tok2_pair = tok2;
		tok2_end = tok2;

		while (tok2_pair != NULL) {
			strsep(&tok2_end, "=");
			if (tok2_end) {
				error = gotweb_assign_querystring(qs, tok2_pair,
				    tok2_end);
				if (error)
					goto err;
			}
			tok2_pair = tok2_end;
		}
		free(tok2);
		tok1_pair = tok1_end;
	}
	free(tok1);
	return error;
err:
	free(tok2);
	free(tok1);
	return error;
}

/*
 * Adapted from usr.sbin/httpd/httpd.c url_decode.
 */
static const struct got_error *
gotweb_urldecode(char *url)
{
	char		*p, *q;
	char		 hex[3];
	unsigned long	 x;

	hex[2] = '\0';
	p = q = url;

	while (*p != '\0') {
		switch (*p) {
		case '%':
			/* Encoding character is followed by two hex chars */
			if (!isxdigit((unsigned char)p[1]) ||
			    !isxdigit((unsigned char)p[2]) ||
			    (p[1] == '0' && p[2] == '0'))
				return got_error(GOT_ERR_BAD_QUERYSTRING);

			hex[0] = p[1];
			hex[1] = p[2];

			/*
			 * We don't have to validate "hex" because it is
			 * guaranteed to include two hex chars followed by nul.
			 */
			x = strtoul(hex, NULL, 16);
			*q = (char)x;
			p += 2;
			break;
		default:
			*q = *p;
			break;
		}
		p++;
		q++;
	}
	*q = '\0';

	return NULL;
}

static const struct got_error *
gotweb_assign_querystring(struct querystring *qs, char *key, char *value)
{
	const struct got_error *error = NULL;
	const char *errstr;
	int a_cnt, el_cnt;

	error = gotweb_urldecode(value);
	if (error)
		return error;

	for (el_cnt = 0; el_cnt < nitems(querystring_keys); el_cnt++) {
		if (strcmp(key, querystring_keys[el_cnt].name) != 0)
			continue;

		switch (querystring_keys[el_cnt].element) {
		case ACTION:
			for (a_cnt = 0; a_cnt < nitems(action_keys); a_cnt++) {
				if (strcmp(value, action_keys[a_cnt].name) != 0)
					continue;
				qs->action = action_keys[a_cnt].action;
				break;
			}
			if (a_cnt == nitems(action_keys))
				qs->action = ERR;
			break;
		case COMMIT:
			qs->commit = strdup(value);
			if (qs->commit == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case RFILE:
			qs->file = strdup(value);
			if (qs->file == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case FOLDER:
			qs->folder = strdup(value);
			if (qs->folder == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case HEADREF:
			free(qs->headref);
			qs->headref = strdup(value);
			if (qs->headref == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case INDEX_PAGE:
			if (*value == '\0')
				break;
			qs->index_page = strtonum(value, INT64_MIN,
			    INT64_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3(__func__,
				    "strtonum", errstr);
				goto done;
			}
			if (qs->index_page < 0)
				qs->index_page = 0;
			break;
		case PATH:
			qs->path = strdup(value);
			if (qs->path == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		}

		/* entry found */
		break;
	}
done:
	return error;
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
gotweb_free_querystring(struct querystring *qs)
{
	if (qs != NULL) {
		free(qs->commit);
		free(qs->file);
		free(qs->folder);
		free(qs->headref);
		free(qs->path);
	}
	free(qs);
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
	gotweb_free_querystring(t->qs);
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
	struct querystring *qs = t->qs;
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
	struct querystring *qs = t->qs;
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
		    c);
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
		tmp = gotweb_urlencode(url->folder);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sfolder=%s", sep, tmp);
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

static const struct got_error *
gotweb_load_got_path(struct repo_dir **rp, const char *dir,
    struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct repo_dir *repo_dir;
	DIR *dt;
	char *dir_test;

	*rp = calloc(1, sizeof(**rp));
	if (*rp == NULL)
		return got_error_from_errno("calloc");
	repo_dir = *rp;

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, dir,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

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

	repo_dir->name = strdup(repo_dir->path + strlen(srv->repos_path) + 1);
	if (repo_dir->name == NULL) {
		error = got_error_from_errno("strdup");
		goto err;
	}

	if (srv->respect_exportok &&
	    faccessat(dirfd(dt), "git-daemon-export-ok", F_OK, 0) == -1) {
		error = got_error_path(repo_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto err;
	}

	error = got_repo_open(&t->repo, repo_dir->path, NULL,
	    gotwebd_env->pack_fds);
	if (error)
		goto err;
	error = gotweb_get_repo_description(&repo_dir->description, srv,
	    repo_dir->path, dirfd(dt));
	if (error)
		goto err;
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
	struct gotwebd *env = gotwebd_env;
	int i;

	imsgbuf_clear(&gotwebd_env->iev_parent->ibuf);
	free(gotwebd_env->iev_parent);

	for (i = 0; i < env->server_cnt - env->servers_pending; i++)
		imsgbuf_clear(&gotwebd_env->iev_server[i].ibuf);
	free(gotwebd_env->iev_server);

	while (!TAILQ_EMPTY(&gotwebd_env->servers)) {
		struct server *srv;

		srv = TAILQ_FIRST(&gotwebd_env->servers);
		TAILQ_REMOVE(&gotwebd_env->servers, srv, entry);
		free(srv);
	}

	while (!TAILQ_EMPTY(&gotwebd_env->sockets)) {
		struct socket *sock;

		sock = TAILQ_FIRST(&gotwebd_env->sockets);
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		free(sock);
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
	case SIGINT:
	case SIGTERM:
		gotweb_shutdown();
		break;
	default:
		log_warn("unhandled signal %d", sig);
	}
}

static void
gotweb_launch(struct gotwebd *env)
{
	struct server *srv;
	const struct got_error *error;
	int i;

	if (env->servers_pending != 0)
		fatal("server process not connected");

#ifndef PROFILE
	if (pledge("stdio rpath recvfd sendfd proc exec unveil", NULL) == -1)
		fatal("pledge");
#endif

	TAILQ_FOREACH(srv, &gotwebd_env->servers, entry) {
		if (unveil(srv->repos_path, "r") == -1)
			fatal("unveil %s", srv->repos_path);
	}

	error = got_privsep_unveil_exec_helpers();
	if (error)
		fatalx("%s", error->msg);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	for (i = 0; i < env->server_cnt; i++)
		event_add(&env->iev_server[i].ev, NULL);
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
				log_info("%u: %s: request %u", getpid(), __func__, c->request_id);
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
recv_server_pipe(struct gotwebd *env, struct imsg *imsg)
{
	struct imsgev *iev;
	int fd;

	if (env->servers_pending <= 0) {
		log_warn("server pipes already received");
		return;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid server pipe fd");

	iev = &env->iev_server[env->servers_pending - 1];
	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);

	iev->handler = gotweb_dispatch_server;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, gotweb_dispatch_server, iev);
	imsg_event_add(iev);

	env->servers_pending--;
}

static void
gotweb_dispatch_main(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct gotwebd		*env = gotwebd_env;
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
		case GOTWEBD_IMSG_CFG_SRV:
			config_getserver(env, &imsg);
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
			recv_server_pipe(env, &imsg);
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

	if (env->server_cnt <= 0)
		fatalx("invalid server count: %d", env->server_cnt);
	env->iev_server = calloc(env->server_cnt, sizeof(*env->iev_server));
	if (env->iev_server == NULL)
		fatal("calloc");
	env->servers_pending = env->server_cnt;

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
