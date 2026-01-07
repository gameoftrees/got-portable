/*
 * Copyright (c) 2020-2022 Tracey Emery <tracey@traceyemery.net>
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

#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_poll.h"

#include "media.h"
#include "gotwebd.h"
#include "log.h"
#include "tmpl.h"

static void	 fcgi_sighdlr(int, short, void *);
static void	 fcgi_shutdown(void);
static void	 fcgi_launch(struct gotwebd *);

void	 fcgi_parse_record(struct gotwebd_fcgi_record *);
int	 fcgi_parse_begin_request(uint8_t *, uint16_t, struct request *,
	    uint16_t);
int	 fcgi_parse_params(uint8_t *, uint16_t, struct gotwebd_fcgi_params *);
int	 fcgi_send_response(struct request *, int, const void *, size_t);

void	 dump_fcgi_request_body(const char *, struct fcgi_record_header *);
void	 dump_fcgi_record_header(const char *, struct fcgi_record_header *);
void	 dump_fcgi_begin_request_body(const char *,
	    struct fcgi_begin_request_body *);
void	 dump_fcgi_end_request_body(const char *,
	    struct fcgi_end_request_body *);

extern struct requestlist requests;

static void
fcgi_shutdown(void)
{
	imsgbuf_clear(&gotwebd_env->iev_parent->ibuf);
	free(gotwebd_env->iev_parent);
	if (gotwebd_env->iev_sockets) {
		imsgbuf_clear(&gotwebd_env->iev_sockets->ibuf);
		free(gotwebd_env->iev_sockets);
	}

	free(gotwebd_env);

	exit(0);
}

static void
fcgi_sighdlr(int sig, short event, void *arg)
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
		fcgi_shutdown();
		break;
	default:
		log_warn("unexpected signal %d", sig);
		break;
	}
}

static void
send_parsed_params(struct gotwebd_fcgi_params *params)
{
	struct gotwebd *env = gotwebd_env;

	if (imsg_compose_event(env->iev_sockets, GOTWEBD_IMSG_FCGI_PARAMS,
	    GOTWEBD_PROC_FCGI, -1, -1, params, sizeof(*params)) == -1)
		log_warn("imsg_compose_event");
}

static void
abort_request(uint32_t request_id)
{
	struct gotwebd *env = gotwebd_env;

	if (imsg_compose_event(env->iev_sockets, GOTWEBD_IMSG_REQ_ABORT,
	    GOTWEBD_PROC_FCGI, -1, -1, &request_id, sizeof(request_id)) == -1)
		log_warn("imsg_compose_event");
}

void
fcgi_parse_record(struct gotwebd_fcgi_record *rec)
{
	struct fcgi_record_header *h;
	uint8_t *record_body;
	struct gotwebd_fcgi_params params = { 0 };

	fcgi_init_querystring(&params.qs);

	if (rec->record_len < sizeof(struct fcgi_record_header) ||
	    rec->record_len > sizeof(rec->record)) {
		log_warnx("invalid fcgi record size");
		abort_request(rec->request_id);
		return;
	}

	h = (struct fcgi_record_header *)&rec->record[0];

	dump_fcgi_record_header("", h);

	if (rec->record_len != sizeof(*h) + ntohs(h->content_len) +
	    h->padding_len) {
		abort_request(rec->request_id);
		return;
	}

	dump_fcgi_request_body("", h);

	if (h->version != 1) {
		log_warn("wrong fcgi header version: %u", h->version);
		abort_request(rec->request_id);
		return;
	}

	record_body = &rec->record[sizeof(*h)];
	switch (h->type) {
	case FCGI_PARAMS:
		if (fcgi_parse_params(record_body,
		    ntohs(h->content_len), &params) == -1) {
			abort_request(rec->request_id);
			break;
		}
		params.request_id = rec->request_id;
		send_parsed_params(&params);
		break;
	default:
		log_warn("unexpected fcgi type %d", h->type);
		abort_request(rec->request_id);
		break;
	}
}

static const struct querystring_keys querystring_keys[] = {
	{ "action",		GOTWEBD_QS_ACTION },
	{ "commit",		GOTWEBD_QS_COMMIT },
	{ "file",		GOTWEBD_QS_RFILE },
	{ "folder",		GOTWEBD_QS_FOLDER },
	{ "headref",		GOTWEBD_QS_HEADREF },
	{ "index_page",	GOTWEBD_QS_INDEX_PAGE },
	{ "path",		GOTWEBD_QS_PATH },
	{ "login",		GOTWEBD_QS_LOGIN },
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


void
fcgi_init_querystring(struct querystring *qs)
{
	memset(qs, 0, sizeof(*qs));
	qs->action = NO_ACTION;
	qs->index_page = -1;
}

/*
 * Adapted from usr.sbin/httpd/httpd.c url_decode.
 */
static const struct got_error *
urldecode(char *url)
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
validate_path(const char *path)
{
	size_t len = strlen(path);

	if (len >= 3 && strncmp(path, "../", 3) == 0)
		return got_error(GOT_ERR_BAD_QUERYSTRING);

	if (len >= 4 && strstr(path, "/../") != NULL)
		return got_error(GOT_ERR_BAD_QUERYSTRING);

	if (len >= 3 && strcmp(path + len - 3, "/..") == 0)
		return got_error(GOT_ERR_BAD_QUERYSTRING);

	return NULL;

}

static const struct got_error *
assign_querystring(struct querystring *qs, char *key, char *value)
{
	const struct got_error *error = NULL;
	const char *errstr;
	int a_cnt, el_cnt;

	error = urldecode(value);
	if (error)
		return error;

	for (el_cnt = 0; el_cnt < nitems(querystring_keys); el_cnt++) {
		if (strcmp(key, querystring_keys[el_cnt].name) != 0)
			continue;

		switch (querystring_keys[el_cnt].element) {
		case GOTWEBD_QS_ACTION:
			for (a_cnt = 0; a_cnt < nitems(action_keys); a_cnt++) {
				if (strcmp(value, action_keys[a_cnt].name) != 0)
					continue;
				qs->action = action_keys[a_cnt].action;
				break;
			}
			if (a_cnt == nitems(action_keys))
				qs->action = ERR;
			break;
		case GOTWEBD_QS_COMMIT:
			if (strlcpy(qs->commit, value, sizeof(qs->commit)) >=
			    sizeof(qs->commit)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "requested commit ID too long");
				goto done;
			}
			break;
		case GOTWEBD_QS_RFILE:
			error = validate_path(value);
			if (error)
				goto done;
			if (strlcpy(qs->file, value, sizeof(qs->file)) >=
			    sizeof(qs->file)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "requested in-repository path too long");
				goto done;
			}
			break;
		case GOTWEBD_QS_FOLDER:
			error = validate_path(value);
			if (error)
				goto done;
			if (strlcpy(qs->folder, value[0] ? value : "/",
			    sizeof(qs->folder)) >= sizeof(qs->folder)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "requested repository folder path "
				    "too long");
				goto done;
			}
			break;
		case GOTWEBD_QS_HEADREF:
			error = validate_path(value);
			if (error)
				goto done;
			if (strlcpy(qs->headref, value, sizeof(qs->headref)) >=
			    sizeof(qs->headref)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "requested repository head ref too long");
				goto done;
			}
			break;
		case GOTWEBD_QS_INDEX_PAGE:
			if (*value == '\0')
				break;
			qs->index_page = strtonum(value, 0, INT_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3(__func__,
				    "strtonum", errstr);
				goto done;
			}
			break;
		case GOTWEBD_QS_PATH:
			error = validate_path(value);
			if (error)
				goto done;
			if (strlcpy(qs->path, value, sizeof(qs->path)) >=
			    sizeof(qs->path)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "requested repository path too long");
				goto done;
			}
			break;
		case GOTWEBD_QS_LOGIN:
			if (strlcpy(qs->login, value, sizeof(qs->login)) >=
			    sizeof(qs->login)) {
				error = got_error_msg(GOT_ERR_NO_SPACE,
				    "login token too long");
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

static const struct got_error *
parse_querystring(struct querystring *qs, char *qst)
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
				error = assign_querystring(qs, tok2_pair,
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

static void
parse_cookie_hdr(struct gotwebd_fcgi_params *params, char *hdr, size_t len)
{
	size_t	 l;
	char	*end;

	memset(params->auth_cookie, 0, sizeof(params->auth_cookie));

	while (len > 0) {
		if (hdr[0] == ' ' || hdr[0] == '\t') {
			hdr++;
			len--;
			continue;
		}

		/* looking at the start of name=val */

		if ((end = memchr(hdr, ' ', len)) == NULL ||
		    (end = memchr(hdr, '\t', len)) == NULL)
			end = hdr + len;
		l = end - hdr;

		if (len > 8 && !strncmp(hdr, "gwdauth=", 8)) {
			hdr += 8;
			len -= 8;
			l -= 8;

			if (l < MAX_AUTH_COOKIE - 1) {
				memcpy(params->auth_cookie, hdr, l);
				params->auth_cookie[l] = '\0';
			}

			return;
		}

		/* skip to the next one */
		hdr += l;
		len -= l;
	}
}

int
fcgi_parse_params(uint8_t *buf, uint16_t n, struct gotwebd_fcgi_params *params)
{
	const struct got_error *error;
	uint32_t name_len, val_len;
	uint8_t *val;

	if (n == 0)
		return 0;

	while (n > 0) {
		if (buf[0] >> 7 == 0) {
			name_len = buf[0];
			n--;
			buf++;
		} else {
			if (n > 3) {
				name_len = ((buf[0] & 0x7f) << 24) +
				    (buf[1] << 16) + (buf[2] << 8) + buf[3];
				n -= 4;
				buf += 4;
			} else
				return -1;
		}

		if (n == 0)
			return -1;

		if (buf[0] >> 7 == 0) {
			val_len = buf[0];
			n--;
			buf++;
		} else {
			if (n > 3) {
				val_len = ((buf[0] & 0x7f) << 24) +
					(buf[1] << 16) + (buf[2] << 8) +
					buf[3];
				n -= 4;
				buf += 4;
			} else
				return -1;
		}

		if (n < name_len + val_len)
			return -1;

		val = buf + name_len;

		if (val_len < MAX_QUERYSTRING && name_len == 12 &&
		    strncmp(buf, "QUERY_STRING", 12) == 0) {
			char querystring[MAX_QUERYSTRING];

			memcpy(querystring, val, val_len);
			querystring[val_len] = '\0';

			fcgi_init_querystring(&params->qs);

			error = parse_querystring(&params->qs, querystring);
			if (error) {
				log_warnx("%s: %s", __func__, error->msg);
				return -1;
			}
		}

		if (val_len < MAX_DOCUMENT_URI &&
		    name_len == 12 &&
		    strncmp(buf, "DOCUMENT_URI", 12) == 0) {
			memcpy(params->document_uri, val, val_len);
			params->document_uri[val_len] = '\0';
		}

		if (val_len < MAX_SERVER_NAME &&
		    name_len == 11 &&
		    strncmp(buf, "SERVER_NAME", 11) == 0) {
			memcpy(params->server_name, val, val_len);
			params->server_name[val_len] = '\0';
		}

		if (name_len == 5 &&
		    strncmp(buf, "HTTPS", 5) == 0)
			params->https = 1;

		if (name_len == 11 &&
		    strncmp(buf, "HTTP_COOKIE", 11) == 0)
			parse_cookie_hdr(params, val, val_len);

		buf += name_len + val_len;
		n -= name_len - val_len;
	}

	return 0;
}

static int
send_response(struct request *c, int type, const uint8_t *data,
    size_t len)
{
	static const uint8_t padding[FCGI_PADDING_SIZE];
	struct fcgi_record_header header;
	struct iovec iov[3];
	struct timespec ts;
	ssize_t nw;
	size_t padded_len, tot;
	int i, err = 0, th = 20;

	ts.tv_sec = 0;
	ts.tv_nsec = 50;

	memset(&header, 0, sizeof(header));
	header.version = 1;
	header.type = type;
	header.id = htons(c->id);
	header.content_len = htons(len);

	/* The FastCGI spec suggests to align the output buffer */
	tot = sizeof(header) + len;
	padded_len = FCGI_ALIGN(tot);
	if (padded_len > tot) {
		header.padding_len = padded_len - tot;
		tot += header.padding_len;
	}

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);

	iov[1].iov_base = (void *)data;
	iov[1].iov_len = len;

	iov[2].iov_base = (void *)padding;
	iov[2].iov_len = header.padding_len;

	dump_fcgi_record_header("resp ", &header);

	/*
	 * XXX: add some simple write heuristics here
	 * On slower VMs, spotty connections, etc., we don't want to go right to
	 * disconnect. Let's at least try to write the data a few times before
	 * giving up.
	 */
	while (tot > 0) {
		nw = writev(c->fd, iov, nitems(iov));
		if (nw == 0) {
			c->client_status = CLIENT_DISCONNECT;
			break;
		}
		if (nw == -1) {
			err++;
			if (errno == EAGAIN && err < th) {
				nanosleep(&ts, NULL);
				continue;
			}
			log_warn("%s: write failure", __func__);
			c->client_status = CLIENT_DISCONNECT;
			return -1;
		}

		if (nw != tot)
			log_warnx("%s: partial write: %zu vs %zu", __func__,
			    nw, tot);

		tot -= nw;
		for (i = 0; i < nitems(iov); ++i) {
			if (nw < iov[i].iov_len) {
				iov[i].iov_base += nw;
				iov[i].iov_len -= nw;
				break;
			}
			nw -= iov[i].iov_len;
			iov[i].iov_len = 0;
		}
	}

	return 0;
}

int
fcgi_send_response(struct request *c, int type, const void *data,
    size_t len)
{
	size_t		 avail;

	if (c->client_status == CLIENT_DISCONNECT)
		return -1;

	while (len > 0) {
		avail = len;
		if (avail > FCGI_CONTENT_SIZE)
			avail = FCGI_CONTENT_SIZE;

		if (send_response(c, type, data, avail) == -1)
			return -1;
		data += avail;
		len -= avail;
	}

	return 0;
}

int
fcgi_write(void *arg, const void *buf, size_t len)
{
	struct request	*c = arg;

	return fcgi_send_response(c, FCGI_STDOUT, buf, len);
}

void
fcgi_create_end_record(struct request *c)
{
	struct fcgi_end_request_body end_request;

	memset(&end_request, 0, sizeof(end_request));
	end_request.app_status = htonl(0); /* script status */
	end_request.protocol_status = FCGI_REQUEST_COMPLETE;

	fcgi_send_response(c, FCGI_END_REQUEST, &end_request,
	    sizeof(end_request));
}

void
fcgi_cleanup_request(struct request *c)
{
	if (evtimer_initialized(&c->tmo))
		evtimer_del(&c->tmo);
	if (event_initialized(&c->ev))
		event_del(&c->ev);

	if (c->fd != -1)
		close(c->fd);
	if (c->tp != NULL)
		template_free(c->tp);
	if (c->t != NULL)
		gotweb_free_transport(c->t);
	free(c->buf);
	free(c->outbuf);
	free(c);
}

void
dump_fcgi_request_body(const char *p, struct fcgi_record_header *h)
{
	if (h->type == FCGI_BEGIN_REQUEST)
		dump_fcgi_begin_request_body(p,
		    (struct fcgi_begin_request_body *)(h + 1));
	else if (h->type == FCGI_END_REQUEST)
		dump_fcgi_end_request_body(p,
		    (struct fcgi_end_request_body *)(h + 1));
}

void
dump_fcgi_record_header(const char* p, struct fcgi_record_header *h)
{
	log_debug("%sversion:         %d", p, h->version);
	log_debug("%stype:            %d", p, h->type);
	log_debug("%srequestId:       %d", p, ntohs(h->id));
	log_debug("%scontentLength:   %d", p, ntohs(h->content_len));
	log_debug("%spaddingLength:   %d", p, h->padding_len);
	log_debug("%sreserved:        %d", p, h->reserved);
}

void
dump_fcgi_begin_request_body(const char *p, struct fcgi_begin_request_body *b)
{
	log_debug("%srole             %d", p, ntohs(b->role));
	log_debug("%sflags            %d", p, b->flags);
}

void
dump_fcgi_end_request_body(const char *p, struct fcgi_end_request_body *b)
{
	log_debug("%sappStatus:       %d", p, ntohl(b->app_status));
	log_debug("%sprotocolStatus:  %d", p, b->protocol_status);
}

static void
fcgi_launch(struct gotwebd *env)
{
	if (env->iev_sockets == NULL)
		fatalx("sockets process not connected");
#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");
#endif
	event_add(&env->iev_sockets->ev, NULL);
}

static struct gotwebd_fcgi_record *
recv_record(struct imsg *imsg)
{
	struct gotwebd_fcgi_record *record;

	record = calloc(1, sizeof(*record));
	if (record == NULL) {
		log_warn("calloc");
		return NULL;
	}

	if (imsg_get_data(imsg, record, sizeof(*record)) == -1) {
		log_warn("imsg_get_data");
		free(record);
		return NULL;
	}

	return record;
}

static void
fcgi_dispatch_server(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
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
		case GOTWEBD_IMSG_FCGI_PARSE_PARAMS: {
			struct gotwebd_fcgi_record *rec;

			rec = recv_record(&imsg);
			if (rec) {
				fcgi_parse_record(rec);
				free(rec);
			}
			break;
		}
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

	if (env->iev_sockets != NULL) {
		log_warn("sockets pipe already received");
		return;
	}

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		fatalx("invalid server pipe fd");

	iev = calloc(1, sizeof(*iev));
	if (iev == NULL)
		fatal("calloc");

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	imsgbuf_set_maxsize(&iev->ibuf, sizeof(struct gotwebd_fcgi_record));

	iev->handler = fcgi_dispatch_server;
	iev->data = iev;
	event_set(&iev->ev, fd, EV_READ, fcgi_dispatch_server, iev);
	imsg_event_add(iev);

	env->iev_sockets = iev;
}

static void
fcgi_dispatch_main(int fd, short event, void *arg)
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
		case GOTWEBD_IMSG_CFG_DONE:
			config_getcfg(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_PIPE:
			recv_server_pipe(env, &imsg);
			break;
		case GOTWEBD_IMSG_CTL_START:
			fcgi_launch(env);
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
gotwebd_fcgi(struct gotwebd *env, int fd)
{
	struct event	 sighup, sigint, sigusr1, sigchld, sigterm;
	struct event_base *evb;

	evb = event_init();

	if ((env->iev_parent = malloc(sizeof(*env->iev_parent))) == NULL)
		fatal("malloc");
	if (imsgbuf_init(&env->iev_parent->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&env->iev_parent->ibuf);
	env->iev_parent->handler = fcgi_dispatch_main;
	env->iev_parent->data = env->iev_parent;
	event_set(&env->iev_parent->ev, fd, EV_READ, fcgi_dispatch_main,
	    env->iev_parent);
	event_add(&env->iev_parent->ev, NULL);

	signal(SIGPIPE, SIG_IGN);

	signal_set(&sighup, SIGHUP, fcgi_sighdlr, env);
	signal_add(&sighup, NULL);
	signal_set(&sigint, SIGINT, fcgi_sighdlr, env);
	signal_add(&sigint, NULL);
	signal_set(&sigusr1, SIGUSR1, fcgi_sighdlr, env);
	signal_add(&sigusr1, NULL);
	signal_set(&sigchld, SIGCHLD, fcgi_sighdlr, env);
	signal_add(&sigchld, NULL);
	signal_set(&sigterm, SIGTERM, fcgi_sighdlr, env);
	signal_add(&sigterm, NULL);

#ifndef PROFILE
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
#endif
	event_dispatch();
	event_base_free(evb);
	fcgi_shutdown();
}
