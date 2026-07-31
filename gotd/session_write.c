/*
 * Copyright (c) 2022, 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_opentemp.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"
#include "got_lib_gitproto.h"

#include "gotd.h"
#include "log.h"
#include "session_write.h"

struct gotd_session_notif {
	STAILQ_ENTRY(gotd_session_notif) entry;
	int fd;
	enum gotd_notification_action action;
	char *refname;
	struct got_object_id old_id;
	struct got_object_id new_id;
};
STAILQ_HEAD(gotd_session_notifications, gotd_session_notif) notifications;

enum gotd_session_write_state {
	GOTD_STATE_EXPECT_LIST_REFS,
	GOTD_STATE_EXPECT_CAPABILITIES,
	GOTD_STATE_EXPECT_REF_UPDATE,
	GOTD_STATE_EXPECT_MORE_REF_UPDATES,
	GOTD_STATE_EXPECT_PACKFILE,
	GOTD_STATE_NOTIFY,
};

static struct gotd_session_write {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	char repo_name[NAME_MAX];
	int *pack_fds;
	int *temp_fds;
	int content_fd;
	struct gotd_imsgev parent_iev;
	struct gotd_imsgev notifier_iev;
	struct timeval request_timeout;
	enum gotd_session_write_state state;
	struct gotd_imsgev repo_child_iev;
	struct got_pathlist_head notification_refs;
	struct got_pathlist_head notification_ref_namespaces;
	size_t num_notification_refs_needed;
	size_t num_notification_refs_received;
	struct got_pathlist_head *notification_refs_cur;
	struct gotd_notification_targets notification_targets;
	int repo_child_packfd;
} gotd_session;

static struct gotd_session_client {
	struct gotd_client_capability	*capabilities;
	size_t				 ncapa_alloc;
	size_t				 ncapabilities;
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	struct gotd_imsgev		 iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	char				*username;
	char				*packfile_path;
	char				*packidx_path;
	int				 nref_updates;
	int				 accept_flush_pkt;
	int				 flush_disconnect;
} gotd_session_client;

static void session_write_shutdown(void);

static void
disconnect(struct gotd_session_client *client)
{
	log_debug("uid %d: disconnecting", client->euid);

	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_DISCONNECT, GOTD_PROC_SESSION_WRITE, -1, NULL, 0) == -1)
		log_warn("imsg compose DISCONNECT");

	imsgbuf_clear(&gotd_session.repo_child_iev.ibuf);
	event_del(&gotd_session.repo_child_iev.ev);
	evtimer_del(&client->tmo);
	close(client->fd);
	if (client->delta_cache_fd != -1)
		close(client->delta_cache_fd);
	if (client->packfile_path) {
		if (unlink(client->packfile_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packfile_path);
		free(client->packfile_path);
	}
	if (client->packidx_path) {
		if (unlink(client->packidx_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packidx_path);
		free(client->packidx_path);
	}
	free(client->capabilities);

	session_write_shutdown();
}

static void
disconnect_on_error(struct gotd_session_client *client,
    const struct got_error *err)
{
	struct imsgbuf ibuf;

	if (err->code != GOT_ERR_EOF) {
		log_warnx("uid %d: %s", client->euid, err->msg);
		if (imsgbuf_init(&ibuf, client->fd) == -1) {
			log_warn("imsgbuf_init");
		} else {
			gotd_imsg_send_error(&ibuf, 0,
			    GOTD_PROC_SESSION_WRITE, err);
			imsgbuf_clear(&ibuf);
		}
	}

	disconnect(client);
}

static void
gotd_request_timeout(int fd, short events, void *arg)
{
	struct gotd_session_client *client = arg;

	log_warnx("disconnecting uid %d due to timeout", client->euid);
	disconnect(client);
}

static void
session_write_sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		session_write_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static const struct got_error *
recv_packfile_received(int *pack_empty, struct imsg *imsg)
{
	struct gotd_imsg_packfile_received recvd;
	size_t datalen;

	*pack_empty = 0;

	log_debug("packfile-received received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(recvd))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&recvd, imsg->data, sizeof(recvd));

	if (recvd.pack_empty)
		*pack_empty = 1;

	return NULL;
}

static const struct got_error *
request_gotsys_conf(struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_packfile_get_content content_req;
	const char *refname = "refs/heads/main";
	const char *path = "gotsys.conf";
	struct ibuf *wbuf;
	size_t len;
	int fd = -1;

	err = got_opentemp_truncatefd(gotd_session.content_fd);
	if (err)
		return err;
	
	len = sizeof(content_req) + strlen(refname) + strlen(path);
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_PACKFILE_GET_CONTENT,
	    GOTD_PROC_SESSION_WRITE, gotd_session.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create PACKFILE_GET_CONTENT");

	memset(&content_req, 0, sizeof(content_req));
	content_req.refname_len = strlen(refname);
	content_req.path_len = strlen(path);

	if (imsg_add(wbuf, &content_req, sizeof(content_req)) == -1)
		return got_error_from_errno("imsg_add PACKFILE_GET_CONTENT");
	if (imsg_add(wbuf, refname, content_req.refname_len) == -1)
		return got_error_from_errno("imsg_add PACKFILE_GET_CONTENT");
	if (imsg_add(wbuf, path, content_req.path_len) == -1)
		return got_error_from_errno("imsg_add PACKFILE_GET_CONTENT");

	fd = dup(gotd_session.content_fd);
	if (fd == -1) {
		ibuf_free(wbuf);
		return got_error_from_errno("dup");
	}
	ibuf_fd_set(wbuf, fd);

	imsg_close(&iev->ibuf, wbuf);

	return gotd_imsg_flush(&iev->ibuf);
}

static int
need_packfile_verification(void)
{
	return (strcmp(gotd_session.repo_name, "gotsys") == 0 ||
	    strcmp(gotd_session.repo_name, "gotsys.git") == 0);
}

static const struct got_error *
verify_packfile(struct gotd_imsgev *iev)
{
	/* For now, verification is only implemented for gotsys.git. */
	return request_gotsys_conf(iev);
}

static const struct got_error *
recv_content_written(int *ref_found, struct imsg *imsg)
{
	struct gotd_imsg_packfile_content_written cw;
	size_t datalen;

	*ref_found = 0;

	log_debug("content-written received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(cw))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&cw, imsg->data, sizeof(cw));
	
	if (cw.ref_found) {
		*ref_found = 1;

		/* Currently we only look for gotsys.conf content. */
		if (!cw.wrote_content) {
			return got_error_msg(GOT_ERR_BAD_OBJ_DATA,
			    "gotsys.conf not found in pack file");
		}
	}

	return NULL;
}

static const struct got_error *
verify_gotsys_conf(void)
{
	struct gotd_imsgev *iev = &gotd_session.parent_iev;
	int fd;

	fd = dup(gotd_session.content_fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_RUN_GOTSYS_CHECK,
	    GOTD_PROC_SESSION_WRITE, fd, NULL, 0) == -1) {
		close(fd);
		return got_error_from_errno("imsg compose RUN_GOTSYS_CHECK");
	}

	return NULL;
}

static const struct got_error *
send_packfile_verified(struct gotd_imsgev *iev)
{
	if (gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_VERIFIED,
	    GOTD_PROC_SESSION_WRITE, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose PACKFILE_VERIFIED");

	return NULL;
}

static const struct got_error *
recv_packfile_install(struct imsg *imsg)
{
	struct gotd_imsg_packfile_install inst;
	size_t datalen;

	log_debug("packfile-install received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(inst))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&inst, imsg->data, sizeof(inst));

	return NULL;
}

static const struct got_error *
recv_ref_updates_start(struct imsg *imsg)
{
	struct gotd_imsg_ref_updates_start istart;
	size_t datalen;

	log_debug("ref-updates-start received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(istart))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&istart, imsg->data, sizeof(istart));

	return NULL;
}

static const struct got_error *
recv_ref_update(struct imsg *imsg)
{
	struct gotd_imsg_ref_update iref;
	size_t datalen;

	log_debug("ref-update received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));

	return NULL;
}

static const struct got_error *
send_ref_update_ok(struct gotd_session_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname)
{
	struct gotd_imsg_ref_update_ok iok;
	struct gotd_imsgev *iev = &client->iev;
	struct ibuf *wbuf;
	size_t len;

	memset(&iok, 0, sizeof(iok));
	memcpy(iok.old_id, iref->old_id, SHA1_DIGEST_LENGTH);
	memcpy(iok.new_id, iref->new_id, SHA1_DIGEST_LENGTH);
	iok.name_len = strlen(refname);

	len = sizeof(iok) + iok.name_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE_OK,
	    GOTD_PROC_SESSION_WRITE, gotd_session.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_OK");

	if (imsg_add(wbuf, &iok, sizeof(iok)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");
	if (imsg_add(wbuf, refname, iok.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");

	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
send_refs_updated(struct gotd_imsgev *iev)
{
	if (gotd_imsg_compose_event(iev, GOTD_IMSG_REFS_UPDATED,
	    GOTD_PROC_SESSION_WRITE, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg compose REFS_UPDATED");

	return NULL;
}

static const struct got_error *
send_ref_update_ng(struct gotd_session_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname,
    const char *reason)
{
	const struct got_error *ng_err;
	struct gotd_imsg_ref_update_ng ing;
	struct gotd_imsgev *iev = &client->iev;
	struct ibuf *wbuf;
	size_t len;

	memset(&ing, 0, sizeof(ing));
	memcpy(ing.old_id, iref->old_id, SHA1_DIGEST_LENGTH);
	memcpy(ing.new_id, iref->new_id, SHA1_DIGEST_LENGTH);
	ing.name_len = strlen(refname);

	ng_err = got_error_fmt(GOT_ERR_REF_BUSY, "%s", reason);
	ing.reason_len = strlen(ng_err->msg);

	len = sizeof(ing) + ing.name_len + ing.reason_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE_NG,
	    GOTD_PROC_SESSION_WRITE, gotd_session.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_NG");

	if (imsg_add(wbuf, &ing, sizeof(ing)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, refname, ing.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, ng_err->msg, ing.reason_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");

	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
install_pack(struct gotd_session_client *client, const char *repo_path,
    struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_packfile_install inst;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	size_t datalen;
	char *packfile_path = NULL, *packidx_path = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(inst))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&inst, imsg->data, sizeof(inst));

	if (client->packfile_path == NULL)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "client has no pack file");
	if (client->packidx_path == NULL)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "client has no pack file index");

	if (got_sha1_digest_to_str(inst.pack_sha1, hex, sizeof(hex)) == NULL)
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "could not convert pack file SHA1 to hex");

	if (asprintf(&packfile_path, "/%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, hex) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&packidx_path, "/%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, hex) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (rename(client->packfile_path, packfile_path) == -1) {
		err = got_error_from_errno3("rename", client->packfile_path,
		    packfile_path);
		goto done;
	}

	free(client->packfile_path);
	client->packfile_path = NULL;

	if (rename(client->packidx_path, packidx_path) == -1) {
		err = got_error_from_errno3("rename", client->packidx_path,
		    packidx_path);
		goto done;
	}

	/* Ensure we re-read the pack index list upon next access. */
	gotd_session.repo->pack_path_mtime.tv_sec = 0;
	gotd_session.repo->pack_path_mtime.tv_nsec = 0;

	free(client->packidx_path);
	client->packidx_path = NULL;
done:
	free(packfile_path);
	free(packidx_path);
	return err;
}

static const struct got_error *
begin_ref_updates(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_ref_updates_start istart;
	size_t datalen;

	if (client->nref_updates != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(istart))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&istart, imsg->data, sizeof(istart));

	if (istart.nref_updates <= 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->nref_updates = istart.nref_updates;
	return NULL;
}

static const struct got_error *
validate_namespace(const char *namespace)
{
	size_t len = strlen(namespace);

	if (len < 5 || strncmp("refs/", namespace, 5) != 0 ||
	    namespace[len - 1] != '/') {
		return got_error_fmt(GOT_ERR_BAD_REF_NAME,
		    "reference namespace '%s'", namespace);
	}

	return NULL;
}

static const struct got_error *
queue_notification(struct got_object_id *old_id, struct got_object_id *new_id,
    struct got_repository *repo, struct got_reference *ref)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = &gotd_session.repo_child_iev;
	struct got_pathlist_entry *pe;
	struct gotd_session_notif *notif;

	if (iev->ibuf.fd == -1 ||
	    STAILQ_EMPTY(&gotd_session.notification_targets))
		return NULL; /* notifications unused */

	RB_FOREACH(pe, got_pathlist_head, &gotd_session.notification_refs) {
		const char *refname = pe->path;
		if (strcmp(got_ref_get_name(ref), refname) == 0)
			break;
	}
	if (pe == NULL) {
		RB_FOREACH(pe, got_pathlist_head,
		    &gotd_session.notification_ref_namespaces) {
			const char *namespace = pe->path;

			err = validate_namespace(namespace);
			if (err)
				return err;
			if (strncmp(namespace, got_ref_get_name(ref),
			    strlen(namespace)) == 0)
				break;
		}
	}

	/*
	 * If a branch or a reference namespace was specified in the
	 * configuration file then only send notifications if a match
	 * was found.
	 */
	if (pe == NULL && (!RB_EMPTY(&gotd_session.notification_refs) ||
	    !RB_EMPTY(&gotd_session.notification_ref_namespaces)))
		return NULL;

	notif = calloc(1, sizeof(*notif));
	if (notif == NULL)
		return got_error_from_errno("calloc");

	notif->fd = -1;

	if (old_id == NULL)
		notif->action = GOTD_NOTIF_ACTION_CREATED;
	else if (new_id == NULL)
		notif->action = GOTD_NOTIF_ACTION_REMOVED;
	else
		notif->action = GOTD_NOTIF_ACTION_CHANGED;

	if (old_id != NULL)
		memcpy(&notif->old_id, old_id, sizeof(notif->old_id));
	if (new_id != NULL)
		memcpy(&notif->new_id, new_id, sizeof(notif->new_id));

	notif->refname = strdup(got_ref_get_name(ref));
	if (notif->refname == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	STAILQ_INSERT_TAIL(&notifications, notif, entry);
done:
	if (err && notif) {
		free(notif->refname);
		free(notif);
	}
	return err;
}

/* Forward notification content to the NOTIFY process. */
static const struct got_error *
forward_notification(struct gotd_session_client *client, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = &gotd_session.notifier_iev;
	struct gotd_session_notif *notif;
	struct gotd_imsg_notification_content icontent;
	char *refname = NULL, *id_str = NULL;
	size_t datalen;
	struct gotd_imsg_notify inotify;
	const char *action;
	struct ibuf *wbuf;

	memset(&inotify, 0, sizeof(inotify));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(icontent))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icontent, imsg->data, sizeof(icontent));
	if (datalen != sizeof(icontent) + icontent.refname_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	refname = strndup(imsg->data + sizeof(icontent), icontent.refname_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	notif = STAILQ_FIRST(&notifications);
	if (notif == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	if (notif->action != icontent.action || notif->fd == -1 ||
	    strcmp(notif->refname, refname) != 0) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (notif->action == GOTD_NOTIF_ACTION_CREATED) {
		if (memcmp(&notif->new_id, &icontent.new_id,
		    sizeof(notif->new_id)) != 0) {
			err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "received notification content for unknown event");
			goto done;
		}
	} else if (notif->action == GOTD_NOTIF_ACTION_REMOVED) {
		if (memcmp(&notif->old_id, &icontent.old_id,
		    sizeof(notif->old_id)) != 0) {
			err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "received notification content for unknown event");
			goto done;
		}
	} else if (memcmp(&notif->old_id, &icontent.old_id,
	    sizeof(notif->old_id)) != 0 ||
	    memcmp(&notif->new_id, &icontent.new_id,
	    sizeof(notif->old_id)) != 0) {
		err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "received notification content for unknown event");
		goto done;
	}

	switch (notif->action) {
	case GOTD_NOTIF_ACTION_CREATED:
		action = "created";
		err = got_object_id_str(&id_str, &notif->new_id);
		if (err)
			goto done;
		break;
	case GOTD_NOTIF_ACTION_REMOVED:
		action = "removed";
		err = got_object_id_str(&id_str, &notif->old_id);
		if (err)
			goto done;
		break;
	case GOTD_NOTIF_ACTION_CHANGED:
		action = "changed";
		err = got_object_id_str(&id_str, &notif->new_id);
		if (err)
			goto done;
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	strlcpy(inotify.repo_name, gotd_session.repo_name,
	    sizeof(inotify.repo_name));

	snprintf(inotify.subject_line, sizeof(inotify.subject_line),
	    "%s: %s %s %s: %.12s", gotd_session.repo_name,
	    client->username, action, notif->refname, id_str);

	inotify.username_len = strlen(client->username);
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_NOTIFY,
	    GOTD_PROC_SESSION_WRITE, gotd_session.pid,
	    sizeof(inotify) + inotify.username_len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create NOTIFY");
		goto done;
	}
	if (imsg_add(wbuf, &inotify, sizeof(inotify)) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}
	if (imsg_add(wbuf, client->username, inotify.username_len) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}

	ibuf_fd_set(wbuf, notif->fd);
	notif->fd = -1;

	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
done:
	free(refname);
	free(id_str);
	return err;
}

/* Request notification content from REPO_WRITE process. */
static const struct got_error *
request_notification(struct gotd_session_notif *notif)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = &gotd_session.repo_child_iev;
	struct gotd_imsg_notification_content icontent;
	struct ibuf *wbuf;
	size_t len;
	int fd;

	fd = got_opentempfd();
	if (fd == -1)
		return got_error_from_errno("got_opentemp");

	memset(&icontent, 0, sizeof(icontent));

	icontent.action = notif->action;
	memcpy(&icontent.old_id, &notif->old_id, sizeof(notif->old_id));
	memcpy(&icontent.new_id, &notif->new_id, sizeof(notif->new_id));
	icontent.refname_len = strlen(notif->refname);

	len = sizeof(icontent) + icontent.refname_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_NOTIFY,
	    GOTD_PROC_SESSION_WRITE, gotd_session.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create NOTIFY");
		goto done;
	}
	if (imsg_add(wbuf, &icontent, sizeof(icontent)) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}
	if (imsg_add(wbuf, notif->refname, icontent.refname_len) == -1) {
		err = got_error_from_errno("imsg_add NOTIFY");
		goto done;
	}

	notif->fd = dup(fd);
	if (notif->fd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	ibuf_fd_set(wbuf, fd);
	fd = -1;

	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
done:
	if (err && fd != -1)
		close(fd);
	return err;
}

static const struct got_error *
update_ref(int *shut, struct gotd_session_client *client,
    const char *repo_path, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct got_repository *repo = gotd_session.repo;
	struct got_reference *ref = NULL;
	struct gotd_imsg_ref_update iref;
	struct got_object_id old_id, new_id;
	struct got_object_id *id = NULL;
	char *refname = NULL;
	size_t datalen;
	int locked = 0;
	char hex1[SHA1_DIGEST_STRING_LENGTH];
	char hex2[SHA1_DIGEST_STRING_LENGTH];

	log_debug("update-ref from uid %d", client->euid);

	if (client->nref_updates <= 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));
	if (datalen != sizeof(iref) + iref.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	refname = strndup(imsg->data + sizeof(iref), iref.name_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	log_debug("updating ref %s for uid %d", refname, client->euid);

	memset(&old_id, 0, sizeof(old_id));
	memcpy(old_id.hash, iref.old_id, SHA1_DIGEST_LENGTH);
	memset(&new_id, 0, sizeof(new_id));
	memcpy(new_id.hash, iref.new_id, SHA1_DIGEST_LENGTH);
	err = got_repo_find_object_id(iref.delete_ref ? &old_id : &new_id,
	    repo);
	if (err)
		goto done;

	if (iref.ref_is_new) {
		err = got_ref_open(&ref, repo, refname, 0);
		if (err) {
			if (err->code != GOT_ERR_NOT_REF)
				goto done;
			err = got_ref_alloc(&ref, refname, &new_id);
			if (err)
				goto done;
			err = got_ref_write(ref, repo); /* will lock/unlock */
			if (err)
				goto done;
			err = queue_notification(NULL, &new_id, repo, ref);
			if (err)
				goto done;
		} else {
			err = got_ref_resolve(&id, repo, ref);
			if (err)
				goto done;
			got_object_id_hex(&new_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Addition %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}
	} else if (iref.delete_ref) {
		err = got_ref_open(&ref, repo, refname, 1 /* lock */);
		if (err)
			goto done;
		locked = 1;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &old_id) != 0) {
			got_object_id_hex(&old_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Deletion %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}

		err = got_ref_delete(ref, repo);
		if (err)
			goto done;
		err = queue_notification(&old_id, NULL, repo, ref);
		if (err)
			goto done;
		free(id);
		id = NULL;
	} else {
		err = got_ref_open(&ref, repo, refname, 1 /* lock */);
		if (err)
			goto done;
		locked = 1;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &old_id) != 0) {
			got_object_id_hex(&old_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Update %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}

		if (got_object_id_cmp(&new_id, &old_id) != 0) {
			err = got_ref_change_ref(ref, &new_id);
			if (err)
				goto done;
			err = got_ref_write(ref, repo);
			if (err)
				goto done;
			err = queue_notification(&old_id, &new_id, repo, ref);
			if (err)
				goto done;
		}

		free(id);
		id = NULL;
	}
done:
	if (err) {
		if (err->code == GOT_ERR_LOCKFILE_TIMEOUT) {
			err = got_error_fmt(GOT_ERR_LOCKFILE_TIMEOUT,
			    "could not acquire exclusive file lock for %s",
			    refname);
		}
		send_ref_update_ng(client, &iref, refname, err->msg);
	} else
		send_ref_update_ok(client, &iref, refname);

	if (locked) {
		const struct got_error *unlock_err;
		unlock_err = got_ref_unlock(ref);
		if (unlock_err && err == NULL)
			err = unlock_err;
	}
	if (ref)
		got_ref_close(ref);
	free(refname);
	free(id);
	return err;
}

static const struct got_error *
recv_notification_content(struct imsg *imsg)
{
	struct gotd_imsg_notification_content inotif;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(inotif))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&inotif, imsg->data, sizeof(inotif));

	return NULL;
}

static const struct got_error *
report_ref_updates(int do_notify)
{
	const struct got_error *err;
	struct gotd_session_notif *notif;

	err = send_refs_updated(&gotd_session.parent_iev);
	if (err) {
		log_warn("%s", err->msg);
		return err;
	}

	if (do_notify) {
		notif = STAILQ_FIRST(&notifications);
		if (notif == NULL)
			return NULL;

		err = request_notification(notif);
		if (err) {
			log_warn("could not send notification: %s", err->msg);
			return err;
		}
	}

	return NULL;
}

static void
session_dispatch_repo_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;
		int do_ref_updates = 0, do_ref_update = 0;
		int do_packfile_verification = 0;
		int do_content_verification = 0;
		int packfile_verified = 0;
		int do_packfile_install = 0, do_notify = 0;

		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_RECEIVED: {
			int pack_empty;

			err = recv_packfile_received(&pack_empty, &imsg);
			if (err)
				break;
			if (!pack_empty && need_packfile_verification())
				do_packfile_verification = 1;
			else
				packfile_verified = 1;
			break;
		}
		case GOTD_IMSG_PACKFILE_CONTENT_WRITTEN: {
			int ref_found;

			err = recv_content_written(&ref_found, &imsg);
			if (err == NULL) {
				if (ref_found)
					do_content_verification = 1;
				else
					packfile_verified = 1;
			}
			break;
		}
		case GOTD_IMSG_PACKFILE_INSTALL:
			err = recv_packfile_install(&imsg);
			if (err == NULL)
				do_packfile_install = 1;
			break;
		case GOTD_IMSG_REF_UPDATES_START:
			err = recv_ref_updates_start(&imsg);
			if (err == NULL)
				do_ref_updates = 1;
			break;
		case GOTD_IMSG_REF_UPDATE:
			err = recv_ref_update(&imsg);
			if (err == NULL)
				do_ref_update = 1;
			break;
		case GOTD_IMSG_NOTIFY:
			err = recv_notification_content(&imsg);
			if (err == NULL)
				do_notify = 1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (do_disconnect || err) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else {
			if (do_packfile_verification) {
				err = verify_packfile(iev);
			} else if (do_content_verification) {
				err = verify_gotsys_conf();
			} else if (packfile_verified) {
				err = send_packfile_verified(iev);
			} else if (do_packfile_install)
				err = install_pack(client,
				    gotd_session.repo->path, &imsg);
			else if (do_ref_updates)
				err = begin_ref_updates(client, &imsg);
			else if (do_ref_update)
				err = update_ref(&shut, client,
				    gotd_session.repo->path, &imsg);
			else if (do_notify)
				err = forward_notification(client, &imsg);
			if (err)
				log_warnx("uid %d: %s", client->euid, err->msg);

			if (do_ref_update && client->nref_updates > 0) {
				client->nref_updates--;
				if (client->nref_updates == 0) {
					err = report_ref_updates(do_notify);
					if (err)
						shut = 1;
				}
			}
		}

		imsg_free(&imsg);

		if (err)
			break;
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static const struct got_error *
recv_capabilities(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capabilities icapas;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(icapas))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapas, imsg->data, sizeof(icapas));

	client->ncapa_alloc = icapas.ncapabilities;
	client->capabilities = calloc(client->ncapa_alloc,
	    sizeof(*client->capabilities));
	if (client->capabilities == NULL) {
		client->ncapa_alloc = 0;
		return got_error_from_errno("calloc");
	}

	log_debug("expecting %zu capabilities from uid %d",
	    client->ncapa_alloc, client->euid);
	return NULL;
}

static const struct got_error *
recv_capability(struct gotd_session_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capability icapa;
	struct gotd_client_capability *capa;
	size_t datalen;
	char *key, *value = NULL;

	if (client->capabilities == NULL ||
	    client->ncapabilities >= client->ncapa_alloc) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "unexpected capability received");
	}

	memset(&icapa, 0, sizeof(icapa));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(icapa))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapa, imsg->data, sizeof(icapa));

	if (datalen != sizeof(icapa) + icapa.key_len + icapa.value_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	key = strndup(imsg->data + sizeof(icapa), icapa.key_len);
	if (key == NULL)
		return got_error_from_errno("strndup");
	if (icapa.value_len > 0) {
		value = strndup(imsg->data + sizeof(icapa) + icapa.key_len,
		    icapa.value_len);
		if (value == NULL) {
			free(key);
			return got_error_from_errno("strndup");
		}
	}

	capa = &client->capabilities[client->ncapabilities++];
	capa->key = key;
	capa->value = value;

	if (value)
		log_debug("uid %d: capability %s=%s", client->euid, key, value);
	else
		log_debug("uid %d: capability %s", client->euid, key);

	return NULL;
}

static const struct got_error *
forward_ref_update(struct gotd_session_client *client, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_ref_update ireq;
	struct gotd_imsg_ref_update *iref = NULL;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));
	if (datalen != sizeof(ireq) + ireq.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	iref = malloc(datalen);
	if (iref == NULL)
		return got_error_from_errno("malloc");
	memcpy(iref, imsg->data, datalen);

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_REF_UPDATE, GOTD_PROC_SESSION_WRITE, -1,
	    iref, datalen) == -1)
		err = got_error_from_errno("imsg compose REF_UPDATE");
	free(iref);
	return err;
}

static int
client_has_capability(struct gotd_session_client *client, const char *capastr)
{
	struct gotd_client_capability *capa;
	size_t i;

	if (client->ncapabilities == 0)
		return 0;

	for (i = 0; i < client->ncapabilities; i++) {
		capa = &client->capabilities[i];
		if (strcmp(capa->key, capastr) == 0)
			return 1;
	}

	return 0;
}

static const struct got_error *
recv_packfile(struct gotd_session_client *client)
{
	const struct got_error *err = NULL;
	int pipe[2] = { -1, -1 };

	if (client->packfile_path) {
		return got_error_fmt(GOT_ERR_PRIVSEP_MSG,
		    "uid %d already has a pack file", client->euid);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	/*
	 * Send pack data pipe end 0 to gotsh(1) (expects just an fd, no data).
	 *
	 * We will forward the other pipe end to the repo_write process only
	 * once we have confirmation that gotsh(1) has received its end.
	 */
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_PACKFILE_PIPE, GOTD_PROC_GOTD, pipe[0], NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
		goto done;
	}
	pipe[0] = -1;

	gotd_session.repo_child_packfd = pipe[1];
	pipe[1] = -1;
done:
	if (pipe[0] != -1 && close(pipe[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (pipe[1] != -1 && close(pipe[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
send_packfds_to_repo_child(void)
{
	const struct got_error *err = NULL;
	struct gotd_session_client *client = &gotd_session_client;
	char *basepath = NULL, *pack_path = NULL, *idx_path = NULL;
	int packfd = -1, idxfd = -1;
	struct gotd_imsg_recv_packfile ipack;

	/*
	 * gotsh(1) has received its end of the pack pipe.
	 * Send pack pipe end 1 to repo child process.
	 */
	if (gotd_imsg_compose_event(
	    &gotd_session.repo_child_iev,
	    GOTD_IMSG_PACKFILE_PIPE, GOTD_PROC_SESSION_WRITE,
	    gotd_session.repo_child_packfd, NULL, 0) == -1)
		return got_error_from_errno("imsg compose PACKFILE_PIPE");

	gotd_session.repo_child_packfd = -1;

	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.pack",
	    got_repo_get_path(gotd_session.repo), GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(&pack_path, &packfd, basepath, "");
	if (err)
		goto done;
	if (fchmod(packfd, GOT_DEFAULT_PACK_MODE) == -1) {
		err = got_error_from_errno2("fchmod", pack_path);
		goto done;
	}

	free(basepath);
	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.idx",
	    got_repo_get_path(gotd_session.repo), GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		basepath = NULL;
		goto done;
	}
	err = got_opentemp_named_fd(&idx_path, &idxfd, basepath, "");
	if (err)
		goto done;
	if (fchmod(idxfd, GOT_DEFAULT_PACK_MODE) == -1) {
		err = got_error_from_errno2("fchmod", idx_path);
		goto done;
	}

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_PACKIDX_FILE, GOTD_PROC_SESSION_WRITE,
	    idxfd, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose PACKIDX_FILE");
		goto done;
	}
	idxfd = -1;

	memset(&ipack, 0, sizeof(ipack));
	if (client_has_capability(client, GOT_CAPA_REPORT_STATUS))
		ipack.report_status = 1;

	if (gotd_imsg_compose_event(&gotd_session.repo_child_iev,
	    GOTD_IMSG_RECV_PACKFILE, GOTD_PROC_SESSION_WRITE, packfd,
	    &ipack, sizeof(ipack)) == -1) {
		err = got_error_from_errno("imsg compose RECV_PACKFILE");
		goto done;
	}
	packfd = -1;
done:
	free(basepath);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		free(pack_path);
		free(idx_path);
	} else {
		client->packfile_path = pack_path;
		client->packidx_path = idx_path;
	}
	return err;
}

static void
session_dispatch_client(int fd, short events, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
	const struct got_error *err = NULL;
	struct imsg imsg;
	ssize_t n;

	if (events & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err) {
			/*
			 * The client has closed its socket.  This can
			 * happen when Git clients are done sending
			 * pack file data.
			 * Pending notifications should still be sent.
			 */
			if (STAILQ_FIRST(&notifications) != NULL)
				return;
			if (err->code == GOT_ERR_ERRNO && errno == EPIPE) {
				disconnect(client);
				return;
			}
			disconnect_on_error(client, err);
			return;
		}

		if (client->flush_disconnect) {
			disconnect(client);
			return;
		}
	}

	if (events & EV_READ) {
		n = imsgbuf_read(ibuf);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_read");
			disconnect_on_error(client, err);
			return;
		}
		if (n == 0) {
			/*
			 * The client has closed its socket.  This can
			 * happen when Git clients are done sending
			 * pack file data.
			 * Pending notifications should still be sent.
			 */
			if (STAILQ_FIRST(&notifications) != NULL)
				return;
			err = got_error(GOT_ERR_EOF);
			disconnect_on_error(client, err);
			return;
		}
	}

	while (err == NULL) {
		n = imsgbuf_get(ibuf, &imsg);
		if (n == -1) {
			err = got_error_from_errno("imsgbuf_get");
			break;
		}
		if (n == 0)
			break;

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
		case GOTD_IMSG_CAPABILITIES:
			if (gotd_session.state !=
			    GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capabilities received");
				break;
			}
			log_debug("receiving capabilities from uid %d",
			    client->euid);
			err = recv_capabilities(client, &imsg);
			break;
		case GOTD_IMSG_CAPABILITY:
			if (gotd_session.state != GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capability received");
				break;
			}
			err = recv_capability(client, &imsg);
			if (err || client->ncapabilities < client->ncapa_alloc)
				break;
			gotd_session.state = GOTD_STATE_EXPECT_REF_UPDATE;
			client->accept_flush_pkt = 1;
			log_debug("uid %d: expecting ref-update-lines",
			    client->euid);
			break;
		case GOTD_IMSG_REF_UPDATE:
			if (gotd_session.state != GOTD_STATE_EXPECT_REF_UPDATE &&
			    gotd_session.state !=
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected ref-update-line received");
				break;
			}
			log_debug("received ref-update-line from uid %d",
			    client->euid);
			err = forward_ref_update(client, &imsg);
			if (err)
				break;
			gotd_session.state = GOTD_STATE_EXPECT_MORE_REF_UPDATES;
			client->accept_flush_pkt = 1;
			break;
		case GOTD_IMSG_FLUSH:
			if (gotd_session.state !=
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			if (!client->accept_flush_pkt) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}

			/*
			 * Accept just one flush packet at a time.
			 * Future client state transitions will set this flag
			 * again if another flush packet is expected.
			 */
			client->accept_flush_pkt = 0;

			log_debug("received flush-pkt from uid %d",
			    client->euid);
			if (gotd_session.state ==
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				gotd_session.state = GOTD_STATE_EXPECT_PACKFILE;
				log_debug("uid %d: expecting packfile",
				    client->euid);
				err = recv_packfile(client);
			} else {
				/* should not happen, see above */
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected client state");
				break;
			}
			break;
		case GOTD_IMSG_PACKFILE_READY:
			if (gotd_session.state != GOTD_STATE_EXPECT_PACKFILE ||
			    gotd_session.repo_child_packfd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = send_packfds_to_repo_child();
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err) {
		if (err->code != GOT_ERR_EOF ||
		    (gotd_session.state != GOTD_STATE_EXPECT_PACKFILE &&
		    gotd_session.state != GOTD_STATE_NOTIFY))
			disconnect_on_error(client, err);
	} else {
		gotd_imsg_event_add(iev);
		evtimer_add(&client->tmo, &gotd_session.request_timeout);
	}
}

static const struct got_error *
list_refs_request(void)
{
	static const struct got_error *err;
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsgev *iev = &gotd_session.repo_child_iev;
	int fd;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_LIST_REFS_INTERNAL,
	    GOTD_PROC_SESSION_WRITE, fd, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose LIST_REFS_INTERNAL");
		close(fd);
		return err;
	}

	gotd_session.state = GOTD_STATE_EXPECT_CAPABILITIES;
	log_debug("uid %d: expecting capabilities", client->euid);
	return NULL;
}

static const struct got_error *
recv_connect(struct imsg *imsg)
{
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsg_connect iconnect;
	size_t datalen;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iconnect, imsg->data, sizeof(iconnect));
	if (iconnect.username_len == 0 ||
	    datalen != sizeof(iconnect) + iconnect.username_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	client->euid = iconnect.euid;
	client->egid = iconnect.egid;
	client->fd = imsg_get_fd(imsg);
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	client->username = strndup(imsg->data + sizeof(iconnect),
	    iconnect.username_len);
	if (client->username == NULL)
		return got_error_from_errno("strndup");

	if (imsgbuf_init(&client->iev.ibuf, client->fd) == -1)
		return got_error_from_errno("imsgbuf_init");
	imsgbuf_allow_fdpass(&client->iev.ibuf);
	client->iev.handler = session_dispatch_client;
	client->iev.events = EV_READ;
	client->iev.handler_arg = NULL;
	event_set(&client->iev.ev, client->iev.ibuf.fd, EV_READ,
	    session_dispatch_client, &client->iev);
	gotd_imsg_event_add(&client->iev);
	evtimer_set(&client->tmo, gotd_request_timeout, client);
	evtimer_add(&client->tmo, &gotd_session.request_timeout);

	return NULL;
}

static void
session_dispatch_notifier(int fd, short event, void *arg)
{
	const struct got_error *err;
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;
	struct gotd_session_notif *notif;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_NOTIFICATION_SENT:
			if (gotd_session.state != GOTD_STATE_NOTIFY) {
				log_warn("unexpected imsg %d", imsg.hdr.type);
				break;
			}

			/* First notification on our list has now been sent. */
			notif = STAILQ_FIRST(&notifications);
			STAILQ_REMOVE_HEAD(&notifications, entry);
			if (notif->fd != -1)
				close(notif->fd);
			free(notif);

			notif = STAILQ_FIRST(&notifications);
			if (notif == NULL) {
				disconnect(client);
				break; /* NOTREACHED */
			}
			/* Request content for the next notification. */
			err = request_notification(notif);
			if (err) {
				log_warn("could not send notification: %s",
				    err->msg);
				disconnect(client);
			}
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		imsgbuf_clear(&iev->ibuf);
	}
}

static const struct got_error *
recv_notifier(struct imsg *imsg)
{
	struct gotd_imsgev *iev = &gotd_session.notifier_iev;
	struct gotd_session_client *client = &gotd_session_client;
	size_t datalen;
	int fd;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	/* We should already have received a pipe to the listener. */
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return NULL; /* notifications unused */

	if (imsgbuf_init(&iev->ibuf, fd) == -1) {
		close(fd);
		return got_error_from_errno("imsgbuf_init");
	}
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = session_dispatch_notifier;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ,
	    session_dispatch_notifier, iev);
	gotd_imsg_event_add(iev);

	return NULL;
}

static const struct got_error *
recv_repo_child(struct imsg *imsg)
{
	struct gotd_imsg_connect_repo_child ichild;
	struct gotd_session_client *client = &gotd_session_client;
	size_t datalen;
	int fd;

	if (gotd_session.state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	/* We should already have received a pipe to the listener. */
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ichild))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ichild, imsg->data, sizeof(ichild));

	if (ichild.proc_id != GOTD_PROC_REPO_WRITE)
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad child process type");

	fd = imsg_get_fd(imsg);
	if (fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (strlcpy(gotd_session.repo_name, ichild.repo_name,
	    sizeof(gotd_session.repo_name)) >= sizeof(gotd_session.repo_name)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "repository name too long");
	}

	if (imsgbuf_init(&gotd_session.repo_child_iev.ibuf, fd) == -1) {
		close(fd);
		return got_error_from_errno("imsgbuf_init");
	}
	imsgbuf_allow_fdpass(&gotd_session.repo_child_iev.ibuf);
	gotd_session.repo_child_iev.handler = session_dispatch_repo_child;
	gotd_session.repo_child_iev.events = EV_READ;
	gotd_session.repo_child_iev.handler_arg = NULL;
	event_set(&gotd_session.repo_child_iev.ev,
	    gotd_session.repo_child_iev.ibuf.fd, EV_READ,
	    session_dispatch_repo_child, &gotd_session.repo_child_iev);
	gotd_imsg_event_add(&gotd_session.repo_child_iev);

	/* The "recvfd" pledge promise is no longer needed. */
	if (pledge("stdio rpath wpath cpath sendfd fattr flock", NULL) == -1)
		fatal("pledge");

	return NULL;
}

static void
session_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_imsgev *repo_child_iev = &gotd_session.repo_child_iev;
	struct gotd_session_client *client = &gotd_session_client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;
	size_t npaths;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		err = gotd_imsg_flush(ibuf);
		if (err)
			fatalx("%s", err->msg);
	}

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0, do_list_refs = 0;
		int send_notifications = 0;

		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_CONNECT:
			err = recv_connect(&imsg);
			break;
		case GOTD_IMSG_DISCONNECT:
			do_disconnect = 1;
			break;
		case GOTD_IMSG_NOTIFICATION_REFS:
			if (gotd_session.notification_refs_cur != NULL ||
			    gotd_session.num_notification_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotd_session.notification_refs_cur =
			    &gotd_session.notification_refs;
			gotd_session.num_notification_refs_needed = npaths;
			gotd_session.num_notification_refs_received = 0;
			break;
		case GOTD_IMSG_NOTIFICATION_REF_NAMESPACES:
			if (gotd_session.notification_refs_cur != NULL ||
			    gotd_session.num_notification_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			gotd_session.notification_refs_cur =
			    &gotd_session.notification_ref_namespaces;
			gotd_session.num_notification_refs_needed = npaths;
			gotd_session.num_notification_refs_received = 0;
			break;
		case GOTD_IMSG_NOTIFICATION_REFS_ELEM:
		case GOTD_IMSG_NOTIFICATION_REF_NAMESPACES_ELEM:
			if (gotd_session.notification_refs_cur == NULL ||
			    gotd_session.num_notification_refs_needed == 0 ||
			    gotd_session.num_notification_refs_received >=
			    gotd_session.num_notification_refs_needed) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotd_imsg_recv_pathlist_elem(&imsg,
			    gotd_session.notification_refs_cur);
			if (err)
				break;
			if (++gotd_session.num_notification_refs_received >=
			    gotd_session.num_notification_refs_needed) {
				gotd_session.notification_refs_cur = NULL;
				gotd_session.num_notification_refs_needed = 0;
			}
			break;
		case GOTD_IMSG_NOTIFICATION_TARGET_EMAIL: {
			struct gotd_notification_target *target;

			err = gotd_imsg_recv_notification_target_email(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&gotd_session.notification_targets,
			    target, entry);
			break;
		}
		case GOTD_IMSG_NOTIFICATION_TARGET_HTTP: {
			struct gotd_notification_target *target;

			err = gotd_imsg_recv_notification_target_http(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&gotd_session.notification_targets,
			    target, entry);
			break;
		}
		case GOTD_IMSG_REQUEST_TIMEOUT:
			if (imsg_get_data(&imsg, &gotd_session.request_timeout,
			    sizeof(gotd_session.request_timeout)) == -1)
				err = got_error_from_errno("imsg_get_data");
			break;
		case GOTD_IMSG_CONNECT_NOTIFIER:
			err = recv_notifier(&imsg);
			break;
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_repo_child(&imsg);
			if (err)
				break;
			do_list_refs = 1;
			break;
		case GOTD_IMSG_NOTIFY:
			send_notifications = 1;
			break;
		case GOTD_IMSG_PACKFILE_VERIFIED:
			if (gotd_session.state != GOTD_STATE_EXPECT_PACKFILE) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				do_disconnect = 1;
				break;
			}
			if (repo_child_iev->ibuf.fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				do_disconnect = 1;
				break;
			}
			if (gotd_imsg_forward(repo_child_iev, &imsg,
			    -1) == -1) {
				err = got_error_from_errno("imsg compose "
				    " PACKFILE_VERIFIED");
				do_disconnect = 1;
			}
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else if (do_list_refs)
			err = list_refs_request();
		else if (send_notifications) {
			struct gotd_session_notif *notif;

			err = send_refs_updated(&client->iev);
			if (err) {
				log_warnx("uid %d: %s", client->euid, err->msg);
				err = NULL;
			}

			notif = STAILQ_FIRST(&notifications);
			if (notif) {
				gotd_session.state = GOTD_STATE_NOTIFY;
				err = request_notification(notif);
				if (err) {
					log_warn("could not send notification: "
					    "%s", err->msg);
					client->flush_disconnect = 1;
				}
			} else
				client->flush_disconnect = 1;
		}

		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
session_write_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds, int content_fd)
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	STAILQ_INIT(&notifications);

	gotd_session.title = title;
	gotd_session.pid = getpid();
	gotd_session.pack_fds = pack_fds;
	gotd_session.temp_fds = temp_fds;
	gotd_session.content_fd = content_fd;
	gotd_session.request_timeout.tv_sec = GOTD_DEFAULT_REQUEST_TIMEOUT;
	gotd_session.request_timeout.tv_usec = 0;
	RB_INIT(&gotd_session.notification_refs);
	RB_INIT(&gotd_session.notification_ref_namespaces);
	STAILQ_INIT(&gotd_session.notification_targets);
	gotd_session.repo_child_packfd = -1;

	if (imsgbuf_init(&gotd_session.notifier_iev.ibuf, -1) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&gotd_session.notifier_iev.ibuf);

	err = got_repo_open(&gotd_session.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(gotd_session.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}
	if (got_repo_get_object_format(gotd_session.repo) != GOT_HASH_SHA1) {
		err = got_error_msg(GOT_ERR_NOT_IMPL,
		    "sha256 object IDs unsupported in network protocol");
		goto done;
	}

	got_repo_temp_fds_set(gotd_session.repo, temp_fds);

	signal_set(&evsigint, SIGINT, session_write_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, session_write_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, session_write_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, session_write_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	gotd_session.state = GOTD_STATE_EXPECT_LIST_REFS;

	gotd_session_client.fd = -1;
	gotd_session_client.nref_updates = -1;
	gotd_session_client.delta_cache_fd = -1;
	gotd_session_client.accept_flush_pkt = 1;

	gotd_session.repo_child_iev.ibuf.fd = -1;

	if (imsgbuf_init(&gotd_session.parent_iev.ibuf, GOTD_FILENO_MSG_PIPE)
	    == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(&gotd_session.parent_iev.ibuf);
	gotd_session.parent_iev.handler = session_dispatch;
	gotd_session.parent_iev.events = EV_READ;
	gotd_session.parent_iev.handler_arg = NULL;
	event_set(&gotd_session.parent_iev.ev, gotd_session.parent_iev.ibuf.fd,
	    EV_READ, session_dispatch, &gotd_session.parent_iev);
	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_CLIENT_SESSION_READY, GOTD_PROC_SESSION_WRITE,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CLIENT_SESSION_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	session_write_shutdown();
}

static void
session_write_shutdown(void)
{
	struct gotd_session_notif *notif;

	log_debug("%s: shutting down", gotd_session.title);

	while (!STAILQ_EMPTY(&notifications)) {
		notif = STAILQ_FIRST(&notifications);
		STAILQ_REMOVE_HEAD(&notifications, entry);
		if (notif->fd != -1)
			close(notif->fd);
		free(notif->refname);
		free(notif);
	}

	if (gotd_session.repo)
		got_repo_close(gotd_session.repo);
	got_repo_pack_fds_close(gotd_session.pack_fds);
	got_repo_temp_fds_close(gotd_session.temp_fds);
	free(gotd_session_client.username);
	exit(0);
}
