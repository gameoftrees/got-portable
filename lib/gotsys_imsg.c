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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_reference.h"

#include "media.h"
#include "gotsysd.h"
#include "gotwebd.h"
#include "gotsys.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
gotsys_imsg_send_users(struct gotsysd_imsgev *iev,
    struct gotsys_userlist *users, int imsg_type, int imsg_done_type,
    int send_passwords)
{
	struct gotsys_user *u;
	size_t totlen, remain, mlen;
	const size_t maxmesg  = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
	struct gotsysd_imsg_sysconf_user iuser;
	struct ibuf *wbuf = NULL;

	u = STAILQ_FIRST(users);
	totlen = 0;
	while (u) {
		size_t namelen, pwlen = 0, ulen;

		namelen = strlen(u->name);
		if (send_passwords)
			pwlen = (u->password ? strlen(u->password) : 0);
		if (namelen + pwlen < namelen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user name/password length overflow");
		}

		ulen = namelen + pwlen;
		if (totlen > INT_MAX - sizeof(iuser) - ulen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user data length overflow");
		}

		totlen += sizeof(iuser) + ulen;
		u = STAILQ_NEXT(u, entry);
	}
	if (totlen == 0)
		return NULL;

	u = STAILQ_FIRST(users);
	remain = totlen;
	mlen = 0;
	while (u) {
		size_t ulen;

		iuser.name_len = strlen(u->name);
		iuser.password_len = (send_passwords && u->password ?
		    strlen(u->password) : 0);

		ulen = iuser.name_len + iuser.password_len;

		if (wbuf != NULL && mlen + sizeof(iuser) + ulen > maxmesg) {
			imsg_close(&iev->ibuf, wbuf);
			gotsysd_imsg_event_add(iev);
			wbuf = NULL;
			mlen = 0;
		}

		if (wbuf == NULL) {
			wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
			    MIN(remain, maxmesg));
			if (wbuf == NULL) {
				return got_error_from_errno_fmt(
				    "imsg_create %d", imsg_type);
			}
		}

		if (imsg_add(wbuf, &iuser, sizeof(iuser)) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, u->name, iuser.name_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, u->password, iuser.password_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);

		remain -= sizeof(iuser) + ulen;
		mlen += sizeof(iuser) + ulen;
		u = STAILQ_NEXT(u, entry);
	}

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);

	if (gotsysd_imsg_compose_event(iev, imsg_done_type, 0,
	    -1, NULL, 0) == -1)
		return got_error_from_errno_fmt("imsg_compose %d",
		    imsg_done_type);
	
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_users(struct imsg *imsg, struct gotsys_userlist *users)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_user iuser;
	struct gotsys_user *user = NULL;
	char *name = NULL;
	size_t datalen, offset, remain;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iuser))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	remain = datalen;
	offset = 0;
	while (remain > 0) {
		size_t namelen, pwlen, ulen;
		int is_anonymous_user = 0;

		if (remain < sizeof(iuser))
			return got_error(GOT_ERR_PRIVSEP_LEN);

		memcpy(&iuser, imsg->data + offset, sizeof(iuser));

		namelen = iuser.name_len;
		if (namelen <= 0 || namelen > _PW_NAME_LEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);
		pwlen = iuser.password_len;
		if (pwlen > _PASSWORD_LEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		if (namelen + pwlen < namelen ||
		    namelen + pwlen < namelen || 
		    namelen + pwlen < namelen + pwlen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user name/password/sshpubkey length overflow");
		}

		ulen = namelen + pwlen;
		if (sizeof(iuser) + ulen < sizeof(iuser)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user data length overflow");
		}
		if (sizeof(iuser) + ulen > remain)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		name = strndup(imsg->data + offset + sizeof(iuser), namelen);
		if (name == NULL)
			return got_error_from_errno("strndup");
		if (strlen(name) != namelen) {
			free(name);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}
		STAILQ_FOREACH(user, users, entry) {
			if (strcmp(name, user->name) == 0)
				break;
		}
		if (user != NULL) {
			free(name);
			name = NULL;
			user = NULL;
			continue;
		}

		is_anonymous_user = (strcmp(name, "anonymous") == 0);
		if (!is_anonymous_user) {
			err = gotsys_conf_validate_name(name, "user");
			if (err) {
				free(name);
				return err;
			}
		}

		err = gotsys_conf_new_user(&user, name);
		free(name);
		name = NULL;
		if (err)
			return err;

		if (pwlen) {
			if (is_anonymous_user) {
				err = got_error_msg(GOT_ERR_PRIVSEP_MSG,
				    "the \"anonymous\" user must use an "
				    "empty password");
				gotsys_user_free(user);
				return err;
			}
			user->password = strndup(imsg->data + offset +
			    sizeof(iuser) + namelen, pwlen);
			if (user->password == NULL) {
				err = got_error_from_errno("strndup");
				gotsys_user_free(user);
				return err;
			}
			if (strlen(user->password) != pwlen) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				gotsys_user_free(user);
				return err;
			}
		} else if (is_anonymous_user) {
			user->password = strdup("");
			if (user->password == NULL) {
				err = got_error_from_errno("strdup");
				gotsys_user_free(user);
				return err;
			}
		}
#if 0
		log_debug("user %s: password '%s' ssh key '%s'", user->name,
		    user->password ? user->password : "",
		    user->ssh_pubkey ? user->ssh_pubkey : "");
#endif
		STAILQ_INSERT_TAIL(users, user, entry);
		user = NULL;

		offset += sizeof(iuser) + ulen;
		remain -= sizeof(iuser) + ulen;
	}

	return NULL;
}

const struct got_error *
gotsys_imsg_send_groups(struct gotsysd_imsgev *iev,
    struct gotsys_grouplist *groups, int imsg_group_type,
    int imsg_group_members_type, int imsg_group_members_done_type,
    int imsg_done_type)
{
	const struct got_error *err;
	struct gotsys_group *g;
	struct gotsysd_imsg_sysconf_group igroup;
	struct ibuf *wbuf = NULL;

	g = STAILQ_FIRST(groups);
	while (g) {
		igroup.name_len = strlen(g->name);

		wbuf = imsg_create(&iev->ibuf, imsg_group_type,
		    0, 0, sizeof(igroup) + igroup.name_len);
		if (wbuf == NULL) {
			return got_error_from_errno(
			    "imsg_create SYSCONF_GROUP");
		}

		if (imsg_add(wbuf, &igroup, sizeof(igroup)) == -1) {
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_group_type);
		}
		if (imsg_add(wbuf, g->name, igroup.name_len) == -1) {
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_group_type);
		}

		imsg_close(&iev->ibuf, wbuf);

		err = gotsys_imsg_send_users(iev, &g->members,
		    imsg_group_members_type,
		    imsg_group_members_done_type, 0);
		if (err)
			return err;

		g = STAILQ_NEXT(g, entry);
	}

	if (gotsysd_imsg_compose_event(iev, imsg_done_type,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno_fmt("imsg_compose %d",
		    imsg_done_type);
	}
	
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_group(struct imsg *imsg, struct gotsys_group **group)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_group igroup;
	char *name = NULL;
	size_t datalen;

	*group = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(igroup))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&igroup, imsg->data, sizeof(igroup));

	if (igroup.name_len <= 0 || igroup.name_len > _PW_NAME_LEN ||
	    sizeof(igroup) + igroup.name_len > datalen)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	name = strndup(imsg->data + sizeof(igroup), igroup.name_len);
	if (name == NULL)
		return got_error_from_errno("strdup");

	if (strlen(name) != igroup.name_len) {
		free(name);
		return got_error(GOT_ERR_PRIVSEP_LEN);
	}

	err = gotsys_conf_validate_name(name, "group");
	if (err) {
		free(name);
		return err;
	}
		
	err = gotsys_conf_new_group(group, name);
	free(name);
	return err;
}

const struct got_error *
gotsys_imsg_send_authorized_keys_user(struct gotsysd_imsgev *iev,
    const char *username, int imsg_type)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_authorized_keys_user iuser;
	struct ibuf *wbuf = NULL;
	size_t userlen;

	err = gotsys_conf_validate_name(username, "user");
	if (err)
		return err;

	userlen = strlen(username);

	iuser.name_len = strlen(username);

	wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
	    sizeof(iuser) + userlen);
	if (wbuf == NULL)
		return got_error_from_errno_fmt("imsg_create %d", imsg_type);

	if (imsg_add(wbuf, &iuser, sizeof(iuser)) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);
	if (imsg_add(wbuf, username, userlen) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_authorized_keys_user(char **username, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_authorized_keys_user iuser;
	size_t datalen;

	*username = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iuser))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iuser, imsg->data, sizeof(iuser));

	if (iuser.name_len > _PW_NAME_LEN ||
	    datalen != sizeof(iuser) + iuser.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	*username = strndup(imsg->data + sizeof(iuser), iuser.name_len);
	if (*username == NULL)
		return got_error_from_errno("strndup");

	if (strlen(*username) != iuser.name_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	err = gotsys_conf_validate_name(*username, "user");
done:
	if (err) {
		free(*username);
		*username = NULL;
	}

	return err;
}

const struct got_error *
gotsys_imsg_send_authorized_keys(struct gotsysd_imsgev *iev,
    struct gotsys_authorized_keys_list *keys, int imsg_type)
{
	struct gotsys_authorized_key *k;
	size_t totlen, remain, mlen;
	const size_t maxmesg  = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
	struct gotsysd_imsg_sysconf_authorized_key ikey;
	struct ibuf *wbuf = NULL;

	k = STAILQ_FIRST(keys);
	totlen = 0;
	while (k) {
		size_t typelen, datalen, commentlen, klen;

		typelen = strlen(k->keytype);
		if (typelen == 0) {
			return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
			    "empty authorized key type");
		}
		if (typelen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key type too long: %s:", k->keytype);
		}
		datalen = strlen(k->key);
		if (datalen == 0) {
			return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
			    "empty authorized key");
		}
		if (datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    typelen + datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key too long: %s:", k->key);
		}

		if (k->comment) {
			commentlen = strlen(k->comment);
			if (commentlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
				return got_error_fmt(GOT_ERR_NO_SPACE,
				    "authorized key comment too long: %s:",
				    k->comment);
			}
		} else
			commentlen = 0;

		klen = typelen + datalen + commentlen;
		if (klen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key too long: %s:", k->key);
		}

		totlen += sizeof(ikey) + klen;
		k = STAILQ_NEXT(k, entry);
	}

	k = STAILQ_FIRST(keys);
	remain = totlen;
	mlen = 0;
	while (k && remain > 0) {
		size_t klen;

		ikey.keytype_len = strlen(k->keytype);
		ikey.keydata_len = strlen(k->key);
		ikey.comment_len = k->comment ? strlen(k->comment) : 0;

		klen = ikey.keytype_len + ikey.keydata_len + ikey.comment_len;

		if (wbuf != NULL && mlen + sizeof(ikey) + klen > maxmesg) {
			imsg_close(&iev->ibuf, wbuf);
			wbuf = NULL;
			mlen = 0;
			gotsysd_imsg_event_add(iev);
		}

		if (wbuf == NULL) {
			wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
			    MIN(remain, maxmesg));
			if (wbuf == NULL) {
				return got_error_from_errno_fmt(
				    "imsg_create %d", imsg_type);
			}
		}

		if (imsg_add(wbuf, &ikey, sizeof(ikey)) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, k->keytype, ikey.keytype_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, k->key, ikey.keydata_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (ikey.comment_len > 0 &&
		    imsg_add(wbuf, k->comment, ikey.comment_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);

		remain -= sizeof(ikey) + klen;
		mlen += sizeof(ikey) + klen;
		k = STAILQ_NEXT(k, entry);
	}

	if (wbuf) {
		imsg_close(&iev->ibuf, wbuf);
		gotsysd_imsg_event_add(iev);
	}

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_authorized_keys(struct imsg *imsg,
    struct gotsys_authorized_keys_list *keys)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_authorized_key ikey;
	struct gotsys_authorized_key *key = NULL;
	char *keytype = NULL, *keydata = NULL, *comment = NULL;
	size_t datalen, offset, remain;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ikey))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	remain = datalen;
	offset = 0;
	while (remain > 0) {
		size_t klen;

		if (remain < sizeof(ikey))
			return got_error(GOT_ERR_PRIVSEP_LEN);

		memcpy(&ikey, imsg->data + offset, sizeof(ikey));

		if (ikey.keytype_len == 0 ||
		    ikey.keydata_len == 0 ||
		    ikey.keytype_len > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    ikey.keydata_len > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    ikey.comment_len > GOTSYS_AUTHORIZED_KEY_MAXLEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		klen = ikey.keytype_len + ikey.keydata_len + ikey.comment_len;
		if (klen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    sizeof(ikey) + klen > remain)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		keytype = strndup(imsg->data + offset + sizeof(ikey),
		    ikey.keytype_len);
		if (keytype == NULL)
			return got_error_from_errno("strndup");
		if (strlen(keytype) != ikey.keytype_len) {
			free(keytype);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}

		keydata = strndup(imsg->data + offset + sizeof(ikey) +
		    ikey.keytype_len, ikey.keydata_len);
		if (keydata == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(keydata) != ikey.keydata_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		if (ikey.comment_len > 0) {
			comment = strndup(imsg->data + offset + sizeof(ikey) +
			    ikey.keytype_len + ikey.keydata_len,
			    ikey.comment_len);
			if (comment == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			if (strlen(comment) != ikey.comment_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
		}
		err = gotsys_conf_new_authorized_key(&key, keytype,
		    keydata, comment);
		if (err)
			goto done;
		free(keytype);
		free(keydata);
		free(comment);
		keytype = NULL;
		keydata = NULL;
		comment = NULL;

		STAILQ_INSERT_TAIL(keys, key, entry);
		key = NULL;
		offset += sizeof(ikey) + klen;
		remain -= sizeof(ikey) + klen;
	}

done:
	free(keytype);
	free(keydata);
	free(comment);
	gotsys_authorized_key_free(key);
	return err;
}

const struct got_error *
gotsys_imsg_send_access_rule(struct gotsysd_imsgev *iev,
    struct gotsys_access_rule *rule, int imsg_type)
{
	struct gotsysd_imsg_sysconf_access_rule irule;
	struct ibuf *wbuf = NULL;

	switch (rule->access) {
	case GOTSYS_ACCESS_DENIED:
		irule.access = GOTSYSD_IMSG_ACCESS_DENIED;
		break;
	case GOTSYS_ACCESS_PERMITTED:
		irule.access = GOTSYSD_IMSG_ACCESS_PERMITTED;
		break;
	default:
		return got_error_fmt(GOT_ERR_NOT_IMPL,
		    "unknown access %d", rule->access);
	}
	irule.authorization = rule->authorization;
	irule.identifier_len = strlen(rule->identifier);

	wbuf = imsg_create(&iev->ibuf, imsg_type,
	    0, 0, sizeof(irule) + irule.identifier_len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SYSCONF_ACCESS_RULE");

	if (imsg_add(wbuf, &irule, sizeof(irule)) == -1)
		return got_error_from_errno("imsg_add SYSCONF_ACCESS_FULE");
	if (imsg_add(wbuf, rule->identifier, irule.identifier_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_ACCESS_FULE");

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
send_pathlist_elem(struct gotsysd_imsgev *iev, const char *refname,
    int imsg_type)
{
	struct gotsysd_imsg_pathlist_elem ielem;
	struct ibuf *wbuf = NULL;

	memset(&ielem, 0, sizeof(ielem));
	ielem.path_len = strlen(refname);

	wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
	    sizeof(ielem) + ielem.path_len);
	if (wbuf == NULL)
		return got_error_from_errno_fmt("imsg_create %d", imsg_type);

	if (imsg_add(wbuf, &ielem, sizeof(ielem)) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);
	if (imsg_add(wbuf, refname, ielem.path_len) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
send_protected_refs(struct gotsysd_imsgev *iev, struct gotsys_repo *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	struct gotsysd_imsg_pathlist ilist;

	memset(&ilist, 0, sizeof(ilist));

	ilist.nelem = repo->nprotected_tag_namespaces;
	if (ilist.nelem > 0) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES,
		    0, -1, &ilist, sizeof(ilist)) == -1) {
			return got_error_from_errno("imsg compose "
			    "PROTECTED_TAG_NAMESPACES");
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo->protected_tag_namespaces) {
			err = send_pathlist_elem(iev, pe->path,
			    GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM);
			if (err)
				return err;
		}
	}

	ilist.nelem = repo->nprotected_branch_namespaces;
	if (ilist.nelem > 0) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES,
		    0, -1, &ilist, sizeof(ilist)) == -1) {
			return got_error_from_errno("imsg compose "
			    "PROTECTED_BRANCH_NAMESPACES");
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo->protected_branch_namespaces) {
			err = send_pathlist_elem(iev, pe->path,
			    GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM);
			if (err)
				return err;
		}
	}

	ilist.nelem = repo->nprotected_branches;
	if (ilist.nelem > 0) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES,
		    0, -1, &ilist, sizeof(ilist)) == -1) {
			return got_error_from_errno("imsg compose "
			    "PROTECTED_BRANCH_NAMESPACES");
		}

		RB_FOREACH(pe, got_pathlist_head, &repo->protected_branches) {
			err = send_pathlist_elem(iev, pe->path,
			    GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM);
			if (err)
				return err;
		}
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

static const struct got_error *
send_notification_target_email(struct gotsysd_imsgev *iev,
    const char *repo_name, struct gotsys_notification_target *target)
{
	struct gotsysd_imsg_notitfication_target_email itarget;
	struct ibuf *wbuf = NULL;

	memset(&itarget, 0, sizeof(itarget));

	if (target->conf.email.sender)
		itarget.sender_len = strlen(target->conf.email.sender);
	if (target->conf.email.recipient)
		itarget.recipient_len = strlen(target->conf.email.recipient);
	if (target->conf.email.responder)
		itarget.responder_len = strlen(target->conf.email.responder);
	if (target->conf.email.hostname)
		itarget.hostname_len = strlen(target->conf.email.hostname);
	if (target->conf.email.port)
		itarget.port_len = strlen(target->conf.email.port);
	itarget.repo_name_len = strlen(repo_name);

	wbuf = imsg_create(&iev->ibuf,
	    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL,
	    0, 0, sizeof(itarget) + itarget.sender_len + itarget.recipient_len +
	    itarget.responder_len + itarget.hostname_len + itarget.port_len +
	    itarget.repo_name_len);
	if (wbuf == NULL) {
		return got_error_from_errno("imsg_create "
		    "NOTIFICATION_TARGET_EMAIL");
	}

	if (imsg_add(wbuf, &itarget, sizeof(itarget)) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_EMAIL");
	}
	if (target->conf.email.sender) {
		if (imsg_add(wbuf, target->conf.email.sender,
		    itarget.sender_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_EMAIL");
		}
	}

	if (target->conf.email.recipient) {
		if (imsg_add(wbuf, target->conf.email.recipient,
		    itarget.recipient_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_EMAIL");
		}
	}
	if (target->conf.email.responder) {
		if (imsg_add(wbuf, target->conf.email.responder,
		    itarget.responder_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_EMAIL");
		}
	}
	if (target->conf.email.hostname) {
		if (imsg_add(wbuf, target->conf.email.hostname,
		    itarget.hostname_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_EMAIL");
		}
	}
	if (target->conf.email.port) {
		if (imsg_add(wbuf, target->conf.email.port,
		    itarget.port_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_EMAIL");
		}
	}
	if (imsg_add(wbuf, repo_name, itarget.repo_name_len) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_EMAIL");
	}

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
send_notification_target_http(struct gotsysd_imsgev *iev, const char *repo_name,
    struct gotsys_notification_target *target)
{
	struct gotsysd_imsg_notitfication_target_http itarget;
	struct ibuf *wbuf = NULL;

	memset(&itarget, 0, sizeof(itarget));

	itarget.tls = target->conf.http.tls;
	itarget.hostname_len = strlen(target->conf.http.hostname);
	itarget.port_len = strlen(target->conf.http.port);
	itarget.path_len = strlen(target->conf.http.path);
	if (target->conf.http.user)
		itarget.user_len = strlen(target->conf.http.user);
	if (target->conf.http.password)
		itarget.password_len = strlen(target->conf.http.password);
	if (target->conf.http.hmac_secret)
		itarget.hmac_len = strlen(target->conf.http.hmac_secret);
	itarget.repo_name_len = strlen(repo_name);

	wbuf = imsg_create(&iev->ibuf,
	    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP,
	    0, 0, sizeof(itarget) + itarget.hostname_len + itarget.port_len +
	    itarget.path_len + itarget.user_len + itarget.password_len +
	    itarget.hmac_len + itarget.repo_name_len);
	if (wbuf == NULL) {
		return got_error_from_errno("imsg_create "
		    "NOTIFICATION_TARGET_HTTP");
	}

	if (imsg_add(wbuf, &itarget, sizeof(itarget)) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_HTTP");
	}
	if (imsg_add(wbuf, target->conf.http.hostname,
	    itarget.hostname_len) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_HTTP");
	}
	if (imsg_add(wbuf, target->conf.http.port,
	    itarget.port_len) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_HTTP");
	}
	if (imsg_add(wbuf, target->conf.http.path,
	    itarget.path_len) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_HTTP");
	}

	if (target->conf.http.user) {
		if (imsg_add(wbuf, target->conf.http.user, itarget.user_len) == -1)
			return got_error_from_errno("imsg_add NOTIFICATION_TARGET_HTTP");
	}
	if (target->conf.http.password) {
		if (imsg_add(wbuf, target->conf.http.password,
		    itarget.password_len) == -1)
			return got_error_from_errno("imsg_add NOTIFICATION_TARGET_HTTP");
	}
	if (target->conf.http.hmac_secret) {
		if (imsg_add(wbuf, target->conf.http.hmac_secret,
		    itarget.hmac_len) == -1) {
			return got_error_from_errno("imsg_add "
			    "NOTIFICATION_TARGET_HTTP");
		}
	}
	if (imsg_add(wbuf, repo_name, itarget.repo_name_len) == -1) {
		return got_error_from_errno("imsg_add "
		    "NOTIFICATION_TARGET_HTTP");
	}

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
send_notification_target(struct gotsysd_imsgev *iev, const char *repo_name,
    struct gotsys_notification_target *target)
{
	const struct got_error *err = NULL;

	switch (target->type) {
	case GOTSYS_NOTIFICATION_VIA_EMAIL:
		err = send_notification_target_email(iev, repo_name, target);
		break;
	case GOTSYS_NOTIFICATION_VIA_HTTP:
		err = send_notification_target_http(iev, repo_name, target);
		break;
	default:
		break;
	}

	return err;
}

static const struct got_error *
send_notification_targets(struct gotsysd_imsgev *iev, const char *repo_name,
    struct gotsys_notification_targets *targets)
{
	const struct got_error *err = NULL;
	struct gotsys_notification_target *target;

	STAILQ_FOREACH(target, targets, entry) {
		err = send_notification_target(iev, repo_name, target);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

static const struct got_error *
send_notification_config(struct gotsysd_imsgev *iev, struct gotsys_repo *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	struct gotsysd_imsg_pathlist ilist;

	memset(&ilist, 0, sizeof(ilist));

	ilist.nelem = repo->num_notification_refs;
	if (ilist.nelem > 0) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS, 0, -1,
		    &ilist, sizeof(ilist)) == -1) {
			return got_error_from_errno("imsg compose "
			    "NOTIFICATION_REFS");
		}

		RB_FOREACH(pe, got_pathlist_head, &repo->notification_refs) {
			err = send_pathlist_elem(iev, pe->path,
			    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM);
			if (err)
				return err;
		}
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	ilist.nelem = repo->num_notification_ref_namespaces;
	if (ilist.nelem > 0) {
		if (gotsysd_imsg_compose_event(iev,
		    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES, 0, -1,
		    &ilist, sizeof(ilist)) == -1) {
			return got_error_from_errno("imsg compose "
			    "NOTIFICATION_REF_NAMESPACES");
		}

		RB_FOREACH(pe, got_pathlist_head,
		    &repo->notification_ref_namespaces) {
			err = send_pathlist_elem(iev, pe->path,
			    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM);
			if (err)
				return err;
		}
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return send_notification_targets(iev, repo->name, &repo->notification_targets);
}


void
gotsysd_web_config_init(struct gotsysd_web_config *webcfg)
{
	memset(webcfg, 0, sizeof(*webcfg));
	TAILQ_INIT(&webcfg->listen_addrs);
	STAILQ_INIT(&webcfg->servers);
	webcfg->auth_config = GOTSYSD_WEB_AUTH_UNSET;
}

const struct got_error *
gotsys_imsg_recv_web_cfg(struct gotsysd_web_config *new, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsysd_web_config cfg;

	if (imsg_get_data(imsg, &cfg, sizeof(cfg)) == -1)
		return got_error_from_errno("imsg_get_data");

	switch (cfg.auth_config) {
	case GOTSYSD_WEB_AUTH_UNSET:
	case GOTSYSD_WEB_AUTH_DISABLED:
	case GOTSYSD_WEB_AUTH_SECURE:
	case GOTSYSD_WEB_AUTH_INSECURE:
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad web authentication setting");
	}

	if (cfg.control_socket[nitems(cfg.control_socket) - 1] != '\0' ||
	    cfg.httpd_chroot[nitems(cfg.httpd_chroot) - 1] != '\0'||
	    cfg.htdocs_path[nitems(cfg.htdocs_path) - 1] != '\0' ||
	    cfg.repos_path[nitems(cfg.repos_path) - 1] != '\0' ||
	    cfg.gotwebd_user[nitems(cfg.gotwebd_user) - 1] != '\0' ||
	    cfg.www_user[nitems(cfg.www_user) - 1] != '\0' ||
	    cfg.login_hint_user[nitems(cfg.login_hint_user) - 1] != '\0' ||
	    cfg.login_hint_port[nitems(cfg.login_hint_port) - 1] != '\0')
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (cfg.control_socket[0] != '\0') {
		err = gotsys_conf_validate_path(cfg.control_socket);
		if (err)
			return err;
	}

	if (cfg.httpd_chroot[0] != '\0') {
		err = gotsys_conf_validate_path(cfg.httpd_chroot);
		if (err)
			return err;
	}

	if (cfg.htdocs_path[0] != '\0') {
		err = gotsys_conf_validate_path(cfg.htdocs_path);
		if (err)
			return err;
	}

	if (cfg.repos_path[0] == '\0') {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "empty repos_path in web config");
	}
	err = gotsys_conf_validate_path(cfg.repos_path);
	if (err)
		return err;

	if (cfg.gotwebd_user[0] != '\0') {
		err = gotsys_conf_validate_name(cfg.gotwebd_user, "user");
		if (err)
			return err;
	}

	if (cfg.www_user[0] != '\0') {
		err = gotsys_conf_validate_name(cfg.www_user, "user");
		if (err)
			return err;
	}

	if (cfg.login_hint_user[0] != '\0') {
		err = gotsys_conf_validate_name(cfg.login_hint_user, "user");
		if (err)
			return err;
	}

	if (cfg.login_hint_port[0] != '\0') {
		const char *errstr = NULL;

		strtonum(cfg.login_hint_port, 1, USHRT_MAX, &errstr);
		if (errstr) {
			return got_error_fmt(GOT_ERR_PRIVSEP_LEN,
			    "port number %s is %s", cfg.login_hint_port,
			    errstr);
		}

	}

	memcpy(new, &cfg, sizeof(*new));
	TAILQ_INIT(&new->listen_addrs);
	STAILQ_INIT(&new->servers);

	return NULL;
}

const struct got_error *
gotsysd_conf_validate_inet_addr(const char *hostname, const char *servname)
{
	struct addrinfo hints, *res0;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	error = getaddrinfo(hostname, servname, &hints, &res0);
	if (error) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "could not parse \"%s:%s\": %s", hostname, servname,
		    gai_strerror(error));
	}

	freeaddrinfo(res0);
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_webaddr(struct gotsysd_web_address **new, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_web_address *addr = NULL;

	*new = NULL;

	addr = calloc(1, sizeof(*addr));
	if (addr == NULL)
		return got_error_from_errno("calloc");

	if (imsg_get_data(imsg, addr, sizeof(*addr)) == -1)
		return got_error_from_errno("imsg_get_data");

	switch (addr->family) {
	case GOTSYSD_LISTEN_ADDR_UNIX:
		err = gotsys_conf_validate_path(addr->addr.unix_socket_path);
		break;
	case GOTSYSD_LISTEN_ADDR_INET:
		err = gotsysd_conf_validate_inet_addr(
		    addr->addr.inet.address, addr->addr.inet.port);
		break;
	default:
		return got_error_fmt(GOT_ERR_PRIVSEP_MSG,
		    "bad listen address family %u", addr->family);
	}

	if (err)
		free(addr);
	else
		*new = addr;

	return err;
}

const struct got_error *
gotsys_imsg_recv_gotweb_server(struct gotsysd_web_server **new,
    struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_web_server *srv = NULL;

	*new = NULL;

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		return got_error_from_errno("calloc");

	if (imsg_get_data(imsg, srv, sizeof(*srv)) == -1)
		return got_error_from_errno("imsg_get_data");

	switch (srv->auth_config) {
	case GOTSYSD_WEB_AUTH_UNSET:
	case GOTSYSD_WEB_AUTH_DISABLED:
	case GOTSYSD_WEB_AUTH_SECURE:
	case GOTSYSD_WEB_AUTH_INSECURE:
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad web authentication setting");
	}

	if (srv->server_name[nitems(srv->server_name) - 1] != '\0' ||
	    srv->gotweb_url_root[nitems(srv->gotweb_url_root) - 1] != '\0' ||
	    srv->htdocs_path[nitems(srv->htdocs_path) - 1] != '\0')
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (srv->server_name[0] != '\0') {
		err = gotsys_conf_validate_hostname(srv->server_name);
		if (err)
			goto done;
	}

	if (srv->gotweb_url_root[0] != '\0') {
		err = gotsys_conf_validate_path(srv->gotweb_url_root);
		if (err)
			goto done;
	}

	if (srv->htdocs_path[0] != '\0') {
		err = gotsys_conf_validate_path(srv->htdocs_path);
		if (err)
			goto done;
	}
done:
	if (err)
		free(srv);
	else
		*new = srv;

	return err;
}


static const struct got_error *
send_webrepo(struct gotsysd_imsgev *iev, struct gotsys_webrepo *webrepo)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_WEBREPO,
	    0, -1, webrepo, sizeof(*webrepo)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	STAILQ_FOREACH(rule, &webrepo->access_rules, entry) {
		err = gotsys_imsg_send_access_rule(iev, rule,
		    GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

static const struct got_error *
send_website(struct gotsysd_imsgev *iev, const char *path,
    struct gotsys_website *web)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH,
	    0, -1, (void *)path, strlen(path)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	if (gotsysd_imsg_compose_event(iev, GOTSYSD_IMSG_SYSCONF_WEBSITE,
	    0, -1, web, sizeof(*web)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	STAILQ_FOREACH(rule, &web->access_rules, entry) {
		err = gotsys_imsg_send_access_rule(iev, rule,
		    GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_website_path(struct gotsys_website **site, struct imsg *imsg)
{
	const struct got_error *err;
	size_t datalen;
	char *url_path = NULL;

	*site = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen >= sizeof((*site)->url_path))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	
	url_path = strndup((const char *)imsg->data, datalen);
	if (url_path == NULL)
		return got_error_from_errno("strndup");
	
	err = gotsys_conf_new_website(site, url_path);
	free(url_path);
	return err;
}

const struct got_error *
gotsys_imsg_recv_website(struct gotsys_website *new, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsys_website site;

	if (imsg_get_data(imsg, &site, sizeof(site)) == -1)
		return got_error_from_errno("imsg_get_data");

	switch (site.auth_config) {
	case GOTSYS_AUTH_UNSET:
	case GOTSYS_AUTH_DISABLED:
	case GOTSYS_AUTH_ENABLED:
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad website authentication setting");
	}

	if (site.url_path[nitems(site.url_path) - 1] != '\0' ||
	    site.branch_name[nitems(site.branch_name) - 1] != '\0'||
	    site.path[nitems(site.path) - 1] != '\0')
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (strcmp(new->url_path, site.url_path) != 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	if (site.branch_name[0] != '\0') {
		if (!got_ref_name_is_valid(site.branch_name))
			return got_error_path(site.branch_name,
			    GOT_ERR_BAD_REF_NAME);
	}

	if (site.path[0] != '\0') {
		err = gotsys_conf_validate_path(site.path);
		if (err)
			return err;
	}

	memcpy(new, &site, sizeof(*new));
	STAILQ_INIT(&new->access_rules);

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_webrepo(struct gotsys_webrepo *new, struct imsg *imsg)
{
	struct gotsys_webrepo web;

	if (imsg_get_data(imsg, &web, sizeof(web)) == -1)
		return got_error_from_errno("imsg_get_data");

	switch (web.auth_config) {
	case GOTSYS_AUTH_UNSET:
	case GOTSYS_AUTH_DISABLED:
	case GOTSYS_AUTH_ENABLED:
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad web authentication setting");
	}

	memcpy(new, &web, sizeof(*new));
	STAILQ_INIT(&new->access_rules);

	return NULL;
}

static const struct got_error *
send_repo(struct gotsysd_imsgev *iev, struct gotsys_repo *repo)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_repo irepo;
	struct gotsys_access_rule *rule;
	struct ibuf *wbuf = NULL;

	irepo.name_len = strlen(repo->name);
	if (repo->headref)
		irepo.headref_len = strlen(repo->headref);
	irepo.description_len = strlen(repo->description);

	wbuf = imsg_create(&iev->ibuf, GOTSYSD_IMSG_SYSCONF_REPO,
	    0, 0, sizeof(irepo) + irepo.name_len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SYSCONF_REPO");

	if (imsg_add(wbuf, &irepo, sizeof(irepo)) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");
	if (imsg_add(wbuf, repo->name, irepo.name_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");
	if (repo->headref &&
	    imsg_add(wbuf, repo->headref, irepo.headref_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");
	if (irepo.description_len > 0 &&
	    imsg_add(wbuf, repo->description, irepo.description_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");

	imsg_close(&iev->ibuf, wbuf);

	STAILQ_FOREACH(rule, &repo->access_rules, entry) {
		err = gotsys_imsg_send_access_rule(iev, rule,
		    GOTSYSD_IMSG_SYSCONF_ACCESS_RULE);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE, 0, -1, NULL, 0) == -1) {
		return got_error_from_errno("gotsysd_imsg_compose_event");
	}

	err = send_protected_refs(iev, repo);
	if (err)
		return err;

	err = send_notification_config(iev, repo);
	if (err)
		return err;

	return NULL;
}

static const struct got_error *
send_media_type(struct gotsysd_imsgev *iev,
    struct media_type *media, int imsg_type)
{
	if (gotsysd_imsg_compose_event(iev, imsg_type, 0, -1,
	        media, sizeof(*media)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");
	
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_media_type(struct media_type *new, struct imsg *imsg)
{
	const struct got_error *err;
	struct media_type media;

	if (imsg_get_data(imsg, &media, sizeof(media)) == -1)
		return got_error_from_errno("imsg_get_data");

	if (media.media_name[nitems(media.media_name) - 1] != '\0' ||
	    media.media_type[nitems(media.media_type) - 1] != '\0' ||
	    media.media_subtype[nitems(media.media_subtype) - 1] != '\0')
		return got_error(GOT_ERR_PRIVSEP_LEN);

	err = gotsys_conf_validate_mediatype(media.media_name);
	if (err)
		return err;

	err = gotsys_conf_validate_mediatype(media.media_type);
	if (err)
		return err;
	
	err = gotsys_conf_validate_mediatype(media.media_subtype);
	if (err)
		return err;

	memcpy(new, &media, sizeof(*new));
	return NULL;
}


static const struct got_error *
send_webserver(struct gotsysd_imsgev *iev, struct gotsys_webserver *srv)
{
	const struct got_error *err = NULL;
	struct gotsys_access_rule *rule;
	struct gotsys_webrepo *webrepo;
	struct got_pathlist_entry *pe;

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEB_SERVER, 0, -1, srv, sizeof(*srv)) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");
	
	STAILQ_FOREACH(rule, &srv->access_rules, entry) {
		err = gotsys_imsg_send_access_rule(iev, rule,
		    GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	STAILQ_FOREACH(webrepo, &srv->repos, entry) {
		err = send_webrepo(iev, webrepo);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	RB_FOREACH(pe, got_pathlist_head, &srv->websites) {
		struct gotsys_website *site = pe->data;

		err = send_website(iev, pe->path, site);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	err = gotsys_imsg_send_mediatypes(iev, &srv->mediatypes,
	    GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE,
	    GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE);
	if (err)
		return err;

	return NULL;
}

const struct got_error *
gotsys_imsg_send_webservers(struct gotsysd_imsgev *iev,
    struct gotsys_webserverlist *servers)
{
	const struct got_error *err = NULL;
	struct gotsys_webserver *srv;

	STAILQ_FOREACH(srv, servers, entry) {
		err = send_webserver(iev, srv);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE, 0, -1, NULL, 0) == -1) {
		return got_error_from_errno("gotsysd_imsg_compose_event");
	}

	return NULL;
}

const struct got_error *
gotsys_imsg_send_mediatypes(struct gotsysd_imsgev *iev,
    struct mediatypes *mediatypes, int imsg_code, int done_code)
{
	const struct got_error *err;
	struct media_type *media;

	RB_FOREACH(media, mediatypes, mediatypes) {
		err = send_media_type(iev, media, imsg_code);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev, done_code, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_web_server(struct gotsys_webserver *new, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsys_webserver srv;

	if (imsg_get_data(imsg, &srv, sizeof(srv)) == -1)
		return got_error_from_errno("imsg_get_data");

	err = gotsys_conf_validate_hostname(srv.server_name);
	if (err)
		return err;

	switch (srv.auth_config) {
	case GOTSYS_AUTH_UNSET:
	case GOTSYS_AUTH_DISABLED:
	case GOTSYS_AUTH_ENABLED:
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad web server authentication setting");
	}

	if (srv.css[nitems(srv.css) - 1] != '\0' ||
	    srv.logo[nitems(srv.logo) - 1] != '\0'||
	    srv.logo_url[nitems(srv.logo_url) - 1] != '\0'||
	    srv.site_owner[nitems(srv.site_owner) - 1] != '\0' ||
	    srv.repos_url_path[nitems(srv.repos_url_path) - 1] != '\0')
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (srv.css[0] != '\0') {
		err = gotsys_conf_validate_path(srv.css);
		if (err)
			return err;
	}

	if (srv.logo[0] != '\0') {
		err = gotsys_conf_validate_path(srv.logo);
		if (err)
			return err;
	}

	if (srv.logo_url[0] != '\0') {
		err = gotsys_conf_validate_url(srv.logo_url);
		if (err)
			return err;
	}

	if (srv.site_owner[0] != '\0') {
		err = gotsys_conf_validate_string(srv.site_owner);
		if (err)
			return err;
	}

	if (srv.repos_url_path[0] != '\0') {
		err = gotsys_conf_validate_path(srv.repos_url_path);
		if (err)
			return err;
	}

	memcpy(new, &srv, sizeof(*new));
	STAILQ_INIT(&new->access_rules);
	RB_INIT(&new->mediatypes);
	STAILQ_INIT(&new->repos);
	RB_INIT(&new->websites);

	return NULL;
}

const struct got_error *
gotsys_imsg_send_repositories(struct gotsysd_imsgev *iev,
    struct gotsys_repolist *repos)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;

	TAILQ_FOREACH(repo, repos, entry) {
		err = send_repo(iev, repo);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_REPOS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_repository(struct gotsys_repo **repo, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_repo irepo;
	size_t datalen;
	char *name = NULL, *headref = NULL, *description = NULL;

	*repo = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(irepo))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	
	memcpy(&irepo, imsg->data, sizeof(irepo));
	if (datalen != sizeof(irepo) +
	    irepo.name_len + irepo.headref_len + irepo.description_len ||
	    irepo.name_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	name = strndup(imsg->data + sizeof(irepo), irepo.name_len);
	if (name == NULL)
		return got_error_from_errno("strndup");
	if (strlen(name) != irepo.name_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	err = gotsys_conf_validate_repo_name(name);
	if (err)
		goto done;

	if (irepo.headref_len > 0) {
		headref = strndup(imsg->data + sizeof(irepo) + irepo.name_len,
		    irepo.headref_len);
		if (headref == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(headref) != irepo.headref_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		if (!got_ref_name_is_valid(headref)) {
			err = got_error_path(headref, GOT_ERR_BAD_REF_NAME);
			goto done;
		}
	}

	if (irepo.description_len > 0) {
		description = strndup(imsg->data + sizeof(irepo) +
		    irepo.name_len + irepo.headref_len,
		    irepo.description_len);
		if (description == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(description) != irepo.description_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		err = gotsys_conf_validate_string(description);
		if (err)
			goto done;
	}

	err = gotsys_conf_new_repo(repo, name);
	if (err)
		goto done;

	(*repo)->headref = headref;
	if (description != NULL) {
		if (strlcpy((*repo)->description, description,
		    sizeof((*repo)->description)) >=
		    sizeof((*repo)->description)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}
done:
	free(name);
	free(description);
	if (err)
		free(headref);
	return err;
}

const struct got_error *
gotsys_imsg_recv_access_rule(struct gotsys_access_rule **rule,
    struct imsg *imsg, struct gotsys_userlist *users,
    struct gotsys_grouplist *groups)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_access_rule irule;
	enum gotsys_access access;
	size_t datalen;
	char *identifier = NULL;

	*rule = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(irule))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&irule, imsg->data, sizeof(irule));
	if (datalen != sizeof(irule) + irule.identifier_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (irule.identifier_len == 0) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "empty access rule identifier");
	}
	if (irule.identifier_len > _PW_NAME_LEN) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "access rule identifier too long");
	}

	switch (irule.access) {
	case GOTSYSD_IMSG_ACCESS_PERMITTED:
		if (irule.authorization == 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "permit access rule without read or write "
			    "authorization");
		}
		access = GOTSYS_ACCESS_PERMITTED;
		break;
	case GOTSYSD_IMSG_ACCESS_DENIED:
		if (irule.authorization != 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "deny access rule with read or write "
			    "authorization");
		}
		access = GOTSYS_ACCESS_DENIED;
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule");
	}

	if (irule.authorization & ~(GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE)) {
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule authorization flags");
	}
	
	identifier = strndup(imsg->data + sizeof(irule), irule.identifier_len);
	if (identifier == NULL)
		return got_error_from_errno("strndup");
	if (strlen(identifier) != irule.identifier_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		free(identifier);
		return err;
	}

	err = gotsys_conf_new_access_rule(rule, access, irule.authorization,
	    identifier, users, groups);
	free(identifier);
	return err;
}

const struct got_error *
gotsys_imsg_recv_pathlist(size_t *npaths, struct imsg *imsg)
{
	struct gotsysd_imsg_pathlist ilist;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ilist))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ilist, imsg->data, sizeof(ilist));

	if (ilist.nelem == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	*npaths = ilist.nelem;
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_pathlist_elem(struct imsg *imsg,
    struct got_pathlist_head *paths)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_pathlist_elem ielem;
	size_t datalen;
	char *path;
	struct got_pathlist_entry *pe;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ielem))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ielem, imsg->data, sizeof(ielem));

	if (datalen != sizeof(ielem) + ielem.path_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	path = strndup(imsg->data + sizeof(ielem), ielem.path_len);
	if (path == NULL)
		return got_error_from_errno("strndup");

	err = got_pathlist_insert(&pe, paths, path, NULL);
	if (err || pe == NULL)
		free(path);
	return err;
}

const struct got_error *
gotsys_imsg_recv_notification_target_email(char **repo_name,
    struct gotsys_notification_target **new_target, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_notitfication_target_email itarget;
	struct gotsys_notification_target *target;
	size_t datalen;

	if (repo_name)
		*repo_name = NULL;
	*new_target = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(itarget))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&itarget, imsg->data, sizeof(itarget));

	if (datalen != sizeof(itarget) + itarget.sender_len +
	    itarget.recipient_len + itarget.responder_len +
	    itarget.hostname_len + itarget.port_len + itarget.repo_name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (itarget.recipient_len == 0 || itarget.repo_name_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	target = calloc(1, sizeof(*target));
	if (target == NULL)
		return got_error_from_errno("calloc");

	target->type = GOTSYS_NOTIFICATION_VIA_EMAIL;

	if (itarget.sender_len) {
		target->conf.email.sender = strndup(imsg->data +
		    sizeof(itarget), itarget.sender_len);
		if (target->conf.email.sender == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.sender) != itarget.sender_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	target->conf.email.recipient = strndup(imsg->data + sizeof(itarget) +
	    itarget.sender_len, itarget.recipient_len);
	if (target->conf.email.recipient == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.email.recipient) != itarget.recipient_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	
	if (itarget.responder_len) {
		target->conf.email.responder = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len, itarget.responder_len);
		if (target->conf.email.responder == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.responder) !=
		    itarget.responder_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.hostname_len) {
		target->conf.email.hostname = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len,
		    itarget.hostname_len);
		if (target->conf.email.hostname == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.hostname) !=
		    itarget.hostname_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.port_len) {
		target->conf.email.port = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len +
		    itarget.hostname_len, itarget.port_len);
		if (target->conf.email.port == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.email.port) != itarget.port_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (repo_name) {
		*repo_name = strndup(imsg->data +
		    sizeof(itarget) + itarget.sender_len +
		    itarget.recipient_len + itarget.responder_len +
		    itarget.hostname_len + itarget.port_len,
		    itarget.repo_name_len);
		if (*repo_name == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(*repo_name) != itarget.repo_name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			free(*repo_name);
			*repo_name = NULL;
			goto done;
		}
	}

	*new_target = target;
done:
	if (err)
		gotsys_notification_target_free(target);
	return err;
}

const struct got_error *
gotsys_imsg_recv_notification_target_http(char **repo_name,
    struct gotsys_notification_target **new_target, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_notitfication_target_http itarget;
	struct gotsys_notification_target *target;
	size_t datalen;

	if (repo_name)
		*repo_name = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(itarget))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&itarget, imsg->data, sizeof(itarget));

	if (datalen != sizeof(itarget) + itarget.hostname_len +
	    itarget.port_len + itarget.path_len + itarget.user_len +
	    itarget.password_len + itarget.hmac_len + itarget.repo_name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	if (itarget.hostname_len == 0 || itarget.port_len == 0 ||
	    itarget.path_len == 0 || itarget.repo_name_len == 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	target = calloc(1, sizeof(*target));
	if (target == NULL)
		return got_error_from_errno("calloc");

	target->type = GOTSYS_NOTIFICATION_VIA_HTTP;

	target->conf.http.tls = itarget.tls;

	target->conf.http.hostname = strndup(imsg->data +
	    sizeof(itarget), itarget.hostname_len);
	if (target->conf.http.hostname == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.hostname) != itarget.hostname_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	target->conf.http.port = strndup(imsg->data + sizeof(itarget) +
	    itarget.hostname_len, itarget.port_len);
	if (target->conf.http.port == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.port) != itarget.port_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	
	target->conf.http.path = strndup(imsg->data +
	    sizeof(itarget) + itarget.hostname_len + itarget.port_len,
	    itarget.path_len);
	if (target->conf.http.path == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	if (strlen(target->conf.http.path) != itarget.path_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	if (itarget.user_len) {
		target->conf.http.user = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len,
		    itarget.user_len);
		if (target->conf.http.user == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.http.user) != itarget.user_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.password_len) {
		target->conf.http.password = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len + itarget.user_len,
		    itarget.password_len);
		if (target->conf.http.password == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.http.password) !=
		    itarget.password_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (itarget.hmac_len) {
		target->conf.http.hmac_secret = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len +
		    itarget.user_len + itarget.password_len,
		    itarget.hmac_len);
		if (target->conf.http.hmac_secret == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(target->conf.http.hmac_secret) != itarget.hmac_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (repo_name) {
		*repo_name = strndup(imsg->data +
		    sizeof(itarget) + itarget.hostname_len +
		    itarget.port_len + itarget.path_len +
		    itarget.user_len + itarget.password_len +
		    itarget.hmac_len, itarget.repo_name_len);
		if (*repo_name == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(*repo_name) != itarget.repo_name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			free(*repo_name);
			*repo_name = NULL;
			goto done;
		}
	}
		
	*new_target = target;
done:
	if (err)
		gotsys_notification_target_free(target);
	return err;
}
