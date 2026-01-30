
/*
 * Copyright (c) 2020, 2025 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "media.h"
#include "gotwebd.h"
#include "gotsys.h"

static struct gotsysd_web_config webcfg;
static struct gotsys_conf gotsysconf;
static struct gotsys_userlist *users_cur;
static struct gotsys_repo *repo_cur;
static struct gotsys_website *site_cur;
static struct got_pathlist_head *protected_refs_cur;
static size_t nprotected_refs_needed;
static size_t nprotected_refs_received;
static int gotd_conf_tmpfd = -1;
static char *gotd_conf_tmppath;
static int gotd_secrets_tmpfd = -1;
static char *gotd_secrets_tmppath;
static int gotwebd_conf_tmpfd = -1;
static char *gotwebd_conf_tmppath;
static struct gotsys_access_rule_list global_repo_access_rules;
static struct got_pathlist_head *notif_refs_cur;
static size_t *num_notif_refs_cur;
static size_t num_notif_refs_needed;
static size_t num_notif_refs_received;

enum writeconf_state {
	WRITECONF_STATE_EXPECT_GOTWEB_CFG,
	WRITECONF_STATE_EXPECT_GOTWEB_ADDRS,
	WRITECONF_STATE_EXPECT_GOTWEB_SERVERS,
	WRITECONF_STATE_EXPECT_USERS,
	WRITECONF_STATE_EXPECT_GROUPS,
	WRITECONF_STATE_EXPECT_GLOBAL_ACCESS_RULES,
	WRITECONF_STATE_EXPECT_REPOS,
	WRITECONF_STATE_EXPECT_MEDIA_TYPES,
	WRITECONF_STATE_EXPECT_WEB_SERVERS,
	WRITECONF_STATE_WRITE_CONF,
	WRITECONF_STATE_DONE
};

static enum writeconf_state writeconf_state = WRITECONF_STATE_EXPECT_GOTWEB_CFG;

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
send_done(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_DONE,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose "
		    "SYSCONF_WRITE_CONF_DONE");
	}

	return NULL;
}

static const struct got_error *
write_access_rule(int fd, const char *path, const char *prefix,
    const char *access, const char * authorization, const char *identifier)
{
	int ret;

	ret = dprintf(fd, "%s%s%s%s\n", prefix, access, authorization,
	    identifier);
	if (ret == -1)
		return got_error_from_errno2("dprintf", path);
	if (ret != strlen(prefix) + strlen(access) + strlen(authorization) +
	    strlen(identifier) + 1) {
		return got_error_fmt(GOT_ERR_IO,
		    "short write to %s", path);
	}

	return NULL;
}

static const struct got_error *
write_gotsys_auth_config(int fd, const char *path,
    const char *prefix, enum gotsys_auth_config auth_config,
    enum gotsysd_web_auth_config webd_auth_config)
{
	int ret;

	switch (auth_config) {
	case GOTSYS_AUTH_UNSET:
		break;
	case GOTSYS_AUTH_DISABLED:
		ret = dprintf(fd, "%sdisable authentication\n", prefix);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != strlen(prefix) + 22 + 1) {
			return got_error_fmt(GOT_ERR_IO,
			"short write to %s", path);
		}
		break;
	case GOTSYS_AUTH_ENABLED:
		if (webd_auth_config == GOTSYSD_WEB_AUTH_INSECURE) {
			ret = dprintf(fd,
			    "%senable authentication insecure\n", prefix);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != strlen(prefix) + 30 + 1) {
				return got_error_fmt(GOT_ERR_IO,
				"short write to %s", path);
			}
		} else {
			ret = dprintf(fd, "%senable authentication\n", prefix);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != strlen(prefix) + 21 + 1) {
				return got_error_fmt(GOT_ERR_IO,
				"short write to %s", path);
			}
		}
		break;
	default:
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "bad gotsysd web authentication mode %u", auth_config);
	}

	return NULL;
}

static const struct got_error *
write_gotsysd_web_auth_config(int fd, const char *path,
    enum gotsysd_web_auth_config auth_config)
{
	int ret;

	switch (auth_config) {
	case GOTSYSD_WEB_AUTH_UNSET:
		break;
	case GOTSYSD_WEB_AUTH_DISABLED:
		ret = dprintf(fd, "\tdisable authentication\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		break;
	case GOTSYSD_WEB_AUTH_SECURE:
		ret = dprintf(fd, "\tenable authentication\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		break;
	case GOTSYSD_WEB_AUTH_INSECURE:
		ret = dprintf(fd, "\tenable authentication insecure\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		break;
	default:
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "bad gotsysd web authentication mode %u", auth_config);
	}

	return NULL;
}

static const struct got_error *
write_global_access_rules(void)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	STAILQ_FOREACH(rule, &global_repo_access_rules, entry) {
		const char *access, *authorization;

		switch (rule->access) {
		case GOTSYS_ACCESS_DENIED:
			access = "deny ";
			break;
		case GOTSYS_ACCESS_PERMITTED:
			access = "permit ";
			break;
		default:
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "access rule with unknown access flag %d",
			    rule->access);
		}

		if (rule->authorization & GOTSYS_AUTH_WRITE)
			authorization = "rw ";
		else if (rule->authorization & GOTSYS_AUTH_READ)
			authorization = "ro ";
		else
			authorization = "";
	
		if (strcmp(rule->identifier, "*") == 0) {
			struct gotsys_user *user;

			STAILQ_FOREACH(user, &gotsysconf.users, entry) {
				/*
				 * Anonymous read access must be enabled
				 * explicitly, not via *.
				 */
				if (rule->access == GOTSYS_ACCESS_PERMITTED &&
				    strcmp(user->name, "anonymous") == 0)
					continue;
				err = write_access_rule(gotd_conf_tmpfd,
				    gotd_conf_tmppath, "\t",
				    access, authorization, user->name);
				if (err)
					return err;
			}
		} else {
			err = write_access_rule(gotd_conf_tmpfd,
			    gotd_conf_tmppath, "\t", access, authorization,
			    rule->identifier);
			if (err)
				return err;
		}
	}

	return NULL;
}

static const struct got_error *
write_access_rules(int fd, const char *path,
    struct gotsys_access_rule_list *rules)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	STAILQ_FOREACH(rule, rules, entry) {
		const char *access, *authorization;

		switch (rule->access) {
		case GOTSYS_ACCESS_DENIED:
			access = "deny ";
			break;
		case GOTSYS_ACCESS_PERMITTED:
			access = "permit ";
			break;
		default:
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "access rule with unknown access flag %d",
			    rule->access);
		}

		if (rule->authorization & GOTSYS_AUTH_WRITE)
			authorization = "rw ";
		else if (rule->authorization & GOTSYS_AUTH_READ)
			authorization = "ro ";
		else
			authorization = "";

		err = write_access_rule(fd, path, "\t",
		    access, authorization, rule->identifier);
		if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
write_web_access_rules(int fd, const char *path,
    const char *prefix, struct gotsys_access_rule_list *rules)
{
	const struct got_error *err;
	struct gotsys_access_rule *rule;

	STAILQ_FOREACH(rule, rules, entry) {
		const char *access;

		switch (rule->access) {
		case GOTSYS_ACCESS_DENIED:
			access = "deny ";
			break;
		case GOTSYS_ACCESS_PERMITTED:
			access = "permit ";
			break;
		default:
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "access rule with unknown access flag %d",
			    rule->access);
		}

		err = write_access_rule(fd, path, prefix, access, "",
		    rule->identifier); if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
refname_is_valid(const char *refname)
{
	if (strncmp(refname, "refs/", 5) != 0) {
		return got_error_fmt( GOT_ERR_BAD_REF_NAME,
		    "reference name must begin with \"refs/\": %s", refname);
	}

	if (!got_ref_name_is_valid(refname))
		return got_error_path(refname, GOT_ERR_BAD_REF_NAME);

	return NULL;
}

static const struct got_error *
write_protected_refs(struct gotsys_repo *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	int ret;
	const char *opening = "protect {";
	const char *closing = "}";
	char *namespace = NULL;

	if (RB_EMPTY(&repo->protected_tag_namespaces) &&
	    RB_EMPTY(&repo->protected_branch_namespaces) &&
	    RB_EMPTY(&repo->protected_branches))
		return NULL;

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", opening);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(opening))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_tag_namespaces) {
		namespace = strdup(pe->path);
		if (namespace == NULL)
			return got_error_from_errno("strdup");

		got_path_strip_trailing_slashes(namespace);
		err = refname_is_valid(namespace);
		if (err)
			goto done;

		ret = dprintf(gotd_conf_tmpfd, "\t\ttag namespace \"%s\"\n",
		    namespace);
		if (ret == -1) {
			err = got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
			goto done;
		}
		if (ret != 19 + strlen(namespace)) {
			err = got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
			goto done;
		}
		free(namespace);
		namespace = NULL;
	}

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_branch_namespaces) {
		namespace = strdup(pe->path);
		if (namespace == NULL)
			return got_error_from_errno("strdup");

		got_path_strip_trailing_slashes(namespace);
		err = refname_is_valid(namespace);
		if (err)
			goto done;

		ret = dprintf(gotd_conf_tmpfd, "\t\tbranch namespace \"%s\"\n",
		    namespace);
		if (ret == -1) {
			err = got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
			goto done;
		}
		if (ret != 22 + strlen(namespace)) {
			err = got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
			goto done;
		}
		free(namespace);
		namespace = NULL;
	}

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_branches) {
		err = refname_is_valid(pe->path);
		if (err)
			return err;
		ret = dprintf(gotd_conf_tmpfd, "\t\tbranch \"%s\"\n", pe->path);
		if (ret == -1) {
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		}
		if (ret != 12 + strlen(pe->path))
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
	}

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", closing);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(closing))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);
done:
	free(namespace);
	return NULL;
}

static const struct got_error *
write_notification_target_email(struct gotsys_notification_target *target)
{
	char sender[128];
	char recipient[128];
	char responder[128];
	int ret = 0;

	if (target->conf.email.sender) {
		ret = snprintf(sender, sizeof(sender), " from \"%s\"",
		    target->conf.email.sender);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(sender)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "notification email sender too long");
		}
	} else
		sender[0] = '\0';

	ret = snprintf(recipient, sizeof(recipient), " to \"%s\"",
	    target->conf.email.recipient);
	if (ret == -1)
		return got_error_from_errno("snprintf");
	if ((size_t)ret >= sizeof(recipient)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "notification email recipient too long");
	}

	if (target->conf.email.responder) {
		ret = snprintf(responder, sizeof(responder), " reply to \"%s\"",
		    target->conf.email.responder);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(responder)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "notification email responder too long");
		}
	} else
		responder[0] = '\0';

	ret = dprintf(gotd_conf_tmpfd, "\t\temail%s%s%s\n",
	    sender, recipient, responder);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 8 + strlen(sender) + strlen(recipient) + strlen(responder)) {
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);
	}

	return NULL;
}

static const struct got_error *
write_notification_target_http(struct gotsys_notification_target *target,
    int idx)
{
	char proto[16];
	char port[16];
	char label[16];
	char auth[128];
	char insecure[16];
	char hmac[128];
	int ret = 0;

	insecure[0] = '\0';

	if (target->conf.http.tls) {
		if (strlcpy(proto, "https://", sizeof(proto)) >=
		    sizeof(proto)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "http notification protocol too long");
		}
	} else {
		if (strlcpy(proto, "http://", sizeof(proto)) >=
		    sizeof(proto)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "http notification protocol too long");
		}

		if (target->conf.http.user && target->conf.http.password) {
			if (strlcpy(insecure, " insecure", sizeof(insecure)) >=
			    sizeof(insecure)) {
				return got_error_msg(GOT_ERR_NO_SPACE, "http "
				    "notification insecure keyword too long");
			}
		}
	}

	if (target->conf.http.port) {
		ret = snprintf(port, sizeof(port), ":%s",
		    target->conf.http.port);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(port)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "notification http port too long");
		}
	} else
		port[0] = '\0';

	if (target->conf.http.user && target->conf.http.password) {
		ret = snprintf(label, sizeof(label), "basic%d", idx);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(label)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "basic auth label too long");
		}

		ret = snprintf(auth, sizeof(auth), " auth %s", label);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(label)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "http notification auth too long");
		}
	} else
		auth[0] = '\0';

	if (target->conf.http.hmac_secret) {
		ret = snprintf(label, sizeof(label), "hmac%d", idx);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(label)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "notification http hmac label too long");
		}

		ret = snprintf(hmac, sizeof(hmac), " hmac %s", label);
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(label)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "http notification hmac too long");
		}
	} else
		hmac[0] = '\0';

	ret = dprintf(gotd_conf_tmpfd, "\t\turl \"%s%s%s/%s\"%s%s%s\n",
		proto, target->conf.http.hostname, port,
		target->conf.http.path, auth, insecure, hmac);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 10 + strlen(proto) + strlen(target->conf.http.hostname) +
	    strlen(port) + strlen(target->conf.http.path) + strlen(auth) +
	    strlen(insecure) + strlen(hmac)) {
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);
	}

	return NULL;
}

static const struct got_error *
write_notification_targets(struct gotsys_repo *repo, int *auth_idx)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	struct gotsys_notification_target *target;
	const char *opening = "notify {";
	const char *closing = "}";
	char *namespace = NULL;
	int ret = 0;

	if (STAILQ_EMPTY(&repo->notification_targets))
		return NULL;

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", opening);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(opening))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);

	RB_FOREACH(pe, got_pathlist_head, &repo->notification_refs) {
		err = refname_is_valid(pe->path);
		if (err)
			return err;
		ret = dprintf(gotd_conf_tmpfd, "\t\tbranch \"%s\"\n", pe->path);
		if (ret == -1) {
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		}
		if (ret != 12 + strlen(pe->path))
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
	}

	RB_FOREACH(pe, got_pathlist_head, &repo->notification_ref_namespaces) {
		namespace = strdup(pe->path);
		if (namespace == NULL)
			return got_error_from_errno("strdup");

		got_path_strip_trailing_slashes(namespace);
		err = refname_is_valid(namespace);
		if (err)
			goto done;

		ret = dprintf(gotd_conf_tmpfd,
		    "\t\treference namespace \"%s\"\n", namespace);
		if (ret == -1) {
			err = got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
			goto done;
		}
		if (ret != 25 + strlen(namespace)) {
			err = got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
			goto done;
		}
		free(namespace);
		namespace = NULL;
	}

	STAILQ_FOREACH(target, &repo->notification_targets, entry) {
		(*auth_idx)++;
		switch (target->type) {
		case GOTSYS_NOTIFICATION_VIA_EMAIL:
			err = write_notification_target_email(target);
			break;
		case GOTSYS_NOTIFICATION_VIA_HTTP:
			err = write_notification_target_http(target, *auth_idx);
			break;
		default:
			break;
		}
	}

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", closing);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(closing))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);
done:
	free(namespace);
	return err;
}

static const struct got_error *
write_repo_secrets(off_t *written, struct gotsys_repo *repo,
    int *auth_idx)
{
	struct gotsys_notification_target *target;
	char label[32];
	int ret = 0;
	size_t len;

	STAILQ_FOREACH(target, &repo->notification_targets, entry) {
		(*auth_idx)++;
		if (target->type != GOTSYS_NOTIFICATION_VIA_HTTP)
			continue;

		if (target->conf.http.user == NULL &&
		    target->conf.http.password == NULL &&
		    target->conf.http.hmac_secret == NULL)
			continue;

		if (target->conf.http.user && target->conf.http.password) {
			ret = snprintf(label, sizeof(label), "basic%d",
			    *auth_idx);
			if (ret == -1)
				return got_error_from_errno("snprintf");
			if ((size_t)ret >= sizeof(label)) {
				return got_error_msg(GOT_ERR_NO_SPACE,
				    "basic auth label too long");
			}

			ret = dprintf(gotd_secrets_tmpfd,
			    "auth %s user \"%s\" password \"%s\"\n", label,
			    target->conf.http.user, target->conf.http.password);
			if (ret == -1)
				return got_error_from_errno2("dprintf",
				    gotd_secrets_tmppath);
			len = strlen(label) +
			    strlen(target->conf.http.user) +
			    strlen(target->conf.http.password);
			if (ret != 26 + len) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", gotd_secrets_tmppath);
			}
			*written += ret;
		}

		if (target->conf.http.hmac_secret) {
			ret = snprintf(label, sizeof(label), "hmac%d",
			    *auth_idx);
			if (ret == -1)
				return got_error_from_errno("snprintf");
			if ((size_t)ret >= sizeof(label)) {
				return got_error_msg(GOT_ERR_NO_SPACE,
				    "hmac secret label too long");
			}
			ret = dprintf(gotd_secrets_tmpfd, "hmac %s \"%s\"\n",
			    label, target->conf.http.hmac_secret);
			if (ret == -1)
				return got_error_from_errno2("dprintf",
				    gotd_secrets_tmppath);
			len = strlen(label) +
			    strlen(target->conf.http.hmac_secret);
			if (ret != 9 + len) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", gotd_secrets_tmppath);
			}
			*written += ret;
		}
	}

	return NULL;
}

static const struct got_error *
prepare_gotd_secrets(int *auth_idx)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;
	off_t written = 0;

	if (ftruncate(gotd_secrets_tmpfd, 0) == -1)
		return got_error_from_errno("ftruncate");

	TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
		err = write_repo_secrets(&written, repo, auth_idx);
		if (err)
			return err;
	}

	if (written == 0) {
		if (unlink(gotd_secrets_tmppath) == -1) {
			return got_error_from_errno2("unlink",
			    gotd_secrets_tmppath);
		}
		free(gotd_secrets_tmppath);
		gotd_secrets_tmppath = NULL;

		if (close(gotd_secrets_tmpfd) == -1)
			return got_error_from_errno("close");
		gotd_secrets_tmpfd = -1;
	}

	return NULL;
}

static const struct got_error *
write_gotd_conf(int *auth_idx)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;
	int ret;
	char repo_path[_POSIX_PATH_MAX];
	struct timespec now;

	err = got_opentemp_truncatefd(gotd_conf_tmpfd);
	if (err)
		return err;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return got_error_from_errno("clock_gettime");

	/* TODO: show gotsys.git commit hash */
	ret = dprintf(gotd_conf_tmpfd, "# generated by gotsysd, do not edit\n");
	if (ret == -1)
		return got_error_from_errno2("dprintf",
		    gotd_conf_tmppath);
	if (ret != 35 + 1) {
		return got_error_fmt(GOT_ERR_IO,
		    "short write to %s", gotd_conf_tmppath);
	}

	TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
		char *name = NULL;
		size_t namelen;

		ret = dprintf(gotd_conf_tmpfd, "repository \"%s\" {\n",
		    repo->name);
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 15 + strlen(repo->name) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}

		namelen = strlen(repo->name);
		if (namelen < 4 ||
		    strcmp(&repo->name[namelen - 4], ".git") != 0) {
			if (asprintf(&name, "%s.git", repo->name) == -1)
				return got_error_from_errno("asprintf");
		} else {
			name = strdup(repo->name);
			if (name == NULL)
				return got_error_from_errno("strdup");
		}
		/* TODO: Honour repository path set in gotsysd.conf. */
		ret = snprintf(repo_path, sizeof(repo_path),
		    "%s/%s", GOTSYSD_REPOSITORIES_PATH, name);
		free(name);
		name = NULL;
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(repo_path)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "repository path too long");
		}

		ret = dprintf(gotd_conf_tmpfd, "\tpath \"%s\"\n", repo_path);
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 8 + strlen(repo_path) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}

		err = write_access_rules(gotd_conf_tmpfd, gotd_conf_tmppath,
		    &repo->access_rules);
		if (err)
			return err;

		err = write_global_access_rules();
		if (err)
			return err;

		err = write_protected_refs(repo);
		if (err)
			return err;

		err = write_notification_targets(repo, auth_idx);
		if (err)
			return err;

		ret = dprintf(gotd_conf_tmpfd, "}\n");
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 2) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}
	}

	if (gotd_secrets_tmppath != NULL && gotd_secrets_tmpfd != -1) {
		if (fchmod(gotd_secrets_tmpfd, 0600) == -1) {
			return got_error_from_errno_fmt("chmod 0600 %s",
			    gotd_secrets_tmppath);
		}
			
		if (rename(gotd_secrets_tmppath, GOTD_SECRETS_PATH) == -1) {
			return got_error_from_errno_fmt("rename %s to %s",
			    gotd_secrets_tmppath, GOTD_SECRETS_PATH);
		}

		free(gotd_secrets_tmppath);
		gotd_secrets_tmppath = NULL;
	}

	if (fchmod(gotd_conf_tmpfd, 0644) == -1) {
		return got_error_from_errno_fmt("chmod 0644 %s",
		    gotd_conf_tmppath);
	}
		
	if (rename(gotd_conf_tmppath, GOTD_CONF_PATH) == -1) {
		return got_error_from_errno_fmt("rename %s to %s",
		    gotd_conf_tmppath, GOTD_CONF_PATH);
	}

	free(gotd_conf_tmppath);
	gotd_conf_tmppath = NULL;
	return NULL;
}

static const struct got_error *
hide_gotsys_repo(int fd, const char *path)
{
	int ret;

	ret = dprintf(fd,
	    "\trepository \"gotsys\" {\n"
	    "\t\thide repository on\n"
	    "\t\tenable authentication\n"
	    "\t}\n");
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 23 + 21 + 24 + 3)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	return NULL;
}

static const struct got_error *
write_webrepo(int *show_repo_description, int fd, const char *path,
    struct gotsys_webrepo *webrepo,
    enum gotsysd_web_auth_config webd_auth_config)
{
	const struct got_error *err;
	struct gotsys_repo *repo;
	int ret;
	char repo_name[_POSIX_PATH_MAX];
	size_t namelen;

	namelen = strlcpy(repo_name, webrepo->repo_name, sizeof(repo_name));
	if (namelen >= sizeof(repo_name)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "repository name too long");
	}

	if (namelen > 4 &&
	    strcmp(&repo_name[namelen - 4], GOTWEB_GIT_DIR) == 0)
		repo_name[namelen - 4] = '\0';

	ret = dprintf(fd, "\trepository \"%s\" {\n", repo_name);
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 16 + strlen(repo_name) + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	err = write_gotsys_auth_config(fd, path, "\t\t", webrepo->auth_config,
	    webd_auth_config);
	if (err)
		return err;

	err = write_web_access_rules(fd, path, "\t\t", &webrepo->access_rules);
	if (err)
		return err;

	if (webrepo->hidden != -1) {
		const char *val;

		val = webrepo->hidden ? "on" : "off";
		ret = dprintf(fd, "\t\thide repository %s\n", val);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 18 + strlen(val) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", path);
		}
	}

	repo = gotsys_find_repo_by_name(webrepo->repo_name, &gotsysconf.repos);
	if (repo && repo->description[0] != '\0') {
		ret = dprintf(fd, "\t\tdescription \"%s\"\n", repo->description);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 16 + strlen(repo->description) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", path);
		}

		*show_repo_description = 1;
	}

	ret = dprintf(fd, "\t}\n");
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 3)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	return NULL;
}

static const struct got_error *
write_website(int fd, const char *path, struct gotsys_website *site,
    enum gotsysd_web_auth_config webd_auth_config)
{
	const struct got_error *err;
	int ret;
	char repo_name[_POSIX_PATH_MAX];
	size_t namelen;

	ret = dprintf(fd, "\twebsite \"%s\" {\n", site->url_path);
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 13 + strlen(site->url_path) + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);


	namelen = strlcpy(repo_name, site->repo_name, sizeof(repo_name));
	if (namelen >= sizeof(repo_name)) {
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "repository name too long");
	}

	if (namelen > 4 &&
	    strcmp(&repo_name[namelen - 4], GOTWEB_GIT_DIR) == 0)
		repo_name[namelen - 4] = '\0';

	ret = dprintf(fd, "\t\trepository \"%s\"\n", repo_name);
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 15 + strlen(repo_name) + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	if (site->branch_name[0] != '\0') {
		ret = dprintf(fd, "\t\tbranch \"%s\"\n", site->branch_name);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 11 + strlen(site->branch_name) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", path);
		}
	}

	ret = dprintf(fd, "\t\tpath \"%s\"\n", site->path[0] ? site->path : "/");
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 9 + (site->path[0] ? strlen(site->path) : 1) + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	err = write_gotsys_auth_config(fd, path, "\t\t", site->auth_config,
	    webd_auth_config);
	if (err)
		return err;

	err = write_web_access_rules(fd, path, "\t\t", &site->access_rules);
	if (err)
		return err;

	ret = dprintf(fd, "\t}\n");
	if (ret == -1) 
		return got_error_from_errno2("dprintf", path);
	if (ret != 3)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	return NULL;
}

static const struct got_error *
write_gotwebd_conf(void)
{
	const struct got_error *err = NULL;
	int ret, fd = gotwebd_conf_tmpfd;
	const char *path = gotwebd_conf_tmppath;
	struct gotsysd_web_address *addr;
	struct gotsysd_web_server *srv_cfg;

	err = got_opentemp_truncatefd(fd);
	if (err)
		return err;

	/* TODO: show gotsys.git commit hash */
	ret = dprintf(fd, "# generated by gotsysd, do not edit\n");
	if (ret == -1)
		return got_error_from_errno2("dprintf", path);
	if (ret != 35 + 1)
		return got_error_fmt(GOT_ERR_IO, "short write to %s", path);

	if (webcfg.control_socket[0] != '\0') {
		ret = dprintf(fd, "control socket \"%s\"\n",
		    webcfg.control_socket);
		if (ret == -1)
			return got_error_from_errno2("dprintf", path);
		if (ret != 17 + strlen(webcfg.control_socket) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.httpd_chroot[0] != '\0') {
		ret = dprintf(fd, "chroot \"%s\"\n", webcfg.httpd_chroot);
		if (ret == -1)
			return got_error_from_errno2("dprintf", path);
		if (ret != 9 + strlen(webcfg.httpd_chroot) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.htdocs_path[0] != '\0') {
		ret = dprintf(fd, "htdocs \"%s\"\n", webcfg.htdocs_path);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 9 + strlen(webcfg.htdocs_path) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.gotwebd_user[0] != '\0') {
		ret = dprintf(fd, "user \"%s\"\n", webcfg.gotwebd_user);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 7 + strlen(webcfg.gotwebd_user) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.www_user[0] != '\0') {
		ret = dprintf(fd, "www user \"%s\"\n", webcfg.www_user);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 11 + strlen(webcfg.www_user) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.login_hint_user[0] != '\0') {
		ret = dprintf(fd, "login hint user \"%s\"\n",
		    webcfg.login_hint_user);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 18 + strlen(webcfg.login_hint_user) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.login_hint_port[0] != '\0') {
		ret = dprintf(fd, "login hint port \"%s\"\n",
		    webcfg.login_hint_port);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 18 + strlen(webcfg.login_hint_port) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	switch (webcfg.auth_config) {
	case GOTSYSD_WEB_AUTH_UNSET:
		break;
	case GOTSYSD_WEB_AUTH_DISABLED:
		ret = dprintf(fd, "disable authentication\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 22 + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
		break;
	case GOTSYSD_WEB_AUTH_SECURE:
		ret = dprintf(fd, "enable authentication\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 21 + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
		break;
	case GOTSYSD_WEB_AUTH_INSECURE:
		ret = dprintf(fd, "enable authentication insecure\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 30 + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
		break;
	default:
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "bad global authentication mode %u", webcfg.auth_config);
	}

	TAILQ_FOREACH(addr, &webcfg.listen_addrs, entry) {
		switch (addr->family) {
		case GOTSYSD_LISTEN_ADDR_UNIX:
			ret = dprintf(fd, "listen on socket \"%s\"\n",
			    addr->addr.unix_socket_path);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 19 +
			    strlen(addr->addr.unix_socket_path) + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
			break;
		case GOTSYSD_LISTEN_ADDR_INET:
			ret = dprintf(fd, "listen on \"%s\" port \"%s\"\n",
			    addr->addr.inet.address, addr->addr.inet.port);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 20 +
			    strlen(addr->addr.inet.address) +
			    strlen(addr->addr.inet.port) + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
			break;
		default:
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "bad listen address family %u", addr->family);
		}
	}

	STAILQ_FOREACH(srv_cfg, &webcfg.servers, entry) {
		struct gotsys_webserver *srv;
		int hide_repositories = -1;

		STAILQ_FOREACH(srv, &gotsysconf.webservers, entry) {
			if (strcmp(srv->server_name, srv_cfg->server_name) == 0)
				break;
		}

		ret = dprintf(fd, "server \"%s\" {\n", srv_cfg->server_name);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 11 + strlen(srv_cfg->server_name) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", path);
		}

		ret = dprintf(fd, "\trepos_path \"%s\"\n", webcfg.repos_path);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 14 + strlen(webcfg.repos_path) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", path);
		}

		if (srv_cfg->gotweb_url_root[0] != '\0') {
			ret = dprintf(fd, "\tgotweb_url_root \"%s\"\n",
			    srv_cfg->gotweb_url_root);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 19 + strlen(srv_cfg->gotweb_url_root) + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
		}

		if (srv_cfg->htdocs_path[0] != '\0') {
			ret = dprintf(fd, "\thtdocs \"%s\"\n",
			    srv_cfg->htdocs_path);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 10 + strlen(srv_cfg->htdocs_path) + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
		}

		if (srv && srv->auth_config != GOTSYS_AUTH_UNSET) {
			err = write_gotsys_auth_config(fd, path, "\t",
			    srv->auth_config, srv_cfg->auth_config);
			if (err)
				return err;
		} else {
			err = write_gotsysd_web_auth_config(fd, path,
			    srv_cfg->auth_config);
			if (err)
				return err;
		}

		if (srv && srv->hide_repositories != -1)
			hide_repositories = srv->hide_repositories;
		else if (srv_cfg->hide_repositories != -1)
			hide_repositories = srv_cfg->hide_repositories;

		if (hide_repositories != -1) {
			const char *val;

			val = srv->hide_repositories ? "on" : "off";
			ret = dprintf(fd, "\thide repositories %s\n", val);
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 19 + strlen(val) + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
		}

		if (srv) {
			struct gotsys_webrepo *webrepo;
			struct got_pathlist_entry *pe;
			int show_repo_description = 0;

			err = write_web_access_rules(fd, path, "\t",
			    &srv->access_rules);
			if (err)
				return err;

			/* TODO: css, logo, logo URL */

			if (srv->site_owner[0] != '\0') {
				ret = dprintf(fd, "\tsite_owner \"%s\"\n",
				    srv->site_owner);
				if (ret == -1) {
					return got_error_from_errno2("dprintf",
					    path);
				}
				if (ret != 14 + strlen(srv->site_owner) + 1) {
					return got_error_fmt(GOT_ERR_IO,
					    "short write to %s", path);
				}
			} else {
				ret = dprintf(fd, "\tshow_site_owner off\n");
				if (ret == -1)  {
					return got_error_from_errno2("dprintf",
					    path);
				}
				if (ret != 20 + 1) {
					return got_error_fmt(GOT_ERR_IO,
					    "short write to %s", path);
				}
			}

			if (srv->repos_url_path[0] != '\0') {
				ret = dprintf(fd, "\trepos_url_path \"%s\"\n",
				    srv->repos_url_path);
				if (ret == -1)  {
					return got_error_from_errno2("dprintf",
					    path);
				}
				if (ret != 18 +
				    strlen(srv->repos_url_path) + 1) {
					return got_error_fmt(GOT_ERR_IO,
					    "short write to %s", path);
				}
			}

			/* TODO mediatypes */

			err = hide_gotsys_repo(fd, path);
			if (err)
				return err;

			STAILQ_FOREACH(webrepo, &srv->repos, entry) {
				err = write_webrepo(&show_repo_description,
				    fd, path, webrepo, srv_cfg->auth_config);
				if (err)
					return err;
			}
			if (!show_repo_description) {
				ret = dprintf(fd,
				    "\tshow_repo_description off\n");
				if (ret == -1)  {
					return got_error_from_errno2("dprintf",
					    path);
				}
				if (ret != 26 + 1) {
					return got_error_fmt(GOT_ERR_IO,
					    "short write to %s", path);
				}
			}

			/*
			 * Repository age and owner currently need to be off
			 * to keep our regression tests passing: And these
			 * options cannot be controlled via gotsys.conf yet.
			 */
			ret = dprintf(fd, "\tshow_repo_age off\n");
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 18 + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}
			ret = dprintf(fd, "\tshow_repo_owner off\n");
			if (ret == -1) 
				return got_error_from_errno2("dprintf", path);
			if (ret != 20 + 1) {
				return got_error_fmt(GOT_ERR_IO,
				    "short write to %s", path);
			}

			RB_FOREACH(pe, got_pathlist_head, &srv->websites) {
				struct gotsys_website *site = pe->data;

				err = write_website(fd, path, site,
				    srv_cfg->auth_config);
				if (err)
					return err;
			}
		}

		ret = dprintf(fd, "}\n");
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 2) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (webcfg.prefork != 0 && webcfg.prefork <= PROC_MAX_INSTANCES) {
		char buf[8];

		ret = snprintf(buf, sizeof(buf), "%d", webcfg.prefork);
		if (ret == -1) 
			return got_error_from_errno2("snprintf", path);
		if ((size_t)ret >= sizeof(buf))
			return got_error(GOT_ERR_NO_SPACE);

		ret = dprintf(fd, "prefork %s\n", buf);
		if (ret == -1) 
			return got_error_from_errno2("dprintf", path);
		if (ret != 8 + strlen(buf) + 1) {
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    path);
		}
	}

	if (fchmod(gotwebd_conf_tmpfd, 0644) == -1) {
		return got_error_from_errno_fmt("chmod 0644 %s",
		    gotwebd_conf_tmppath);
	}
		
	if (rename(gotwebd_conf_tmppath, GOTWEBD_CONF) == -1) {
		return got_error_from_errno_fmt("rename %s to %s",
		    gotwebd_conf_tmppath, GOTWEBD_CONF);
	}


	free(gotwebd_conf_tmppath);
	gotwebd_conf_tmppath = NULL;

	return NULL;
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	size_t npaths;
	int shut = 0, auth_idx;
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
		if (imsgbuf_flush(ibuf) == -1) {
			warn("imsgbuf_flush");
			goto fatal;
		} else if (imsgbuf_queuelen(ibuf) == 0 && flush_and_exit) {
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GOTWEB_CFG) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_web_cfg(&webcfg, &imsg);
			if (err)
				break;
			writeconf_state = WRITECONF_STATE_EXPECT_GOTWEB_ADDRS;
			break;
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDR: {
			struct gotsysd_web_address *addr;
			const struct got_error *err;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GOTWEB_ADDRS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_webaddr(&addr, &imsg);
			if (err)
				break;
			TAILQ_INSERT_TAIL(&webcfg.listen_addrs, addr, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_ADDRS_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GOTWEB_ADDRS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_GOTWEB_SERVERS;
			break;
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVER: {
			const struct got_error *err;
			struct gotsysd_web_server *srv;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GOTWEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_gotweb_server(&srv, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&webcfg.servers, srv, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_SERVERS_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GOTWEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_GOTWEB_CFG_DONE:
			writeconf_state = WRITECONF_STATE_EXPECT_USERS;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS:
			if (writeconf_state != WRITECONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, &gotsysconf.users);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_GROUPS;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP: {
			struct gotsys_group *group;

			if (writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_group(&imsg, &group);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&gotsysconf.groups, group, entry);
			users_cur = &group->members;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS:
			if (users_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, users_cur);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS_DONE:
			if (users_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			users_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUPS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state =
			    WRITECONF_STATE_EXPECT_GLOBAL_ACCESS_RULES;
			break;
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GLOBAL_ACCESS_RULES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    NULL, NULL);
			if (err)
				break;
			rules = &global_repo_access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_ACCESS_RULES_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_GLOBAL_ACCESS_RULES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_REPOS;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO: {
			struct gotsys_repo *repo;

			if (writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_repository(&repo, &imsg);
			if (err)
				break;
			TAILQ_INSERT_TAIL(&gotsysconf.repos, repo, entry);
			repo_cur = repo;
			site_cur = NULL;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			rules = &repo_cur->access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_tag_namespaces;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_branch_namespaces;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_branches;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM:
			if (protected_refs_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    nprotected_refs_needed == 0 ||
			    nprotected_refs_received >=
			    nprotected_refs_needed) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			/* TODO: validate refname validity */
			err = gotsys_imsg_recv_pathlist_elem(&imsg,
			    protected_refs_cur);
			if (err)
				break;
			if (++nprotected_refs_received >=
			    nprotected_refs_needed) {
				protected_refs_cur = NULL;
				nprotected_refs_needed = 0;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE:
			if (repo_cur == NULL ||
			    nprotected_refs_needed != 0 ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS:
			if (repo_cur == NULL ||
			    notif_refs_cur != NULL ||
			    num_notif_refs_needed != 0 ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			notif_refs_cur = &repo_cur->notification_refs;
			num_notif_refs_cur = &repo_cur->num_notification_refs;
			num_notif_refs_needed = npaths;
			num_notif_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES:
			if (repo_cur == NULL ||
			    notif_refs_cur != NULL ||
			    num_notif_refs_needed != 0 ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			notif_refs_cur =
			    &repo_cur->notification_ref_namespaces;
			num_notif_refs_cur =
			    &repo_cur->num_notification_ref_namespaces;
			num_notif_refs_needed = npaths;
			num_notif_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_ELEM:
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_ELEM:
			if (notif_refs_cur == NULL ||
			    num_notif_refs_cur == NULL ||
			    num_notif_refs_needed == 0 ||
			    num_notif_refs_received >=
			    num_notif_refs_needed ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist_elem(&imsg,
			    notif_refs_cur);
			if (err)
				break;
			if (++num_notif_refs_received >=
			    num_notif_refs_needed) {
				notif_refs_cur = NULL;
				*num_notif_refs_cur = num_notif_refs_received;
				num_notif_refs_needed = 0;
				num_notif_refs_received = 0;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REFS_DONE:
			if (repo_cur == NULL ||
			    num_notif_refs_needed != 0 ||
			    notif_refs_cur != NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_REF_NAMESPACES_DONE:
			if (repo_cur == NULL ||
			    num_notif_refs_needed != 0 ||
			    notif_refs_cur != NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_EMAIL: {
			struct gotsys_notification_target *target;

			if (repo_cur == NULL ||
			    num_notif_refs_needed != 0 ||
			    notif_refs_cur != NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_notification_target_email(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&repo_cur->notification_targets,
			    target, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGET_HTTP: {
			struct gotsys_notification_target *target;

			if (repo_cur == NULL ||
			    num_notif_refs_needed != 0 ||
			    notif_refs_cur != NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_notification_target_http(NULL,
			    &target, &imsg);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&repo_cur->notification_targets,
			    target, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_NOTIFICATION_TARGETS_DONE:
			if (repo_cur == NULL ||
			    num_notif_refs_needed != 0 ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			num_notif_refs_needed = 0;
			notif_refs_cur = NULL;
 			break;
		case GOTSYSD_IMSG_SYSCONF_REPOS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			repo_cur = NULL;
			writeconf_state = WRITECONF_STATE_EXPECT_MEDIA_TYPES;
			break;
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPE: {
			struct media_type media;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_MEDIA_TYPES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_media_type(&media, &imsg);
			if (err)
				break;
			if (media_add(&gotsysconf.mediatypes, &media) == NULL)
				err = got_error_from_errno("media_add");
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_GLOBAL_MEDIA_TYPES_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_MEDIA_TYPES) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_WEB_SERVERS;
			break;

		case GOTSYSD_IMSG_SYSCONF_WEB_SERVER: {
			struct gotsys_webserver *srv;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = calloc(1, sizeof(*srv));
			if (srv == NULL) {
				err = got_error_from_errno("calloc");
				break;
			}
			err = gotsys_imsg_recv_web_server(srv, &imsg);
			if (err) {
				free(srv);
				break;
			}
			STAILQ_INSERT_TAIL(&gotsysconf.webservers, srv, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULE: {
			struct gotsys_webserver *srv;
			struct gotsys_access_rule *rule;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&srv->access_rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEB_ACCESS_RULES_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBREPO: {
			struct gotsys_webserver *srv;
			struct gotsys_webrepo *webrepo;
			struct gotsys_repo *repo;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			webrepo = calloc(1, sizeof(*webrepo));
			if (webrepo == NULL) {
				err = got_error_from_errno("calloc");
				break;
			}

			err = gotsys_imsg_recv_webrepo(webrepo, &imsg);
			if (err)
				break;

			repo = gotsys_find_repo_by_name(webrepo->repo_name,
			    &gotsysconf.repos);
			if (repo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "web repository refers to nonexistent "
				    "repository %s while in state %d\n",
				    webrepo->repo_name, writeconf_state);
				free(webrepo);
				break;
			}
			if (strcmp(repo->name, "gotsys") == 0 ||
			    strcmp(repo->name, "gotsys.git") == 0) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "gotsys repository cannot be used on "
				    "the web");
				free(webrepo);
				break;
			}

			STAILQ_INSERT_TAIL(&srv->repos, webrepo, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULE: {
			struct gotsys_webserver *srv;
			struct gotsys_webrepo *webrepo;
			struct gotsys_access_rule *rule;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			webrepo = STAILQ_LAST(&srv->repos, gotsys_webrepo,
			    entry);
			if (webrepo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&webrepo->access_rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBREPO_ACCESS_RULES_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBREPOS_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_PATH: {
			struct gotsys_webserver *srv;
			struct gotsys_website *site;
			struct got_pathlist_entry *new;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_website_path(&site, &imsg);
			if (err)
				break;
			err = got_pathlist_insert(&new, &srv->websites,
			    site->url_path, site);
			if (err)
				break;
			if (new == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "duplicate web site '%s' in "
				    "repository '%s'", site->url_path,
				    repo_cur->name);
				free(site);
				break;
			}
			site_cur = site;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE: {
			struct gotsys_repo *repo;

			if (site_cur == NULL ||
			    writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_website(site_cur, &imsg);
			if (err)
				break;

			repo = gotsys_find_repo_by_name(site_cur->repo_name,
			    &gotsysconf.repos);
			if (repo == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "web repository refers to nonexistent "
				    "repository %s while in state %d\n",
				    site_cur->repo_name,
				    writeconf_state);
				break;
			}
			if (strcmp(repo->name, "gotsys") == 0 ||
			    strcmp(repo->name, "gotsys.git") == 0) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "gotsys repository cannot be used for "
				    "web sites");
				break;
			}
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (site_cur == NULL ||
			    writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			rules = &site_cur->access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WEBSITE_ACCESS_RULES_DONE:
			if (site_cur == NULL ||
			    writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			site_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_WEBSITES_DONE:
			if (site_cur != NULL ||
			    writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPE: {
			struct gotsys_webserver *srv;
			struct media_type media;

			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			srv = STAILQ_LAST(&gotsysconf.webservers,
			    gotsys_webserver, entry);
			if (srv == NULL) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}

			err = gotsys_imsg_recv_media_type(&media, &imsg);
			if (err)
				break;
			if (media_add(&srv->mediatypes, &media) == NULL)
				err = got_error_from_errno("media_add");
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_MEDIA_TYPES_DONE:
			if (writeconf_state !=
			    WRITECONF_STATE_EXPECT_WEB_SERVERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_WEB_SERVERS_DONE:
			writeconf_state = WRITECONF_STATE_WRITE_CONF;
			if (!STAILQ_EMPTY(&webcfg.servers)) {
				err = write_gotwebd_conf();
				if (err)
					break;
			}
			auth_idx = 0;
			err = prepare_gotd_secrets(&auth_idx);
			if (err)
				break;
			auth_idx = 0;
			err = write_gotd_conf(&auth_idx);
			if (err)
				break;
			writeconf_state = WRITECONF_STATE_DONE;
			err = send_done(iev);
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			flush_and_exit = 1;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
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
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	STAILQ_INIT(&global_repo_access_rules);
	gotsys_conf_init(&gotsysconf);
	gotsysd_web_config_init(&webcfg);

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

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1) {
		warn("imsgbuf_init");
		return 1;
	}

	/* TODO: make gotd.conf path configurable -- pass via argv[1] */
	err = got_opentemp_named_fd(&gotd_conf_tmppath, &gotd_conf_tmpfd,
	    GOTD_CONF_PATH, "");
	if (err)
		goto done;
	err = got_opentemp_named_fd(&gotd_secrets_tmppath, &gotd_secrets_tmpfd,
	    GOTD_CONF_PATH, "");
	if (err)
		goto done;
	err = got_opentemp_named_fd(&gotwebd_conf_tmppath, &gotwebd_conf_tmpfd,
	    GOTWEBD_CONF, "");
	if (err)
		goto done;
#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr chown unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (unveil(gotd_conf_tmppath, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", gotd_conf_tmppath);
		goto done;
	}

	if (unveil(gotd_secrets_tmppath, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", gotd_secrets_tmppath);
		goto done;
	}

	if (unveil(gotwebd_conf_tmppath, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", gotwebd_conf_tmppath);
		goto done;
	}

	if (unveil(GOTD_CONF_PATH, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", GOTD_CONF_PATH);
		goto done;
	}

	if (unveil(GOTD_SECRETS_PATH, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", GOTD_SECRETS_PATH);
		goto done;
	}

	if (unveil(GOTWEBD_CONF, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", GOTWEBD_CONF);
		goto done;
	}

	if (unveil(NULL, NULL) == -1) {
		err = got_error_from_errno("unveil");
		goto done;
	}

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);
	if (gotsysd_imsg_compose_event(&iev, GOTSYSD_IMSG_PROG_READY, 0,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("gotsysd_imsg_compose_event");
		goto done;
	}

	event_dispatch();
done:
	gotsys_conf_clear(&gotsysconf);
	if (gotd_conf_tmppath && unlink(gotd_conf_tmppath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", gotd_conf_tmppath);
	free(gotd_conf_tmppath);
	if (gotd_secrets_tmppath && unlink(gotd_secrets_tmppath) == -1 &&
	    err == NULL)
		err = got_error_from_errno2("unlink", gotd_secrets_tmppath);
	free(gotd_secrets_tmppath);
	if (gotwebd_conf_tmppath && unlink(gotwebd_conf_tmppath) == -1 &&
	    err == NULL)
		err = got_error_from_errno2("unlink", gotwebd_conf_tmppath);
	free(gotwebd_conf_tmppath);
	if (gotd_conf_tmpfd != -1 && close(gotd_conf_tmpfd) == -1 &&
	    err == NULL)
		err = got_error_from_errno("close");
	if (gotd_secrets_tmpfd != -1 && close(gotd_secrets_tmpfd) == -1 &&
	    err == NULL)
		err = got_error_from_errno("close");
	if (gotwebd_conf_tmpfd != -1 && close(gotwebd_conf_tmpfd) == -1 &&
	    err == NULL)
		err = got_error_from_errno("close");
	if (err)
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL) {
		err = got_error_from_errno("close");
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	}
	imsgbuf_clear(&iev.ibuf);
	return err ? 1 : 0;
}
