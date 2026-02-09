/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "got_lib_gitproto.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static void
free_tokens(char **tokens, size_t ntokens)
{
	int i;

	for (i = 0; i < ntokens; i++) {
		free(tokens[i]);
		tokens[i] = NULL;
	}
}

static const struct got_error *
tokenize_line(char **tokens, char *line, int len, int mintokens, int maxtokens)
{
	const struct got_error *err = NULL;
	char *p;
	size_t i, n = 0;

	for (i = 0; i < maxtokens; i++)
		tokens[i] = NULL;

	for (i = 0; n < len && i < maxtokens; i++) {
		while (n < len && isspace((unsigned char)*line)) {
			line++;
			n++;
		}
		p = line;
		while (*line != '\0' && n < len &&
		    (!isspace((unsigned char)*line) || i == maxtokens - 1)) {
			line++;
			n++;
		}
		tokens[i] = strndup(p, line - p);
		if (tokens[i] == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		/* Skip \0 field-delimiter at end of token. */
		while (line[0] == '\0' && n < len) {
			line++;
			n++;
		}
	}
	if (i < mintokens)
		err = got_error_msg(GOT_ERR_BAD_PACKET,
		    "pkt-line contains too few tokens");
done:
	if (err)
		free_tokens(tokens, i);
	return err;
}

const struct got_error *
got_gitproto_parse_refline(char **id_str, char **refname,
    char **server_capabilities, char *line, int len)
{
	const struct got_error *err = NULL;
	char *tokens[3];

	*id_str = NULL;
	*refname = NULL;
	/* don't reset *server_capabilities */

	err = tokenize_line(tokens, line, len, 2, nitems(tokens));
	if (err)
		return err;

	if (tokens[0])
		*id_str = tokens[0];
	if (tokens[1])
		*refname = tokens[1];
	if (tokens[2]) {
		if (*server_capabilities == NULL) {
			char *p;
			*server_capabilities = tokens[2];
			p = strrchr(*server_capabilities, '\n');
			if (p)
				*p = '\0';
		} else
			free(tokens[2]);
	}

	return NULL;
}

const struct got_error *
got_gitproto_parse_want_line(char **id_str,
    char **capabilities, char *line, int len)
{
	const struct got_error *err = NULL;
	char *tokens[3];

	*id_str = NULL;
	/* don't reset *capabilities */

	err = tokenize_line(tokens, line, len, 2, nitems(tokens));
	if (err)
		return err;

	if (tokens[0] == NULL) {
		free_tokens(tokens, nitems(tokens));
		return got_error_msg(GOT_ERR_BAD_PACKET, "empty want-line");
	}

	if (strcmp(tokens[0], "want") != 0) {
		free_tokens(tokens, nitems(tokens));
		return got_error_msg(GOT_ERR_BAD_PACKET, "bad want-line");
	}

	free(tokens[0]);
	if (tokens[1])
		*id_str = tokens[1];
	if (tokens[2]) {
		if (*capabilities == NULL) {
			char *p;
			*capabilities = tokens[2];
			p = strrchr(*capabilities, '\n');
			if (p)
				*p = '\0';
		} else
			free(tokens[2]);
	}

	return NULL;
}

const struct got_error *
got_gitproto_parse_have_line(char **id_str, char *line, int len)
{
	const struct got_error *err = NULL;
	char *tokens[2];

	*id_str = NULL;

	err = tokenize_line(tokens, line, len, 2, nitems(tokens));
	if (err)
		return err;

	if (tokens[0] == NULL) {
		free_tokens(tokens, nitems(tokens));
		return got_error_msg(GOT_ERR_BAD_PACKET, "empty have-line");
	}

	if (strcmp(tokens[0], "have") != 0) {
		free_tokens(tokens, nitems(tokens));
		return got_error_msg(GOT_ERR_BAD_PACKET, "bad have-line");
	}

	free(tokens[0]);
	if (tokens[1])
		*id_str = tokens[1];

	return NULL;
}

const struct got_error *
got_gitproto_parse_ref_update_line(char **old_id_str, char **new_id_str,
    char **refname, char **capabilities, char *line, size_t len)
{
	const struct got_error *err = NULL;
	char *tokens[4];

	*old_id_str = NULL;
	*new_id_str = NULL;
	*refname = NULL;

	/* don't reset *capabilities */

	err = tokenize_line(tokens, line, len, 3, nitems(tokens));
	if (err)
		return err;

	if (tokens[0] == NULL || tokens[1] == NULL || tokens[2] == NULL) {
		free_tokens(tokens, nitems(tokens));
		return got_error_msg(GOT_ERR_BAD_PACKET, "empty ref-update");
	}

	*old_id_str = tokens[0];
	*new_id_str = tokens[1];
	*refname = tokens[2];
	if (tokens[3]) {
		if (*capabilities == NULL) {
			char *p;
			*capabilities = tokens[3];
			p = strrchr(*capabilities, '\n');
			if (p)
				*p = '\0';
		} else
			free(tokens[3]);
	}

	return NULL;
}

static const struct got_error *
match_capability(char **my_capabilities, const char *capa,
    const struct got_capability *mycapa, enum got_hash_algorithm *algo)
{
	char *equalsign;
	char *s;

	equalsign = strchr(capa, '=');
	if (equalsign) {
		if (strncmp(capa, mycapa->key, equalsign - capa) != 0)
			return NULL;

		if (strcmp(mycapa->key, GOT_CAPA_OBJECT_FORMAT) == 0) {
			/* require an exact match on object-format value */
			if (strcmp(equalsign + 1, mycapa->value) != 0)
				return NULL;

			if (strcmp(mycapa->value, GOT_CAPA_OBJECT_FORMAT_SHA256)
			    == 0)
				*algo = GOT_HASH_SHA256;
		}

	} else {
		if (strcmp(capa, mycapa->key) != 0)
			return NULL;
	}

	if (asprintf(&s, "%s %s%s%s",
	    *my_capabilities != NULL ? *my_capabilities : "",
	    mycapa->key,
	    mycapa->value != NULL ? "=" : "",
	    mycapa->value != NULL ? mycapa->value : "") == -1)
		return got_error_from_errno("asprintf");

	free(*my_capabilities);
	*my_capabilities = s;
	return NULL;
}

static const struct got_error *
add_symref(struct got_pathlist_head *symrefs, char *capa)
{
	const struct got_error *err = NULL;
	char *colon, *name = NULL, *target = NULL;
	struct got_pathlist_entry *new;

	/* Need at least "A:B" */
	if (strlen(capa) < 3)
		return NULL;

	colon = strchr(capa, ':');
	if (colon == NULL)
		return NULL;

	*colon = '\0';
	name = strdup(capa);
	if (name == NULL)
		return got_error_from_errno("strdup");

	target = strdup(colon + 1);
	if (target == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	/* We can't validate the ref itself here. The main process will. */
	err = got_pathlist_insert(&new, symrefs, name, target);
	if (err == NULL && new == NULL)
		err = got_error(GOT_ERR_REF_DUP_ENTRY);
done:
	if (err) {
		free(name);
		free(target);
	}
	return err;
}

const struct got_error *
got_gitproto_match_capabilities(char **common_capabilities,
    struct got_pathlist_head *symrefs, char *capabilities,
    const struct got_capability my_capabilities[], size_t ncapa,
    enum got_hash_algorithm *algo)
{
	const struct got_error *err = NULL;
	char *capa, *equalsign;
	size_t i;

	*common_capabilities = NULL;
	*algo = GOT_HASH_SHA1;
	do {
		capa = strsep(&capabilities, " ");
		if (capa == NULL)
			return NULL;

		equalsign = strchr(capa, '=');
		if (equalsign != NULL && symrefs != NULL &&
		    strncmp(capa, "symref", equalsign - capa) == 0) {
			err = add_symref(symrefs, equalsign + 1);
			if (err && err->code != GOT_ERR_REF_DUP_ENTRY)
				break;
			continue;
		}

		for (i = 0; i < ncapa; i++) {
			err = match_capability(common_capabilities,
			    capa, &my_capabilities[i], algo);
			if (err)
				break;
		}
	} while (capa);

	if (*common_capabilities == NULL) {
		*common_capabilities = strdup("");
		if (*common_capabilities == NULL)
			err = got_error_from_errno("strdup");
	}
	return err;
}

const struct got_error *
got_gitproto_append_capabilities(size_t *capalen, char *buf, size_t offset,
    size_t bufsize, const struct got_capability my_capabilities[], size_t ncapa)
{
	char *p = buf + offset;
	size_t i, len, remain = bufsize - offset;

	*capalen = 0;

	if (offset >= bufsize || remain < 1)
		return got_error(GOT_ERR_NO_SPACE);

	/* Capabilities are hidden behind a NUL byte. */
	*p = '\0';
	p++;
	remain--;
	*capalen += 1;

	for (i = 0; i < ncapa; i++) {
		len = strlcat(p, " ", remain);
		if (len >= remain)
			return got_error(GOT_ERR_NO_SPACE);
		remain -= len;
		*capalen += 1;

		len = strlcat(p, my_capabilities[i].key, remain);
		if (len >= remain)
			return got_error(GOT_ERR_NO_SPACE);
		remain -= len;
		*capalen += strlen(my_capabilities[i].key);

		if (my_capabilities[i].value == NULL)
			continue;

		len = strlcat(p, "=", remain);
		if (len >= remain)
			return got_error(GOT_ERR_NO_SPACE);
		remain -= len;
		*capalen += 1;

		len = strlcat(p, my_capabilities[i].value, remain);
		if (len >= remain)
			return got_error(GOT_ERR_NO_SPACE);
		remain -= len;
		*capalen += strlen(my_capabilities[i].value);
	}

	return NULL;
}

const struct got_error *
got_gitproto_split_capabilities_str(struct got_capability **capabilities,
    size_t *ncapabilities, char *capabilities_str)
{
	char *capastr, *capa;
	size_t i;

	*capabilities = NULL;
	*ncapabilities = 0;

	/* Compute number of capabilities on a copy of the input string. */
	capastr = strdup(capabilities_str);
	if (capastr == NULL)
		return got_error_from_errno("strdup");
	do {
		capa = strsep(&capastr, " ");
		if (capa && *capa != '\0')
			(*ncapabilities)++;
	} while (capa);
	free(capastr);

	*capabilities = calloc(*ncapabilities, sizeof(**capabilities));
	if (*capabilities == NULL)
		return got_error_from_errno("calloc");

	/* Modify input string in place, splitting it into key/value tuples. */
	i = 0;
	for (;;) {
		char *key = NULL, *value = NULL, *equalsign;

		capa = strsep(&capabilities_str, " ");
		if (capa == NULL)
			break;
		if (*capa == '\0')
			continue;

		if (i >= *ncapabilities) { /* should not happen */
			free(*capabilities);
			*capabilities = NULL;
			*ncapabilities = 0;
			return got_error(GOT_ERR_NO_SPACE);
		}

		key = capa;

		equalsign = strchr(capa, '=');
		if (equalsign != NULL) {
			*equalsign = '\0';
			value = equalsign + 1;
		}

		(*capabilities)[i].key = key;
		(*capabilities)[i].value = value;
		i++;
	}

	return NULL;
}
