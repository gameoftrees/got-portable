/*
 * Copyright (c) 2025 Omar Polo <op@openbsd.org>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/tree.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "media.h"

struct media_type *
media_add(struct mediatypes *types, struct media_type *media)
{
	struct media_type	*entry;

	if ((entry = RB_FIND(mediatypes, types, media)) != NULL)
		media_delete(types, entry);

	if ((entry = malloc(sizeof(*media))) == NULL)
		return (NULL);

	memcpy(entry, media, sizeof(*entry));
	RB_INSERT(mediatypes, types, entry);

	return (entry);
}

void
media_delete(struct mediatypes *types, struct media_type *media)
{
	RB_REMOVE(mediatypes, types, media);

	free(media);
}

void
media_purge(struct mediatypes *types)
{
	struct media_type	*media;

	while ((media = RB_MIN(mediatypes, types)) != NULL)
		media_delete(types, media);
}

struct media_type *
media_find(struct mediatypes *types, const char *file)
{
	struct media_type	*match, media;
	char			*p;

	/* Last component of the file name */
	p = strchr(file, '\0');
	while (p > file && p[-1] != '.' && p[-1] != '/')
		p--;
	if (*p == '\0')
		return (NULL);

	if (strlcpy(media.media_name, p,
	    sizeof(media.media_name)) >=
	    sizeof(media.media_name)) {
		return (NULL);
	}

	/* Find media type by extension name */
	match = RB_FIND(mediatypes, types, &media);

	return (match);
}

static int
media_cmp(struct media_type *a, struct media_type *b)
{
	return (strcasecmp(a->media_name, b->media_name));
}

RB_GENERATE(mediatypes, media_type, media_entry, media_cmp);
