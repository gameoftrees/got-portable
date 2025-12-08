/*
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

#define MEDIATYPE_NAMEMAX	128	/* file name extension */
#define MEDIATYPE_TYPEMAX	64	/* length of type/subtype */
#define MEDIA_STRMAX		(MEDIATYPE_NAMEMAX + 1 + MEDIATYPE_TYPEMAX)

struct media_type {
	char			 media_name[MEDIATYPE_NAMEMAX];
	char			 media_type[MEDIATYPE_TYPEMAX];
	char			 media_subtype[MEDIATYPE_TYPEMAX];
	RB_ENTRY(media_type)	 media_entry;
};
RB_HEAD(mediatypes, media_type);

struct media_type	*media_add(struct mediatypes *, struct media_type *);
void			 media_delete(struct mediatypes *, struct media_type *);
void			 media_purge(struct mediatypes *);
struct media_type	*media_find(struct mediatypes *, const char *);

RB_PROTOTYPE(mediatypes, media_type, media_entry, media_cmp);
