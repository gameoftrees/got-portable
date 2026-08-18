/*
 * Copyright (c) 2022 Omar Polo <op@openbsd.org>
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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tmpl.h"

int
tp_write(struct template *tp, const char *str, size_t len)
{
	size_t	 avail;

	while (len > 0) {
		avail = tp->tp_cap - tp->tp_len;
		if (avail == 0) {
			if (template_flush(tp) == -1)
				return (-1);
			avail = tp->tp_cap;
		}

		if (len < avail)
			avail = len;

		memcpy(tp->tp_buf + tp->tp_len, str, avail);
		tp->tp_len += avail;
		str += avail;
		len -= avail;
	}

	return (0);
}

int
tp_writes(struct template *tp, const char *str)
{
	return (tp_write(tp, str, strlen(str)));
}

int
tp_writef(struct template *tp, const char *fmt, ...)
{
	va_list	 ap;
	char	*str;
	int	 r;

	va_start(ap, fmt);
	r = vasprintf(&str, fmt, ap);
	va_end(ap);
	if (r == -1)
		return (-1);
	r = tp_write(tp, str, r);
	free(str);
	return (r);
}

int
tp_urlescape(struct template *tp, const char *str)
{
	int	 r;
	char	 tmp[4];

	if (str == NULL)
		return (0);

	for (; *str; ++str) {
		if (iscntrl((unsigned char)*str) ||
		    isspace((unsigned char)*str) ||
		    *str == '\'' || *str == '"' || *str == '\\') {
			r = snprintf(tmp, sizeof(tmp), "%%%02X", *str);
			if (r < 0  || (size_t)r >= sizeof(tmp))
				return (0);
			if (tp_write(tp, tmp, r) == -1)
				return (-1);
		} else {
			if (tp_write(tp, str, 1) == -1)
				return (-1);
		}
	}

	return (0);
}

static inline int
htmlescape(struct template *tp, char c)
{
	switch (c) {
	case '<':
		return tp_write(tp, "&lt;", 4);
	case '>':
		return tp_write(tp, "&gt;", 4);
	case '&':
		return tp_write(tp, "&amp;", 5);
	case '"':
		return tp_write(tp, "&quot;", 6);
	case '\'':
		return tp_write(tp, "&apos;", 6);
	default:
		return tp_write(tp, &c, 1);
	}
}

int
tp_htmlescape(struct template *tp, const char *str)
{
	if (str == NULL)
		return (0);

	for (; *str; ++str) {
		if (htmlescape(tp, *str) == -1)
			return (-1);
	}

	return (0);
}

int
tp_write_htmlescape(struct template *tp, const char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		if (htmlescape(tp, str[i]) == -1)
			return (-1);
	}

	return (0);
}

struct template *
template(void *arg, tmpl_write writefn, char *buf, size_t siz)
{
	struct template *tp;

	if ((tp = calloc(1, sizeof(*tp))) == NULL)
		return (NULL);

	tp->tp_arg = arg;
	tp->tp_write = writefn;
	tp->tp_buf = buf;
	tp->tp_cap = siz;

	return (tp);
}

int
template_flush(struct template *tp)
{
	if (tp->tp_len == 0)
		return (0);

	if (tp->tp_write(tp->tp_arg, tp->tp_buf, tp->tp_len) == -1)
		return (-1);
	tp->tp_len = 0;
	return (0);
}

void
template_free(struct template *tp)
{
	free(tp->tp_tmp);
	free(tp);
}
