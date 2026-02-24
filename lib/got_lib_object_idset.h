/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2019 Ori Bernstein <stsp@openbsd.org>
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

struct got_object_idset;

struct got_object_idset *got_object_idset_alloc(void);
void got_object_idset_free(struct got_object_idset *);

const struct got_error *got_object_idset_add(struct got_object_idset *,
    struct got_object_id *, void *);
void *got_object_idset_get(struct got_object_idset *, struct got_object_id *);
const struct got_error *got_object_idset_remove(void **,
    struct got_object_idset *, struct got_object_id *);
int got_object_idset_contains(struct got_object_idset *,
    struct got_object_id *);
int got_object_idset_contains_hash(struct got_object_idset *,
    enum got_hash_algorithm, uint8_t *);
const struct got_error *got_object_idset_for_each(struct got_object_idset *,
    const struct got_error *(*cb)(struct got_object_id *, void *, void *),
    void *);
int got_object_idset_num_elements(struct got_object_idset *);
