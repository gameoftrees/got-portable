/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <zlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>

#include "got_compat.h"

#include "got_object.h"
#include "got_error.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_qid.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_parse.h"

#define GOT_OBJECT_IDSET_MIN_BUCKETS	64

#define GOT_OBJECT_IDSET_SLOT_EMPTY	GOT_NUM_HASH_ALGOS

struct got_object_idset_bucket {
	/* The first element hashed into this bucket is stored inline. */
	struct got_object_id id;
	void *data;

	/* List of further elements populated during hash collisions. */
	struct got_object_id_queue ids;
};

struct got_object_idset {
	struct got_object_idset_bucket *buckets;
	size_t nbuckets;
	unsigned int totelem;
	unsigned int flags;
#define GOT_OBJECT_IDSET_F_TRAVERSAL	0x01
#define GOT_OBJECT_IDSET_F_NOMEM	0x02
	SIPHASH_KEY key;
};

static void
init_hash_buckets(struct got_object_idset_bucket *buckets, int nbuckets)
{
	int i;

	for (i = 0; i < nbuckets; i++) {
		buckets[i].id.algo = GOT_OBJECT_IDSET_SLOT_EMPTY;
		STAILQ_INIT(&buckets[i].ids);
	}
}

struct got_object_idset *
got_object_idset_alloc(void)
{
	struct got_object_idset *set;

	set = malloc(sizeof(*set));
	if (set == NULL)
		return NULL;

	set->buckets = calloc(GOT_OBJECT_IDSET_MIN_BUCKETS,
	    sizeof(set->buckets[0]));
	if (set->buckets == NULL) {
		free(set);
		return NULL;
	} 

	init_hash_buckets(set->buckets, GOT_OBJECT_IDSET_MIN_BUCKETS);

	set->totelem = 0;
	set->nbuckets = GOT_OBJECT_IDSET_MIN_BUCKETS;
	set->flags = 0;
	arc4random_buf(&set->key, sizeof(set->key));
	return set;
}

void
got_object_idset_free(struct got_object_idset *set)
{
	size_t i;
	struct got_object_qid *qid;

	for (i = 0; i < set->nbuckets; i++) {
		while (!STAILQ_EMPTY(&set->buckets[i].ids)) {
			qid = STAILQ_FIRST(&set->buckets[i].ids);
			STAILQ_REMOVE(&set->buckets[i].ids, qid,
			    got_object_qid, entry);
			got_object_qid_free(qid);
		}
	}
	/* User data should be freed by caller. */
	free(set->buckets);
	free(set);
}

static uint64_t
idset_hash(SIPHASH_KEY *key, struct got_object_id *id)
{
	return SipHash24(key, id->hash, got_hash_digest_length(id->algo));
}

static uint64_t
idset_hash_hash(SIPHASH_KEY *key, enum got_hash_algorithm algo, uint8_t *hash)
{
	return SipHash24(key, hash, got_hash_digest_length(algo));
}

static const struct got_error *
idset_add(struct got_object_idset_bucket *bucket, struct got_object_id *id,
    void *data)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	/*
	 * The initial element added is stored in the array itself to
	 * to save some malloc/free calls.
	 j We overload id->algo as an 'empty slot' flag which works
	 * because valid IDs always use a valid hash algorithm.
	 */
	if (id->algo == GOT_OBJECT_IDSET_SLOT_EMPTY)
		return got_error_fmt(GOT_ERR_BAD_OBJ_ID, "%s", __func__);
	if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY) {
		memcpy(&bucket->id, id, sizeof(bucket->id));
		bucket->data = data;
		return NULL;
	}

	/*
	 * There is a hash collision. Append this element to the linked list
	 * instead of storing it inline, paying the cost of malloc/free.
	 */
	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;

	memcpy(&qid->id, id, sizeof(qid->id));
	qid->data = data;
	STAILQ_INSERT_HEAD(&bucket->ids, qid, entry);
	return NULL;
}

static const struct got_error *
idset_resize(struct got_object_idset *set, size_t nbuckets)
{
	const struct got_error *err = NULL;
	struct got_object_idset_bucket *buckets;
	SIPHASH_KEY key;
	size_t i;

	buckets = calloc(nbuckets, sizeof(buckets[0]));
	if (buckets == NULL) {
		if (errno != ENOMEM)
			return got_error_from_errno("calloc");
		/* Proceed with our current amount of hash buckets. */
		set->flags |= GOT_OBJECT_IDSET_F_NOMEM;
		return NULL;
	}

	init_hash_buckets(buckets, nbuckets);

	arc4random_buf(&key, sizeof(key));

	for (i = 0; i < set->nbuckets; i++) {
		uint64_t idx;
	
		if (set->buckets[i].id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)
			continue;

		/*
		 * Copy collisions into the new table first since this
		 * might free up some memory. The new larger hash table
		 * should be able to store more elements inline.
		 */
		while (!STAILQ_EMPTY(&set->buckets[i].ids)) {
			struct got_object_qid *qid;

			qid = STAILQ_FIRST(&set->buckets[i].ids);
			STAILQ_REMOVE(&set->buckets[i].ids, qid,
			    got_object_qid, entry);
			idx = idset_hash(&key, &qid->id) % nbuckets;

			if (buckets[idx].id.algo ==
			    GOT_OBJECT_IDSET_SLOT_EMPTY) {
				memcpy(&buckets[idx].id, &qid->id,
				    sizeof(buckets[idx].id));
				buckets[idx].data = qid->data;
				got_object_qid_free(qid);
			} else {
				STAILQ_INSERT_HEAD(&buckets[idx].ids, qid,
				    entry);
			}
		}

		/*
		 * Now add the inline element. We will have to allocate memory
		 * if there is a hash collision. We don't try to cope with
		 * allocation failure here because our previous hash table
		 * has already been partly destroyed and trying to rebuild
		 * it would likely also fail.
		 */
		idx = idset_hash(&key, &set->buckets[i].id) % nbuckets;
		err = idset_add(&buckets[idx], &set->buckets[i].id,
		    set->buckets[i].data);
		if (err)
			return err;

	}

	free(set->buckets);
	set->buckets = buckets;
	set->nbuckets = nbuckets;
	memcpy(&set->key, &key, sizeof(set->key));
	return NULL;
}

static const struct got_error *
idset_grow(struct got_object_idset *set)
{
	size_t nbuckets;

	if ((set->flags & GOT_OBJECT_IDSET_F_NOMEM) ||
	    set->nbuckets == UINT_MAX)
		return NULL;

	if (set->nbuckets >= UINT_MAX / 2)
		nbuckets = UINT_MAX;
	else
		nbuckets = set->nbuckets * 2;

	return idset_resize(set, nbuckets);
}

const struct got_error *
got_object_idset_add(struct got_object_idset *set, struct got_object_id *id,
    void *data)
{
	const struct got_error *err;
	uint64_t idx;
	struct got_object_idset_bucket *bucket;

	/* This function may resize the set. */
	if (set->flags & GOT_OBJECT_IDSET_F_TRAVERSAL)
		return got_error_msg(GOT_ERR_NOT_IMPL,
		    "cannot add elements to idset during traversal");

	if (set->totelem == UINT_MAX)
		return got_error(GOT_ERR_NO_SPACE);

	idx = idset_hash(&set->key, id) % set->nbuckets;
	bucket = &set->buckets[idx];
	err = idset_add(bucket, id, data);
	if (err)
		return err;
	set->totelem++;

	if (((uint64_t)set->nbuckets) * 3 < ((uint64_t)set->totelem) * 4)
		err = idset_grow(set);

	return err;
}

static void
find_element(struct got_object_id **id_found, void **data_found,
    struct got_object_idset *set, struct got_object_id *id)
{
	uint64_t idx = idset_hash(&set->key, id) % set->nbuckets;
	struct got_object_idset_bucket *bucket = &set->buckets[idx];
	struct got_object_qid *qid;

	*id_found = NULL;
	*data_found = NULL;

	if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)
		return;

	if (got_object_id_cmp(&bucket->id, id) == 0) {
		*id_found = id;
		*data_found = bucket->data;
		return;
	}

	STAILQ_FOREACH(qid, &bucket->ids, entry) {
		if (got_object_id_cmp(&qid->id, id) == 0) {
			*id_found = id;
			*data_found = qid->data;
			return;
		}
	}
}

void *
got_object_idset_get(struct got_object_idset *set, struct got_object_id *id)
{
	struct got_object_id *id_found;
	void *data_found;

	find_element(&id_found, &data_found, set, id);
	return id_found ? data_found : NULL;
}

const struct got_error *
got_object_idset_remove(void **data, struct got_object_idset *set,
    struct got_object_id *id)
{
	uint64_t idx;
	struct got_object_idset_bucket *bucket;
	struct got_object_qid *qid = NULL;

	if (data)
		*data = NULL;

	if (set->totelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	if (id == NULL) {
		/* Remove a "random" element. */
		for (idx = 0; idx < set->nbuckets; idx++) {
			bucket = &set->buckets[idx];
			if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)	
				continue;

			if (STAILQ_EMPTY(&bucket->ids)) {
				if (data)
					*data = bucket->data;
				bucket->data = NULL;
				memset(&bucket->id, 0, sizeof(bucket->id));
				bucket->id.algo = GOT_OBJECT_IDSET_SLOT_EMPTY;
				break;
			} else {
				qid = STAILQ_FIRST(&bucket->ids);
				STAILQ_REMOVE(&bucket->ids, qid,
				    got_object_qid, entry);
				if (data)
					*data = qid->data;
				got_object_qid_free(qid);
				break;
			}
		}
	} else {
		idx = idset_hash(&set->key, id) % set->nbuckets;
		bucket = &set->buckets[idx];
		if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)	
			return got_error_no_obj(id);

		if (got_object_id_cmp(&bucket->id, id) == 0) {
			if (data)
				*data = bucket->data;
			if (STAILQ_EMPTY(&bucket->ids)) {
				bucket->data = NULL;
				memset(&bucket->id, 0, sizeof(bucket->id));
				bucket->id.algo = GOT_OBJECT_IDSET_SLOT_EMPTY;
			} else {
				qid = STAILQ_FIRST(&bucket->ids);
				STAILQ_REMOVE(&bucket->ids, qid,
				    got_object_qid, entry);
				memcpy(&bucket->id, &qid->id,
				    sizeof(bucket->id));
				bucket->data = qid->data;
				got_object_qid_free(qid);
			}
		} else {
			STAILQ_FOREACH(qid, &bucket->ids, entry) {
				if (got_object_id_cmp(&qid->id, id) == 0)
					break;
			}
			if (qid == NULL)
				return got_error_no_obj(id);

			STAILQ_REMOVE(&bucket->ids, qid, got_object_qid, entry);
			if (data)
				*data = qid->data;
			got_object_qid_free(qid);
		}
	}

	set->totelem--;

	return NULL;
}

int
got_object_idset_contains(struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_id *id_found;
	void *data_found;

	find_element(&id_found, &data_found, set, id);
	return id_found ? 1 : 0;
}

static void
find_element_hash(struct got_object_id **id_found, void **data_found,
    struct got_object_idset *set, enum got_hash_algorithm algo,
    uint8_t *hash)
{
	uint64_t idx = idset_hash_hash(&set->key, algo, hash) % set->nbuckets;
	struct got_object_idset_bucket *bucket = &set->buckets[idx];
	struct got_object_qid *qid;

	*id_found = NULL;
	*data_found = NULL;

	if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)
		return;

	if (got_hash_cmp(algo, bucket->id.hash, hash) == 0) {
		*id_found = &bucket->id;
		*data_found = bucket->data;
		return;
	}

	STAILQ_FOREACH(qid, &bucket->ids, entry) {
		if (got_hash_cmp(algo, qid->id.hash, hash) == 0) {
			*id_found = &qid->id;
			*data_found = qid->data;
			return;
		}
	}
}

int
got_object_idset_contains_hash(struct got_object_idset *set,
    enum got_hash_algorithm algo, uint8_t *hash)
{
	struct got_object_id *id_found;
	void *data_found;

	find_element_hash(&id_found, &data_found, set, algo, hash);
	return id_found ? 1 : 0;
}

const struct got_error *
got_object_idset_for_each(struct got_object_idset *set,
    const struct got_error *(*cb)(struct got_object_id *, void *, void *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_object_idset_bucket *bucket;
	struct got_object_qid *qid, *tmp;
	size_t i;

	set->flags |= GOT_OBJECT_IDSET_F_TRAVERSAL;
	for (i = 0; i < set->nbuckets; i++) {
		bucket = &set->buckets[i];
	
		if (bucket->id.algo == GOT_OBJECT_IDSET_SLOT_EMPTY)
			continue;

		err = (*cb)(&bucket->id, bucket->data, arg);
		if (err)
			break;

		STAILQ_FOREACH_SAFE(qid, &bucket->ids, entry, tmp) {
			err = (*cb)(&qid->id, qid->data, arg);
			if (err)
				goto done;
		}
	}
done:
	set->flags &= ~GOT_OBJECT_IDSET_F_TRAVERSAL;
	return err;
}

int
got_object_idset_num_elements(struct got_object_idset *set)
{
	return set->totelem;
}
