/*
 * Copyright (c) 2026 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <zlib.h>
#include <imsg.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

void
got_repo_free_remote_repo_data(struct got_remote_repo *repo)
{
	int i;

	if (repo == NULL)
		return;

	free(repo->name);
	repo->name = NULL;
	free(repo->fetch_url);
	repo->fetch_url = NULL;
	free(repo->send_url);
	repo->send_url = NULL;
	for (i = 0; i < repo->nfetch_branches; i++)
		free(repo->fetch_branches[i]);
	free(repo->fetch_branches);
	repo->fetch_branches = NULL;
	repo->nfetch_branches = 0;
	for (i = 0; i < repo->nsend_branches; i++)
		free(repo->send_branches[i]);
	free(repo->send_branches);
	repo->send_branches = NULL;
	repo->nsend_branches = 0;
	for (i = 0; i < repo->nfetch_refs; i++)
		free(repo->fetch_refs[i]);
	free(repo->fetch_refs);
	repo->fetch_refs = NULL;
	repo->nfetch_refs = 0;
}

void
got_repo_free_gitconfig(struct got_repository *repo)
{
	size_t i;

	free(repo->gitconfig_author_name);
	free(repo->gitconfig_author_email);
	for (i = 0; i < repo->ngitconfig_remotes; i++)
		got_repo_free_remote_repo_data(&repo->gitconfig_remotes[i]);
	free(repo->gitconfig_remotes);
	for (i = 0; i < repo->nextensions; i++) {
		free(repo->extnames[i]);
		free(repo->extvals[i]);
	}
	free(repo->extnames);
	free(repo->extvals);
}

