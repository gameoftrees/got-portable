/*
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

#include "got_compat.h"

#include <sys/queue.h>
#include <sys/types.h>

#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "got_version.h"
#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_cancel.h"
#include "got_repository.h"
#include "got_repository_admin.h"
#include "got_repository_dump.h"
#include "got_repository_load.h"
#include "got_gotconfig.h"
#include "got_path.h"
#include "got_privsep.h"
#include "got_opentemp.h"
#include "got_worktree.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigpipe_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigpipe(int signo)
{
	sigpipe_received = 1;
}

static const struct got_error *
check_cancelled(void *arg)
{
	if (sigint_received || sigpipe_received)
		return got_error(GOT_ERR_CANCELLED);
	return NULL;
}

struct gotadmin_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(int);
	const char	*cmd_alias;
};

__dead static void	usage(int, int);
__dead static void	usage_init(int);
__dead static void	usage_info(int);
__dead static void	usage_pack(int);
__dead static void	usage_indexpack(int);
__dead static void	usage_listpack(int);
__dead static void	usage_cleanup(int);
__dead static void	usage_dump(int);
__dead static void	usage_load(int);

static const struct got_error*		cmd_init(int, char *[]);
static const struct got_error*		cmd_info(int, char *[]);
static const struct got_error*		cmd_pack(int, char *[]);
static const struct got_error*		cmd_indexpack(int, char *[]);
static const struct got_error*		cmd_listpack(int, char *[]);
static const struct got_error*		cmd_cleanup(int, char *[]);
static const struct got_error*		cmd_dump(int, char *[]);
static const struct got_error*		cmd_load(int, char *[]);

static const struct gotadmin_cmd gotadmin_commands[] = {
	{ "init",	cmd_init,	usage_init,	"" },
	{ "info",	cmd_info,	usage_info,	"" },
	{ "pack",	cmd_pack,	usage_pack,	"" },
	{ "indexpack",	cmd_indexpack,	usage_indexpack,"ix" },
	{ "listpack",	cmd_listpack,	usage_listpack,	"ls" },
	{ "cleanup",	cmd_cleanup,	usage_cleanup,	"cl" },
	{ "dump",	cmd_dump,	usage_dump,	"" },
	{ "load",	cmd_load,	usage_load,	"" },
};

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotadmin_commands); i++) {
		const struct gotadmin_cmd *cmd = &gotadmin_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

int
main(int argc, char *argv[])
{
	const struct gotadmin_cmd *cmd;
	size_t i;
	int ch;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};

	setlocale(LC_CTYPE, "");

	while ((ch = getopt_long(argc, argv, "+hV", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
			break;
		case 'V':
			Vflag = 1;
			break;
		default:
			usage(hflag, 1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	optind = 1;
	optreset = 1;

	if (Vflag) {
		got_version_print_str();
		return 0;
	}

	if (argc <= 0)
		usage(hflag, hflag ? 0 : 1);

	signal(SIGINT, catch_sigint);
	signal(SIGPIPE, catch_sigpipe);

	for (i = 0; i < nitems(gotadmin_commands); i++) {
		const struct got_error *error;

		cmd = &gotadmin_commands[i];

		if (strcmp(cmd->cmd_name, argv[0]) != 0 &&
		    strcmp(cmd->cmd_alias, argv[0]) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage(0);

		error = cmd->cmd_main(argc, argv);
		if (error && error->code != GOT_ERR_CANCELLED &&
		    error->code != GOT_ERR_PRIVSEP_EXIT &&
		    !(sigpipe_received &&
		      error->code == GOT_ERR_ERRNO && errno == EPIPE) &&
		    !(sigint_received &&
		      error->code == GOT_ERR_ERRNO && errno == EINTR)) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-hV] command [arg ...]\n",
	    getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

static const struct got_error *
apply_unveil(const char *repo_path, int repo_read_only)
{
	const struct got_error *err;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, repo_read_only ? "r" : "rwc") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

	err = got_privsep_unveil_exec_helpers();
	if (err != NULL)
		return err;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

__dead static void
usage_info(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s info [-r repository-path]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
get_repo_path(char **repo_path)
{
	const struct got_error *err = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd;

	*repo_path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno("getcwd");

	err = got_worktree_open(&worktree, cwd, NULL);
	if (err) {
		if (err->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		err = NULL;
	}

	if (worktree)
		*repo_path = strdup(got_worktree_get_repo_path(worktree));
	else
		*repo_path = strdup(cwd);
	if (*repo_path == NULL)
		err = got_error_from_errno("strdup");
done:
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	return err;
}

__dead static void
usage_init(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s init [-A hashing-algorithm] [-b branch]"
	    " repository-path\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
cmd_init(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	const char *head_name = NULL;
	char *repo_path = NULL;
	enum got_hash_algorithm algo = GOT_HASH_SHA1;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "A:b:")) != -1) {
		switch (ch) {
		case 'A':
			if (!strcmp(optarg, "sha1"))
				algo = GOT_HASH_SHA1;
			else if (!strcmp(optarg, "sha256"))
				algo = GOT_HASH_SHA256;
			else
				return got_error_path(optarg,
				    GOT_ERR_OBJECT_FORMAT);
			break;
		case 'b':
			head_name = optarg;
			break;
		default:
			usage_init(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_init(1);

	repo_path = strdup(argv[0]);
	if (repo_path == NULL)
		return got_error_from_errno("strdup");

	got_path_strip_trailing_slashes(repo_path);

	error = got_path_mkdir(repo_path);
	if (error &&
	    !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
		goto done;

	error = apply_unveil(repo_path, 0);
	if (error)
		goto done;

	error = got_repo_init(repo_path, head_name, algo);
done:
	free(repo_path);
	return error;
}

static const struct got_error *
cmd_info(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *repo_path = NULL;
	struct got_repository *repo = NULL;
	const struct got_gotconfig *gotconfig = NULL;
	int ch, npackfiles, npackedobj, nobj;
	off_t packsize, loose_size;
	char scaled[FMT_SCALED_STRSIZE];
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "r:")) != -1) {
		switch (ch) {
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_info(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (repo_path == NULL) {
		error = get_repo_path(&repo_path);
		if (error)
			goto done;
	}
	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;
#ifndef PROFILE
	/* Remove "cpath" promise. */
	if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	error = apply_unveil(got_repo_get_path_git_dir(repo), 1);
	if (error)
		goto done;

	printf("repository: %s\n", got_repo_get_path_git_dir(repo));
	printf("hashing algorithm: %s\n",
	    got_repo_get_object_format(repo) == GOT_HASH_SHA1 ? "sha1"
	    : "sha256");

	gotconfig = got_repo_get_gotconfig(repo);
	if (gotconfig) {
		const struct got_remote_repo *remotes;
		int i, nremotes;
		if (got_gotconfig_get_author(gotconfig)) {
			printf("default author: %s\n",
			    got_gotconfig_get_author(gotconfig));
		}
		got_gotconfig_get_remotes(&nremotes, &remotes, gotconfig);
		for (i = 0; i < nremotes; i++) {
			const char *fetch_url = remotes[i].fetch_url;
			const char *send_url = remotes[i].send_url;
			if (strcmp(fetch_url, send_url) == 0) {
				printf("remote \"%s\": %s\n", remotes[i].name,
				    remotes[i].fetch_url);
			} else {
				printf("remote \"%s\" (fetch): %s\n",
				    remotes[i].name, remotes[i].fetch_url);
				printf("remote \"%s\" (send): %s\n",
				    remotes[i].name, remotes[i].send_url);
			}
		}
	}

	error = got_repo_get_packfile_info(&npackfiles, &npackedobj,
	    &packsize, repo);
	if (error)
		goto done;
	printf("pack files: %d\n", npackfiles);
	if (npackfiles > 0) {
		if (fmt_scaled(packsize, scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		printf("packed objects: %d\n", npackedobj);
		printf("packed total size: %s\n", scaled);
	}

	error = got_repo_get_loose_object_info(&nobj, &loose_size, repo);
	if (error)
		goto done;
	printf("loose objects: %d\n", nobj);
	if (nobj > 0) {
		if (fmt_scaled(loose_size, scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		printf("loose total size: %s\n", scaled);
	}
done:
	if (repo)
		got_repo_close(repo);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}

	free(repo_path);
	return error;
}

__dead static void
usage_pack(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s pack [-aDq] [-r repository-path] "
	    "[-x reference] [reference ...]\n", getprogname());
	exit(status);
}

struct got_pack_progress_arg {
	FILE *out;
	char last_scaled_size[FMT_SCALED_STRSIZE];
	int last_ncolored;
	int last_nfound;
	int last_ntrees;
	int loading_done;
	int last_ncommits;
	int last_nobj_total;
	int last_p_deltify;
	int last_p_written;
	int last_p_indexed;
	int last_p_resolved;
	int verbosity;
	int printed_something;
};

static void
print_load_info(FILE *out, int print_colored, int print_found, int print_trees,
    int ncolored, int nfound, int ntrees)
{
	if (print_colored) {
		fprintf(out, "%d commit%s colored", ncolored,
		    ncolored == 1 ? "" : "s");
	}
	if (print_found) {
		fprintf(out, "%s%d object%s found",
		    ncolored > 0 ? "; " : "",
		    nfound, nfound == 1 ? "" : "s");
	}
	if (print_trees) {
		fprintf(out, "; %d tree%s scanned", ntrees,
		    ntrees == 1 ? "" : "s");
	}
}

static const struct got_error *
pack_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written, int pack_done)
{
	struct got_pack_progress_arg *a = arg;
	char scaled_size[FMT_SCALED_STRSIZE];
	int p_deltify, p_written;
	int print_colored = 0, print_found = 0, print_trees = 0;
	int print_searching = 0, print_total = 0;
	int print_deltify = 0, print_written = 0;

	if (a->verbosity < 0)
		return NULL;

	if (a->last_ncolored != ncolored) {
		print_colored = 1;
		a->last_ncolored = ncolored;
	}

	if (a->last_nfound != nfound) {
		print_colored = 1;
		print_found = 1;
		a->last_nfound = nfound;
	}

	if (a->last_ntrees != ntrees) {
		print_colored = 1;
		print_found = 1;
		print_trees = 1;
		a->last_ntrees = ntrees;
	}

	if ((print_colored || print_found || print_trees) &&
	    !a->loading_done) {
		fprintf(a->out, "\r");
		print_load_info(a->out, print_colored, print_found,
		    print_trees, ncolored, nfound, ntrees);
		a->printed_something = 1;
		fflush(a->out);
		return NULL;
	} else if (!a->loading_done) {
		fprintf(a->out, "\r");
		print_load_info(a->out, 1, 1, 1, ncolored, nfound, ntrees);
		fprintf(a->out, "\n");
		a->loading_done = 1;
	}

	if (fmt_scaled(packfile_size, scaled_size) == -1)
		return got_error_from_errno("fmt_scaled");

	if (a->last_ncommits != ncommits) {
		print_searching = 1;
		a->last_ncommits = ncommits;
	}

	if (a->last_nobj_total != nobj_total) {
		print_searching = 1;
		print_total = 1;
		a->last_nobj_total = nobj_total;
	}

	if (packfile_size > 0 && (a->last_scaled_size[0] == '\0' ||
	    strcmp(scaled_size, a->last_scaled_size)) != 0) {
		if (strlcpy(a->last_scaled_size, scaled_size,
		    FMT_SCALED_STRSIZE) >= FMT_SCALED_STRSIZE)
			return got_error(GOT_ERR_NO_SPACE);
	}

	if (nobj_deltify > 0 || nobj_written > 0) {
		if (nobj_deltify > 0) {
			p_deltify = (nobj_deltify * 100) / nobj_total;
			if (p_deltify != a->last_p_deltify) {
				a->last_p_deltify = p_deltify;
				print_searching = 1;
				print_total = 1;
				print_deltify = 1;
			}
		}
		if (nobj_written > 0) {
			p_written = (nobj_written * 100) / nobj_total;
			if (p_written != a->last_p_written) {
				a->last_p_written = p_written;
				print_searching = 1;
				print_total = 1;
				print_deltify = 1;
				print_written = 1;
			}
		}
	}

	if (print_searching || print_total || print_deltify || print_written)
		fprintf(a->out, "\r");
	if (print_searching)
		fprintf(a->out, "packing %d reference%s", ncommits,
		    ncommits == 1 ? "" : "s");
	if (print_total)
		fprintf(a->out, "; %d object%s", nobj_total,
		    nobj_total == 1 ? "" : "s");
	if (print_deltify)
		fprintf(a->out, "; deltify: %d%%", p_deltify);
	if (print_written)
		fprintf(a->out, "; writing pack: %*s %d%%",
		    FMT_SCALED_STRSIZE - 2, scaled_size, p_written);
	if (print_searching || print_total || print_deltify || print_written) {
		a->printed_something = 1;
		fflush(a->out);
	}
	if (pack_done)
		fprintf(a->out, "\n");
	return NULL;
}

static const struct got_error *
pack_index_progress(void *arg, off_t packfile_size, int nobj_total,
    int nobj_indexed, int nobj_loose, int nobj_resolved, int indexing_done)
{
	struct got_pack_progress_arg *a = arg;
	char scaled_size[FMT_SCALED_STRSIZE];
	int p_indexed, p_resolved;
	int print_size = 0, print_indexed = 0, print_resolved = 0;

	if (a->verbosity < 0)
		return NULL;

	if (packfile_size > 0 || nobj_indexed > 0) {
		if (fmt_scaled(packfile_size, scaled_size) == 0 &&
		    (a->last_scaled_size[0] == '\0' ||
		    strcmp(scaled_size, a->last_scaled_size)) != 0) {
			print_size = 1;
			if (strlcpy(a->last_scaled_size, scaled_size,
			    FMT_SCALED_STRSIZE) >= FMT_SCALED_STRSIZE)
				return got_error(GOT_ERR_NO_SPACE);
		}
		if (nobj_indexed > 0) {
			p_indexed = (nobj_indexed * 100) / nobj_total;
			if (p_indexed != a->last_p_indexed) {
				a->last_p_indexed = p_indexed;
				print_indexed = 1;
				print_size = 1;
			}
		}
		if (nobj_resolved > 0) {
			p_resolved = (nobj_resolved * 100) /
			    (nobj_total - nobj_loose);
			if (p_resolved != a->last_p_resolved) {
				a->last_p_resolved = p_resolved;
				print_resolved = 1;
				print_indexed = 1;
				print_size = 1;
			}
		}

	}
	if (print_size || print_indexed || print_resolved)
		printf("\r");
	if (print_size)
		printf("%*s packed", FMT_SCALED_STRSIZE - 2, scaled_size);
	if (print_indexed)
		printf("; indexing %d%%", p_indexed);
	if (print_resolved)
		printf("; resolving deltas %d%%", p_resolved);
	if (indexing_done)
		printf("\n");
	if (print_size || print_indexed || print_resolved || indexing_done)
		fflush(stdout);

	return NULL;
}

static const struct got_error *
add_ref(struct got_reflist_entry **new, struct got_reflist_head *refs,
    const char *refname, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *ref;

	*new = NULL;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			return err;

		/* Treat argument as a reference prefix. */
		err = got_ref_list(refs, repo, refname,
		    got_ref_cmp_by_name, NULL);
	} else {
		err = got_reflist_insert(new, refs, ref,
		    got_ref_cmp_by_name, NULL);
		if (err || *new == NULL /* duplicate */)
			got_ref_close(ref);
	}

	return err;
}

static const struct got_error *
cmd_pack(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *repo_path = NULL;
	struct got_repository *repo = NULL;
	int ch, i, loose_obj_only = 1, force_refdelta = 0, verbosity = 0;
	struct got_object_id *pack_hash = NULL;
	char *id_str = NULL, *idxpath = NULL;
	struct got_pack_progress_arg ppa;
	FILE *packfile = NULL;
	struct got_pathlist_head exclude_args;
	struct got_pathlist_entry *pe;
	struct got_reflist_head exclude_refs;
	struct got_reflist_head include_refs;
	struct got_reflist_entry *re, *new;
	int *pack_fds = NULL;

	RB_INIT(&exclude_args);
	TAILQ_INIT(&exclude_refs);
	TAILQ_INIT(&include_refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aDqr:x:")) != -1) {
		switch (ch) {
		case 'a':
			loose_obj_only = 0;
			break;
		case 'D':
			force_refdelta = 1;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'x':
			got_path_strip_trailing_slashes(optarg);
			error = got_pathlist_insert(NULL, &exclude_args,
			    optarg, NULL);
			if (error)
				return error;
			break;
		default:
			usage_pack(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (repo_path == NULL) {
		error = get_repo_path(&repo_path);
		if (error)
			goto done;
	}
	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 0);
	if (error)
		goto done;

	RB_FOREACH(pe, got_pathlist_head, &exclude_args) {
		const char *refname = pe->path;
		error = add_ref(&new, &exclude_refs, refname, repo);
		if (error)
			goto done;
	}

	if (argc == 0) {
		error = got_ref_list(&include_refs, repo, "",
		    got_ref_cmp_by_name, NULL);
		if (error)
			goto done;
	} else {
		for (i = 0; i < argc; i++) {
			const char *refname;
			got_path_strip_trailing_slashes(argv[i]);
			refname = argv[i];
			error = add_ref(&new, &include_refs, refname, repo);
			if (error)
				goto done;
		}
	}

	/* Ignore references in the refs/got/ namespace. */
	TAILQ_FOREACH_SAFE(re, &include_refs, entry, new) {
		const char *refname = got_ref_get_name(re->ref);
		if (strncmp("refs/got/", refname, 9) != 0)
			continue;
		TAILQ_REMOVE(&include_refs, re, entry);
		got_ref_close(re->ref);
		free(re);
	}

	memset(&ppa, 0, sizeof(ppa));
	ppa.out = stdout;
	ppa.last_scaled_size[0] = '\0';
	ppa.last_p_indexed = -1;
	ppa.last_p_resolved = -1;
	ppa.verbosity = verbosity;

	error = got_repo_pack_objects(&packfile, &pack_hash,
	    &include_refs, &exclude_refs, repo, loose_obj_only,
	    force_refdelta, pack_progress, &ppa, check_cancelled, NULL);
	if (error) {
		if (ppa.printed_something)
			printf("\n");
		goto done;
	}

	error = got_object_id_str(&id_str, pack_hash);
	if (error)
		goto done;
	if (verbosity >= 0)
		printf("\nWrote %s.pack\n", id_str);

	error = got_repo_index_pack(&idxpath, packfile, pack_hash, repo,
	    pack_index_progress, &ppa, check_cancelled, NULL);
	if (error)
		goto done;
	if (verbosity >= 0)
		printf("\nIndexed %s.pack\n", id_str);
done:
	if (repo)
		got_repo_close(repo);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&exclude_args, GOT_PATHLIST_FREE_NONE);
	got_ref_list_free(&exclude_refs);
	got_ref_list_free(&include_refs);
	free(id_str);
	free(pack_hash);
	free(repo_path);
	free(idxpath);
	return error;
}

__dead static void
usage_indexpack(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s indexpack packfile-path\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
cmd_indexpack(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	int ch;
	struct got_object_id *pack_hash = NULL;
	char *packfile_path = NULL, *idxpath = NULL;
	char *id_str = NULL;
	struct got_pack_progress_arg ppa;
	FILE *packfile = NULL;
	int *pack_fds = NULL;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_indexpack(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_indexpack(1);

	packfile_path = realpath(argv[0], NULL);
	if (packfile_path == NULL)
		return got_error_from_errno2("realpath", argv[0]);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, packfile_path, NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 0);
	if (error)
		goto done;

	memset(&ppa, 0, sizeof(ppa));
	ppa.out = stdout;
	ppa.last_scaled_size[0] = '\0';
	ppa.last_p_indexed = -1;
	ppa.last_p_resolved = -1;

	error = got_repo_find_pack(&packfile, &pack_hash, repo,
	    packfile_path);
	if (error)
		goto done;

	error = got_object_id_str(&id_str, pack_hash);
	if (error)
		goto done;

	error = got_repo_index_pack(&idxpath, packfile, pack_hash, repo,
	    pack_index_progress, &ppa, check_cancelled, NULL);
	if (error)
		goto done;
	printf("\nIndexed %s.pack\n", id_str);
done:
	if (repo)
		got_repo_close(repo);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(id_str);
	free(pack_hash);
	free(idxpath);
	return error;
}

__dead static void
usage_listpack(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s listpack [-hs] packfile-path\n",
	    getprogname());
	exit(status);
}

struct gotadmin_list_pack_cb_args {
	int nblobs;
	int ntrees;
	int ncommits;
	int ntags;
	int noffdeltas;
	int nrefdeltas;
	int human_readable;
};

static const struct got_error *
list_pack_cb(void *arg, struct got_object_id *id, int type, off_t offset,
    off_t size, off_t base_offset, struct got_object_id *base_id)
{
	const struct got_error *err;
	struct gotadmin_list_pack_cb_args *a = arg;
	char *id_str, *delta_str = NULL, *base_id_str = NULL;
	const char *type_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	switch (type) {
	case GOT_OBJ_TYPE_BLOB:
		type_str = GOT_OBJ_LABEL_BLOB;
		a->nblobs++;
		break;
	case GOT_OBJ_TYPE_TREE:
		type_str = GOT_OBJ_LABEL_TREE;
		a->ntrees++;
		break;
	case GOT_OBJ_TYPE_COMMIT:
		type_str = GOT_OBJ_LABEL_COMMIT;
		a->ncommits++;
		break;
	case GOT_OBJ_TYPE_TAG:
		type_str = GOT_OBJ_LABEL_TAG;
		a->ntags++;
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		type_str = "offset-delta";
		if (asprintf(&delta_str, " base-offset %lld",
		    (long long)base_offset) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		a->noffdeltas++;
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		type_str = "ref-delta";
		err = got_object_id_str(&base_id_str, base_id);
		if (err)
			goto done;
		if (asprintf(&delta_str, " base-id %s", base_id_str) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		a->nrefdeltas++;
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}
	if (a->human_readable) {
		char scaled[FMT_SCALED_STRSIZE];
		char *s;;
		if (fmt_scaled(size, scaled) == -1) {
			err = got_error_from_errno("fmt_scaled");
			goto done;
		}
		s = scaled;
		while (isspace((unsigned char)*s))
			s++;
		printf("%s %s at %lld size %s%s\n", id_str, type_str,
		    (long long)offset, s, delta_str ? delta_str : "");
	} else {
		printf("%s %s at %lld size %lld%s\n", id_str, type_str,
		    (long long)offset, (long long)size,
		    delta_str ? delta_str : "");
	}
done:
	free(id_str);
	free(base_id_str);
	free(delta_str);
	return err;
}

static const struct got_error *
cmd_listpack(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	int ch;
	struct got_object_id *pack_hash = NULL;
	char *packfile_path = NULL;
	char *id_str = NULL;
	struct gotadmin_list_pack_cb_args lpa;
	FILE *packfile = NULL;
	int show_stats = 0, human_readable = 0;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "hs")) != -1) {
		switch (ch) {
		case 'h':
			human_readable = 1;
			break;
		case 's':
			show_stats = 1;
			break;
		default:
			usage_listpack(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_listpack(1);
	packfile_path = realpath(argv[0], NULL);
	if (packfile_path == NULL)
		return got_error_from_errno2("realpath", argv[0]);

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, packfile_path, NULL, pack_fds);
	if (error)
		goto done;
#ifndef PROFILE
	/* Remove "cpath" promise. */
	if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	error = apply_unveil(got_repo_get_path_git_dir(repo), 1);
	if (error)
		goto done;

	error = got_repo_find_pack(&packfile, &pack_hash, repo,
	    packfile_path);
	if (error)
		goto done;
	error = got_object_id_str(&id_str, pack_hash);
	if (error)
		goto done;

	memset(&lpa, 0, sizeof(lpa));
	lpa.human_readable = human_readable;
	error = got_repo_list_pack(packfile, pack_hash, repo,
	    list_pack_cb, &lpa, check_cancelled, NULL);
	if (error)
		goto done;
	if (show_stats) {
		printf("objects: %d\n  blobs: %d\n  trees: %d\n  commits: %d\n"
		    "  tags: %d\n  offset-deltas: %d\n  ref-deltas: %d\n",
		    lpa.nblobs + lpa.ntrees + lpa.ncommits + lpa.ntags +
		    lpa.noffdeltas + lpa.nrefdeltas,
		    lpa.nblobs, lpa.ntrees, lpa.ncommits, lpa.ntags,
		    lpa.noffdeltas, lpa.nrefdeltas);
	}
done:
	if (repo)
		got_repo_close(repo);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(id_str);
	free(pack_hash);
	free(packfile_path);
	return error;
}

__dead static void
usage_cleanup(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s cleanup [-anpq] [-r repository-path]\n",
	    getprogname());
	exit(status);
}

struct got_cleanup_progress_arg {
	int last_nloose;
	int last_ncommits;
	int last_npurged;
	int last_nredundant;
	int verbosity;
	int printed_something;
	int dry_run;
};

static const struct got_error *
cleanup_progress(void *arg, int ncommits, int nloose, int npurged,
    int nredundant)
{
	struct got_cleanup_progress_arg *a = arg;
	int print_loose = 0, print_commits = 0, print_purged = 0;
	int print_redundant = 0;

	if (a->last_ncommits != ncommits) {
		print_commits = 1;
		a->last_ncommits = ncommits;
	}
	if (a->last_nloose != nloose) {
		print_commits = 1;
		print_loose = 1;
		a->last_nloose = nloose;
	}
	if (a->last_npurged != npurged) {
		print_commits = 1;
		print_loose = 1;
		print_purged = 1;
		a->last_npurged = npurged;
	}
	if (a->last_nredundant != nredundant) {
		print_commits = 1;
		print_loose = 1;
		print_purged = 1;
		print_redundant = 1;
		a->last_nredundant = nredundant;
	}

	if (a->verbosity < 0)
		return NULL;

	if (print_loose || print_commits || print_purged || print_redundant)
		printf("\r");
	if (print_commits)
		printf("%d commit%s scanned", ncommits,
		    ncommits == 1 ? "" : "s");
	if (print_loose)
		printf("; %d loose object%s", nloose, nloose == 1 ? "" : "s");
	if (print_purged || print_redundant) {
		if (a->dry_run) {
			printf("; could purge %d object%s", npurged,
			    npurged == 1 ? "" : "s");
		} else {
			printf("; purged %d object%s", npurged,
			    npurged == 1 ? "" : "s");
		}
	}
	if (print_redundant) {
		if (a->dry_run) {
			printf(", %d pack file%s", nredundant,
			    nredundant == 1 ? "" : "s");
		} else {
			printf(", %d pack file%s", nredundant,
			    nredundant == 1 ? "" : "s");
		}
	}
	if (print_loose || print_commits || print_purged || print_redundant) {
		a->printed_something = 1;
		fflush(stdout);
	}
	return NULL;
}

struct got_lonely_packidx_progress_arg {
	int verbosity;
	int printed_something;
	int dry_run;
};

static const struct got_error *
lonely_packidx_progress(void *arg, const char *path)
{
	struct got_lonely_packidx_progress_arg *a = arg;

	if (a->verbosity < 0)
		return NULL;

	if (a->dry_run)
		printf("%s could be removed\n", path);
	else
		printf("%s removed\n", path);

	a->printed_something = 1;
	return NULL;
}

static const struct got_error *
cmd_cleanup(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *repo_path = NULL;
	struct got_repository *repo = NULL;
	int ch, dry_run = 0, verbosity = 0;
	int ncommits = 0, nloose = 0, npacked = 0;
	int remove_lonely_packidx = 0, ignore_mtime = 0;
	struct got_pack_progress_arg ppa;
	struct got_cleanup_progress_arg cpa;
	struct got_lonely_packidx_progress_arg lpa;
	off_t loose_before, loose_after;
	off_t pack_before, pack_after;
	off_t total_size;
	char loose_before_scaled[FMT_SCALED_STRSIZE];
	char loose_after_scaled[FMT_SCALED_STRSIZE];
	char pack_before_scaled[FMT_SCALED_STRSIZE];
	char pack_after_scaled[FMT_SCALED_STRSIZE];
	char total_size_scaled[FMT_SCALED_STRSIZE];
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "anpqr:")) != -1) {
		switch (ch) {
		case 'a':
			ignore_mtime = 1;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'p':
			remove_lonely_packidx = 1;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_cleanup(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (repo_path == NULL) {
		error = get_repo_path(&repo_path);
		if (error)
			goto done;
	}
	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 0);
	if (error)
		goto done;

	if (got_repo_has_extension(repo, "preciousObjects")) {
		error = got_error_msg(GOT_ERR_GIT_REPO_EXT,
		    "the preciousObjects Git extension is enabled; "
		    "this implies that objects must not be deleted");
		goto done;
	}

	if (remove_lonely_packidx) {
		memset(&lpa, 0, sizeof(lpa));
		lpa.dry_run = dry_run;
		lpa.verbosity = verbosity;
		error = got_repo_remove_lonely_packidx(repo, dry_run,
		    lonely_packidx_progress, &lpa, check_cancelled, NULL);
		goto done;
	}

	memset(&cpa, 0, sizeof(cpa));
	cpa.last_nloose = -1;
	cpa.last_npurged = -1;
	cpa.last_nredundant = -1;
	cpa.dry_run = dry_run;
	cpa.verbosity = verbosity;

	memset(&ppa, 0, sizeof(ppa));
	ppa.out = stdout;
	ppa.verbosity = verbosity;

	error = got_repo_cleanup(repo, &loose_before, &loose_after,
	    &pack_before, &pack_after, &ncommits, &nloose, &npacked,
	    dry_run, ignore_mtime, cleanup_progress, &cpa,
	    pack_progress, &ppa, pack_index_progress, &ppa,
	    check_cancelled, NULL);
	if (ppa.printed_something || cpa.printed_something)
		printf("\n");
	if (error)
		goto done;

	total_size = (loose_before - loose_after) + (pack_before - pack_after);

	if (cpa.printed_something) {
		if (fmt_scaled(loose_before, loose_before_scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		if (fmt_scaled(loose_after, loose_after_scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		if (fmt_scaled(pack_before, pack_before_scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		if (fmt_scaled(pack_after, pack_after_scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		if (fmt_scaled(total_size, total_size_scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		printf("loose total size before: %s\n", loose_before_scaled);
		printf("loose total size after: %s\n", loose_after_scaled);
		printf("pack files total size before: %s\n",
		    pack_before_scaled);
		printf("pack files total size after: %s\n", pack_after_scaled);
		if (dry_run) {
			printf("disk space which would be freed: %s\n",
			    total_size_scaled);
		} else
			printf("disk space freed: %s\n", total_size_scaled);
		printf("loose objects also found in pack files: %d\n", npacked);
	}

done:
	if (repo)
		got_repo_close(repo);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(repo_path);
	return error;
}

__dead static void
usage_dump(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s dump [-q] [-r repository-path] "
	    "[-x reference] [reference]...\n", getprogname());
	exit(status);
}

static const struct got_error *
cmd_dump(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_pack_progress_arg ppa;
	struct got_repository *repo = NULL;
	struct got_pathlist_head exclude_args;
	struct got_pathlist_entry *pe;
	struct got_reflist_head exclude_refs;
	struct got_reflist_head include_refs;
	struct got_reflist_entry *re, *new;
	const char *refname;
	char *repo_path = NULL;
	int *pack_fds = NULL;
	int verbosity = 0;
	int i, ch;

	RB_INIT(&exclude_args);
	TAILQ_INIT(&exclude_refs);
	TAILQ_INIT(&include_refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "qr:x:")) != -1) {
		switch (ch) {
		case 'q':
			verbosity = -1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'x':
			error = got_pathlist_insert(NULL, &exclude_args,
			    optarg, NULL);
			if (error)
				return error;
			break;
		default:
			usage_dump(1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (repo_path == NULL) {
		error = get_repo_path(&repo_path);
		if (error)
			goto done;
	}
	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 1);
	if (error)
		goto done;

	RB_FOREACH(pe, got_pathlist_head, &exclude_args) {
		refname = pe->path;
		error = add_ref(&new, &exclude_refs, refname, repo);
		if (error)
			goto done;
	}

	if (argc == 0) {
		error = got_ref_list(&include_refs, repo, "",
		    got_ref_cmp_by_name, NULL);
		if (error)
			goto done;
	} else {
		for (i = 0; i < argc; i++) {
			got_path_strip_trailing_slashes(argv[i]);
			refname = argv[i];
			error = add_ref(&new, &include_refs, refname, repo);
			if (error)
				goto done;
		}
	}

	/* Ignore references in the refs/got/ namespace. */
	TAILQ_FOREACH_SAFE(re, &include_refs, entry, new) {
		refname = got_ref_get_name(re->ref);
		if (strncmp("refs/got/", refname, 9) != 0)
			continue;
		TAILQ_REMOVE(&include_refs, re, entry);
		got_ref_close(re->ref);
		free(re);
	}

	memset(&ppa, 0, sizeof(ppa));
	ppa.out = stderr;
	ppa.verbosity = verbosity;

	error = got_repo_dump(stdout, &include_refs, &exclude_refs,
	    repo, pack_progress, &ppa, check_cancelled, NULL);
	if (ppa.printed_something)
		fprintf(stderr, "\n");
 done:
	if (repo)
		got_repo_close(repo);

	if (pack_fds) {
		const struct got_error *pack_err;

		pack_err = got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}

	got_pathlist_free(&exclude_args, GOT_PATHLIST_FREE_NONE);
	got_ref_list_free(&exclude_refs);
	got_ref_list_free(&include_refs);
	free(repo_path);

	return error;
}

__dead static void
usage_load(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s load [-nq] [-l bundle-file] "
	    "[-r repository-path] [reference ...]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
load_progress(void *arg, off_t packfile_size, int nobj_total,
    int nobj_indexed, int nobj_loose, int nobj_resolved)
{
	return pack_index_progress(arg, packfile_size, nobj_total,
	    nobj_indexed, nobj_loose, nobj_resolved, 0);
}

static int
is_wanted_ref(struct got_pathlist_head *wanted, const char *ref)
{
	struct got_pathlist_entry *pe;

	if (RB_EMPTY(wanted))
		return 1;

	RB_FOREACH(pe, got_pathlist_head, wanted) {
		if (strcmp(pe->path, ref) == 0)
			return 1;
	}

	return 0;
}

static const struct got_error *
create_ref(const char *refname, struct got_object_id *id,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
	got_ref_close(ref);

	if (err == NULL && verbosity >= 0)
		printf("Created reference %s: %s\n", refname, id_str);
done:
	free(id_str);
	return err;
}

static const struct got_error *
update_ref(struct got_reference *ref, struct got_object_id *new_id,
    int replace_tags, int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *new_id_str = NULL;
	struct got_object_id *old_id = NULL;

	err = got_object_id_str(&new_id_str, new_id);
	if (err)
		goto done;

	if (!replace_tags &&
	    strncmp(got_ref_get_name(ref), "refs/tags/", 10) == 0) {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;
		if (verbosity >= 0) {
			printf("Rejecting update of existing tag %s: %s\n",
			    got_ref_get_name(ref), new_id_str);
		}
		goto done;
	}

	if (got_ref_is_symbolic(ref)) {
		if (verbosity >= 0) {
			printf("Replacing reference %s: %s\n",
			    got_ref_get_name(ref),
			    got_ref_get_symref_target(ref));
		}
		err = got_ref_change_symref_to_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	} else {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;

		err = got_ref_change_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	}

	if (verbosity >= 0)
		printf("Updated %s: %s\n", got_ref_get_name(ref),
		    new_id_str);
done:
	free(old_id);
	free(new_id_str);
	return err;
}

static const struct got_error *
cmd_load(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_pathlist_head include_args;
	struct got_pathlist_head available_refs;
	struct got_pathlist_entry *pe;
	struct got_pack_progress_arg ppa;
	FILE *in = stdin;
	int *pack_fds = NULL;
	char *repo_path = NULL;
	int list_refs_only = 0;
	int noop = 0;
	int verbosity = 0;
	int ch, i;

	RB_INIT(&include_args);
	RB_INIT(&available_refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec "
	    "sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "l:nqr:")) != -1) {
		switch (ch) {
		case 'l':
			list_refs_only = 1;
			in = fopen(optarg, "re");
			if (in == NULL)
				return got_error_from_errno2("open", optarg);
			break;
		case 'n':
			noop = 1;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_load(1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (list_refs_only && argc > 1)
		errx(1, "-l and references on the command line are exclusive");
	if (list_refs_only && noop)
		errx(1, "-n and -l are mutually exclusive");

	for (i = 0; i < argc; i++) {
		char *refname = argv[i];
		got_path_strip_trailing_slashes(refname);
		if (!got_ref_name_is_valid(refname))
			errx(1, "invalid reference name %s", refname);
		error = got_pathlist_insert(NULL, &include_args, refname, NULL);
		if (error)
			goto done;
	}

	if (repo_path == NULL) {
		error = get_repo_path(&repo_path);
		if (error)
			goto done;
	}
	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 0);
	if (error)
		goto done;

	memset(&ppa, 0, sizeof(ppa));
	ppa.out = stdout;
	ppa.verbosity = verbosity;

	error = got_repo_load(in, &available_refs, repo, list_refs_only, noop,
	    load_progress, &ppa, check_cancelled, NULL);
	if (verbosity >= 0 && !list_refs_only)
		printf("\n");
	if (error)
		goto done;

	if (list_refs_only) {
		RB_FOREACH(pe, got_pathlist_head, &available_refs) {
			const char *refname = pe->path;
			struct got_object_id *id = pe->data;
			char *idstr;

			error = got_object_id_str(&idstr, id);
			if (error)
				goto done;

			printf("%s: %s\n", refname, idstr);
			free(idstr);
		}
		goto done;
	}

	if (noop)
		goto done;

	/* Update references */
	RB_FOREACH(pe, got_pathlist_head, &available_refs) {
		const struct got_error *unlock_err;
		struct got_reference *ref;
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;

		if (!is_wanted_ref(&include_args, pe->path))
			continue;

		error = got_ref_open(&ref, repo, refname, 1);
		if (error) {
			if (error->code != GOT_ERR_NOT_REF)
				goto done;
			error = create_ref(refname, id, verbosity, repo);
			if (error)
				goto done;
		} else {
			/* XXX: check advances only and add -f to force? */
			error = update_ref(ref, id, 1, verbosity, repo);
			unlock_err = got_ref_unlock(ref);
			if (unlock_err && error == NULL)
				error = unlock_err;
			got_ref_close(ref);
			if (error)
				goto done;
		}
	}

 done:
	if (in != stdin && fclose(in) == EOF && error == NULL)
		error = got_error_from_errno("fclose");

	if (repo)
		got_repo_close(repo);

	if (pack_fds) {
		const struct got_error *pack_err;

		pack_err = got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}

	got_pathlist_free(&include_args, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&available_refs, GOT_PATHLIST_FREE_ALL);
	free(repo_path);

	return error;
}
