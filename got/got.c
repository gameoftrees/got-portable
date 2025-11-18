/*
 * Copyright (c) 2017 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2020 Ori Bernstein <ori@openbsd.org>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>
#include <paths.h>
#include <regex.h>
#include <getopt.h>

#include "got_version.h"
#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_fetch.h"
#include "got_send.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_opentemp.h"
#include "got_gotconfig.h"
#include "got_dial.h"
#include "got_patch.h"
#include "got_sigs.h"
#include "got_date.h"
#include "got_keyword.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef GOT_DEFAULT_EDITOR
#define GOT_DEFAULT_EDITOR "/usr/bin/vi"
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


struct got_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(int);
	const char	*cmd_alias;
};

__dead static void	usage(int, int);
__dead static void	usage_init(int);
__dead static void	usage_import(int);
__dead static void	usage_clone(int);
__dead static void	usage_fetch(int);
__dead static void	usage_checkout(int);
__dead static void	usage_update(int);
__dead static void	usage_log(int);
__dead static void	usage_diff(int);
__dead static void	usage_blame(int);
__dead static void	usage_tree(int);
__dead static void	usage_status(int);
__dead static void	usage_ref(int);
__dead static void	usage_branch(int);
__dead static void	usage_tag(int);
__dead static void	usage_add(int);
__dead static void	usage_remove(int);
__dead static void	usage_patch(int);
__dead static void	usage_revert(int);
__dead static void	usage_commit(int);
__dead static void	usage_send(int);
__dead static void	usage_cherrypick(int);
__dead static void	usage_backout(int);
__dead static void	usage_rebase(int);
__dead static void	usage_histedit(int);
__dead static void	usage_integrate(int);
__dead static void	usage_merge(int);
__dead static void	usage_stage(int);
__dead static void	usage_unstage(int);
__dead static void	usage_cat(int);
__dead static void	usage_info(int);

static const struct got_error*		cmd_init(int, char *[]);
static const struct got_error*		cmd_import(int, char *[]);
static const struct got_error*		cmd_clone(int, char *[]);
static const struct got_error*		cmd_fetch(int, char *[]);
static const struct got_error*		cmd_checkout(int, char *[]);
static const struct got_error*		cmd_update(int, char *[]);
static const struct got_error*		cmd_log(int, char *[]);
static const struct got_error*		cmd_diff(int, char *[]);
static const struct got_error*		cmd_blame(int, char *[]);
static const struct got_error*		cmd_tree(int, char *[]);
static const struct got_error*		cmd_status(int, char *[]);
static const struct got_error*		cmd_ref(int, char *[]);
static const struct got_error*		cmd_branch(int, char *[]);
static const struct got_error*		cmd_tag(int, char *[]);
static const struct got_error*		cmd_add(int, char *[]);
static const struct got_error*		cmd_remove(int, char *[]);
static const struct got_error*		cmd_patch(int, char *[]);
static const struct got_error*		cmd_revert(int, char *[]);
static const struct got_error*		cmd_commit(int, char *[]);
static const struct got_error*		cmd_send(int, char *[]);
static const struct got_error*		cmd_cherrypick(int, char *[]);
static const struct got_error*		cmd_backout(int, char *[]);
static const struct got_error*		cmd_rebase(int, char *[]);
static const struct got_error*		cmd_histedit(int, char *[]);
static const struct got_error*		cmd_integrate(int, char *[]);
static const struct got_error*		cmd_merge(int, char *[]);
static const struct got_error*		cmd_stage(int, char *[]);
static const struct got_error*		cmd_unstage(int, char *[]);
static const struct got_error*		cmd_cat(int, char *[]);
static const struct got_error*		cmd_info(int, char *[]);

static const struct got_cmd got_commands[] = {
	{ "init",	cmd_init,	usage_init,	"" },
	{ "import",	cmd_import,	usage_import,	"im" },
	{ "clone",	cmd_clone,	usage_clone,	"cl" },
	{ "fetch",	cmd_fetch,	usage_fetch,	"fe" },
	{ "checkout",	cmd_checkout,	usage_checkout,	"co" },
	{ "update",	cmd_update,	usage_update,	"up" },
	{ "log",	cmd_log,	usage_log,	"" },
	{ "diff",	cmd_diff,	usage_diff,	"di" },
	{ "blame",	cmd_blame,	usage_blame,	"bl" },
	{ "tree",	cmd_tree,	usage_tree,	"tr" },
	{ "status",	cmd_status,	usage_status,	"st" },
	{ "ref",	cmd_ref,	usage_ref,	"" },
	{ "branch",	cmd_branch,	usage_branch,	"br" },
	{ "tag",	cmd_tag,	usage_tag,	"" },
	{ "add",	cmd_add,	usage_add,	"" },
	{ "remove",	cmd_remove,	usage_remove,	"rm" },
	{ "patch",	cmd_patch,	usage_patch,	"pa" },
	{ "revert",	cmd_revert,	usage_revert,	"rv" },
	{ "commit",	cmd_commit,	usage_commit,	"ci" },
	{ "send",	cmd_send,	usage_send,	"se" },
	{ "cherrypick",	cmd_cherrypick,	usage_cherrypick, "cy" },
	{ "backout",	cmd_backout,	usage_backout,	"bo" },
	{ "rebase",	cmd_rebase,	usage_rebase,	"rb" },
	{ "histedit",	cmd_histedit,	usage_histedit,	"he" },
	{ "integrate",  cmd_integrate,  usage_integrate,"ig" },
	{ "merge",	cmd_merge,	usage_merge,	"mg" },
	{ "stage",	cmd_stage,	usage_stage,	"sg" },
	{ "unstage",	cmd_unstage,	usage_unstage,	"ug" },
	{ "cat",	cmd_cat,	usage_cat,	"" },
	{ "info",	cmd_info,	usage_info,	"" },
};

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(got_commands); i++) {
		const struct got_cmd *cmd = &got_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

__dead static void
option_conflict(char a, char b)
{
	errx(1, "-%c and -%c options are mutually exclusive", a, b);
}

int
main(int argc, char *argv[])
{
	const struct got_cmd *cmd;
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

	for (i = 0; i < nitems(got_commands); i++) {
		const struct got_error *error;

		cmd = &got_commands[i];

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
			fflush(stdout);
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
get_editor(char **abspath)
{
	const struct got_error *err = NULL;
	const char *editor;

	*abspath = NULL;

	editor = getenv("VISUAL");
	if (editor == NULL)
		editor = getenv("EDITOR");

	if (editor) {
		err = got_path_find_prog(abspath, editor);
		if (err)
			return err;
	}

	if (*abspath == NULL) {
		*abspath = strdup(GOT_DEFAULT_EDITOR);
		if (*abspath == NULL)
			return got_error_from_errno("strdup");
	}

	return NULL;
}

static const struct got_error *
apply_unveil(const char *repo_path, int repo_read_only,
    const char *worktree_path)
{
	const struct got_error *err;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, repo_read_only ? "r" : "rwc") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (worktree_path && unveil(worktree_path, "rwc") != 0)
		return got_error_from_errno2("unveil", worktree_path);

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

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unveil", NULL) == -1)
		err(1, "pledge");
#endif
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

	error = apply_unveil(repo_path, 0, NULL);
	if (error)
		goto done;

	error = got_repo_init(repo_path, head_name, algo);
done:
	free(repo_path);
	return error;
}

__dead static void
usage_import(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s import [-b branch] [-I pattern] [-m message] "
	    "[-r repository-path] directory\n", getprogname());
	exit(status);
}

static int
spawn_editor(const char *editor, const char *file)
{
	pid_t pid;
	sig_t sighup, sigint, sigquit;
	int st = -1;

	sighup = signal(SIGHUP, SIG_IGN);
	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);

	switch (pid = fork()) {
	case -1:
		goto doneediting;
	case 0:
		execl(editor, editor, file, (char *)NULL);
		_exit(127);
	}

	while (waitpid(pid, &st, 0) == -1)
		if (errno != EINTR)
			break;

doneediting:
	(void)signal(SIGHUP, sighup);
	(void)signal(SIGINT, sigint);
	(void)signal(SIGQUIT, sigquit);

	if (!WIFEXITED(st)) {
		errno = EINTR;
		return -1;
	}

	return WEXITSTATUS(st);
}

static const struct got_error *
read_logmsg(char **logmsg, size_t *len, FILE *fp, size_t filesize)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0;

	*logmsg = NULL;
	*len = 0;

	if (fseeko(fp, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	*logmsg = malloc(filesize + 1);
	if (*logmsg == NULL)
		return got_error_from_errno("malloc");
	(*logmsg)[0] = '\0';

	while (getline(&line, &linesize, fp) != -1) {
		if (line[0] == '#' || (*len == 0 && line[0] == '\n'))
			continue; /* remove comments and leading empty lines */
		*len = strlcat(*logmsg, line, filesize + 1);
		if (*len >= filesize + 1) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
	}
	if (ferror(fp)) {
		err = got_ferror(fp, GOT_ERR_IO);
		goto done;
	}

	while (*len > 0 && (*logmsg)[*len - 1] == '\n') {
		(*logmsg)[*len - 1] = '\0';
		(*len)--;
	}
done:
	free(line);
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
		*len = 0;
	}
	return err;
}

static const struct got_error *
edit_logmsg(char **logmsg, const char *editor, const char *logmsg_path,
    const char *initial_content, size_t initial_content_len,
    int require_modification)
{
	const struct got_error *err = NULL;
	struct stat st, st2;
	FILE *fp = NULL;
	size_t logmsg_len;

	*logmsg = NULL;

	if (stat(logmsg_path, &st) == -1)
		return got_error_from_errno2("stat", logmsg_path);

	if (spawn_editor(editor, logmsg_path) == -1)
		return got_error_from_errno("failed spawning editor");

	if (require_modification) {
		struct timespec timeout;

		timeout.tv_sec = 0;
		timeout.tv_nsec = 1;
		nanosleep(&timeout,  NULL);
	}

	if (stat(logmsg_path, &st2) == -1)
		return got_error_from_errno2("stat", logmsg_path);

	if (require_modification && st.st_size == st2.st_size &&
	    timespeccmp(&st.st_mtim, &st2.st_mtim, ==))
		return got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "no changes made to commit message, aborting");

	fp = fopen(logmsg_path, "re");
	if (fp == NULL) {
		err = got_error_from_errno("fopen");
		goto done;
	}

	/* strip comments and leading/trailing newlines */
	err = read_logmsg(logmsg, &logmsg_len, fp, st2.st_size);
	if (err)
		goto done;
	if (logmsg_len == 0) {
		err = got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "commit message cannot be empty, aborting");
		goto done;
	}
done:
	if (fp && fclose(fp) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

static const struct got_error *
collect_import_msg(char **logmsg, char **logmsg_path, const char *editor,
    const char *path_dir, const char *branch_name)
{
	char *initial_content = NULL;
	const struct got_error *err = NULL;
	int initial_content_len;
	int fd = -1;

	initial_content_len = asprintf(&initial_content,
	    "\n# %s to be imported to branch %s\n", path_dir,
	    branch_name);
	if (initial_content_len == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(logmsg_path, &fd,
	    GOT_TMPDIR_STR "/got-importmsg", "");
	if (err)
		goto done;

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", *logmsg_path);
		goto done;
	}
	if (close(fd) == -1) {
		err = got_error_from_errno2("close", *logmsg_path);
		goto done;
	}
	fd = -1;

	err = edit_logmsg(logmsg, editor, *logmsg_path, initial_content,
	    initial_content_len, 1);
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", *logmsg_path);
	free(initial_content);

	if (err && *logmsg_path) {
		unlink(*logmsg_path);
		free(*logmsg_path);
		*logmsg_path = NULL;
	}
	return err;
}

static const struct got_error *
import_progress(void *arg, const char *path)
{
	printf("A  %s\n", path);
	return NULL;
}

static const struct got_error *
valid_author(const char *author)
{
	const char *email = author;

	/*
	 * Git' expects the author (or committer) to be in the form
	 * "name <email>", which are mostly free form (see the
	 * "committer" description in git-fast-import(1)).  We're only
	 * doing this to avoid git's object parser breaking on commits
	 * we create.
	 */

	while (*author && *author != '\n' && *author != '<' && *author != '>')
		author++;
	if (author != email && *author == '<' && *(author - 1) != ' ')
		return got_error_fmt(GOT_ERR_COMMIT_BAD_AUTHOR, "%s: space "
		    "between author name and email required", email);
	if (*author++ != '<')
		return got_error_fmt(GOT_ERR_COMMIT_NO_EMAIL, "%s", email);
	while (*author && *author != '\n' && *author != '<' && *author != '>')
		author++;
	if (strcmp(author, ">") != 0)
		return got_error_fmt(GOT_ERR_COMMIT_NO_EMAIL, "%s", email);
	return NULL;
}

static const struct got_error *
get_author(char **author, struct got_repository *repo,
    struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	const char *got_author = NULL, *name, *email;
	const struct got_gotconfig *worktree_conf = NULL, *repo_conf = NULL;

	*author = NULL;

	if (worktree)
		worktree_conf = got_worktree_get_gotconfig(worktree);
	repo_conf = got_repo_get_gotconfig(repo);

	/*
	 * Priority of potential author information sources, from most
	 * significant to least significant:
	 * 1) work tree's .got/got.conf file
	 * 2) repository's got.conf file
	 * 3) repository's git config file
	 * 4) environment variables
	 * 5) global git config files (in user's home directory or /etc)
	 */

	if (worktree_conf)
		got_author = got_gotconfig_get_author(worktree_conf);
	if (got_author == NULL)
		got_author = got_gotconfig_get_author(repo_conf);
	if (got_author == NULL) {
		name = got_repo_get_gitconfig_author_name(repo);
		email = got_repo_get_gitconfig_author_email(repo);
		if (name && email) {
			if (asprintf(author, "%s <%s>", name, email) == -1)
				return got_error_from_errno("asprintf");
			return NULL;
		}

		got_author = getenv("GOT_AUTHOR");
		if (got_author == NULL) {
			name = got_repo_get_global_gitconfig_author_name(repo);
			email = got_repo_get_global_gitconfig_author_email(
			    repo);
			if (name && email) {
				if (asprintf(author, "%s <%s>", name, email)
				    == -1)
					return got_error_from_errno("asprintf");
				return NULL;
			}
			/* TODO: Look up user in password database? */
			return got_error(GOT_ERR_COMMIT_NO_AUTHOR);
		}
	}

	*author = strdup(got_author);
	if (*author == NULL)
		return got_error_from_errno("strdup");

	err = valid_author(*author);
	if (err) {
		free(*author);
		*author = NULL;
	}
	return err;
}

static const struct got_error *
get_allowed_signers(char **allowed_signers, struct got_repository *repo,
    struct got_worktree *worktree)
{
	const char *got_allowed_signers = NULL;
	const struct got_gotconfig *worktree_conf = NULL, *repo_conf = NULL;

	*allowed_signers = NULL;

	if (worktree)
		worktree_conf = got_worktree_get_gotconfig(worktree);
	repo_conf = got_repo_get_gotconfig(repo);

	/*
	 * Priority of potential author information sources, from most
	 * significant to least significant:
	 * 1) work tree's .got/got.conf file
	 * 2) repository's got.conf file
	 */

	if (worktree_conf)
		got_allowed_signers = got_gotconfig_get_allowed_signers_file(
		    worktree_conf);
	if (got_allowed_signers == NULL)
		got_allowed_signers = got_gotconfig_get_allowed_signers_file(
		    repo_conf);

	if (got_allowed_signers) {
		*allowed_signers = strdup(got_allowed_signers);
		if (*allowed_signers == NULL)
			return got_error_from_errno("strdup");
	}
	return NULL;
}

static const struct got_error *
get_revoked_signers(char **revoked_signers, struct got_repository *repo,
    struct got_worktree *worktree)
{
	const char *got_revoked_signers = NULL;
	const struct got_gotconfig *worktree_conf = NULL, *repo_conf = NULL;

	*revoked_signers = NULL;

	if (worktree)
		worktree_conf = got_worktree_get_gotconfig(worktree);
	repo_conf = got_repo_get_gotconfig(repo);

	/*
	 * Priority of potential author information sources, from most
	 * significant to least significant:
	 * 1) work tree's .got/got.conf file
	 * 2) repository's got.conf file
	 */

	if (worktree_conf)
		got_revoked_signers = got_gotconfig_get_revoked_signers_file(
		    worktree_conf);
	if (got_revoked_signers == NULL)
		got_revoked_signers = got_gotconfig_get_revoked_signers_file(
		    repo_conf);

	if (got_revoked_signers) {
		*revoked_signers = strdup(got_revoked_signers);
		if (*revoked_signers == NULL)
			return got_error_from_errno("strdup");
	}
	return NULL;
}

static const char *
get_signer_id(struct got_repository *repo, struct got_worktree *worktree)
{
	const char *got_signer_id = NULL;
	const struct got_gotconfig *worktree_conf = NULL, *repo_conf = NULL;

	if (worktree)
		worktree_conf = got_worktree_get_gotconfig(worktree);
	repo_conf = got_repo_get_gotconfig(repo);

	/*
	 * Priority of potential author information sources, from most
	 * significant to least significant:
	 * 1) work tree's .got/got.conf file
	 * 2) repository's got.conf file
	 */

	if (worktree_conf)
		got_signer_id = got_gotconfig_get_signer_id(worktree_conf);
	if (got_signer_id == NULL)
		got_signer_id = got_gotconfig_get_signer_id(repo_conf);

	return got_signer_id;
}

static const struct got_error *
get_gitconfig_path(char **gitconfig_path)
{
	const char *homedir = getenv("HOME");

	*gitconfig_path = NULL;
	if (homedir) {
		if (asprintf(gitconfig_path, "%s/.gitconfig", homedir) == -1)
			return got_error_from_errno("asprintf");

	}
	return NULL;
}

static const struct got_error *
cmd_import(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *path_dir = NULL, *repo_path = NULL, *logmsg = NULL;
	char *gitconfig_path = NULL, *editor = NULL, *author = NULL;
	const char *branch_name = NULL;
	char *id_str = NULL, *logmsg_path = NULL;
	char refname[PATH_MAX] = "refs/heads/";
	struct got_repository *repo = NULL;
	struct got_reference *branch_ref = NULL, *head_ref = NULL;
	struct got_object_id *new_commit_id = NULL;
	int ch, n = 0;
	struct got_pathlist_head ignores;
	struct got_pathlist_entry *pe;
	int preserve_logmsg = 0;

	RB_INIT(&ignores);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "b:I:m:r:")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'I':
			if (optarg[0] == '\0')
				break;
			error = got_pathlist_insert(&pe, &ignores, optarg,
			    NULL);
			if (error)
				goto done;
			break;
		case 'm':
			logmsg = strdup(optarg);
			if (logmsg == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL) {
				error = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			break;
		default:
			usage_import(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_import(1);

	if (repo_path == NULL) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL) {
			error = got_error_from_errno("getcwd");
			goto done;
		}
	}
	got_path_strip_trailing_slashes(repo_path);
	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo, repo_path, gitconfig_path, NULL);
	if (error)
		goto done;

	path_dir = realpath(argv[0], NULL);
	if (path_dir == NULL) {
		error = got_error_from_errno2("realpath", argv[0]);
		goto done;
	}
	got_path_strip_trailing_slashes(path_dir);

	error = get_editor(&editor);
	if (error)
		goto done;

	if (unveil(path_dir, "r") != 0) {
		error = got_error_from_errno2("unveil", path_dir);
		goto done;
	}
	if (unveil(editor, "x") != 0) {
		error = got_error_from_errno2("unveil", editor);
		goto done;
	}
	error = apply_unveil(got_repo_get_path(repo), 0, NULL);
	if (error)
		goto done;

	error = get_author(&author, repo, NULL);
	if (error)
		goto done;

	/*
	 * Don't let the user create a branch name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (branch_name && branch_name[0] == '-') {
		error = got_error_path(branch_name, GOT_ERR_REF_NAME_MINUS);
		goto done;
	}

	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (error && error->code != GOT_ERR_NOT_REF)
		goto done;

	if (branch_name)
		n = strlcat(refname, branch_name, sizeof(refname));
	else if (head_ref && got_ref_is_symbolic(head_ref))
		n = strlcpy(refname, got_ref_get_symref_target(head_ref),
		    sizeof(refname));
	else
		n = strlcat(refname, "main", sizeof(refname));
	if (n >= sizeof(refname)) {
		error = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	error = got_ref_open(&branch_ref, repo, refname, 0);
	if (error) {
		if (error->code != GOT_ERR_NOT_REF)
			goto done;
	} else {
		error = got_error_msg(GOT_ERR_BRANCH_EXISTS,
		    "import target branch already exists");
		goto done;
	}

	if (logmsg == NULL || *logmsg == '\0') {
		free(logmsg);
		error = collect_import_msg(&logmsg, &logmsg_path, editor,
		    path_dir, refname);
		if (error) {
			if (error->code != GOT_ERR_COMMIT_MSG_EMPTY &&
			    logmsg_path != NULL)
				preserve_logmsg = 1;
			goto done;
		}
	}

	error = got_repo_import(&new_commit_id, path_dir, logmsg,
	    author, &ignores, repo, import_progress, NULL);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_alloc(&branch_ref, refname, new_commit_id);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_write(branch_ref, repo);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_object_id_str(&id_str, new_commit_id);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (error) {
		if (error->code != GOT_ERR_NOT_REF) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}

		error = got_ref_alloc_symref(&head_ref, GOT_REF_HEAD,
		    branch_ref);
		if (error) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}

		error = got_ref_write(head_ref, repo);
		if (error) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}
	}

	printf("Created branch %s with commit %s\n",
	    got_ref_get_name(branch_ref), id_str);
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (preserve_logmsg) {
		fprintf(stderr, "%s: log message preserved in %s\n",
		    getprogname(), logmsg_path);
	} else if (logmsg_path && unlink(logmsg_path) == -1 && error == NULL)
		error = got_error_from_errno2("unlink", logmsg_path);
	got_pathlist_free(&ignores, GOT_PATHLIST_FREE_NONE);
	free(logmsg);
	free(logmsg_path);
	free(path_dir);
	free(repo_path);
	free(editor);
	free(new_commit_id);
	free(id_str);
	free(author);
	free(gitconfig_path);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (head_ref)
		got_ref_close(head_ref);
	return error;
}

__dead static void
usage_clone(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s clone [-almqv] [-b branch] "
	    "[-i identity-file] [-J jumphost] [-R reference] "
	    "repository-URL [directory]\n", getprogname());
	exit(status);
}

struct got_fetch_progress_arg {
	char last_scaled_size[FMT_SCALED_STRSIZE];
	int last_p_indexed;
	int last_p_resolved;
	int verbosity;

	struct got_repository *repo;

	int create_configs;
	int configs_created;
	struct {
		struct got_pathlist_head *symrefs;
		struct got_pathlist_head *wanted_branches;
		struct got_pathlist_head *wanted_refs;
		const char *proto;
		const char *host;
		const char *port;
		const char *remote_repo_path;
		const char *git_url;
		int fetch_all_branches;
		int mirror_references;
	} config_info;
};

/* XXX forward declaration */
static const struct got_error *
create_config_files(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, const char *git_url, int fetch_all_branches,
    int mirror_references, struct got_pathlist_head *symrefs,
    struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, struct got_repository *repo);

static const struct got_error *
fetch_progress(void *arg, const char *message, off_t packfile_size,
    int nobj_total, int nobj_indexed, int nobj_loose, int nobj_resolved)
{
	const struct got_error *err = NULL;
	struct got_fetch_progress_arg *a = arg;
	char scaled_size[FMT_SCALED_STRSIZE];
	int p_indexed, p_resolved;
	int print_size = 0, print_indexed = 0, print_resolved = 0;

	/*
	 * In order to allow a failed clone to be resumed with 'got fetch'
	 * we try to create configuration files as soon as possible.
	 * Once the server has sent information about its default branch
	 * we have all required information.
	 */
	if (a->create_configs && !a->configs_created &&
	    !RB_EMPTY(a->config_info.symrefs)) {
		err = create_config_files(a->config_info.proto,
		    a->config_info.host, a->config_info.port,
		    a->config_info.remote_repo_path,
		    a->config_info.git_url,
		    a->config_info.fetch_all_branches,
		    a->config_info.mirror_references,
		    a->config_info.symrefs,
		    a->config_info.wanted_branches,
		    a->config_info.wanted_refs, a->repo);
		if (err)
			return err;
		a->configs_created = 1;
	}

	if (a->verbosity < 0)
		return NULL;

	if (message && message[0] != '\0') {
		printf("\rserver: %s", message);
		fflush(stdout);
		return NULL;
	}

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
		printf("%*s fetched", FMT_SCALED_STRSIZE - 2, scaled_size);
	if (print_indexed)
		printf("; indexing %d%%", p_indexed);
	if (print_resolved)
		printf("; resolving deltas %d%%", p_resolved);
	if (print_size || print_indexed || print_resolved)
		fflush(stdout);

	return NULL;
}

static const struct got_error *
create_symref(const char *refname, struct got_reference *target_ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *head_symref;

	err = got_ref_alloc_symref(&head_symref, refname, target_ref);
	if (err)
		return err;

	err = got_ref_write(head_symref, repo);
	if (err == NULL && verbosity > 0) {
		printf("Created reference %s: %s\n", GOT_REF_HEAD,
		    got_ref_get_name(target_ref));
	}
	got_ref_close(head_symref);
	return err;
}

static const struct got_error *
list_remote_refs(struct got_pathlist_head *symrefs,
    struct got_pathlist_head *refs)
{
	const struct got_error *err;
	struct got_pathlist_entry *pe;

	RB_FOREACH(pe, got_pathlist_head, symrefs) {
		const char *refname = pe->path;
		const char *targetref = pe->data;

		printf("%s: %s\n", refname, targetref);
	}

	RB_FOREACH(pe,got_pathlist_head, refs) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		char *id_str;

		err = got_object_id_str(&id_str, id);
		if (err)
			return err;
		printf("%s: %s\n", refname, id_str);
		free(id_str);
	}

	return NULL;
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

static int
match_wanted_ref(const char *refname, const char *wanted_ref)
{
	if (strncmp(refname, "refs/", 5) != 0)
		return 0;
	refname += 5;

	/*
	 * Prevent fetching of references that won't make any
	 * sense outside of the remote repository's context.
	 */
	if (strncmp(refname, "got/", 4) == 0)
		return 0;
	if (strncmp(refname, "remotes/", 8) == 0)
		return 0;

	if (strncmp(wanted_ref, "refs/", 5) == 0)
		wanted_ref += 5;

	/* Allow prefix match. */
	if (got_path_is_child(refname, wanted_ref, strlen(wanted_ref)))
		return 1;

	/* Allow exact match. */
	return (strcmp(refname, wanted_ref) == 0);
}

static int
is_wanted_ref(struct got_pathlist_head *wanted_refs, const char *refname)
{
	struct got_pathlist_entry *pe;

	RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
		if (match_wanted_ref(refname, pe->path))
			return 1;
	}

	return 0;
}

static const struct got_error *
create_wanted_ref(const char *refname, struct got_object_id *id,
    const char *remote_repo_name, int verbosity, struct got_repository *repo)
{
	const struct got_error *err;
	char *remote_refname;

	if (strncmp("refs/", refname, 5) == 0)
		refname += 5;

	if (asprintf(&remote_refname, "refs/remotes/%s/%s",
	    remote_repo_name, refname) == -1)
		return got_error_from_errno("asprintf");

	err = create_ref(remote_refname, id, verbosity, repo);
	free(remote_refname);
	return err;
}

static const struct got_error *
create_gotconfig(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, const char *default_branch,
    int fetch_all_branches, struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, int mirror_references,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *gotconfig_path = NULL;
	char *gotconfig = NULL;
	FILE *gotconfig_file = NULL;
	const char *branchname = NULL;
	char *branches = NULL, *refs = NULL;
	ssize_t n;

	if (!fetch_all_branches && !RB_EMPTY(wanted_branches)) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, wanted_branches) {
			char *s;
			branchname = pe->path;
			if (strncmp(branchname, "refs/heads/", 11) == 0)
				branchname += 11;
			if (asprintf(&s, "%s\"%s\" ",
			    branches ? branches : "", branchname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			free(branches);
			branches = s;
		}
	} else if (!fetch_all_branches && default_branch) {
		branchname = default_branch;
		if (strncmp(branchname, "refs/heads/", 11) == 0)
			branchname += 11;
		if (asprintf(&branches, "\"%s\" ", branchname) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}
	if (!RB_EMPTY(wanted_refs)) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
			char *s;
			const char *refname = pe->path;
			if (strncmp(refname, "refs/", 5) == 0)
				branchname += 5;
			if (asprintf(&s, "%s\"%s\" ",
			    refs ? refs : "", refname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			free(refs);
			refs = s;
		}
	}

	/* Create got.conf(5). */
	gotconfig_path = got_repo_get_path_gotconfig(repo);
	if (gotconfig_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_gotconfig");
		goto done;
	}
	gotconfig_file = fopen(gotconfig_path, "ae");
	if (gotconfig_file == NULL) {
		err = got_error_from_errno2("fopen", gotconfig_path);
		goto done;
	}
	if (asprintf(&gotconfig,
	    "remote \"%s\" {\n"
	    "\tserver %s\n"
	    "\tprotocol %s\n"
	    "%s%s%s"
	    "\trepository \"%s\"\n"
	    "%s"
	    "%s%s%s"
	    "%s"
	    "%s%s%s"
	    "%s"
	    "%s"
	    "}\n",
	    GOT_FETCH_DEFAULT_REMOTE_NAME, host, proto,
	    port ? "\tport " : "", port ? port : "", port ? "\n" : "",
	    remote_repo_path,
	    branches ? "\tfetch {\n" : "",
	    branches ? "\t\tbranch { " : "",
	    branches ? branches : "",
	    branches ? "}\n" : "",
	    branches ? "\t}\n" : "",
	    refs ? "\treference { " : "", refs ? refs : "", refs ? "}\n" : "",
	    mirror_references ? "\tmirror_references yes\n" : "",
	    fetch_all_branches ? "\tfetch_all_branches yes\n" : "") == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	n = fwrite(gotconfig, 1, strlen(gotconfig), gotconfig_file);
	if (n != strlen(gotconfig)) {
		err = got_ferror(gotconfig_file, GOT_ERR_IO);
		goto done;
	}

done:
	if (gotconfig_file && fclose(gotconfig_file) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", gotconfig_path);
	free(gotconfig_path);
	free(branches);
	return err;
}

static const struct got_error *
create_gitconfig(const char *git_url, const char *default_branch,
    int fetch_all_branches, struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, int mirror_references,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *gitconfig_path = NULL;
	char *gitconfig = NULL;
	FILE *gitconfig_file = NULL;
	char *branches = NULL, *refs = NULL;
	const char *branchname;
	ssize_t n;

	/* Create a config file Git can understand. */
	gitconfig_path = got_repo_get_path_gitconfig(repo);
	if (gitconfig_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_gitconfig");
		goto done;
	}
	gitconfig_file = fopen(gitconfig_path, "ae");
	if (gitconfig_file == NULL) {
		err = got_error_from_errno2("fopen", gitconfig_path);
		goto done;
	}
	if (fetch_all_branches) {
		if (mirror_references) {
			if (asprintf(&branches,
			    "\tfetch = refs/heads/*:refs/heads/*\n") == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		} else if (asprintf(&branches,
		    "\tfetch = refs/heads/*:refs/remotes/%s/*\n",
		    GOT_FETCH_DEFAULT_REMOTE_NAME) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	} else if (!RB_EMPTY(wanted_branches)) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, wanted_branches) {
			char *s;
			branchname = pe->path;
			if (strncmp(branchname, "refs/heads/", 11) == 0)
				branchname += 11;
			if (mirror_references) {
				if (asprintf(&s,
				    "%s\tfetch = refs/heads/%s:refs/heads/%s\n",
				    branches ? branches : "",
				    branchname, branchname) == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
			} else if (asprintf(&s,
			    "%s\tfetch = refs/heads/%s:refs/remotes/%s/%s\n",
			    branches ? branches : "",
			    branchname, GOT_FETCH_DEFAULT_REMOTE_NAME,
			    branchname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			free(branches);
			branches = s;
		}
	} else {
		/*
		 * If the server specified a default branch, use just that one.
		 * Otherwise fall back to fetching all branches on next fetch.
		 */
		if (default_branch) {
			branchname = default_branch;
			if (strncmp(branchname, "refs/heads/", 11) == 0)
				branchname += 11;
		} else
			branchname = "*"; /* fall back to all branches */
		if (mirror_references) {
			if (asprintf(&branches,
			    "\tfetch = refs/heads/%s:refs/heads/%s\n",
			    branchname, branchname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
		} else if (asprintf(&branches,
		    "\tfetch = refs/heads/%s:refs/remotes/%s/%s\n",
		    branchname, GOT_FETCH_DEFAULT_REMOTE_NAME,
		    branchname) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}
	if (!RB_EMPTY(wanted_refs)) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, wanted_refs) {
			char *s;
			const char *refname = pe->path;
			if (strncmp(refname, "refs/", 5) == 0)
				refname += 5;
			if (mirror_references) {
				if (asprintf(&s,
				    "%s\tfetch = refs/%s:refs/%s\n",
				    refs ? refs : "", refname, refname) == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
			} else if (asprintf(&s,
			    "%s\tfetch = refs/%s:refs/remotes/%s/%s\n",
			    refs ? refs : "",
			    refname, GOT_FETCH_DEFAULT_REMOTE_NAME,
			    refname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			free(refs);
			refs = s;
		}
	}

	if (asprintf(&gitconfig,
	    "[remote \"%s\"]\n"
	    "\turl = %s\n"
	    "%s"
	    "%s"
	    "\tfetch = refs/tags/*:refs/tags/*\n",
	    GOT_FETCH_DEFAULT_REMOTE_NAME, git_url, branches ? branches : "",
	    refs ? refs : "") == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	n = fwrite(gitconfig, 1, strlen(gitconfig), gitconfig_file);
	if (n != strlen(gitconfig)) {
		err = got_ferror(gitconfig_file, GOT_ERR_IO);
		goto done;
	}
done:
	if (gitconfig_file && fclose(gitconfig_file) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", gitconfig_path);
	free(gitconfig_path);
	free(branches);
	return err;
}

static const struct got_error *
create_config_files(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, const char *git_url, int fetch_all_branches,
    int mirror_references, struct got_pathlist_head *symrefs,
    struct got_pathlist_head *wanted_branches,
    struct got_pathlist_head *wanted_refs, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	const char *default_branch = NULL;
	struct got_pathlist_entry *pe;

	/*
	 * If we asked for a set of wanted branches then use the first
	 * one of those.
	 */
	if (!RB_EMPTY(wanted_branches)) {
		pe = RB_MIN(got_pathlist_head, wanted_branches);
		default_branch = pe->path;
	} else {
		/* First HEAD ref listed by server is the default branch. */
		RB_FOREACH(pe, got_pathlist_head, symrefs) {
			const char *refname = pe->path;
			const char *target = pe->data;

			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;

			default_branch = target;
			break;
		}
	}

	/* Create got.conf(5). */
	err = create_gotconfig(proto, host, port, remote_repo_path,
	    default_branch, fetch_all_branches, wanted_branches,
	    wanted_refs, mirror_references, repo);
	if (err)
		return err;

	/* Create a config file Git can understand. */
	return create_gitconfig(git_url, default_branch, fetch_all_branches,
	    wanted_branches, wanted_refs, mirror_references, repo);
}

static const struct got_error *
cmd_clone(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	const char *uri, *dirname;
	char *proto, *host, *port, *repo_name, *server_path;
	char *default_destdir = NULL, *id_str = NULL;
	const char *repo_path;
	struct got_repository *repo = NULL;
	struct got_pathlist_head refs, symrefs, wanted_branches, wanted_refs;
	struct got_pathlist_entry *pe;
	struct got_object_id *pack_hash = NULL;
	int ch, fetchfd = -1, fetchstatus;
	pid_t fetchpid = -1;
	struct got_fetch_progress_arg fpa;
	char *git_url = NULL;
	const char *jumphost = NULL, *identity_file = NULL;
	int verbosity = 0, fetch_all_branches = 0, mirror_references = 0;
	int bflag = 0, list_refs_only = 0;
	int *pack_fds = NULL, have_head_ref = 0;

	RB_INIT(&refs);
	RB_INIT(&symrefs);
	RB_INIT(&wanted_branches);
	RB_INIT(&wanted_refs);

	while ((ch = getopt(argc, argv, "ab:i:J:lmqR:v")) != -1) {
		switch (ch) {
		case 'a':
			fetch_all_branches = 1;
			break;
		case 'b':
			error = got_pathlist_insert(NULL, &wanted_branches,
			    optarg, NULL);
			if (error)
				return error;
			bflag = 1;
			break;
		case 'i':
			identity_file = optarg;
			break;
		case 'J':
			jumphost = optarg;
			break;
		case 'l':
			list_refs_only = 1;
			break;
		case 'm':
			mirror_references = 1;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'R':
			error = got_pathlist_insert(NULL, &wanted_refs,
			    optarg, NULL);
			if (error)
				return error;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		default:
			usage_clone(1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fetch_all_branches && !RB_EMPTY(&wanted_branches))
		option_conflict('a', 'b');
	if (list_refs_only) {
		if (!RB_EMPTY(&wanted_branches))
			option_conflict('l', 'b');
		if (fetch_all_branches)
			option_conflict('l', 'a');
		if (mirror_references)
			option_conflict('l', 'm');
		if (!RB_EMPTY(&wanted_refs))
			option_conflict('l', 'R');
	}

	uri = argv[0];

	if (argc == 1)
		dirname = NULL;
	else if (argc == 2)
		dirname = argv[1];
	else
		usage_clone(1);

	error = got_dial_parse_uri(&proto, &host, &port, &server_path,
	    &repo_name, uri);
	if (error)
		goto done;

	if (asprintf(&git_url, "%s://%s%s%s%s%s", proto,
	    host, port ? ":" : "", port ? port : "",
	    server_path[0] != '/' ? "/" : "", server_path) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (strcmp(proto, "git") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd dns inet unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "git+ssh") == 0 ||
	    strcmp(proto, "ssh") == 0 ||
	    strcmp(proto, "git+http") == 0 ||
	    strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+https") == 0 ||
	    strcmp(proto, "https") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else {
		error = got_error_path(proto, GOT_ERR_BAD_PROTO);
		goto done;
	}
	if (dirname == NULL) {
		if (asprintf(&default_destdir, "%s.git", repo_name) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		repo_path = default_destdir;
	} else
		repo_path = dirname;

	if (!list_refs_only) {
		error = got_path_mkdir(repo_path);
		if (error &&
		    (!(error->code == GOT_ERR_ERRNO && errno == EISDIR) &&
		    !(error->code == GOT_ERR_ERRNO && errno == EEXIST)))
			goto done;
		if (!got_path_dir_is_empty(repo_path)) {
			error = got_error_path(repo_path,
			    GOT_ERR_DIR_NOT_EMPTY);
			goto done;
		}
	}

	error = got_dial_apply_unveil(proto);
	if (error)
		goto done;

	error = apply_unveil(repo_path, 0, NULL);
	if (error)
		goto done;

	if (verbosity >= 0)
		printf("Connecting to %s\n", git_url);

	error = got_fetch_connect(&fetchpid, &fetchfd, proto, host, port,
	    server_path, jumphost, identity_file, verbosity);
	if (error)
		goto done;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd",
	     NULL) == -1)
		err(1, "pledge");
#endif
	if (!list_refs_only) {
		error = got_repo_init(repo_path, NULL, GOT_HASH_SHA1);
		if (error)
			goto done;
		error = got_repo_pack_fds_open(&pack_fds);
		if (error != NULL)
			goto done;
		error = got_repo_open(&repo, repo_path, NULL, pack_fds);
		if (error)
			goto done;
	}

	fpa.last_scaled_size[0] = '\0';
	fpa.last_p_indexed = -1;
	fpa.last_p_resolved = -1;
	fpa.verbosity = verbosity;
	fpa.create_configs = 1;
	fpa.configs_created = 0;
	fpa.repo = repo;
	fpa.config_info.symrefs = &symrefs;
	fpa.config_info.wanted_branches = &wanted_branches;
	fpa.config_info.wanted_refs = &wanted_refs;
	fpa.config_info.proto = proto;
	fpa.config_info.host = host;
	fpa.config_info.port = port;
	fpa.config_info.remote_repo_path = server_path;
	fpa.config_info.git_url = git_url;
	fpa.config_info.fetch_all_branches = fetch_all_branches;
	fpa.config_info.mirror_references = mirror_references;
	error = got_fetch_pack(&pack_hash, &refs, &symrefs,
	    GOT_FETCH_DEFAULT_REMOTE_NAME, mirror_references,
	    fetch_all_branches, &wanted_branches, &wanted_refs,
	    list_refs_only, verbosity, fetchfd, repo, NULL, NULL, bflag,
	    fetch_progress, &fpa);
	if (error)
		goto done;

	if (list_refs_only) {
		error = list_remote_refs(&symrefs, &refs);
		goto done;
	}

	if (pack_hash == NULL) {
		error = got_error_fmt(GOT_ERR_FETCH_FAILED, "%s",
		    "server sent an empty pack file");
		goto done;
	}
	error = got_object_id_str(&id_str, pack_hash);
	if (error)
		goto done;
	if (verbosity >= 0)
		printf("\nFetched %s.pack\n", id_str);
	free(id_str);

	/* Set up references provided with the pack file. */
	RB_FOREACH(pe, got_pathlist_head, &refs) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		char *remote_refname;

		if (is_wanted_ref(&wanted_refs, refname) &&
		    !mirror_references) {
			error = create_wanted_ref(refname, id,
			    GOT_FETCH_DEFAULT_REMOTE_NAME,
			    verbosity - 1, repo);
			if (error)
				goto done;
			continue;
		}

		error = create_ref(refname, id, verbosity - 1, repo);
		if (error)
			goto done;

		if (mirror_references)
			continue;

		if (strncmp("refs/heads/", refname, 11) != 0)
			continue;

		if (asprintf(&remote_refname,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    refname + 11) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		error = create_ref(remote_refname, id, verbosity - 1, repo);
		free(remote_refname);
		if (error)
			goto done;
	}

	/* Set the HEAD reference if the server provided one. */
	RB_FOREACH(pe, got_pathlist_head, &symrefs) {
		struct got_reference *target_ref;
		const char *refname = pe->path;
		const char *target = pe->data;
		char *remote_refname = NULL, *remote_target = NULL;

		if (strcmp(refname, GOT_REF_HEAD) != 0)
			continue;

		error = got_ref_open(&target_ref, repo, target, 0);
		if (error) {
			if (error->code == GOT_ERR_NOT_REF) {
				error = NULL;
				continue;
			}
			goto done;
		}

		error = create_symref(refname, target_ref, verbosity, repo);
		got_ref_close(target_ref);
		if (error)
			goto done;
		have_head_ref = 1;

		if (mirror_references)
			continue;

		if (strncmp("refs/heads/", target, 11) != 0)
			continue;

		if (asprintf(&remote_refname,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    refname) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&remote_target,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    target + 11) == -1) {
			error = got_error_from_errno("asprintf");
			free(remote_refname);
			goto done;
		}
		error = got_ref_open(&target_ref, repo, remote_target, 0);
		if (error) {
			free(remote_refname);
			free(remote_target);
			if (error->code == GOT_ERR_NOT_REF) {
				error = NULL;
				continue;
			}
			goto done;
		}
		error = create_symref(remote_refname, target_ref,
		    verbosity - 1, repo);
		free(remote_refname);
		free(remote_target);
		got_ref_close(target_ref);
		if (error)
			goto done;
	}
	if (!have_head_ref) {
		/*
		 * We failed to set the HEAD reference. If we asked for
		 * a set of wanted branches use the first of one of those
		 * which could be fetched instead.
		 */
		RB_FOREACH(pe, got_pathlist_head, &wanted_branches) {
			const char *target = pe->path;
			struct got_reference *target_ref;

			error = got_ref_open(&target_ref, repo, target, 0);
			if (error) {
				if (error->code == GOT_ERR_NOT_REF) {
					error = NULL;
					continue;
				}
				goto done;
			}

			error = create_symref(GOT_REF_HEAD, target_ref,
			    verbosity, repo);
			got_ref_close(target_ref);
			if (error)
				goto done;
			have_head_ref = 1;
			break;
		}

		/*
		 * If we have no HEAD ref yet, set it to the first branch
		 * which was fetched.
		 */
		if (!have_head_ref) {
			RB_FOREACH(pe, got_pathlist_head, &refs) {
				const char *refname = pe->path;
				struct got_reference *target_ref;

				if (strncmp("refs/heads/", refname, 11) != 0)
					continue;

				error = got_ref_open(&target_ref, repo,
				    refname, 0);
				if (error) {
					if (error->code == GOT_ERR_NOT_REF) {
						error = NULL;
						continue;
					}
					goto done;
				}

				error = create_symref(GOT_REF_HEAD, target_ref,
				    verbosity, repo);
				got_ref_close(target_ref);
				if (error)
					goto done;
				break;
			}
		}

		if (!fpa.configs_created && pe != NULL) {
			error = create_config_files(fpa.config_info.proto,
			    fpa.config_info.host, fpa.config_info.port,
			    fpa.config_info.remote_repo_path,
			    fpa.config_info.git_url,
			    fpa.config_info.fetch_all_branches,
			    fpa.config_info.mirror_references,
			    fpa.config_info.symrefs,
			    fpa.config_info.wanted_branches,
			    fpa.config_info.wanted_refs, fpa.repo);
			if (error)
				goto done;
		}
	}

	if (verbosity >= 0)
		printf("Created %s repository '%s'\n",
		    mirror_references ? "mirrored" : "cloned", repo_path);
done:
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (fetchpid > 0) {
		if (kill(fetchpid, SIGTERM) == -1)
			error = got_error_from_errno("kill");
		if (waitpid(fetchpid, &fetchstatus, 0) == -1 && error == NULL)
			error = got_error_from_errno("waitpid");
	}
	if (fetchfd != -1 && close(fetchfd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	got_pathlist_free(&refs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&symrefs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&wanted_branches, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&wanted_refs, GOT_PATHLIST_FREE_NONE);
	free(pack_hash);
	free(proto);
	free(host);
	free(port);
	free(server_path);
	free(repo_name);
	free(default_destdir);
	free(git_url);
	return error;
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
update_symref(const char *refname, struct got_reference *target_ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err;
	struct got_reference *symref;
	int symref_is_locked = 0;

	err = got_ref_open(&symref, repo, refname, 1);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			return err;
		err = got_ref_alloc_symref(&symref, refname, target_ref);
		if (err)
			goto done;

		err = got_ref_write(symref, repo);
		if (err)
			goto done;

		if (verbosity >= 0)
			printf("Created reference %s: %s\n",
			    got_ref_get_name(symref),
			    got_ref_get_symref_target(symref));
	} else {
		symref_is_locked = 1;

		if (strcmp(got_ref_get_symref_target(symref),
		    got_ref_get_name(target_ref)) == 0)
			goto done;

		err = got_ref_change_symref(symref,
		    got_ref_get_name(target_ref));
		if (err)
			goto done;

		err = got_ref_write(symref, repo);
		if (err)
			goto done;

		if (verbosity >= 0)
			printf("Updated %s: %s\n", got_ref_get_name(symref),
			    got_ref_get_symref_target(symref));

	}
done:
	if (symref_is_locked) {
		unlock_err = got_ref_unlock(symref);
		if (unlock_err && err == NULL)
			err = unlock_err;
	}
	got_ref_close(symref);
	return err;
}

__dead static void
usage_fetch(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s fetch [-adlqtvX] [-b branch] "
	    "[-i identity-file] [-J jumphost] [-R reference] "
	    "[-r repository-path] [remote-repository]\n", getprogname());
	exit(status);
}

static const struct got_error *
delete_missing_ref(struct got_reference *ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	char *id_str = NULL;

	if (got_ref_is_symbolic(ref)) {
		err = got_ref_delete(ref, repo);
		if (err)
			return err;
		if (verbosity >= 0) {
			printf("Deleted %s: %s\n",
			    got_ref_get_name(ref),
			    got_ref_get_symref_target(ref));
		}
	} else {
		err = got_ref_resolve(&id, repo, ref);
		if (err)
			return err;
		err = got_object_id_str(&id_str, id);
		if (err)
			goto done;

		err = got_ref_delete(ref, repo);
		if (err)
			goto done;
		if (verbosity >= 0) {
			printf("Deleted %s: %s\n",
			    got_ref_get_name(ref), id_str);
		}
	}
done:
	free(id);
	free(id_str);
	return err;
}

static const struct got_error *
delete_missing_refs(struct got_pathlist_head *their_refs,
    struct got_pathlist_head *their_symrefs,
    const struct got_remote_repo *remote,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err;
	struct got_reflist_head my_refs;
	struct got_reflist_entry *re;
	struct got_pathlist_entry *pe;
	char *remote_namespace = NULL;
	char *local_refname = NULL;

	TAILQ_INIT(&my_refs);

	if (asprintf(&remote_namespace, "refs/remotes/%s/", remote->name)
	    == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_list(&my_refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &my_refs, entry) {
		const char *refname = got_ref_get_name(re->ref);
		const char *their_refname;

		if (strcmp(refname, GOT_REF_HEAD) == 0 ||
		    strncmp(refname, "refs/got/", 9) == 0)
			continue;

		if (remote->mirror_references) {
			their_refname = refname;
		} else {
			if (strncmp(refname, remote_namespace,
			    strlen(remote_namespace)) == 0) {
				if (strcmp(refname + strlen(remote_namespace),
				    GOT_REF_HEAD) == 0)
					continue;
				if (asprintf(&local_refname, "refs/heads/%s",
				    refname + strlen(remote_namespace)) == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
			} else if (strncmp(refname, "refs/tags/", 10) != 0)
				continue;

			their_refname = local_refname;
		}

		RB_FOREACH(pe, got_pathlist_head, their_refs) {
			if (strcmp(their_refname, pe->path) == 0)
				break;
		}
		if (pe != NULL)
			continue;

		RB_FOREACH(pe, got_pathlist_head, their_symrefs) {
			if (strcmp(their_refname, pe->path) == 0)
				break;
		}
		if (pe != NULL)
			continue;

		err = delete_missing_ref(re->ref, verbosity, repo);
		if (err)
			break;

		if (local_refname) {
			struct got_reference *ref;
			err = got_ref_open(&ref, repo, local_refname, 1);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					break;
				free(local_refname);
				local_refname = NULL;
				continue;
			}
			err = delete_missing_ref(ref, verbosity, repo);
			if (err)
				break;
			unlock_err = got_ref_unlock(ref);
			got_ref_close(ref);
			if (unlock_err && err == NULL) {
				err = unlock_err;
				break;
			}

			free(local_refname);
			local_refname = NULL;
		}
	}
done:
	got_ref_list_free(&my_refs);
	free(remote_namespace);
	free(local_refname);
	return err;
}

static const struct got_error *
update_wanted_ref(const char *refname, struct got_object_id *id,
    const char *remote_repo_name, int verbosity, struct got_repository *repo)
{
	const struct got_error *err, *unlock_err;
	char *remote_refname;
	struct got_reference *ref;

	if (strncmp("refs/", refname, 5) == 0)
		refname += 5;

	if (asprintf(&remote_refname, "refs/remotes/%s/%s",
	    remote_repo_name, refname) == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_open(&ref, repo, remote_refname, 1);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = create_ref(remote_refname, id, verbosity, repo);
	} else {
		err = update_ref(ref, id, 0, verbosity, repo);
		unlock_err = got_ref_unlock(ref);
		if (unlock_err && err == NULL)
			err = unlock_err;
		got_ref_close(ref);
	}
done:
	free(remote_refname);
	return err;
}

static const struct got_error *
delete_ref(struct got_repository *repo, struct got_reference *ref)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	char *id_str = NULL;
	const char *target;

	if (got_ref_is_symbolic(ref)) {
		target = got_ref_get_symref_target(ref);
	} else {
		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;
		err = got_object_id_str(&id_str, id);
		if (err)
			goto done;
		target = id_str;
	}

	err = got_ref_delete(ref, repo);
	if (err)
		goto done;

	printf("Deleted %s: %s\n", got_ref_get_name(ref), target);
done:
	free(id);
	free(id_str);
	return err;
}

static const struct got_error *
delete_refs_for_remote(struct got_repository *repo, const char *remote_name)
{
	const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *prefix;

	TAILQ_INIT(&refs);

	if (asprintf(&prefix, "refs/remotes/%s", remote_name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_ref_list(&refs, repo, prefix, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &refs, entry)
		delete_ref(repo, re->ref);
done:
	got_ref_list_free(&refs);
	return err;
}

static const struct got_error *
cmd_fetch(int argc, char *argv[])
{
	const struct got_error *error = NULL, *unlock_err;
	char *cwd = NULL, *repo_path = NULL;
	const char *remote_name;
	char *proto = NULL, *host = NULL, *port = NULL;
	char *repo_name = NULL, *server_path = NULL;
	const struct got_remote_repo *remotes;
	struct got_remote_repo *remote = NULL;
	int nremotes;
	char *id_str = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	const struct got_gotconfig *repo_conf = NULL, *worktree_conf = NULL;
	struct got_pathlist_head refs, symrefs, wanted_branches, wanted_refs;
	char *head_refname = NULL;
	struct got_pathlist_entry *pe;
	struct got_reflist_head remote_refs;
	struct got_reflist_entry *re;
	struct got_object_id *pack_hash = NULL;
	int i, ch, fetchfd = -1, fetchstatus;
	pid_t fetchpid = -1;
	struct got_fetch_progress_arg fpa;
	int verbosity = 0, fetch_all_branches = 0, list_refs_only = 0;
	int delete_refs = 0, replace_tags = 0, delete_remote = 0;
	int *pack_fds = NULL, have_bflag = 0;
	const char *remote_head = NULL, *worktree_branch = NULL;
	const char *jumphost = NULL, *identity_file = NULL;

	RB_INIT(&refs);
	RB_INIT(&symrefs);
	TAILQ_INIT(&remote_refs);
	RB_INIT(&wanted_branches);
	RB_INIT(&wanted_refs);

	while ((ch = getopt(argc, argv, "ab:di:J:lqR:r:tvX")) != -1) {
		switch (ch) {
		case 'a':
			fetch_all_branches = 1;
			break;
		case 'b':
			error = got_pathlist_insert(NULL, &wanted_branches,
			    optarg, NULL);
			if (error)
				return error;
			have_bflag = 1;
			break;
		case 'd':
			delete_refs = 1;
			break;
		case 'i':
			identity_file = optarg;
			break;
		case 'J':
			jumphost = optarg;
			break;
		case 'l':
			list_refs_only = 1;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'R':
			error = got_pathlist_insert(NULL, &wanted_refs,
			    optarg, NULL);
			if (error)
				return error;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 't':
			replace_tags = 1;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		case 'X':
			delete_remote = 1;
			break;
		default:
			usage_fetch(1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fetch_all_branches && !RB_EMPTY(&wanted_branches))
		option_conflict('a', 'b');
	if (list_refs_only) {
		if (!RB_EMPTY(&wanted_branches))
			option_conflict('l', 'b');
		if (fetch_all_branches)
			option_conflict('l', 'a');
		if (delete_refs)
			option_conflict('l', 'd');
		if (delete_remote)
			option_conflict('l', 'X');
	}
	if (delete_remote) {
		if (fetch_all_branches)
			option_conflict('X', 'a');
		if (!RB_EMPTY(&wanted_branches))
			option_conflict('X', 'b');
		if (delete_refs)
			option_conflict('X', 'd');
		if (replace_tags)
			option_conflict('X', 't');
		if (!RB_EMPTY(&wanted_refs))
			option_conflict('X', 'R');
	}

	if (argc == 0) {
		if (delete_remote)
			errx(1, "-X option requires a remote name");
		remote_name = GOT_FETCH_DEFAULT_REMOTE_NAME;
	} else if (argc == 1)
		remote_name = argv[0];
	else
		usage_fetch(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	if (delete_remote) {
		error = delete_refs_for_remote(repo, remote_name);
		goto done; /* nothing else to do */
	}

	if (worktree) {
		worktree_conf = got_worktree_get_gotconfig(worktree);
		if (worktree_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    worktree_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					error = got_repo_remote_repo_dup(&remote,
					    &remotes[i]);
					if (error)
						goto done;
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		repo_conf = got_repo_get_gotconfig(repo);
		if (repo_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    repo_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					error = got_repo_remote_repo_dup(&remote,
					    &remotes[i]);
					if (error)
						goto done;
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		got_repo_get_gitconfig_remotes(&nremotes, &remotes, repo);
		for (i = 0; i < nremotes; i++) {
			if (strcmp(remotes[i].name, remote_name) == 0) {
				error = got_repo_remote_repo_dup(&remote,
				    &remotes[i]);
				if (error)
					goto done;
				break;
			}
		}
	}
	if (remote == NULL) {
		error = got_error_path(remote_name, GOT_ERR_NO_REMOTE);
		goto done;
	}

	if (RB_EMPTY(&wanted_branches)) {
		if (!fetch_all_branches)
			fetch_all_branches = remote->fetch_all_branches;
		for (i = 0; i < remote->nfetch_branches; i++) {
			error = got_pathlist_insert(NULL, &wanted_branches,
			    remote->fetch_branches[i], NULL);
			if (error)
				goto done;
		}
	}
	if (RB_EMPTY(&wanted_refs)) {
		for (i = 0; i < remote->nfetch_refs; i++) {
			error = got_pathlist_insert(NULL, &wanted_refs,
			    remote->fetch_refs[i], NULL);
			if (error)
				goto done;
		}
	}

	error = got_dial_parse_uri(&proto, &host, &port, &server_path,
	    &repo_name, remote->fetch_url);
	if (error)
		goto done;

	if (strcmp(proto, "git") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd dns inet unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "git+ssh") == 0 ||
	    strcmp(proto, "ssh") == 0 ||
	    strcmp(proto, "git+http") == 0 ||
	    strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+https") == 0 ||
	    strcmp(proto, "https") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else {
		error = got_error_path(proto, GOT_ERR_BAD_PROTO);
		goto done;
	}

	error = got_dial_apply_unveil(proto);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0, NULL);
	if (error)
		goto done;

	if (worktree) {
		head_refname = strdup(got_worktree_get_head_ref_name(worktree));
		if (head_refname == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}

		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	if (verbosity >= 0) {
		printf("Connecting to \"%s\" %s://%s%s%s%s%s\n",
		    remote->name, proto, host,
		    port ? ":" : "", port ? port : "",
		    *server_path == '/' ? "" : "/", server_path);
	}

	error = got_fetch_connect(&fetchpid, &fetchfd, proto, host, port,
	    server_path, jumphost, identity_file, verbosity);
	if (error)
		goto done;
#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd",
	     NULL) == -1)
		err(1, "pledge");
#endif
	if (!have_bflag) {
		/*
		 * If set, get this remote's HEAD ref target so
		 * if it has changed on the server we can fetch it.
		 */
		error = got_ref_list(&remote_refs, repo, "refs/remotes",
		    got_ref_cmp_by_name, repo);
		if (error)
			goto done;

		TAILQ_FOREACH(re, &remote_refs, entry) {
			const char	*remote_refname, *remote_target;
			size_t		 remote_name_len;

			if (!got_ref_is_symbolic(re->ref))
				continue;

			remote_name_len = strlen(remote->name);
			remote_refname = got_ref_get_name(re->ref);

			/* we only want refs/remotes/$remote->name/HEAD */
			if (strncmp(remote_refname + 13, remote->name,
			    remote_name_len) != 0)
				continue;

			if (strcmp(remote_refname + remote_name_len + 14,
			    GOT_REF_HEAD) != 0)
				continue;

			/*
			 * Take the name itself because we already
			 * only match with refs/heads/ in fetch_pack().
			 */
			remote_target = got_ref_get_symref_target(re->ref);
			remote_head = remote_target + remote_name_len + 14;
			break;
		}

		if (head_refname &&
		    strncmp(head_refname, "refs/heads/", 11) == 0)
			worktree_branch = head_refname;
	}

	fpa.last_scaled_size[0] = '\0';
	fpa.last_p_indexed = -1;
	fpa.last_p_resolved = -1;
	fpa.verbosity = verbosity;
	fpa.repo = repo;
	fpa.create_configs = 0;
	fpa.configs_created = 0;
	memset(&fpa.config_info, 0, sizeof(fpa.config_info));

	error = got_fetch_pack(&pack_hash, &refs, &symrefs, remote->name,
	    remote->mirror_references, fetch_all_branches, &wanted_branches,
	    &wanted_refs, list_refs_only, verbosity, fetchfd, repo,
	    worktree_branch, remote_head, have_bflag, fetch_progress, &fpa);
	if (error)
		goto done;

	if (list_refs_only) {
		error = list_remote_refs(&symrefs, &refs);
		goto done;
	}

	if (pack_hash == NULL) {
		if (verbosity >= 0)
			printf("Already up-to-date\n");
	} else if (verbosity >= 0) {
		error = got_object_id_str(&id_str, pack_hash);
		if (error)
			goto done;
		printf("\nFetched %s.pack\n", id_str);
		free(id_str);
		id_str = NULL;
	}

	/* Update references provided with the pack file. */
	RB_FOREACH(pe, got_pathlist_head, &refs) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		struct got_reference *ref;
		char *remote_refname;

		if (is_wanted_ref(&wanted_refs, refname) &&
		    !remote->mirror_references) {
			error = update_wanted_ref(refname, id,
			    remote->name, verbosity, repo);
			if (error)
				goto done;
			continue;
		}

		if (remote->mirror_references ||
		    strncmp("refs/tags/", refname, 10) == 0) {
			error = got_ref_open(&ref, repo, refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(refname, id, verbosity,
				    repo);
				if (error)
					goto done;
			} else {
				error = update_ref(ref, id, replace_tags,
				    verbosity, repo);
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
				if (error)
					goto done;
			}
		} else if (strncmp("refs/heads/", refname, 11) == 0) {
			if (asprintf(&remote_refname, "refs/remotes/%s/%s",
			    remote_name, refname + 11) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			error = got_ref_open(&ref, repo, remote_refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(remote_refname, id,
				    verbosity, repo);
				if (error)
					goto done;
			} else {
				error = update_ref(ref, id, replace_tags,
				    verbosity, repo);
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
				if (error)
					goto done;
			}

			/* Also create a local branch if none exists yet. */
			error = got_ref_open(&ref, repo, refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(refname, id, verbosity,
				    repo);
				if (error)
					goto done;
			} else {
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
			}
		}
	}
	if (delete_refs) {
		error = delete_missing_refs(&refs, &symrefs, remote,
		    verbosity, repo);
		if (error)
			goto done;
	}

	if (!remote->mirror_references) {
		/* Update remote HEAD reference if the server provided one. */
		RB_FOREACH(pe, got_pathlist_head, &symrefs) {
			struct got_reference *target_ref;
			const char *refname = pe->path;
			const char *target = pe->data;
			char *remote_refname = NULL, *remote_target = NULL;

			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;

			if (strncmp("refs/heads/", target, 11) != 0)
				continue;

			if (asprintf(&remote_refname, "refs/remotes/%s/%s",
			    remote->name, refname) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (asprintf(&remote_target, "refs/remotes/%s/%s",
			    remote->name, target + 11) == -1) {
				error = got_error_from_errno("asprintf");
				free(remote_refname);
				goto done;
			}

			error = got_ref_open(&target_ref, repo, remote_target,
			    0);
			if (error) {
				free(remote_refname);
				free(remote_target);
				if (error->code == GOT_ERR_NOT_REF) {
					error = NULL;
					continue;
				}
				goto done;
			}
			error = update_symref(remote_refname, target_ref,
			    verbosity, repo);
			free(remote_refname);
			free(remote_target);
			got_ref_close(target_ref);
			if (error)
				goto done;
		}
	}
done:
	if (fetchpid > 0) {
		if (kill(fetchpid, SIGTERM) == -1)
			error = got_error_from_errno("kill");
		if (waitpid(fetchpid, &fetchstatus, 0) == -1 && error == NULL)
			error = got_error_from_errno("waitpid");
	}
	if (fetchfd != -1 && close(fetchfd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&refs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&symrefs, GOT_PATHLIST_FREE_ALL);
	got_pathlist_free(&wanted_branches, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&wanted_refs, GOT_PATHLIST_FREE_NONE);
	got_ref_list_free(&remote_refs);
	got_repo_free_remote_repo_data(remote);
	free(remote);
	free(head_refname);
	free(id_str);
	free(cwd);
	free(repo_path);
	free(pack_hash);
	free(proto);
	free(host);
	free(port);
	free(server_path);
	free(repo_name);
	return error;
}


__dead static void
usage_checkout(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s checkout [-Eq] [-b branch] [-c commit] "
	    "[-p path-prefix] repository-path [work-tree-path]\n",
	    getprogname());
	exit(status);
}

static void
show_worktree_base_ref_warning(void)
{
	fprintf(stderr, "%s: warning: could not create a reference "
	    "to the work tree's base commit; the commit could be "
	    "garbage-collected by Git or 'gotadmin cleanup'; making the "
	    "repository writable and running 'got update' will prevent this\n",
	    getprogname());
}

struct got_checkout_progress_arg {
	const char *worktree_path;
	int had_base_commit_ref_error;
	int verbosity;
};

static const struct got_error *
checkout_progress(void *arg, unsigned char status, const char *path)
{
	struct got_checkout_progress_arg *a = arg;

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return NULL;

	if (status == GOT_STATUS_BASE_REF_ERR) {
		a->had_base_commit_ref_error = 1;
		return NULL;
	}

	while (path[0] == '/')
		path++;

	if (a->verbosity >= 0)
		printf("%c  %s/%s\n", status, a->worktree_path, path);

	return NULL;
}

static const struct got_error *
check_cancelled(void *arg)
{
	if (sigint_received || sigpipe_received)
		return got_error(GOT_ERR_CANCELLED);
	return NULL;
}

static const struct got_error *
check_linear_ancestry(struct got_object_id *commit_id,
    struct got_object_id *base_commit_id, int allow_forwards_in_time_only,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *yca_id;

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    commit_id, base_commit_id, 1, 0, repo, check_cancelled, NULL);
	if (err)
		return err;

	if (yca_id == NULL)
		return got_error(GOT_ERR_ANCESTRY);

	/*
	 * Require a straight line of history between the target commit
	 * and the work tree's base commit.
	 *
	 * Non-linear situations such as this require a rebase:
	 *
	 * (commit) D       F (base_commit)
	 *           \     /
	 *            C   E
	 *             \ /
	 *              B (yca)
	 *              |
	 *              A
	 *
	 * 'got update' only handles linear cases:
	 * Update forwards in time:  A (base/yca) - B - C - D (commit)
	 * Update backwards in time: D (base) - C - B - A (commit/yca)
	 */
	if (allow_forwards_in_time_only) {
	    if (got_object_id_cmp(base_commit_id, yca_id) != 0)
		return got_error(GOT_ERR_ANCESTRY);
	} else if (got_object_id_cmp(commit_id, yca_id) != 0 &&
	    got_object_id_cmp(base_commit_id, yca_id) != 0)
		return got_error(GOT_ERR_ANCESTRY);

	free(yca_id);
	return NULL;
}

static const struct got_error *
check_same_branch(struct got_object_id *commit_id,
    struct got_reference *head_ref, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_object_id *head_commit_id = NULL;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	if (got_object_id_cmp(head_commit_id, commit_id) == 0)
		goto done;

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		goto done;

	err = got_commit_graph_bfsort(graph, head_commit_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;

	for (;;) {
		struct got_object_id id;

		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = got_error(GOT_ERR_ANCESTRY);
			break;
		}

		if (got_object_id_cmp(&id, commit_id) == 0)
			break;
	}
done:
	if (graph)
		got_commit_graph_close(graph);
	free(head_commit_id);
	return err;
}

static const struct got_error *
checkout_ancestry_error(struct got_reference *ref, const char *commit_id_str)
{
	static char msg[512];
	const char *branch_name;

	if (got_ref_is_symbolic(ref))
		branch_name = got_ref_get_symref_target(ref);
	else
		branch_name = got_ref_get_name(ref);

	if (strncmp("refs/heads/", branch_name, 11) == 0)
		branch_name += 11;

	snprintf(msg, sizeof(msg),
	    "target commit is not contained in branch '%s'; "
	    "the branch to use must be specified with -b; "
	    "if necessary a new branch can be created for "
	    "this commit with 'got branch -c %s BRANCH_NAME'",
	    branch_name, commit_id_str);

	return got_error_msg(GOT_ERR_ANCESTRY, msg);
}

static const struct got_error *
cmd_checkout(int argc, char *argv[])
{
	const struct got_error *close_err, *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reference *head_ref = NULL, *ref = NULL;
	struct got_worktree *worktree = NULL;
	char *repo_path = NULL;
	char *worktree_path = NULL;
	const char *path_prefix = "";
	const char *branch_name = GOT_REF_HEAD, *refname = NULL;
	char *commit_id_str = NULL, *keyword_idstr = NULL;
	struct got_object_id *commit_id = NULL;
	char *cwd = NULL;
	int ch, same_path_prefix, allow_nonempty = 0, verbosity = 0;
	struct got_pathlist_head paths;
	struct got_checkout_progress_arg cpa;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "b:c:Ep:q")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno("strdup");
			break;
		case 'E':
			allow_nonempty = 1;
			break;
		case 'p':
			path_prefix = optarg;
			break;
		case 'q':
			verbosity = -1;
			break;
		default:
			usage_checkout(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1) {
		char *base, *dotgit;
		const char *path;
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno2("realpath", argv[0]);
		cwd = getcwd(NULL, 0);
		if (cwd == NULL) {
			error = got_error_from_errno("getcwd");
			goto done;
		}
		if (path_prefix[0])
			path = path_prefix;
		else
			path = repo_path;
		error = got_path_basename(&base, path);
		if (error)
			goto done;
		dotgit = strstr(base, ".git");
		if (dotgit)
			*dotgit = '\0';
		if (asprintf(&worktree_path, "%s/%s", cwd, base) == -1) {
			error = got_error_from_errno("asprintf");
			free(base);
			goto done;
		}
		free(base);
	} else if (argc == 2) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL) {
			error = got_error_from_errno2("realpath", argv[0]);
			goto done;
		}
		worktree_path = realpath(argv[1], NULL);
		if (worktree_path == NULL) {
			if (errno != ENOENT) {
				error = got_error_from_errno2("realpath",
				    argv[1]);
				goto done;
			}
			worktree_path = strdup(argv[1]);
			if (worktree_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else
		usage_checkout(1);

	got_path_strip_trailing_slashes(repo_path);
	got_path_strip_trailing_slashes(worktree_path);

	if (got_path_is_child(worktree_path, repo_path, strlen(repo_path)) ||
	    got_path_is_child(repo_path, worktree_path,
	    strlen(worktree_path))) {
		error = got_error_fmt(GOT_ERR_BAD_PATH,
		    "work tree and repository paths may not overlap: %s",
		    worktree_path);
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	/* Pre-create work tree path for unveil(2) */
	error = got_path_mkdir(worktree_path);
	if (error) {
		if (!(error->code == GOT_ERR_ERRNO && errno == EISDIR) &&
		    !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
			goto done;
		if (!allow_nonempty &&
		    !got_path_dir_is_empty(worktree_path)) {
			error = got_error_path(worktree_path,
			    GOT_ERR_DIR_NOT_EMPTY);
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 0, worktree_path);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo, branch_name, 0);
	if (error != NULL)
		goto done;

	error = got_worktree_init(worktree_path, head_ref, path_prefix,
	    GOT_WORKTREE_GOT_DIR, repo);
	if (error != NULL && !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
		goto done;

	error = got_worktree_open(&worktree, worktree_path,
	    GOT_WORKTREE_GOT_DIR);
	if (error != NULL)
		goto done;

	error = got_worktree_match_path_prefix(&same_path_prefix, worktree,
	    path_prefix);
	if (error != NULL)
		goto done;
	if (!same_path_prefix) {
		error = got_error(GOT_ERR_PATH_PREFIX);
		goto done;
	}

	if (commit_id_str) {
		struct got_reflist_head refs;
		TAILQ_INIT(&refs);
		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;

		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL) {
			free(commit_id_str);
			commit_id_str = keyword_idstr;
		}

		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		got_ref_list_free(&refs);
		if (error)
			goto done;
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), 0, repo);
		if (error != NULL) {
			if (error->code == GOT_ERR_ANCESTRY) {
				error = checkout_ancestry_error(
				    head_ref, commit_id_str);
			}
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, repo);
		if (error) {
			if (error->code == GOT_ERR_ANCESTRY) {
				error = checkout_ancestry_error(
				    head_ref, commit_id_str);
			}
			goto done;
		}
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		if (error)
			goto done;
		/* Expand potentially abbreviated commit ID string. */
		free(commit_id_str);
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error)
			goto done;
	} else {
		commit_id = got_object_id_dup(
		    got_worktree_get_base_commit_id(worktree));
		if (commit_id == NULL) {
			error = got_error_from_errno("got_object_id_dup");
			goto done;
		}
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error)
			goto done;
	}

	error = got_pathlist_insert(NULL, &paths, "", NULL);
	if (error)
		goto done;
	cpa.worktree_path = worktree_path;
	cpa.had_base_commit_ref_error = 0;
	cpa.verbosity = verbosity;
	error = got_worktree_checkout_files(worktree, &paths, repo,
	    checkout_progress, &cpa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (got_ref_is_symbolic(head_ref)) {
		error = got_ref_resolve_symbolic(&ref, repo, head_ref);
		if (error)
			goto done;
		refname = got_ref_get_name(ref);
	} else
		refname = got_ref_get_name(head_ref);
	printf("Checked out %s: %s\n", refname, commit_id_str);
	printf("Now shut up and hack\n");
	if (cpa.had_base_commit_ref_error)
		show_worktree_base_ref_warning();
done:
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (head_ref)
		got_ref_close(head_ref);
	if (ref)
		got_ref_close(ref);
	if (repo) {
		close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree != NULL) {
		close_err = got_worktree_close(worktree);
		if (error == NULL)
			error = close_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_NONE);
	free(commit_id_str);
	free(commit_id);
	free(repo_path);
	free(worktree_path);
	free(cwd);
	return error;
}

struct got_update_progress_arg {
	int did_something;
	int conflicts;
	int obstructed;
	int not_updated;
	int missing;
	int not_deleted;
	int unversioned;
	int verbosity;
};

static void
print_update_progress_stats(struct got_update_progress_arg *upa)
{
	if (!upa->did_something)
		return;

	if (upa->conflicts > 0)
		printf("Files with new merge conflicts: %d\n", upa->conflicts);
	if (upa->obstructed > 0)
		printf("File paths obstructed by a non-regular file: %d\n",
		    upa->obstructed);
	if (upa->not_updated > 0)
		printf("Files not updated because of existing merge "
		    "conflicts: %d\n", upa->not_updated);
}

/*
 * The meaning of some status codes differs between merge-style operations and
 * update operations. For example, the ! status code means "file was missing"
 * if changes were merged into the work tree, and "missing file was restored"
 * if the work tree was updated. This function should be used by any operation
 * which merges changes into the work tree without updating the work tree.
 */
static void
print_merge_progress_stats(struct got_update_progress_arg *upa)
{
	if (!upa->did_something)
		return;

	if (upa->conflicts > 0)
		printf("Files with new merge conflicts: %d\n", upa->conflicts);
	if (upa->obstructed > 0)
		printf("File paths obstructed by a non-regular file: %d\n",
		    upa->obstructed);
	if (upa->missing > 0)
		printf("Files which had incoming changes but could not be "
		    "found in the work tree: %d\n", upa->missing);
	if (upa->not_deleted > 0)
		printf("Files not deleted due to differences in deleted "
		    "content: %d\n", upa->not_deleted);
	if (upa->unversioned > 0)
		printf("Files not merged because an unversioned file was "
		    "found in the work tree: %d\n", upa->unversioned);
}

__dead static void
usage_update(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s update [-q] [-b branch] [-c commit] "
	    "[path ...]\n", getprogname());
	exit(status);
}

static const struct got_error *
update_progress(void *arg, unsigned char status, const char *path)
{
	struct got_update_progress_arg *upa = arg;

	if (status == GOT_STATUS_EXISTS ||
	    status == GOT_STATUS_BASE_REF_ERR)
		return NULL;

	upa->did_something = 1;

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return NULL;

	if (status == GOT_STATUS_CONFLICT)
		upa->conflicts++;
	if (status == GOT_STATUS_OBSTRUCTED)
		upa->obstructed++;
	if (status == GOT_STATUS_CANNOT_UPDATE)
		upa->not_updated++;
	if (status == GOT_STATUS_MISSING)
		upa->missing++;
	if (status == GOT_STATUS_CANNOT_DELETE)
		upa->not_deleted++;
	if (status == GOT_STATUS_UNVERSIONED)
		upa->unversioned++;

	while (path[0] == '/')
		path++;
	if (upa->verbosity >= 0)
		printf("%c  %s\n", status, path);

	return NULL;
}

static const struct got_error *
switch_head_ref(struct got_reference *head_ref,
    struct got_object_id *commit_id, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *base_id_str;
	int ref_has_moved = 0;

	/* Trivial case: switching between two different references. */
	if (strcmp(got_ref_get_name(head_ref),
	    got_worktree_get_head_ref_name(worktree)) != 0) {
		printf("Switching work tree from %s to %s\n",
		    got_worktree_get_head_ref_name(worktree),
		    got_ref_get_name(head_ref));
		return got_worktree_set_head_ref(worktree, head_ref);
	}

	err = check_linear_ancestry(commit_id,
	    got_worktree_get_base_commit_id(worktree), 0, repo);
	if (err) {
		if (err->code != GOT_ERR_ANCESTRY)
			return err;
		ref_has_moved = 1;
	}
	if (!ref_has_moved)
		return NULL;

	/* Switching to a rebased branch with the same reference name. */
	err = got_object_id_str(&base_id_str,
	    got_worktree_get_base_commit_id(worktree));
	if (err)
		return err;
	printf("Reference %s now points at a different branch\n",
	    got_worktree_get_head_ref_name(worktree));
	printf("Switching work tree from %s to %s\n", base_id_str,
	    got_worktree_get_head_ref_name(worktree));
	return NULL;
}

static const struct got_error *
check_rebase_or_histedit_in_progress(struct got_worktree *worktree)
{
	const struct got_error *err;
	int in_progress;

	err = got_worktree_rebase_in_progress(&in_progress, worktree);
	if (err)
		return err;
	if (in_progress)
		return got_error(GOT_ERR_REBASING);

	err = got_worktree_histedit_in_progress(&in_progress, worktree);
	if (err)
		return err;
	if (in_progress)
		return got_error(GOT_ERR_HISTEDIT_BUSY);

	return NULL;
}

static const struct got_error *
check_merge_in_progress(struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err;
	int in_progress;

	err = got_worktree_merge_in_progress(&in_progress, worktree, repo);
	if (err)
		return err;
	if (in_progress)
		return got_error(GOT_ERR_MERGE_BUSY);

	return NULL;
}

static const struct got_error *
get_worktree_paths_from_argv(struct got_pathlist_head *paths, int argc,
    char *argv[], struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	char *path;
	struct got_pathlist_entry *new;
	int i;

	if (argc == 0) {
		path = strdup("");
		if (path == NULL)
			return got_error_from_errno("strdup");
		return got_pathlist_insert(NULL, paths, path, NULL);
	}

	for (i = 0; i < argc; i++) {
		err = got_worktree_resolve_path(&path, worktree, argv[i]);
		if (err)
			break;
		err = got_pathlist_insert(&new, paths, path, NULL);
		if (err || new == NULL /* duplicate */) {
			free(path);
			if (err)
				break;
		}
	}

	return err;
}

static const struct got_error *
wrap_not_worktree_error(const struct got_error *orig_err,
    const char *cmdname, const char *path)
{
	const struct got_error *err;
	struct got_repository *repo;
	static char msg[512];

	err = got_repo_open(&repo, path, NULL, NULL);
	if (err)
		return orig_err;

	snprintf(msg, sizeof(msg),
	    "'got %s' needs a work tree in addition to a git repository\n"
	    "Work trees can be checked out from this Git repository with "
	    "'got checkout'.\n"
	    "The got(1) manual page contains more information.", cmdname);
	err = got_error_msg(GOT_ERR_NOT_WORKTREE, msg);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (err == NULL)
			err = close_err;
	}
	return err;
}

static const struct got_error *
cmd_update(int argc, char *argv[])
{
	const struct got_error *close_err, *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *worktree_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	const char *branch_name = NULL;
	struct got_reference *head_ref = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, verbosity = 0;
	struct got_update_progress_arg upa;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "b:c:q")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno("strdup");
			break;
		case 'q':
			verbosity = -1;
			break;
		default:
			usage_update(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	worktree_path = getcwd(NULL, 0);
	if (worktree_path == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, worktree_path,
	    GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "update",
			    worktree_path);
		goto done;
	}

	error = check_rebase_or_histedit_in_progress(worktree);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = check_merge_in_progress(worktree, repo);
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo, branch_name ? branch_name :
	    got_worktree_get_head_ref_name(worktree), 0);
	if (error != NULL)
		goto done;
	if (commit_id_str == NULL) {
		error = got_ref_resolve(&commit_id, repo, head_ref);
		if (error != NULL)
			goto done;
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error != NULL)
			goto done;
	} else {
		struct got_reflist_head refs;
		char *keyword_idstr = NULL;

		TAILQ_INIT(&refs);

		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;

		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL) {
			free(commit_id_str);
			commit_id_str = keyword_idstr;
		}

		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		got_ref_list_free(&refs);
		free(commit_id_str);
		commit_id_str = NULL;
		if (error)
			goto done;
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error)
			goto done;
	}

	if (branch_name) {
		struct got_object_id *head_commit_id;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (pe->path_len == 0)
				continue;
			error = got_error_msg(GOT_ERR_BAD_PATH,
			    "switching between branches requires that "
			    "the entire work tree gets updated");
			goto done;
		}
		error = got_ref_resolve(&head_commit_id, repo, head_ref);
		if (error)
			goto done;
		error = check_linear_ancestry(commit_id, head_commit_id, 0,
		    repo);
		free(head_commit_id);
		if (error != NULL)
			goto done;
		error = check_same_branch(commit_id, head_ref, repo);
		if (error)
			goto done;
		error = switch_head_ref(head_ref, commit_id, worktree, repo);
		if (error)
			goto done;
	} else {
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), 0, repo);
		if (error != NULL) {
			if (error->code == GOT_ERR_ANCESTRY)
				error = got_error(GOT_ERR_BRANCH_MOVED);
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, repo);
		if (error)
			goto done;
	}

	if (got_object_id_cmp(got_worktree_get_base_commit_id(worktree),
	    commit_id) != 0) {
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		if (error)
			goto done;
	}

	memset(&upa, 0, sizeof(upa));
	upa.verbosity = verbosity;
	error = got_worktree_checkout_files(worktree, &paths, repo,
	    update_progress, &upa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something) {
		printf("Updated to %s: %s\n",
		    got_worktree_get_head_ref_name(worktree), commit_id_str);
	} else
		printf("Already up-to-date\n");

	print_update_progress_stats(&upa);
done:
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (repo) {
		close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree != NULL) {
		close_err = got_worktree_close(worktree);
		if (error == NULL)
			error = close_err;
	}
	if (head_ref != NULL)
		got_ref_close(head_ref);
	free(worktree_path);
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(commit_id);
	free(commit_id_str);
	return error;
}

static const struct got_error *
diff_blobs(struct got_object_id *blob_id1, struct got_object_id *blob_id2,
    const char *path, int diff_context, int ignore_whitespace,
    int force_text_diff, struct got_diffstat_cb_arg *dsa,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL, *blob2 = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	int fd1 = -1, fd2 = -1;

	fd1 = got_opentempfd();
	if (fd1 == -1)
		return got_error_from_errno("got_opentempfd");
	fd2 = got_opentempfd();
	if (fd2 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (blob_id1) {
		err = got_object_open_as_blob(&blob1, repo, blob_id1, 8192,
		    fd1);
		if (err)
			goto done;
	}

	err = got_object_open_as_blob(&blob2, repo, blob_id2, 8192, fd2);
	if (err)
		goto done;

	f1 = got_opentemp();
	if (f1 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	f2 = got_opentemp();
	if (f2 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	while (path[0] == '/')
		path++;
	err = got_diff_blob(NULL, NULL, blob1, blob2, f1, f2, path, path,
	    GOT_DIFF_ALGORITHM_PATIENCE, diff_context, ignore_whitespace,
	    force_text_diff, dsa, outfile);
done:
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob1)
		got_object_blob_close(blob1);
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob2)
		got_object_blob_close(blob2);
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
diff_trees(struct got_object_id *tree_id1, struct got_object_id *tree_id2,
    const char *path, int diff_context, int ignore_whitespace,
    int force_text_diff, struct got_diffstat_cb_arg *dsa,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_diff_blob_output_unidiff_arg arg;
	FILE *f1 = NULL, *f2 = NULL;
	int fd1 = -1, fd2 = -1;

	if (tree_id1) {
		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;
		fd1 = got_opentempfd();
		if (fd1 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	}

	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	f1 = got_opentemp();
	if (f1 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	f2 = got_opentemp();
	if (f2 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	fd2 = got_opentempfd();
	if (fd2 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}
	arg.diff_context = diff_context;
	arg.ignore_whitespace = ignore_whitespace;
	arg.force_text_diff = force_text_diff;
	arg.diffstat = dsa;
	arg.diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;
	arg.outfile = outfile;
	arg.lines = NULL;
	arg.nlines = 0;
	while (path[0] == '/')
		path++;
	err = got_diff_tree(tree1, tree2, f1, f2, fd1, fd2, path, path, repo,
	    got_diff_blob_output_unidiff, &arg, 1);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
get_changed_paths(struct got_pathlist_head *paths,
    struct got_commit_object *commit, struct got_repository *repo,
    struct got_diffstat_cb_arg *dsa)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id1 = NULL, *tree_id2 = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_object_qid *qid;
	got_diff_blob_cb cb = got_diff_tree_collect_changed_paths;
	FILE *f1 = NULL, *f2 = NULL;
	int fd1 = -1, fd2 = -1;

	if (dsa) {
		cb = got_diff_tree_compute_diffstat;

		f1 = got_opentemp();
		if (f1 == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
		f2 = got_opentemp();
		if (f2 == NULL) {
			err = got_error_from_errno("got_opentemp");
			goto done;
		}
		fd1 = got_opentempfd();
		if (fd1 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
		fd2 = got_opentempfd();
		if (fd2 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	}

	qid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		struct got_commit_object *pcommit;
		err = got_object_open_as_commit(&pcommit, repo,
		    &qid->id);
		if (err)
			return err;

		tree_id1 = got_object_id_dup(
		    got_object_commit_get_tree_id(pcommit));
		if (tree_id1 == NULL) {
			got_object_commit_close(pcommit);
			return got_error_from_errno("got_object_id_dup");
		}
		got_object_commit_close(pcommit);

	}

	if (tree_id1) {
		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;
	}

	tree_id2 = got_object_commit_get_tree_id(commit);
	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, f1, f2, fd1, fd2, "", "", repo,
	    cb, dsa ? (void *)dsa : paths, dsa ? 1 : 0);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(tree_id1);
	return err;
}

static const struct got_error *
print_patch(struct got_commit_object *commit, struct got_object_id *id,
    const char *path, int diff_context, struct got_diffstat_cb_arg *dsa,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_commit_object *pcommit = NULL;
	char *id_str1 = NULL, *id_str2 = NULL;
	struct got_object_id *obj_id1 = NULL, *obj_id2 = NULL;
	struct got_object_qid *qid;

	qid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		err = got_object_open_as_commit(&pcommit, repo,
		    &qid->id);
		if (err)
			return err;
		err = got_object_id_str(&id_str1, &qid->id);
		if (err)
			goto done;
	}

	err = got_object_id_str(&id_str2, id);
	if (err)
		goto done;

	if (path && path[0] != '\0') {
		int obj_type;
		err = got_object_id_by_path(&obj_id2, repo, commit, path);
		if (err)
			goto done;
		if (pcommit) {
			err = got_object_id_by_path(&obj_id1, repo,
			    pcommit, path);
			if (err) {
				if (err->code != GOT_ERR_NO_TREE_ENTRY) {
					free(obj_id2);
					goto done;
				}
			}
		}
		err = got_object_get_type(&obj_type, repo, obj_id2);
		if (err) {
			free(obj_id2);
			goto done;
		}
		fprintf(outfile,
		    "diff %s %s\n", id_str1 ? id_str1 : "/dev/null", id_str2);
		fprintf(outfile, "commit - %s\n",
		    id_str1 ? id_str1 : "/dev/null");
		fprintf(outfile, "commit + %s\n", id_str2);
		switch (obj_type) {
		case GOT_OBJ_TYPE_BLOB:
			err = diff_blobs(obj_id1, obj_id2, path, diff_context,
			    0, 0, dsa, repo, outfile);
			break;
		case GOT_OBJ_TYPE_TREE:
			err = diff_trees(obj_id1, obj_id2, path, diff_context,
			    0, 0, dsa, repo, outfile);
			break;
		default:
			err = got_error(GOT_ERR_OBJ_TYPE);
			break;
		}
		free(obj_id1);
		free(obj_id2);
	} else {
		obj_id2 = got_object_commit_get_tree_id(commit);
		if (pcommit)
			obj_id1 = got_object_commit_get_tree_id(pcommit);
		fprintf(outfile,
		    "diff %s %s\n", id_str1 ? id_str1 : "/dev/null", id_str2);
		fprintf(outfile, "commit - %s\n",
		    id_str1 ? id_str1 : "/dev/null");
		fprintf(outfile, "commit + %s\n", id_str2);
		err = diff_trees(obj_id1, obj_id2, "", diff_context, 0, 0,
		    dsa, repo, outfile);
	}
done:
	free(id_str1);
	free(id_str2);
	if (pcommit)
		got_object_commit_close(pcommit);
	return err;
}

static char *
get_datestr(time_t *time, char *datebuf)
{
	struct tm mytm, *tm;
	char *p, *s;

	tm = gmtime_r(time, &mytm);
	if (tm == NULL)
		return NULL;
	s = asctime_r(tm, datebuf);
	if (s == NULL)
		return NULL;
	p = strchr(s, '\n');
	if (p)
		*p = '\0';
	return s;
}

static const struct got_error *
match_commit(int *have_match, struct got_object_id *id,
    struct got_commit_object *commit, regex_t *regex)
{
	const struct got_error *err = NULL;
	regmatch_t regmatch;
	char *id_str = NULL, *logmsg = NULL;

	*have_match = 0;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_object_commit_get_logmsg(&logmsg, commit);
	if (err)
		goto done;

	if (regexec(regex, got_object_commit_get_author(commit), 1,
	    &regmatch, 0) == 0 ||
	    regexec(regex, got_object_commit_get_committer(commit), 1,
	    &regmatch, 0) == 0 ||
	    regexec(regex, id_str, 1, &regmatch, 0) == 0 ||
	    regexec(regex, logmsg, 1, &regmatch, 0) == 0)
		*have_match = 1;
done:
	free(id_str);
	free(logmsg);
	return err;
}

static void
match_changed_paths(int *have_match, struct got_pathlist_head *changed_paths,
    regex_t *regex)
{
	regmatch_t regmatch;
	struct got_pathlist_entry *pe;

	*have_match = 0;

	RB_FOREACH(pe, got_pathlist_head, changed_paths) {
		if (regexec(regex, pe->path, 1, &regmatch, 0) == 0) {
			*have_match = 1;
			break;
		}
	}
}

static const struct got_error *
match_patch(int *have_match, struct got_commit_object *commit,
    struct got_object_id *id, const char *path, int diff_context,
    struct got_repository *repo, regex_t *regex, FILE *f)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0;
	regmatch_t regmatch;

	*have_match = 0;

	err = got_opentemp_truncate(f);
	if (err)
		return err;

	err = print_patch(commit, id, path, diff_context, NULL, repo, f);
	if (err)
		goto done;

	if (fseeko(f, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	while (getline(&line, &linesize, f) != -1) {
		if (regexec(regex, line, 1, &regmatch, 0) == 0) {
			*have_match = 1;
			break;
		}
	}
done:
	free(line);
	return err;
}

#define GOT_COMMIT_SEP_STR "-----------------------------------------------\n"

static const struct got_error*
build_refs_str(char **refs_str, struct got_reflist_head *refs,
    struct got_object_id *id, struct got_repository *repo,
    int local_only)
{
	static const struct got_error *err = NULL;
	struct got_reflist_entry *re;
	char *s;
	const char *name;

	*refs_str = NULL;

	TAILQ_FOREACH(re, refs, entry) {
		struct got_tag_object *tag = NULL;
		struct got_object_id *ref_id;
		int cmp;

		name = got_ref_get_name(re->ref);
		if (strcmp(name, GOT_REF_HEAD) == 0)
			continue;
		if (strncmp(name, "refs/", 5) == 0)
			name += 5;
		if (strncmp(name, "got/", 4) == 0)
			continue;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0) {
			if (local_only)
				continue;
			name += 8;
			s = strstr(name, "/" GOT_REF_HEAD);
			if (s != NULL && strcmp(s, "/" GOT_REF_HEAD) == 0)
				continue;
		}
		err = got_ref_resolve(&ref_id, repo, re->ref);
		if (err)
			break;
		if (strncmp(name, "tags/", 5) == 0) {
			err = got_object_open_as_tag(&tag, repo, ref_id);
			if (err) {
				if (err->code != GOT_ERR_OBJ_TYPE) {
					free(ref_id);
					break;
				}
				/* Ref points at something other than a tag. */
				err = NULL;
				tag = NULL;
			}
		}
		cmp = got_object_id_cmp(tag ?
		    got_object_tag_get_object_id(tag) : ref_id, id);
		free(ref_id);
		if (tag)
			got_object_tag_close(tag);
		if (cmp != 0)
			continue;
		s = *refs_str;
		if (asprintf(refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			err = got_error_from_errno("asprintf");
			free(s);
			*refs_str = NULL;
			break;
		}
		free(s);
	}

	return err;
}

static const struct got_error *
print_commit_oneline(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, struct got_reflist_object_id_map *refs_idmap)
{
	const struct got_error *err = NULL;
	char *ref_str = NULL, *id_str = NULL, *logmsg0 = NULL;
	char *comma, *s, *nl;
	struct got_reflist_head *refs;
	char datebuf[12]; /* YYYY-MM-DD + SPACE + NUL */
	struct tm tm;
	time_t committer_time;

	refs = got_reflist_object_id_map_lookup(refs_idmap, id);
	if (refs) {
		err = build_refs_str(&ref_str, refs, id, repo, 1);
		if (err)
			return err;

		/* Display the first matching ref only. */
		if (ref_str && (comma = strchr(ref_str, ',')) != NULL)
			*comma = '\0';
	}

	if (ref_str == NULL) {
		err = got_object_id_str(&id_str, id);
		if (err)
			return err;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (gmtime_r(&committer_time, &tm) == NULL) {
		err = got_error_from_errno("gmtime_r");
		goto done;
	}
	if (strftime(datebuf, sizeof(datebuf), "%F ", &tm) == 0) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;

	s = logmsg0;
	while (isspace((unsigned char)s[0]))
		s++;

	nl = strchr(s, '\n');
	if (nl) {
		*nl = '\0';
	}

	if (ref_str)
		printf("%s%-7s %s\n", datebuf, ref_str, s);
	else
		printf("%s%.7s %s\n", datebuf, id_str, s);

	if (fflush(stdout) != 0 && err == NULL)
		err = got_error_from_errno("fflush");
done:
	free(id_str);
	free(ref_str);
	free(logmsg0);
	return err;
}

static const struct got_error *
print_diffstat(struct got_diffstat_cb_arg *dsa, const char *header)
{
	struct got_pathlist_entry *pe;

	if (header != NULL)
		printf("%s\n", header);

	RB_FOREACH(pe, got_pathlist_head, dsa->paths) {
		struct got_diff_changed_path *cp = pe->data;
		int pad = dsa->max_path_len - pe->path_len + 1;

		printf(" %c  %s%*c | %*d+ %*d-\n", cp->status, pe->path, pad,
		    ' ', dsa->add_cols + 1, cp->add, dsa->rm_cols + 1, cp->rm);
	}
	printf("\n%d file%s changed, %d insertion%s(+), %d deletion%s(-)\n\n",
	    dsa->nfiles, dsa->nfiles > 1 ? "s" : "", dsa->ins,
	    dsa->ins != 1 ? "s" : "", dsa->del, dsa->del != 1 ? "s" : "");

	if (fflush(stdout) != 0)
		return got_error_from_errno("fflush");

	return NULL;
}

static const struct got_error *
printfile(FILE *f)
{
	char	buf[8192];
	size_t	r;

	if (fseeko(f, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseek");

	for (;;) {
		r = fread(buf, 1, sizeof(buf), f);
		if (r == 0) {
			if (ferror(f))
				return got_error_from_errno("fread");
			if (feof(f))
				break;
		}
		if (fwrite(buf, 1, r, stdout) != r)
			return got_ferror(stdout, GOT_ERR_IO);
	}

	return NULL;
}

static const struct got_error *
print_commit(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, const char *path,
    struct got_pathlist_head *changed_paths,
    struct got_diffstat_cb_arg *diffstat, int show_patch, int diff_context,
    struct got_reflist_object_id_map *refs_idmap, const char *custom_refs_str,
    const char *prefix)
{
	const struct got_error *err = NULL;
	FILE *f = NULL;
	char *id_str, *datestr, *logmsg0, *logmsg, *line;
	char datebuf[26];
	time_t committer_time;
	const char *author, *committer;
	char *refs_str = NULL;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	if (custom_refs_str == NULL) {
		struct got_reflist_head *refs;
		refs = got_reflist_object_id_map_lookup(refs_idmap, id);
		if (refs) {
			err = build_refs_str(&refs_str, refs, id, repo, 0);
			if (err)
				goto done;
		}
	}

	printf(GOT_COMMIT_SEP_STR);
	if (custom_refs_str)
		printf("%s %s (%s)\n", prefix ? prefix : "commit", id_str,
		    custom_refs_str);
	else
		printf("%s %s%s%s%s\n", prefix ? prefix : "commit", id_str,
		    refs_str ? " (" : "", refs_str ? refs_str : "",
		    refs_str ? ")" : "");
	free(id_str);
	id_str = NULL;
	free(refs_str);
	refs_str = NULL;
	printf("from: %s\n", got_object_commit_get_author(commit));
	author = got_object_commit_get_author(commit);
	committer = got_object_commit_get_committer(commit);
	if (strcmp(author, committer) != 0)
		printf("via: %s\n", committer);
	committer_time = got_object_commit_get_committer_time(commit);
	datestr = get_datestr(&committer_time, datebuf);
	if (datestr)
		printf("date: %s UTC\n", datestr);
	if (got_object_commit_get_nparents(commit) > 1) {
		const struct got_object_id_queue *parent_ids;
		struct got_object_qid *qid;
		int n = 1;
		parent_ids = got_object_commit_get_parent_ids(commit);
		STAILQ_FOREACH(qid, parent_ids, entry) {
			err = got_object_id_str(&id_str, &qid->id);
			if (err)
				goto done;
			printf("parent %d: %s\n", n++, id_str);
			free(id_str);
			id_str = NULL;
		}
	}

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;

	logmsg = logmsg0;
	do {
		line = strsep(&logmsg, "\n");
		if (line)
			printf(" %s\n", line);
	} while (line);
	free(logmsg0);

	if (changed_paths && diffstat == NULL) {
		struct got_pathlist_entry *pe;

		RB_FOREACH(pe, got_pathlist_head, changed_paths) {
			struct got_diff_changed_path *cp = pe->data;

			printf(" %c  %s\n", cp->status, pe->path);
		}
		printf("\n");
	}
	if (show_patch) {
		if (diffstat) {
			f = got_opentemp();
			if (f == NULL) {
				err = got_error_from_errno("got_opentemp");
				goto done;
			}
		}

		err = print_patch(commit, id, path, diff_context, diffstat,
		    repo, diffstat == NULL ? stdout : f);
		if (err)
			goto done;
	}
	if (diffstat) {
		err = print_diffstat(diffstat, NULL);
		if (err)
			goto done;
		if (show_patch) {
			err = printfile(f);
			if (err)
				goto done;
		}
	}
	if (show_patch)
		printf("\n");

	if (fflush(stdout) != 0 && err == NULL)
		err = got_error_from_errno("fflush");
done:
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(id_str);
	free(refs_str);
	return err;
}

static const struct got_error *
print_commits(struct got_object_id *root_id, struct got_object_id *end_id,
    struct got_repository *repo, const char *path, int show_changed_paths,
    int show_diffstat, int show_patch, const char *search_pattern,
    int diff_context, int limit, int log_branches, int reverse_display_order,
    struct got_reflist_object_id_map *refs_idmap, int one_line, int toposort,
    FILE *tmpfile)
{
	const struct got_error *err;
	struct got_commit_graph *graph;
	regex_t regex;
	int have_match;
	struct got_object_id_queue reversed_commits;
	struct got_object_qid *qid;
	struct got_commit_object *commit;
	struct got_pathlist_head changed_paths;

	STAILQ_INIT(&reversed_commits);
	RB_INIT(&changed_paths);

	if (search_pattern && regcomp(&regex, search_pattern,
	    REG_EXTENDED | REG_NOSUB | REG_NEWLINE))
		return got_error_msg(GOT_ERR_REGEX, search_pattern);

	err = got_commit_graph_open(&graph, path, !log_branches);
	if (err)
		return err;
	if (log_branches && toposort) {
		err = got_commit_graph_toposort(graph, root_id, repo,
		    check_cancelled, NULL);
	} else {
		err = got_commit_graph_bfsort(graph, root_id, repo,
		    check_cancelled, NULL);
	}
	if (err)
		goto done;
	for (;;) {
		struct got_object_id id;
		struct got_diffstat_cb_arg dsa = { 0, 0, 0, 0, 0, 0,
		    &changed_paths, 0, 0, GOT_DIFF_ALGORITHM_PATIENCE };

		if (sigint_received || sigpipe_received)
			break;

		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		err = got_object_open_as_commit(&commit, repo, &id);
		if (err)
			break;

		if (((show_changed_paths && !show_diffstat) ||
		    (show_diffstat && !show_patch))
		    && !reverse_display_order) {
			err = get_changed_paths(&changed_paths, commit, repo,
			    show_diffstat ? &dsa : NULL);
			if (err)
				break;
		}

		if (search_pattern) {
			err = match_commit(&have_match, &id, commit, &regex);
			if (err) {
				got_object_commit_close(commit);
				break;
			}
			if (have_match == 0 && show_changed_paths)
				match_changed_paths(&have_match,
				    &changed_paths, &regex);
			if (have_match == 0 && show_patch) {
				err = match_patch(&have_match, commit, &id,
				    path, diff_context, repo, &regex, tmpfile);
				if (err)
					break;
			}
			if (have_match == 0) {
				got_object_commit_close(commit);
				got_pathlist_free(&changed_paths,
				    GOT_PATHLIST_FREE_ALL);
				continue;
			}
		}

		if (reverse_display_order) {
			err = got_object_qid_alloc(&qid, &id);
			if (err)
				break;
			STAILQ_INSERT_HEAD(&reversed_commits, qid, entry);
			got_object_commit_close(commit);
		} else {
			if (one_line)
				err = print_commit_oneline(commit, &id,
				    repo, refs_idmap);
			else
				err = print_commit(commit, &id, repo, path,
				    (show_changed_paths || show_diffstat) ?
				    &changed_paths : NULL,
				    show_diffstat ? &dsa : NULL, show_patch,
				    diff_context, refs_idmap, NULL, NULL);
			got_object_commit_close(commit);
			if (err)
				break;
		}
		if ((limit && --limit == 0) ||
		    (end_id && got_object_id_cmp(&id, end_id) == 0))
			break;

		got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
	}
	if (reverse_display_order) {
		STAILQ_FOREACH(qid, &reversed_commits, entry) {
			struct got_diffstat_cb_arg dsa = { 0, 0, 0, 0, 0, 0,
			    &changed_paths, 0, 0, GOT_DIFF_ALGORITHM_PATIENCE };

			err = got_object_open_as_commit(&commit, repo,
			    &qid->id);
			if (err)
				break;
			if ((show_changed_paths && !show_diffstat) ||
			    (show_diffstat && !show_patch)) {
				err = get_changed_paths(&changed_paths, commit,
				    repo, show_diffstat ? &dsa : NULL);
				if (err)
					break;
			}
			if (one_line)
				err = print_commit_oneline(commit, &qid->id,
				    repo, refs_idmap);
			else
				err = print_commit(commit, &qid->id, repo, path,
				    (show_changed_paths || show_diffstat) ?
				    &changed_paths : NULL,
				    show_diffstat ? &dsa : NULL, show_patch,
				    diff_context, refs_idmap, NULL, NULL);
			got_object_commit_close(commit);
			if (err)
				break;
			got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
		}
	}
done:
	got_object_id_queue_free(&reversed_commits);
	got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
	if (search_pattern)
		regfree(&regex);
	got_commit_graph_close(graph);
	return err;
}

__dead static void
usage_log(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s log [-bdPpRst] [-C number] [-c commit] "
	    "[-l N] [-r repository-path] [-S search-pattern] [-x commit] "
	    "[path]\n", getprogname());
	exit(status);
}

static int
get_default_log_limit(void)
{
	const char *got_default_log_limit;
	long long n;
	const char *errstr;

	got_default_log_limit = getenv("GOT_LOG_DEFAULT_LIMIT");
	if (got_default_log_limit == NULL)
		return 0;
	n = strtonum(got_default_log_limit, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		return 0;
	return n;
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_object_id *start_id = NULL, *end_id = NULL;
	char *repo_path = NULL, *path = NULL, *cwd = NULL, *in_repo_path = NULL;
	char *keyword_idstr = NULL;
	const char *start_commit = NULL, *end_commit = NULL;
	const char *search_pattern = NULL;
	int diff_context = -1, ch;
	int show_changed_paths = 0, show_patch = 0, limit = 0, log_branches = 0;
	int show_diffstat = 0, reverse_display_order = 0, one_line = 0;
	int toposort = 0;
	const char *errstr;
	struct got_reflist_head refs;
	struct got_reflist_object_id_map *refs_idmap = NULL;
	FILE *tmpfile = NULL;
	int *pack_fds = NULL;

	TAILQ_INIT(&refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL)
	    == -1)
		err(1, "pledge");
#endif

	limit = get_default_log_limit();

	while ((ch = getopt(argc, argv, "bC:c:dl:PpRr:S:stx:")) != -1) {
		switch (ch) {
		case 'b':
			log_branches = 1;
			break;
		case 'C':
			diff_context = strtonum(optarg, 0, GOT_DIFF_MAX_CONTEXT,
			    &errstr);
			if (errstr != NULL)
				errx(1, "number of context lines is %s: %s",
				    errstr, optarg);
			break;
		case 'c':
			start_commit = optarg;
			break;
		case 'd':
			show_diffstat = 1;
			break;
		case 'l':
			limit = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "number of commits is %s: %s",
				    errstr, optarg);
			break;
		case 'P':
			show_changed_paths = 1;
			break;
		case 'p':
			show_patch = 1;
			break;
		case 'R':
			reverse_display_order = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'S':
			search_pattern = optarg;
			break;
		case 's':
			one_line = 1;
			break;
		case 't':
			toposort = 1;
			break;
		case 'x':
			end_commit = optarg;
			break;
		default:
			usage_log(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (diff_context == -1)
		diff_context = 3;
	else if (!show_patch)
		errx(1, "-C requires -p");

	if (one_line && (show_patch || show_changed_paths || show_diffstat))
		errx(1, "cannot use -s with -d, -p or -P");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		error = NULL;
	}

	if (argc == 1) {
		if (worktree) {
			error = got_worktree_resolve_path(&path, worktree,
			    argv[0]);
			if (error)
				goto done;
		} else {
			path = strdup(argv[0]);
			if (path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else if (argc != 0)
		usage_log(1);

	if (repo_path == NULL) {
		repo_path = worktree ?
		    strdup(got_worktree_get_repo_path(worktree)) : strdup(cwd);
	}
	if (repo_path == NULL) {
		error = got_error_from_errno("strdup");
		goto done;
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = got_reflist_object_id_map_create(&refs_idmap, &refs, repo);
	if (error)
		goto done;

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		struct got_commit_object *commit = NULL;
		error = got_ref_open(&head_ref, repo,
		    worktree ? got_worktree_get_head_ref_name(worktree)
		    : GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&start_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
		error = got_object_open_as_commit(&commit, repo,
		    start_id);
		if (error != NULL)
			goto done;
		got_object_commit_close(commit);
	} else {
		error = got_keyword_to_idstr(&keyword_idstr, start_commit,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			start_commit = keyword_idstr;

		error = got_repo_match_object_id(&start_id, NULL,
		    start_commit, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		if (error != NULL)
			goto done;
	}
	if (end_commit != NULL) {
		error = got_keyword_to_idstr(&keyword_idstr, end_commit,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			end_commit = keyword_idstr;

		error = got_repo_match_object_id(&end_id, NULL,
		    end_commit, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		if (error != NULL)
			goto done;
	}

	if (worktree) {
		/*
		 * If a path was specified on the command line it was resolved
		 * to a path in the work tree above. Prepend the work tree's
		 * path prefix to obtain the corresponding in-repository path.
		 */
		if (path) {
			const char *prefix;
			prefix = got_worktree_get_path_prefix(worktree);
			if (asprintf(&in_repo_path, "%s%s%s", prefix,
			    (path[0] != '\0') ? "/" : "", path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
	} else
		error = got_repo_map_path(&in_repo_path, repo,
		    path ? path : "");
	if (error != NULL)
		goto done;
	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	if (worktree) {
		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	if (search_pattern && show_patch) {
		tmpfile = got_opentemp();
		if (tmpfile == NULL) {
			error = got_error_from_errno("got_opentemp");
			goto done;
		}
	}

	error = print_commits(start_id, end_id, repo, path ? path : "",
	    show_changed_paths, show_diffstat, show_patch, search_pattern,
	    diff_context, limit, log_branches, reverse_display_order,
	    refs_idmap, one_line, toposort, tmpfile);
done:
	free(path);
	free(repo_path);
	free(cwd);
	free(start_id);
	free(end_id);
	free(keyword_idstr);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (refs_idmap)
		got_reflist_object_id_map_free(refs_idmap);
	if (tmpfile && fclose(tmpfile) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	got_ref_list_free(&refs);
	return error;
}

__dead static void
usage_diff(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s diff [-adPsw] [-C number] [-c commit] "
	    "[-r repository-path] [object1 object2 | path ...]\n",
	    getprogname());
	exit(status);
}

struct print_diff_arg {
	struct got_repository *repo;
	struct got_worktree *worktree;
	struct got_diffstat_cb_arg *diffstat;
	int diff_context;
	const char *id_str;
	int header_shown;
	int diff_staged;
	enum got_diff_algorithm diff_algo;
	int ignore_whitespace;
	int force_text_diff;
	FILE *f1;
	FILE *f2;
	FILE *outfile;
};

/*
 * Create a file which contains the target path of a symlink so we can feed
 * it as content to the diff engine.
 */
static const struct got_error *
get_symlink_target_file(int *fd, int dirfd, const char *de_name,
    const char *abspath)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	ssize_t target_len, outlen;

	*fd = -1;

	if (dirfd != -1) {
		target_len = readlinkat(dirfd, de_name, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlinkat", abspath);
	} else {
		target_len = readlink(abspath, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlink", abspath);
	}

	*fd = got_opentempfd();
	if (*fd == -1)
		return got_error_from_errno("got_opentempfd");

	outlen = write(*fd, target_path, target_len);
	if (outlen == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (lseek(*fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", abspath);
		goto done;
	}
done:
	if (err) {
		close(*fd);
		*fd = -1;
	}
	return err;
}

static const struct got_error *
emit_base_commit_header(FILE *f, struct got_object_id *commit_id,
    struct got_worktree *worktree)
{
	const struct got_error	*err;
	struct got_object_id	*base_commit_id;
	char			*base_commit_idstr;

	if (worktree == NULL)	/* shouldn't happen */
		return got_error(GOT_ERR_NOT_WORKTREE);

	base_commit_id = got_worktree_get_base_commit_id(worktree);

	if (commit_id != NULL) {
		if (got_object_id_cmp(commit_id, base_commit_id) != 0)
			base_commit_id = commit_id;
	}

	err = got_object_id_str(&base_commit_idstr, base_commit_id);
	if (err != NULL)
		return err;

	if (fprintf(f, "commit - %s\n", base_commit_idstr) < 0)
		err = got_error_from_errno("fprintf");
	free(base_commit_idstr);
	return err;
}

static const struct got_error *
print_diff(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	struct print_diff_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL;
	int fd = -1, fd1 = -1, fd2 = -1;
	FILE *f2 = NULL;
	char *abspath = NULL, *label1 = NULL;
	struct stat sb;
	off_t size1 = 0;
	int f2_exists = 0;

	memset(&sb, 0, sizeof(sb));

	if (a->diff_staged) {
		if (staged_status != GOT_STATUS_MODIFY &&
		    staged_status != GOT_STATUS_ADD &&
		    staged_status != GOT_STATUS_DELETE)
			return NULL;
	} else {
		if (staged_status == GOT_STATUS_DELETE)
			return NULL;
		if (status == GOT_STATUS_NONEXISTENT)
			return got_error_set_errno(ENOENT, path);
		if (status != GOT_STATUS_MODIFY &&
		    status != GOT_STATUS_ADD &&
		    status != GOT_STATUS_DELETE &&
		    status != GOT_STATUS_CONFLICT)
			return NULL;
	}

	err = got_opentemp_truncate(a->f1);
	if (err)
		return got_error_from_errno("got_opentemp_truncate");
	err = got_opentemp_truncate(a->f2);
	if (err)
		return got_error_from_errno("got_opentemp_truncate");

	if (!a->header_shown) {
		if (fprintf(a->outfile, "diff %s%s\n",
		    a->diff_staged ? "-s " : "",
		    got_worktree_get_root_path(a->worktree)) < 0) {
			err = got_error_from_errno("fprintf");
			goto done;
		}
		if (fprintf(a->outfile, "path + %s%s\n",
		    got_worktree_get_root_path(a->worktree),
		    a->diff_staged ? " (staged changes)" : "") < 0) {
			err = got_error_from_errno("fprintf");
			goto done;
		}
		a->header_shown = 1;
	}

	err = emit_base_commit_header(a->outfile, commit_id, a->worktree);
	if (err != NULL)
		goto done;

	if (a->diff_staged) {
		const char *label1 = NULL, *label2 = NULL;
		switch (staged_status) {
		case GOT_STATUS_MODIFY:
			label1 = path;
			label2 = path;
			break;
		case GOT_STATUS_ADD:
			label2 = path;
			break;
		case GOT_STATUS_DELETE:
			label1 = path;
			break;
		default:
			return got_error(GOT_ERR_FILE_STATUS);
		}
		fd1 = got_opentempfd();
		if (fd1 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
		fd2 = got_opentempfd();
		if (fd2 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
		err = got_diff_objects_as_blobs(NULL, NULL, a->f1, a->f2,
		    fd1, fd2, blob_id, staged_blob_id, label1, label2,
		    a->diff_algo, a->diff_context, a->ignore_whitespace,
		    a->force_text_diff, a->diffstat, a->repo, a->outfile);
		goto done;
	}

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY) {
		char *id_str;
		err = got_object_open_as_blob(&blob1, a->repo, staged_blob_id,
		    8192, fd1);
		if (err)
			goto done;
		err = got_object_id_str(&id_str, staged_blob_id);
		if (err)
			goto done;
		if (asprintf(&label1, "%s (staged)", id_str) == -1) {
			err = got_error_from_errno("asprintf");
			free(id_str);
			goto done;
		}
		free(id_str);
	} else if (status != GOT_STATUS_ADD) {
		err = got_object_open_as_blob(&blob1, a->repo, blob_id, 8192,
		    fd1);
		if (err)
			goto done;
	}

	if (status != GOT_STATUS_DELETE) {
		if (asprintf(&abspath, "%s/%s",
		    got_worktree_get_root_path(a->worktree), path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}

		if (dirfd != -1) {
			fd = openat(dirfd, de_name,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				if (!got_err_open_nofollow_on_symlink()) {
					err = got_error_from_errno2("openat",
					    abspath);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, abspath);
				if (err)
					goto done;
			}
		} else {
			fd = open(abspath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd == -1) {
				if (!got_err_open_nofollow_on_symlink()) {
					err = got_error_from_errno2("open",
					    abspath);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, abspath);
				if (err)
					goto done;
			}
		}
		if (fstatat(fd, abspath, &sb, AT_SYMLINK_NOFOLLOW) == -1) {
			err = got_error_from_errno2("fstatat", abspath);
			goto done;
		}
		f2 = fdopen(fd, "r");
		if (f2 == NULL) {
			err = got_error_from_errno2("fdopen", abspath);
			goto done;
		}
		fd = -1;
		f2_exists = 1;
	}

	if (blob1) {
		err = got_object_blob_dump_to_file(&size1, NULL, NULL,
		    a->f1, blob1);
		if (err)
			goto done;
	}

	err = got_diff_blob_file(NULL, NULL, blob1, a->f1, size1, label1,
	    f2 ? f2 : a->f2, f2_exists, &sb, path, GOT_DIFF_ALGORITHM_PATIENCE,
	    a->diff_context, a->ignore_whitespace, a->force_text_diff,
	    a->diffstat, a->outfile);
done:
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob1)
		got_object_blob_close(blob1);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(abspath);
	return err;
}

static const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	const char *commit_args[2] = { NULL, NULL };
	int ncommit_args = 0;
	struct got_object_id *ids[2] = { NULL, NULL };
	char *labels[2] = { NULL, NULL };
	int type1 = GOT_OBJ_TYPE_ANY, type2 = GOT_OBJ_TYPE_ANY;
	int diff_context = 3, diff_staged = 0, ignore_whitespace = 0, ch, i;
	int force_text_diff = 0, force_path = 0, rflag = 0, show_diffstat = 0;
	const char *errstr;
	struct got_reflist_head refs;
	struct got_pathlist_head diffstat_paths, paths;
	FILE *f1 = NULL, *f2 = NULL, *outfile = NULL;
	int fd1 = -1, fd2 = -1;
	int *pack_fds = NULL;
	struct got_diffstat_cb_arg dsa;

	memset(&dsa, 0, sizeof(dsa));

	TAILQ_INIT(&refs);
	RB_INIT(&paths);
	RB_INIT(&diffstat_paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aC:c:dPr:sw")) != -1) {
		switch (ch) {
		case 'a':
			force_text_diff = 1;
			break;
		case 'C':
			diff_context = strtonum(optarg, 0, GOT_DIFF_MAX_CONTEXT,
			    &errstr);
			if (errstr != NULL)
				errx(1, "number of context lines is %s: %s",
				    errstr, optarg);
			break;
		case 'c':
			if (ncommit_args >= 2)
				errx(1, "too many -c options used");
			commit_args[ncommit_args++] = optarg;
			break;
		case 'd':
			show_diffstat = 1;
			break;
		case 'P':
			force_path = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			rflag = 1;
			break;
		case 's':
			diff_staged = 1;
			break;
		case 'w':
			ignore_whitespace = 1;
			break;
		default:
			usage_diff(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	free(repo_path);
	if (error != NULL)
		goto done;

	if (show_diffstat) {
		dsa.paths = &diffstat_paths;
		dsa.force_text = force_text_diff;
		dsa.ignore_ws = ignore_whitespace;
		dsa.diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;
	}

	if (rflag || worktree == NULL || ncommit_args > 0) {
		if (force_path) {
			error = got_error_msg(GOT_ERR_NOT_IMPL,
			    "-P option can only be used when diffing "
			    "a work tree");
			goto done;
		}
		if (diff_staged) {
			error = got_error_msg(GOT_ERR_NOT_IMPL,
			    "-s option can only be used when diffing "
			    "a work tree");
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if ((!force_path && argc == 2) || ncommit_args > 0) {
		int obj_type = (ncommit_args > 0 ?
		    GOT_OBJ_TYPE_COMMIT : GOT_OBJ_TYPE_ANY);
		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;
		for (i = 0; i < (ncommit_args > 0 ? ncommit_args : argc); i++) {
			const char	*arg;
			char		*keyword_idstr = NULL;

			if (ncommit_args > 0)
				arg = commit_args[i];
			else
				arg = argv[i];

			error = got_keyword_to_idstr(&keyword_idstr, arg,
			    repo, worktree);
			if (error != NULL)
				goto done;
			if (keyword_idstr != NULL)
				arg = keyword_idstr;

			error = got_repo_match_object_id(&ids[i], &labels[i],
			    arg, obj_type, &refs, repo);
			free(keyword_idstr);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF &&
				    error->code != GOT_ERR_NO_OBJ)
					goto done;
				if (ncommit_args > 0)
					goto done;
				error = NULL;
				break;
			}
		}
	}

	f1 = got_opentemp();
	if (f1 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}

	f2 = got_opentemp();
	if (f2 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}

	outfile = got_opentemp();
	if (outfile == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}

	if (ncommit_args == 0 && (ids[0] == NULL || ids[1] == NULL)) {
		struct print_diff_arg arg;
		char *id_str;

		if (worktree == NULL) {
			if (argc == 2 && ids[0] == NULL) {
				error = got_error_path(argv[0], GOT_ERR_NO_OBJ);
				goto done;
			} else if (argc == 2 && ids[1] == NULL) {
				error = got_error_path(argv[1], GOT_ERR_NO_OBJ);
				goto done;
			} else if (argc > 0) {
				error = got_error_fmt(GOT_ERR_NOT_WORKTREE,
				    "%s", "specified paths cannot be resolved");
				goto done;
			} else {
				error = got_error(GOT_ERR_NOT_WORKTREE);
				goto done;
			}
		}

		error = get_worktree_paths_from_argv(&paths, argc, argv,
		    worktree);
		if (error)
			goto done;

		error = got_object_id_str(&id_str,
		    got_worktree_get_base_commit_id(worktree));
		if (error)
			goto done;
		arg.repo = repo;
		arg.worktree = worktree;
		arg.diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;
		arg.diff_context = diff_context;
		arg.id_str = id_str;
		arg.header_shown = 0;
		arg.diff_staged = diff_staged;
		arg.ignore_whitespace = ignore_whitespace;
		arg.force_text_diff = force_text_diff;
		arg.diffstat = show_diffstat ? &dsa : NULL;
		arg.f1 = f1;
		arg.f2 = f2;
		arg.outfile = outfile;

		error = got_worktree_status(worktree, &paths, repo, 0,
		    print_diff, &arg, check_cancelled, NULL);
		free(id_str);
		if (error)
			goto done;

		if (show_diffstat && dsa.nfiles > 0) {
			char *header;

			if (asprintf(&header, "diffstat %s%s",
			    diff_staged ? "-s " : "",
			    got_worktree_get_root_path(worktree)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			error = print_diffstat(&dsa, header);
			free(header);
			if (error)
				goto done;
		}

		error = printfile(outfile);
		goto done;
	}

	if (ncommit_args == 1) {
		struct got_commit_object *commit;
		error = got_object_open_as_commit(&commit, repo, ids[0]);
		if (error)
			goto done;

		labels[1] = labels[0];
		ids[1] = ids[0];
		if (got_object_commit_get_nparents(commit) > 0) {
			const struct got_object_id_queue *pids;
			struct got_object_qid *pid;
			pids = got_object_commit_get_parent_ids(commit);
			pid = STAILQ_FIRST(pids);
			ids[0] = got_object_id_dup(&pid->id);
			if (ids[0] == NULL) {
				error = got_error_from_errno(
				    "got_object_id_dup");
				got_object_commit_close(commit);
				goto done;
			}
			error = got_object_id_str(&labels[0], ids[0]);
			if (error) {
				got_object_commit_close(commit);
				goto done;
			}
		} else {
			ids[0] = NULL;
			labels[0] = strdup("/dev/null");
			if (labels[0] == NULL) {
				error = got_error_from_errno("strdup");
				got_object_commit_close(commit);
				goto done;
			}
		}

		got_object_commit_close(commit);
	}

	if (ncommit_args == 0 && argc > 2) {
		error = got_error_msg(GOT_ERR_BAD_PATH,
		    "path arguments cannot be used when diffing two objects");
		goto done;
	}

	if (ids[0]) {
		error = got_object_get_type(&type1, repo, ids[0]);
		if (error)
			goto done;
	}

	error = got_object_get_type(&type2, repo, ids[1]);
	if (error)
		goto done;
	if (type1 != GOT_OBJ_TYPE_ANY && type1 != type2) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}
	if (type1 == GOT_OBJ_TYPE_BLOB && argc > 2) {
		error = got_error_msg(GOT_ERR_OBJ_TYPE,
		    "path arguments cannot be used when diffing blobs");
		goto done;
	}

	for (i = 0; ncommit_args > 0 && i < argc; i++) {
		char *in_repo_path;
		struct got_pathlist_entry *new;
		if (worktree) {
			const char *prefix;
			char *p;
			error = got_worktree_resolve_path(&p, worktree,
			    argv[i]);
			if (error)
				goto done;
			prefix = got_worktree_get_path_prefix(worktree);
			while (prefix[0] == '/')
				prefix++;
			if (asprintf(&in_repo_path, "%s%s%s", prefix,
			    (p[0] != '\0' && prefix[0] != '\0') ? "/" : "",
			    p) == -1) {
				error = got_error_from_errno("asprintf");
				free(p);
				goto done;
			}
			free(p);
		} else {
			char *mapped_path, *s;
			error = got_repo_map_path(&mapped_path, repo, argv[i]);
			if (error)
				goto done;
			s = mapped_path;
			while (s[0] == '/')
				s++;
			in_repo_path = strdup(s);
			if (in_repo_path == NULL) {
				error = got_error_from_errno("asprintf");
				free(mapped_path);
				goto done;
			}
			free(mapped_path);

		}
		error = got_pathlist_insert(&new, &paths, in_repo_path, NULL);
		if (error || new == NULL /* duplicate */)
			free(in_repo_path);
		if (error)
			goto done;
	}

	if (worktree) {
		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	fd2 = got_opentempfd();
	if (fd2 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	switch (type1 == GOT_OBJ_TYPE_ANY ? type2 : type1) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(NULL, NULL, f1, f2,
		    fd1, fd2, ids[0], ids[1], NULL, NULL,
		    GOT_DIFF_ALGORITHM_PATIENCE, diff_context,
		    ignore_whitespace, force_text_diff,
		    show_diffstat ? &dsa : NULL, repo, outfile);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(NULL, NULL, f1, f2, fd1, fd2,
		    ids[0], ids[1], &paths, "", "",
		    GOT_DIFF_ALGORITHM_PATIENCE, diff_context,
		    ignore_whitespace, force_text_diff,
		    show_diffstat ? &dsa : NULL, repo, outfile);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		fprintf(outfile, "diff %s %s\n", labels[0], labels[1]);
		error = got_diff_objects_as_commits(NULL, NULL, f1, f2,
		    fd1, fd2, ids[0], ids[1], &paths,
		    GOT_DIFF_ALGORITHM_PATIENCE, diff_context,
		    ignore_whitespace, force_text_diff,
		    show_diffstat ? &dsa : NULL, repo, outfile);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}
	if (error)
		goto done;

	if (show_diffstat && dsa.nfiles > 0) {
		char *header = NULL;

		if (asprintf(&header, "diffstat %s %s",
		    labels[0], labels[1]) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		error = print_diffstat(&dsa, header);
		free(header);
		if (error)
			goto done;
	}

	error = printfile(outfile);

done:
	free(cwd);
	free(labels[0]);
	free(labels[1]);
	free(ids[0]);
	free(ids[1]);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&diffstat_paths, GOT_PATHLIST_FREE_ALL);
	got_ref_list_free(&refs);
	if (outfile && fclose(outfile) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f1 && fclose(f1) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (fd1 != -1 && close(fd1) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && error == NULL)
		error = got_error_from_errno("close");
	return error;
}

__dead static void
usage_blame(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp,
	    "usage: %s blame [-c commit] [-r repository-path] path\n",
	    getprogname());
	exit(status);
}

struct blame_line {
	int annotated;
	char *id_str;
	char *committer;
	char datebuf[11]; /* YYYY-MM-DD + NUL */
};

struct blame_cb_args {
	struct blame_line *lines;
	int nlines;
	int nlines_prec;
	int lineno_cur;
	off_t *line_offsets;
	FILE *f;
	struct got_repository *repo;
};

static const struct got_error *
blame_cb(void *arg, int nlines, int lineno,
    struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct blame_cb_args *a = arg;
	struct blame_line *bline;
	char *line = NULL;
	size_t linesize = 0;
	off_t offset;
	struct tm tm;
	time_t committer_time;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	if (sigint_received)
		return got_error(GOT_ERR_ITER_COMPLETED);

	if (lineno == -1)
		return NULL; /* no change in this commit */

	/* Annotate this line. */
	bline = &a->lines[lineno - 1];
	if (bline->annotated)
		return NULL;
	err = got_object_id_str(&bline->id_str, id);
	if (err)
		return err;

	bline->committer = strdup(got_object_commit_get_committer(commit));
	if (bline->committer == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (gmtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(bline->datebuf, sizeof(bline->datebuf), "%F", &tm) == 0) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}
	bline->annotated = 1;

	/* Print lines annotated so far. */
	bline = &a->lines[a->lineno_cur - 1];
	if (!bline->annotated)
		goto done;

	offset = a->line_offsets[a->lineno_cur - 1];
	if (fseeko(a->f, offset, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	while (a->lineno_cur <= a->nlines && bline->annotated) {
		char *smallerthan, *at, *nl, *committer;
		size_t len;

		if (getline(&line, &linesize, a->f) == -1) {
			if (ferror(a->f))
				err = got_error_from_errno("getline");
			break;
		}

		committer = bline->committer;
		smallerthan = strchr(committer, '<');
		if (smallerthan && smallerthan[1] != '\0')
			committer = smallerthan + 1;
		at = strchr(committer, '@');
		if (at)
			*at = '\0';
		len = strlen(committer);
		if (len >= 9)
			committer[8] = '\0';

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		printf("%.*d) %.8s %s %-8s %s\n", a->nlines_prec, a->lineno_cur,
		    bline->id_str, bline->datebuf, committer, line);

		a->lineno_cur++;
		bline = &a->lines[a->lineno_cur - 1];
	}
done:
	free(line);
	return err;
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *path, *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	char *link_target = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_blob_object *blob = NULL;
	char *commit_id_str = NULL, *keyword_idstr = NULL;
	struct blame_cb_args bca;
	int ch, obj_type, i, fd1 = -1, fd2 = -1, fd3 = -1;
	off_t filesize;
	int *pack_fds = NULL;
	FILE *f1 = NULL, *f2 = NULL;

	fd1 = got_opentempfd();
	if (fd1 == -1)
		return got_error_from_errno("got_opentempfd");

	memset(&bca, 0, sizeof(bca));

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:r:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_blame(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		path = argv[0];
	else
		usage_blame(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				if (error)
					goto done;
			}
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p;

		error = got_worktree_resolve_path(&p, worktree, path);
		if (error)
			goto done;
		if (asprintf(&in_repo_path, "%s%s%s", prefix,
		    (p[0] != '\0' && !got_path_is_root_dir(prefix)) ? "/" : "",
		    p) == -1) {
			error = got_error_from_errno("asprintf");
			free(p);
			goto done;
		}
		free(p);
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
	} else {
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		error = got_repo_map_path(&in_repo_path, repo, path);
	}
	if (error)
		goto done;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, worktree ?
		    got_worktree_get_head_ref_name(worktree) : GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		struct got_reflist_head refs;

		TAILQ_INIT(&refs);
		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;

		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			commit_id_str = keyword_idstr;

		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		got_ref_list_free(&refs);
		if (error)
			goto done;
	}

	if (worktree) {
		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_resolve_symlinks(&link_target, in_repo_path,
	    commit, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit,
	    link_target ? link_target : in_repo_path);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error_path(link_target ? link_target : in_repo_path,
		    GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, 8192, fd1);
	if (error)
		goto done;
	bca.f = got_opentemp();
	if (bca.f == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
	error = got_object_blob_dump_to_file(&filesize, &bca.nlines,
	    &bca.line_offsets, bca.f, blob);
	if (error || bca.nlines == 0)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (bca.line_offsets[bca.nlines - 1] == filesize)
		bca.nlines--;

	bca.lines = calloc(bca.nlines, sizeof(*bca.lines));
	if (bca.lines == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}
	bca.lineno_cur = 1;
	bca.nlines_prec = 0;
	i = bca.nlines;
	while (i > 0) {
		i /= 10;
		bca.nlines_prec++;
	}
	bca.repo = repo;

	fd2 = got_opentempfd();
	if (fd2 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}
	fd3 = got_opentempfd();
	if (fd3 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}
	f1 = got_opentemp();
	if (f1 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
	f2 = got_opentemp();
	if (f2 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
	error = got_blame(link_target ? link_target : in_repo_path, commit_id,
	    repo, GOT_DIFF_ALGORITHM_PATIENCE, blame_cb, &bca,
	    check_cancelled, NULL, fd2, fd3, f1, f2);
done:
	free(keyword_idstr);
	free(in_repo_path);
	free(link_target);
	free(repo_path);
	free(cwd);
	free(commit_id);
	free(obj_id);
	if (commit)
		got_object_commit_close(commit);

	if (fd1 != -1 && close(fd1) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd3 != -1 && close(fd3) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (f1 && fclose(f1) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && error == NULL)
		error = got_error_from_errno("fclose");

	if (blob)
		got_object_blob_close(blob);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (bca.lines) {
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
		free(bca.lines);
	}
	free(bca.line_offsets);
	if (bca.f && fclose(bca.f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	return error;
}

__dead static void
usage_tree(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s tree [-iR] [-c commit] [-r repository-path] "
	    "[path]\n", getprogname());
	exit(status);
}

static const struct got_error *
print_entry(struct got_tree_entry *te, const char *id, const char *path,
    const char *root_path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int is_root_path = (strcmp(path, root_path) == 0);
	const char *modestr = "";
	mode_t mode = got_tree_entry_get_mode(te);
	char *link_target = NULL;

	path += strlen(root_path);
	while (path[0] == '/')
		path++;

	if (got_object_tree_entry_is_submodule(te))
		modestr = "$";
	else if (S_ISLNK(mode)) {
		int i;

		err = got_tree_entry_get_symlink_target(&link_target, te, repo);
		if (err)
			return err;
		for (i = 0; link_target[i] != '\0'; i++) {
			if (!isprint((unsigned char)link_target[i]))
				link_target[i] = '?';
		}

		modestr = "@";
	}
	else if (S_ISDIR(mode))
		modestr = "/";
	else if (mode & S_IXUSR)
		modestr = "*";

	printf("%s%s%s%s%s%s%s\n", id ? id : "", path,
	    is_root_path ? "" : "/", got_tree_entry_get_name(te), modestr,
	    link_target ? " -> ": "", link_target ? link_target : "");

	free(link_target);
	return NULL;
}

static const struct got_error *
print_tree(const char *path, struct got_commit_object *commit,
    int show_ids, int recurse, const char *root_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_tree_object *tree = NULL;
	int nentries, i;

	err = got_object_id_by_path(&tree_id, repo, commit, path);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;
	nentries = got_object_tree_get_nentries(tree);
	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		char *id = NULL;

		if (sigint_received || sigpipe_received)
			break;

		te = got_object_tree_get_entry(tree, i);
		if (show_ids) {
			char *id_str;
			err = got_object_id_str(&id_str,
			    got_tree_entry_get_id(te));
			if (err)
				goto done;
			if (asprintf(&id, "%s ", id_str) == -1) {
				err = got_error_from_errno("asprintf");
				free(id_str);
				goto done;
			}
			free(id_str);
		}
		err = print_entry(te, id, path, root_path, repo);
		free(id);
		if (err)
			goto done;

		if (recurse && S_ISDIR(got_tree_entry_get_mode(te))) {
			char *child_path;
			if (asprintf(&child_path, "%s%s%s", path,
			    path[0] == '/' && path[1] == '\0' ? "" : "/",
			    got_tree_entry_get_name(te)) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = print_tree(child_path, commit, show_ids, 1,
			    root_path, repo);
			free(child_path);
			if (err)
				goto done;
		}
	}
done:
	if (tree)
		got_object_tree_close(tree);
	free(tree_id);
	return err;
}

static const struct got_error *
cmd_tree(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	const char *path, *refname = NULL;
	char *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	char *commit_id_str = NULL, *keyword_idstr = NULL;
	int show_ids = 0, recurse = 0;
	int ch;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:iRr:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'i':
			show_ids = 1;
			break;
		case 'R':
			recurse = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_tree(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		path = argv[0];
	else if (argc > 1)
		usage_tree(1);
	else
		path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p;

		if (path == NULL || got_path_is_root_dir(path))
			path = "";
		error = got_worktree_resolve_path(&p, worktree, path);
		if (error)
			goto done;
		if (asprintf(&in_repo_path, "%s%s%s", prefix,
		    (p[0] != '\0' && !got_path_is_root_dir(prefix)) ?  "/" : "",
		    p) == -1) {
			error = got_error_from_errno("asprintf");
			free(p);
			goto done;
		}
		free(p);
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
	} else {
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		if (path == NULL)
			path = "/";
		error = got_repo_map_path(&in_repo_path, repo, path);
		if (error != NULL)
			goto done;
	}

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		if (worktree)
			refname = got_worktree_get_head_ref_name(worktree);
		else
			refname = GOT_REF_HEAD;
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		struct got_reflist_head refs;

		TAILQ_INIT(&refs);
		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;

		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			commit_id_str = keyword_idstr;

		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		got_ref_list_free(&refs);
		if (error)
			goto done;
	}

	if (worktree) {
		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = print_tree(in_repo_path, commit, show_ids, recurse,
	    in_repo_path, repo);
done:
	free(keyword_idstr);
	free(in_repo_path);
	free(repo_path);
	free(cwd);
	free(commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	return error;
}

__dead static void
usage_status(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s status [-I] [-S status-codes] "
	    "[-s status-codes] [path ...]\n", getprogname());
	exit(status);
}

struct got_status_arg {
	char *status_codes;
	int suppress;
};

static const struct got_error *
print_status(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	struct got_status_arg *st = arg;

	if (status == staged_status && (status == GOT_STATUS_DELETE))
		status = GOT_STATUS_NO_CHANGE;
	if (st != NULL && st->status_codes) {
		size_t ncodes = strlen(st->status_codes);
		int i, j = 0;

		for (i = 0; i < ncodes ; i++) {
			if (st->suppress) {
				if (status == st->status_codes[i] ||
				    staged_status == st->status_codes[i]) {
					j++;
					continue;
				}
			} else {
				if (status == st->status_codes[i] ||
				    staged_status == st->status_codes[i])
					break;
			}
		}

		if (st->suppress && j == 0)
			goto print;

		if (i == ncodes)
			return NULL;
	}
print:
	printf("%c%c %s\n", status, staged_status, path);
	return NULL;
}

static const struct got_error *
show_operation_in_progress(struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *new_base_branch_name = NULL;
	char *branch_name = NULL;
	int rebase_in_progress, histedit_in_progress, merge_in_progress;

	err = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (err)
		return err;
	if (rebase_in_progress) {
		err = got_worktree_rebase_info(&new_base_branch_name,
		    &branch_name, worktree, repo);
		if (err)
			return err;
		printf("Work tree is rebasing %s onto %s\n",
		    branch_name, new_base_branch_name);
	}

	err = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (err)
		return err;
	if (histedit_in_progress) {
		err = got_worktree_histedit_info(&branch_name, worktree, repo);
		if (err)
			return err;
		printf("Work tree is editing the history of %s\n", branch_name);
	}

	err = got_worktree_merge_in_progress(&merge_in_progress,
	    worktree, repo);
	if (err)
		return err;
	if (merge_in_progress) {
		err = got_worktree_merge_info(&branch_name, worktree,
		    repo);
		if (err)
			return err;
		printf("Work tree is merging %s into %s\n", branch_name,
		    got_worktree_get_head_ref_name(worktree));
	}

	free(new_base_branch_name);
	free(branch_name);
	return NULL;
}

static const struct got_error *
cmd_status(int argc, char *argv[])
{
	const struct got_error *close_err, *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_status_arg st;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	int ch, i, no_ignores = 0;
	int *pack_fds = NULL;

	RB_INIT(&paths);

	memset(&st, 0, sizeof(st));
	st.status_codes = NULL;
	st.suppress = 0;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "IS:s:")) != -1) {
		switch (ch) {
		case 'I':
			no_ignores = 1;
			break;
		case 'S':
			if (st.status_codes != NULL && st.suppress == 0)
				option_conflict('S', 's');
			st.suppress = 1;
			/* fallthrough */
		case 's':
			for (i = 0; optarg[i] != '\0'; i++) {
				switch (optarg[i]) {
				case GOT_STATUS_MODIFY:
				case GOT_STATUS_ADD:
				case GOT_STATUS_DELETE:
				case GOT_STATUS_CONFLICT:
				case GOT_STATUS_MISSING:
				case GOT_STATUS_OBSTRUCTED:
				case GOT_STATUS_UNVERSIONED:
				case GOT_STATUS_MODE_CHANGE:
				case GOT_STATUS_NONEXISTENT:
					break;
				default:
					errx(1, "invalid status code '%c'",
					    optarg[i]);
				}
			}
			if (ch == 's' && st.suppress)
				option_conflict('s', 'S');
			st.status_codes = optarg;
			break;
		default:
			usage_status(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd,
	    GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "status", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	error = got_worktree_status(worktree, &paths, repo, no_ignores,
	    print_status, &st, check_cancelled, NULL);
	if (error)
		goto done;

	error = show_operation_in_progress(worktree, repo);
done:
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (repo) {
		close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree != NULL) {
		close_err = got_worktree_close(worktree);
		if (error == NULL)
			error = close_err;
	}

	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	return error;
}

__dead static void
usage_ref(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s ref [-dlt] [-c object] [-r repository-path] "
	    "[-s reference] [name]\n", getprogname());
	exit(status);
}

static const struct got_error *
list_refs(struct got_repository *repo, const char *refname, int sort_by_time)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;

	TAILQ_INIT(&refs);
	err = got_ref_list(&refs, repo, refname, sort_by_time ?
	    got_ref_cmp_by_commit_timestamp_descending : got_ref_cmp_by_name,
	    repo);
	if (err)
		return err;

	TAILQ_FOREACH(re, &refs, entry) {
		char *refstr;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL) {
			err = got_error_from_errno("got_ref_to_str");
			break;
		}
		printf("%s: %s\n", got_ref_get_name(re->ref), refstr);
		free(refstr);
	}

	got_ref_list_free(&refs);
	return err;
}

static const struct got_error *
delete_ref_by_name(struct got_repository *repo, const char *refname)
{
	const struct got_error *err;
	struct got_reference *ref;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		return err;

	err = delete_ref(repo, ref);
	got_ref_close(ref);
	return err;
}

static const struct got_error *
add_ref(struct got_repository *repo, const char *refname, const char *target)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	struct got_reference *ref = NULL;
	struct got_reflist_head refs;

	/*
	 * Don't let the user create a reference name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (refname[0] == '-')
		return got_error_path(refname, GOT_ERR_REF_NAME_MINUS);

	TAILQ_INIT(&refs);
	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;
	err = got_repo_match_object_id(&id, NULL, target, GOT_OBJ_TYPE_ANY,
	    &refs, repo);
	got_ref_list_free(&refs);
	if (err)
		goto done;

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
	free(id);
	return err;
}

static const struct got_error *
add_symref(struct got_repository *repo, const char *refname, const char *target)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	struct got_reference *target_ref = NULL;

	/*
	 * Don't let the user create a reference name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (refname[0] == '-')
		return got_error_path(refname, GOT_ERR_REF_NAME_MINUS);

	err = got_ref_open(&target_ref, repo, target, 0);
	if (err)
		return err;

	err = got_ref_alloc_symref(&ref, refname, target_ref);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (target_ref)
		got_ref_close(target_ref);
	if (ref)
		got_ref_close(ref);
	return err;
}

static const struct got_error *
cmd_ref(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch, do_list = 0, do_delete = 0, sort_by_time = 0;
	const char *obj_arg = NULL, *symref_target= NULL;
	char *refname = NULL, *keyword_idstr = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec "
	    "sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:dlr:s:t")) != -1) {
		switch (ch) {
		case 'c':
			obj_arg = optarg;
			break;
		case 'd':
			do_delete = 1;
			break;
		case 'l':
			do_list = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 's':
			symref_target = optarg;
			break;
		case 't':
			sort_by_time = 1;
			break;
		default:
			usage_ref(1);
			/* NOTREACHED */
		}
	}

	if (obj_arg && do_list)
		option_conflict('c', 'l');
	if (obj_arg && do_delete)
		option_conflict('c', 'd');
	if (obj_arg && symref_target)
		option_conflict('c', 's');
	if (symref_target && do_delete)
		option_conflict('s', 'd');
	if (symref_target && do_list)
		option_conflict('s', 'l');
	if (do_delete && do_list)
		option_conflict('d', 'l');
	if (sort_by_time && !do_list)
		errx(1, "-t option requires -l option");

	argc -= optind;
	argv += optind;

	if (do_list) {
		if (argc != 0 && argc != 1)
			usage_ref(1);
		if (argc == 1) {
			refname = strdup(argv[0]);
			if (refname == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else {
		if (argc != 1)
			usage_ref(1);
		refname = strdup(argv[0]);
		if (refname == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (refname)
		got_path_strip_trailing_slashes(refname);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, NULL);
	if (error != NULL)
		goto done;

#ifndef PROFILE
	if (do_list) {
		/* Remove "cpath" promise. */
		if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
		    NULL) == -1)
			err(1, "pledge");
	}
#endif

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (do_list)
		error = list_refs(repo, refname, sort_by_time);
	else if (do_delete)
		error = delete_ref_by_name(repo, refname);
	else if (symref_target)
		error = add_symref(repo, refname, symref_target);
	else {
		if (obj_arg == NULL)
			usage_ref(1);

		error = got_keyword_to_idstr(&keyword_idstr, obj_arg,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			obj_arg = keyword_idstr;

		error = add_ref(repo, refname, obj_arg);
	}
done:
	free(refname);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(repo_path);
	free(keyword_idstr);
	return error;
}

__dead static void
usage_branch(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s branch [-lnt] [-c commit] [-d name] "
	    "[-r repository-path] [name]\n", getprogname());
	exit(status);
}

static const struct got_error *
list_branch(struct got_repository *repo, struct got_worktree *worktree,
    struct got_reference *ref)
{
	const struct got_error *err = NULL;
	const char *refname;
	char *refstr;
	char marker = ' ';

	refname = got_ref_get_name(ref);
	if (worktree && strcmp(refname,
	    got_worktree_get_head_ref_name(worktree)) == 0) {
		err = got_worktree_get_state(&marker, repo, worktree,
		    check_cancelled, NULL);
		if (err != NULL)
			return err;
	}

	if (strncmp(refname, "refs/heads/", 11) == 0)
		refname += 11;
	if (strncmp(refname, "refs/got/worktree/", 18) == 0)
		refname += 18;
	if (strncmp(refname, "refs/remotes/", 13) == 0)
		refname += 13;

	refstr = got_ref_to_str(ref);
	if (refstr == NULL)
		return got_error_from_errno("got_ref_to_str");

	printf("%c %s: %s\n", marker, refname, refstr);
	free(refstr);
	return NULL;
}

static const struct got_error *
show_current_branch(struct got_repository *repo, struct got_worktree *worktree)
{
	const char *refname;

	if (worktree == NULL)
		return got_error(GOT_ERR_NOT_WORKTREE);

	refname = got_worktree_get_head_ref_name(worktree);

	if (strncmp(refname, "refs/heads/", 11) == 0)
		refname += 11;
	if (strncmp(refname, "refs/got/worktree/", 18) == 0)
		refname += 18;

	printf("%s\n", refname);

	return NULL;
}

static const struct got_error *
list_branches(struct got_repository *repo, struct got_worktree *worktree,
    int sort_by_time)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_reference *temp_ref = NULL;
	int rebase_in_progress, histedit_in_progress;

	TAILQ_INIT(&refs);

	if (worktree) {
		err = got_worktree_rebase_in_progress(&rebase_in_progress,
		    worktree);
		if (err)
			return err;

		err = got_worktree_histedit_in_progress(&histedit_in_progress,
		    worktree);
		if (err)
			return err;

		if (rebase_in_progress || histedit_in_progress) {
			err = got_ref_open(&temp_ref, repo,
			    got_worktree_get_head_ref_name(worktree), 0);
			if (err)
				return err;
			list_branch(repo, worktree, temp_ref);
			got_ref_close(temp_ref);
		}
	}

	err = got_ref_list(&refs, repo, "refs/heads", sort_by_time ?
	    got_ref_cmp_by_commit_timestamp_descending : got_ref_cmp_by_name,
	    repo);
	if (err)
		return err;

	TAILQ_FOREACH(re, &refs, entry)
		list_branch(repo, worktree, re->ref);

	got_ref_list_free(&refs);

	err = got_ref_list(&refs, repo, "refs/remotes", sort_by_time ?
	    got_ref_cmp_by_commit_timestamp_descending : got_ref_cmp_by_name,
	    repo);
	if (err)
		return err;

	TAILQ_FOREACH(re, &refs, entry)
		list_branch(repo, worktree, re->ref);

	got_ref_list_free(&refs);

	return NULL;
}

static const struct got_error *
delete_branch(struct got_repository *repo, struct got_worktree *worktree,
    const char *branch_name)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *refname, *remote_refname = NULL;

	if (strncmp(branch_name, "refs/", 5) == 0)
		branch_name += 5;
	if (strncmp(branch_name, "heads/", 6) == 0)
		branch_name += 6;
	else if (strncmp(branch_name, "remotes/", 8) == 0)
		branch_name += 8;

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1)
		return got_error_from_errno("asprintf");

	if (asprintf(&remote_refname, "refs/remotes/%s",
	    branch_name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_ref_open(&ref, repo, refname, 0);
	if (err) {
		const struct got_error *err2;
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		/*
		 * Keep 'err' intact such that if neither branch exists
		 * we report "refs/heads" rather than "refs/remotes" in
		 * our error message.
		 */
		err2 = got_ref_open(&ref, repo, remote_refname, 0);
		if (err2)
			goto done;
		err = NULL;
	}

	if (worktree &&
	    strcmp(got_worktree_get_head_ref_name(worktree),
	    got_ref_get_name(ref)) == 0) {
		err = got_error_msg(GOT_ERR_SAME_BRANCH,
		    "will not delete this work tree's current branch");
		goto done;
	}

	err = delete_ref(repo, ref);
done:
	if (ref)
		got_ref_close(ref);
	free(refname);
	free(remote_refname);
	return err;
}

static const struct got_error *
add_branch(struct got_repository *repo, const char *branch_name,
    struct got_object_id *base_commit_id)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *refname = NULL;

	/*
	 * Don't let the user create a branch name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (branch_name[0] == '-')
		return got_error_path(branch_name, GOT_ERR_REF_NAME_MINUS);

	if (strncmp(branch_name, "refs/heads/", 11) == 0)
		branch_name += 11;

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_ref_open(&ref, repo, refname, 0);
	if (err == NULL) {
		err = got_error(GOT_ERR_BRANCH_EXISTS);
		goto done;
	} else if (err->code != GOT_ERR_NOT_REF)
		goto done;

	err = got_ref_alloc(&ref, refname, base_commit_id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
	free(refname);
	return err;
}

static const struct got_error *
cmd_branch(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch, do_list = 0, do_show = 0, do_update = 1, sort_by_time = 0;
	const char *delref = NULL, *commit_id_arg = NULL;
	struct got_reference *ref = NULL;
	struct got_pathlist_head paths;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL, *keyword_idstr = NULL;;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec "
	    "sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:d:lnr:t")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
			break;
		case 'd':
			delref = optarg;
			break;
		case 'l':
			do_list = 1;
			break;
		case 'n':
			do_update = 0;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 't':
			sort_by_time = 1;
			break;
		default:
			usage_branch(1);
			/* NOTREACHED */
		}
	}

	if (do_list && delref)
		option_conflict('l', 'd');
	if (sort_by_time && !do_list)
		errx(1, "-t option requires -l option");

	argc -= optind;
	argv += optind;

	if (!do_list && !delref && argc == 0)
		do_show = 1;

	if ((do_list || delref || do_show) && commit_id_arg != NULL)
		errx(1, "-c option can only be used when creating a branch");

	if (do_list || delref) {
		if (argc > 0)
			usage_branch(1);
	} else if (!do_show && argc != 1)
		usage_branch(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

#ifndef PROFILE
	if (do_list || do_show) {
		/* Remove "cpath" promise. */
		if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
		    NULL) == -1)
			err(1, "pledge");
	}
#endif

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (do_show)
		error = show_current_branch(repo, worktree);
	else if (do_list)
		error = list_branches(repo, worktree, sort_by_time);
	else if (delref)
		error = delete_branch(repo, worktree, delref);
	else {
		struct got_reflist_head refs;
		TAILQ_INIT(&refs);
		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;
		if (commit_id_arg == NULL)
			commit_id_arg = worktree ?
			    got_worktree_get_head_ref_name(worktree) :
			    GOT_REF_HEAD;
		else {
			error = got_keyword_to_idstr(&keyword_idstr,
			    commit_id_arg, repo, worktree);
			if (error != NULL)
				goto done;
			if (keyword_idstr != NULL)
				commit_id_arg = keyword_idstr;
		}
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_arg, GOT_OBJ_TYPE_COMMIT, &refs, repo);
		got_ref_list_free(&refs);
		if (error)
			goto done;
		error = add_branch(repo, argv[0], commit_id);
		if (error)
			goto done;
		if (worktree && do_update) {
			struct got_update_progress_arg upa;
			char *branch_refname = NULL;

			error = got_object_id_str(&commit_id_str, commit_id);
			if (error)
				goto done;
			error = get_worktree_paths_from_argv(&paths, 0, NULL,
			    worktree);
			if (error)
				goto done;
			if (asprintf(&branch_refname, "refs/heads/%s", argv[0])
			    == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			error = got_ref_open(&ref, repo, branch_refname, 0);
			free(branch_refname);
			if (error)
				goto done;
			error = switch_head_ref(ref, commit_id, worktree,
			    repo);
			if (error)
				goto done;
			error = got_worktree_set_base_commit_id(worktree, repo,
			    commit_id);
			if (error)
				goto done;
			memset(&upa, 0, sizeof(upa));
			error = got_worktree_checkout_files(worktree, &paths,
			    repo, update_progress, &upa, check_cancelled,
			    NULL);
			if (error)
				goto done;
			if (upa.did_something) {
				printf("Updated to %s: %s\n",
				    got_worktree_get_head_ref_name(worktree),
				    commit_id_str);
			}
			print_update_progress_stats(&upa);
		}
	}
done:
	free(keyword_idstr);
	if (ref)
		got_ref_close(ref);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(cwd);
	free(repo_path);
	free(commit_id);
	free(commit_id_str);
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	return error;
}


__dead static void
usage_tag(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s tag [-lsVv] [-c commit] [-m message] "
	    "[-r repository-path] [-S signer-id] name\n", getprogname());
	exit(status);
}

#if 0
static const struct got_error *
sort_tags(struct got_reflist_head *sorted, struct got_reflist_head *tags)
{
	const struct got_error *err = NULL;
	struct got_reflist_entry *re, *se, *new;
	struct got_object_id *re_id, *se_id;
	struct got_tag_object *re_tag, *se_tag;
	time_t re_time, se_time;

	STAILQ_FOREACH(re, tags, entry) {
		se = STAILQ_FIRST(sorted);
		if (se == NULL) {
			err = got_reflist_entry_dup(&new, re);
			if (err)
				return err;
			STAILQ_INSERT_HEAD(sorted, new, entry);
			continue;
		} else {
			err = got_ref_resolve(&re_id, repo, re->ref);
			if (err)
				break;
			err = got_object_open_as_tag(&re_tag, repo, re_id);
			free(re_id);
			if (err)
				break;
			re_time = got_object_tag_get_tagger_time(re_tag);
			got_object_tag_close(re_tag);
		}

		while (se) {
			err = got_ref_resolve(&se_id, repo, re->ref);
			if (err)
				break;
			err = got_object_open_as_tag(&se_tag, repo, se_id);
			free(se_id);
			if (err)
				break;
			se_time = got_object_tag_get_tagger_time(se_tag);
			got_object_tag_close(se_tag);

			if (se_time > re_time) {
				err = got_reflist_entry_dup(&new, re);
				if (err)
					return err;
				STAILQ_INSERT_AFTER(sorted, se, new, entry);
				break;
			}
			se = STAILQ_NEXT(se, entry);
			continue;
		}
	}
done:
	return err;
}
#endif

static const struct got_error *
get_tag_refname(char **refname, const char *tag_name)
{
	const struct got_error *err;

	if (strncmp("refs/tags/", tag_name, 10) == 0) {
		*refname = strdup(tag_name);
		if (*refname == NULL)
			return got_error_from_errno("strdup");
	} else if (asprintf(refname, "refs/tags/%s", tag_name) == -1) {
		err = got_error_from_errno("asprintf");
		*refname = NULL;
		return err;
	}

	return NULL;
}

static const struct got_error *
print_tag_oneline(struct got_tag_object *tag, struct got_commit_object *commit,
    const char *refname, const char *refstr, time_t tagger_time,
    const char *id_str)
{
	static const struct got_error *err = NULL;
	const char *label = NULL;
	struct tm tm;
	char *tagmsg0 = NULL, *tagmsg;
	char datebuf[11];

	if (gmtime_r(&tagger_time, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(datebuf, sizeof(datebuf), "%F", &tm) == 0)
		return got_error(GOT_ERR_NO_SPACE);

	if (commit) {
		err = got_object_commit_get_logmsg(&tagmsg0, commit);
		if (err)
			return err;
	} else {
		tagmsg0 = strdup(got_object_tag_get_message(tag));
		if (tagmsg0 == NULL)
			return got_error_from_errno("strdup");
	}

	tagmsg = tagmsg0;
	while (isspace((unsigned char)*tagmsg))
		tagmsg++;
	tagmsg[strcspn(tagmsg, "\n")] = '\0';

	if (commit)
		label = GOT_OBJ_LABEL_COMMIT;
	else {
		switch (got_object_tag_get_object_type(tag)) {
		case GOT_OBJ_TYPE_BLOB:
			label = GOT_OBJ_LABEL_BLOB;
			break;
		case GOT_OBJ_TYPE_TREE:
			label = GOT_OBJ_LABEL_TREE;
			break;
		case GOT_OBJ_TYPE_COMMIT:
			label = GOT_OBJ_LABEL_COMMIT;
			break;
		case GOT_OBJ_TYPE_TAG:
			label = GOT_OBJ_LABEL_TAG;
			break;
		default:
			break;
		}
	}

	if (label)
		printf("%s %s:%.10s %s: %s\n", datebuf, label, id_str, refname,
		    tagmsg);
	else
		printf("%s tag:%.10s %s: %s\n", datebuf, refstr, refname,
		    tagmsg);

	free(tagmsg0);

	return err;
}

static const struct got_error *
print_tag(struct got_tag_object *tag, struct got_commit_object *commit,
    const char *refname, const char *refstr, const char *tagger,
    time_t tagger_time, const char *id_str, const char *ssh_sig,
    const char *allowed_signers, const char *revoked_signers, int verbosity,
    int *bad_sigs)
{
	static const struct got_error *err = NULL;
	char datebuf[26];
	char *sig_msg = NULL, *tagmsg0 = NULL, *tagmsg, *line, *datestr;

	printf("%stag %s %s\n", GOT_COMMIT_SEP_STR, refname, refstr);
	printf("from: %s\n", tagger);
	datestr = get_datestr(&tagger_time, datebuf);
	if (datestr)
		printf("date: %s UTC\n", datestr);
	if (commit)
		printf("object: %s %s\n", GOT_OBJ_LABEL_COMMIT, id_str);
	else {
		switch (got_object_tag_get_object_type(tag)) {
		case GOT_OBJ_TYPE_BLOB:
			printf("object: %s %s\n", GOT_OBJ_LABEL_BLOB, id_str);
			break;
		case GOT_OBJ_TYPE_TREE:
			printf("object: %s %s\n", GOT_OBJ_LABEL_TREE, id_str);
			break;
		case GOT_OBJ_TYPE_COMMIT:
			printf("object: %s %s\n", GOT_OBJ_LABEL_COMMIT, id_str);
			break;
		case GOT_OBJ_TYPE_TAG:
			printf("object: %s %s\n", GOT_OBJ_LABEL_TAG, id_str);
			break;
		default:
			break;
		}
	}

	if (ssh_sig) {
		err = got_sigs_verify_tag_ssh(&sig_msg, tag, ssh_sig,
		    allowed_signers, revoked_signers, verbosity);
		if (err) {
			if (err->code != GOT_ERR_BAD_TAG_SIGNATURE)
				goto done;
			*bad_sigs = 1;
			err = NULL;
		}
		if (sig_msg)
			printf("signature: %s", sig_msg);
		else
			printf("bad signature\n");
		free(sig_msg);
	}

	if (commit) {
		err = got_object_commit_get_logmsg(&tagmsg0, commit);
		if (err)
			goto done;
	} else {
		tagmsg0 = strdup(got_object_tag_get_message(tag));
		if (tagmsg0 == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	tagmsg = tagmsg0;
	while ((line = strsep(&tagmsg, "\n")) != NULL)
		printf(" %s\n", line);

 done:
	free(tagmsg0);
	return err;
}

static const struct got_error *
list_tags(struct got_repository *repo, const char *tag_name, int verify_tags,
    const char *allowed_signers, const char *revoked_signers, int verbosity,
    int oneline)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *wanted_refname = NULL;
	int bad_sigs = 0;

	TAILQ_INIT(&refs);

	err = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_tags, repo);
	if (err)
		return err;

	if (tag_name) {
		struct got_reference *ref;
		err = get_tag_refname(&wanted_refname, tag_name);
		if (err)
			goto done;
		/* Wanted tag reference should exist. */
		err = got_ref_open(&ref, repo, wanted_refname, 0);
		if (err)
			goto done;
		got_ref_close(ref);
	}

	TAILQ_FOREACH(re, &refs, entry) {
		const char *refname;
		char *refstr, *id_str;
		const char *tagger, *ssh_sig = NULL;
		time_t tagger_time;
		struct got_object_id *id;
		struct got_tag_object *tag;
		struct got_commit_object *commit = NULL;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/tags/", 10) != 0 ||
		    (wanted_refname && strcmp(refname, wanted_refname) != 0))
			continue;
		refname += 10;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL) {
			err = got_error_from_errno("got_ref_to_str");
			break;
		}

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			break;
		err = got_object_open_as_tag(&tag, repo, id);
		if (err) {
			if (err->code != GOT_ERR_OBJ_TYPE) {
				free(id);
				break;
			}
			/* "lightweight" tag */
			err = got_object_open_as_commit(&commit, repo, id);
			if (err) {
				free(id);
				break;
			}
			tagger = got_object_commit_get_committer(commit);
			tagger_time =
			    got_object_commit_get_committer_time(commit);
			err = got_object_id_str(&id_str, id);
			free(id);
			if (err)
				break;
		} else {
			free(id);
			tagger = got_object_tag_get_tagger(tag);
			tagger_time = got_object_tag_get_tagger_time(tag);
			err = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
			if (err)
				break;
		}

		if (tag && verify_tags) {
			ssh_sig = got_sigs_get_tagmsg_ssh_signature(
			    got_object_tag_get_message(tag));
			if (ssh_sig && allowed_signers == NULL) {
				err = got_error_msg(
				    GOT_ERR_VERIFY_TAG_SIGNATURE,
				    "SSH signature verification requires "
				        "setting allowed_signers in "
				        "got.conf(5)");
				break;
			}
		}

		if (oneline)
			err = print_tag_oneline(tag, commit, refname, refstr,
			    tagger_time, id_str);
		else
			err = print_tag(tag, commit, refname, refstr, tagger,
			    tagger_time, id_str, ssh_sig, allowed_signers,
			    revoked_signers, verbosity, &bad_sigs);

		if (commit)
			got_object_commit_close(commit);
		if (tag)
			got_object_tag_close(tag);
		free(id_str);
		free(refstr);

		if (err)
			break;
	}
done:
	got_ref_list_free(&refs);
	free(wanted_refname);

	if (err == NULL && bad_sigs)
		err = got_error(GOT_ERR_BAD_TAG_SIGNATURE);
	return err;
}

static const struct got_error *
get_tag_message(char **tagmsg, char **tagmsg_path, const char *commit_id_str,
    const char *tag_name, const char *editor, const char *repo_path)
{
	const struct got_error *err = NULL;
	char *template = NULL, *initial_content = NULL;
	int initial_content_len;
	int fd = -1;

	if (asprintf(&template, GOT_TMPDIR_STR "/got-tagmsg") == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	initial_content_len = asprintf(&initial_content,
	    "\n# tagging commit %s as %s\n",
	    commit_id_str, tag_name);
	if (initial_content_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(tagmsg_path, &fd, template, "");
	if (err)
		goto done;

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", *tagmsg_path);
		goto done;
	}
	if (close(fd) == -1) {
		err = got_error_from_errno2("close", *tagmsg_path);
		goto done;
	}
	fd = -1;

	err = edit_logmsg(tagmsg, editor, *tagmsg_path, initial_content,
	    initial_content_len, 1);
done:
	free(initial_content);
	free(template);

	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", *tagmsg_path);

	if (err) {
		free(*tagmsg);
		*tagmsg = NULL;
	}
	return err;
}

static const struct got_error *
add_tag(struct got_repository *repo, const char *tagger,
    const char *tag_name, const char *commit_arg, const char *tagmsg_arg,
    const char *signer_id, const char *editor, int verbosity)
{
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL, *tag_id = NULL;
	char *label = NULL, *commit_id_str = NULL;
	struct got_reference *ref = NULL;
	char *refname = NULL, *tagmsg = NULL;
	char *tagmsg_path = NULL, *tag_id_str = NULL;
	int preserve_tagmsg = 0;
	struct got_reflist_head refs;

	TAILQ_INIT(&refs);

	/*
	 * Don't let the user create a tag name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (tag_name[0] == '-')
		return got_error_path(tag_name, GOT_ERR_REF_NAME_MINUS);

	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	err = got_repo_match_object_id(&commit_id, &label, commit_arg,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (err)
		goto done;

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err)
		goto done;

	err = get_tag_refname(&refname, tag_name);
	if (err)
		goto done;
	if (strncmp("refs/tags/", tag_name, 10) == 0)
		tag_name += 10;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err == NULL) {
		err = got_error(GOT_ERR_TAG_EXISTS);
		goto done;
	} else if (err->code != GOT_ERR_NOT_REF)
		goto done;

	if (tagmsg_arg == NULL) {
		err = get_tag_message(&tagmsg, &tagmsg_path, commit_id_str,
		    tag_name, editor, got_repo_get_path(repo));
		if (err) {
			if (err->code != GOT_ERR_COMMIT_MSG_EMPTY &&
			    tagmsg_path != NULL)
				preserve_tagmsg = 1;
			goto done;
		}
	}

	err = got_object_tag_create(&tag_id, tag_name, commit_id,
	    tagger, time(NULL), tagmsg ? tagmsg : tagmsg_arg, signer_id, repo,
	    verbosity);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_ref_alloc(&ref, refname, tag_id);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_ref_write(ref, repo);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_object_id_str(&tag_id_str, tag_id);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}
	printf("Created tag %s\n", tag_id_str);
done:
	if (preserve_tagmsg) {
		fprintf(stderr, "%s: tag message preserved in %s\n",
		    getprogname(), tagmsg_path);
	} else if (tagmsg_path && unlink(tagmsg_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tagmsg_path);
	free(tag_id_str);
	if (ref)
		got_ref_close(ref);
	free(commit_id);
	free(commit_id_str);
	free(refname);
	free(tagmsg);
	free(tagmsg_path);
	got_ref_list_free(&refs);
	return err;
}

static const struct got_error *
cmd_tag(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *commit_id_str = NULL;
	char *gitconfig_path = NULL, *tagger = NULL, *keyword_idstr = NULL;
	char *allowed_signers = NULL, *revoked_signers = NULL, *editor = NULL;
	const char *signer_id = NULL;
	const char *tag_name = NULL, *commit_id_arg = NULL, *tagmsg = NULL;
	int ch, do_list = 0, oneline = 0, verify_tags = 0, verbosity = 0;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec "
	    "sendfd unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:lm:r:S:sVv")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
			break;
		case 'l':
			do_list = 1;
			break;
		case 'm':
			tagmsg = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL) {
				error = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'S':
			signer_id = optarg;
			break;
		case 's':
			oneline = 1;
			break;
		case 'V':
			verify_tags = 1;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		default:
			usage_tag(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (oneline && !do_list)
		errx(1, "-s option can only be used when listing tags");
	else if (do_list || verify_tags) {
		if (commit_id_arg != NULL)
			errx(1,
			    "-c option can only be used when creating a tag");
		if (tagmsg) {
			if (do_list)
				option_conflict('l', 'm');
			else
				option_conflict('V', 'm');
		}
		if (signer_id) {
			if (do_list)
				option_conflict('l', 'S');
			else
				option_conflict('V', 'S');
		}
		if (argc > 1)
			usage_tag(1);
	} else if (argc != 1)
		usage_tag(1);

	if (argc == 1)
		tag_name = argv[0];

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd,
		    GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	if (do_list || verify_tags) {
		error = got_repo_open(&repo, repo_path, NULL, pack_fds);
		if (error != NULL)
			goto done;
		error = get_allowed_signers(&allowed_signers, repo, worktree);
		if (error)
			goto done;
		error = get_revoked_signers(&revoked_signers, repo, worktree);
		if (error)
			goto done;
		if (worktree) {
			/* Release work tree lock. */
			got_worktree_close(worktree);
			worktree = NULL;
		}

		/*
		 * Remove "cpath" promise unless needed for signature tmpfile
		 * creation.
		 */
		if (verify_tags)
		 	got_sigs_apply_unveil();
		else {
#ifndef PROFILE
			if (pledge("stdio rpath wpath flock proc exec sendfd "
			    "unveil", NULL) == -1)
				err(1, "pledge");
#endif
		}
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		error = list_tags(repo, tag_name, verify_tags, allowed_signers,
		    revoked_signers, verbosity, oneline);
	} else {
		error = get_gitconfig_path(&gitconfig_path);
		if (error)
			goto done;
		error = got_repo_open(&repo, repo_path, gitconfig_path,
		    pack_fds);
		if (error != NULL)
			goto done;

		error = get_author(&tagger, repo, worktree);
		if (error)
			goto done;
		if (signer_id == NULL)
			signer_id = get_signer_id(repo, worktree);

		if (tagmsg == NULL) {
			error = get_editor(&editor);
			if (error)
				goto done;
			if (unveil(editor, "x") != 0) {
				error = got_error_from_errno2("unveil", editor);
				goto done;
			}
		}
		if (signer_id) {
			error = got_sigs_apply_unveil();
			if (error)
				goto done;
		}
		error = apply_unveil(got_repo_get_path(repo), 0, NULL);
		if (error)
			goto done;

		if (commit_id_arg == NULL) {
			struct got_reference *head_ref;
			struct got_object_id *commit_id;
			error = got_ref_open(&head_ref, repo,
			    worktree ? got_worktree_get_head_ref_name(worktree)
			    : GOT_REF_HEAD, 0);
			if (error)
				goto done;
			error = got_ref_resolve(&commit_id, repo, head_ref);
			got_ref_close(head_ref);
			if (error)
				goto done;
			error = got_object_id_str(&commit_id_str, commit_id);
			free(commit_id);
			if (error)
				goto done;
		} else {
			error = got_keyword_to_idstr(&keyword_idstr,
			    commit_id_arg, repo, worktree);
			if (error != NULL)
				goto done;
			commit_id_str = keyword_idstr;
		}

		if (worktree) {
			/* Release work tree lock. */
			got_worktree_close(worktree);
			worktree = NULL;
		}

		error = add_tag(repo, tagger, tag_name,
		    commit_id_str ? commit_id_str : commit_id_arg, tagmsg,
		    signer_id, editor, verbosity);
	}
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(cwd);
	free(editor);
	free(repo_path);
	free(gitconfig_path);
	free(commit_id_str);
	free(tagger);
	free(allowed_signers);
	free(revoked_signers);
	return error;
}

__dead static void
usage_add(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s add [-IR] path ...\n", getprogname());
	exit(status);
}

static const struct got_error *
add_progress(void *arg, unsigned char status, const char *path)
{
	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
	return NULL;
}

static const struct got_error *
cmd_add(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, can_recurse = 0, no_ignores = 0;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "IR")) != -1) {
		switch (ch) {
		case 'I':
			no_ignores = 1;
			break;
		case 'R':
			can_recurse = 1;
			break;
		default:
			usage_add(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_add(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "add", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "adding directories requires -R option");
				goto done;
			}
		}
	}

	error = got_worktree_schedule_add(worktree, &paths, add_progress,
	    NULL, repo, no_ignores);
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	return error;
}

__dead static void
usage_remove(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s remove [-fkR] [-s status-codes] path ...\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
print_remove_status(void *arg, unsigned char status,
    unsigned char staged_status, const char *path)
{
	while (path[0] == '/')
		path++;
	if (status == GOT_STATUS_NONEXISTENT)
		return NULL;
	if (status == staged_status && (status == GOT_STATUS_DELETE))
		status = GOT_STATUS_NO_CHANGE;
	printf("%c%c %s\n", status, staged_status, path);
	return NULL;
}

static const struct got_error *
cmd_remove(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	const char *status_codes = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, delete_local_mods = 0, can_recurse = 0, keep_on_disk = 0, i;
	int ignore_missing_paths = 0;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "fkRs:")) != -1) {
		switch (ch) {
		case 'f':
			delete_local_mods = 1;
			ignore_missing_paths = 1;
			break;
		case 'k':
			keep_on_disk = 1;
			break;
		case 'R':
			can_recurse = 1;
			break;
		case 's':
			for (i = 0; optarg[i] != '\0'; i++) {
				switch (optarg[i]) {
				case GOT_STATUS_MODIFY:
					delete_local_mods = 1;
					break;
				case GOT_STATUS_MISSING:
					ignore_missing_paths = 1;
					break;
				default:
					errx(1, "invalid status code '%c'",
					    optarg[i]);
				}
			}
			status_codes = optarg;
			break;
		default:
			usage_remove(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_remove(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "remove", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "removing directories requires -R option");
				goto done;
			}
		}
	}

	error = got_worktree_schedule_delete(worktree, &paths,
	    delete_local_mods, status_codes, print_remove_status, NULL,
	    repo, keep_on_disk, ignore_missing_paths);
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	return error;
}

__dead static void
usage_patch(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s patch [-nR] [-c commit] [-p strip-count] "
	    "[patchfile]\n", getprogname());
	exit(status);
}

static const struct got_error *
patch_from_stdin(int *patchfd)
{
	const struct got_error *err = NULL;
	ssize_t r;
	char buf[BUFSIZ];
	sig_t sighup, sigint, sigquit;

	*patchfd = got_opentempfd();
	if (*patchfd == -1)
		return got_error_from_errno("got_opentempfd");

	sighup = signal(SIGHUP, SIG_DFL);
	sigint = signal(SIGINT, SIG_DFL);
	sigquit = signal(SIGQUIT, SIG_DFL);

	for (;;) {
		r = read(0, buf, sizeof(buf));
		if (r == -1) {
			err = got_error_from_errno("read");
			break;
		}
		if (r == 0)
			break;
		if (write(*patchfd, buf, r) == -1) {
			err = got_error_from_errno("write");
			break;
		}
	}

	signal(SIGHUP, sighup);
	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);

	if (err == NULL && lseek(*patchfd, 0, SEEK_SET) == -1)
		err = got_error_from_errno("lseek");

	if (err != NULL) {
		close(*patchfd);
		*patchfd = -1;
	}

	return err;
}

struct got_patch_progress_arg {
	int did_something;
	int conflicts;
	int rejects;
};

static const struct got_error *
patch_progress(void *arg, const char *old, const char *new,
    unsigned char status, const struct got_error *error, int old_from,
    int old_lines, int new_from, int new_lines, int offset,
    int ws_mangled, const struct got_error *hunk_err)
{
	const char *path = new == NULL ? old : new;
	struct got_patch_progress_arg *a = arg;

	while (*path == '/')
		path++;

	if (status != GOT_STATUS_NO_CHANGE &&
	    status != 0 /* per-hunk progress */) {
		printf("%c  %s\n", status, path);
		a->did_something = 1;
	}

	if (hunk_err == NULL) {
		if (status == GOT_STATUS_CANNOT_UPDATE)
			a->rejects++;
		else if (status == GOT_STATUS_CONFLICT)
			a->conflicts++;
	}

	if (error != NULL)
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);

	if (offset != 0 || hunk_err != NULL || ws_mangled) {
		printf("@@ -%d,%d +%d,%d @@ ", old_from,
		    old_lines, new_from, new_lines);
		if (hunk_err != NULL)
			printf("%s\n", hunk_err->msg);
		else if (offset != 0)
			printf("applied with offset %d\n", offset);
		else
			printf("hunk contains mangled whitespace\n");
	}

	return NULL;
}

static void
print_patch_progress_stats(struct got_patch_progress_arg *ppa)
{
	if (!ppa->did_something)
		return;

	if (ppa->conflicts > 0)
		printf("Files with merge conflicts: %d\n", ppa->conflicts);

	if (ppa->rejects > 0) {
		printf("Files where patch failed to apply: %d\n",
		    ppa->rejects);
	}
}

static const struct got_error *
cmd_patch(int argc, char *argv[])
{
	const struct got_error *error = NULL, *close_error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_object_id *commit_id = NULL;
	const char *commit_id_str = NULL;
	struct stat sb;
	const char *errstr;
	char *cwd = NULL, *keyword_idstr = NULL;
	int ch, nop = 0, strip = -1, reverse = 0;
	int patchfd;
	int *pack_fds = NULL;
	struct got_patch_progress_arg ppa;

	TAILQ_INIT(&refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr proc exec sendfd flock "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:np:R")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'n':
			nop = 1;
			break;
		case 'p':
			strip = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "pathname strip count is %s: %s",
				     errstr, optarg);
			break;
		case 'R':
			reverse = 1;
			break;
		default:
			usage_patch(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		error = patch_from_stdin(&patchfd);
		if (error)
			return error;
	} else if (argc == 1) {
		patchfd = open(argv[0], O_RDONLY);
		if (patchfd == -1)
			return got_error_from_errno2("open", argv[0]);
		if (fstat(patchfd, &sb) == -1) {
			error = got_error_from_errno2("fstat", argv[0]);
			goto done;
		}
		if (!S_ISREG(sb.st_mode)) {
			error = got_error_path(argv[0], GOT_ERR_BAD_FILETYPE);
			goto done;
		}
	} else
		usage_patch(1);

	if ((cwd = getcwd(NULL, 0)) == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error != NULL)
		goto done;

	const char *repo_path = got_worktree_get_repo_path(worktree);
	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error != NULL)
		goto done;

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	if (commit_id_str != NULL) {
		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;

		error = got_repo_match_object_id(&commit_id, NULL,
		    keyword_idstr != NULL ? keyword_idstr : commit_id_str,
		    GOT_OBJ_TYPE_COMMIT, &refs, repo);
		if (error)
			goto done;
	}

	memset(&ppa, 0, sizeof(ppa));
	error = got_patch(patchfd, worktree, repo, nop, strip, reverse,
	    commit_id, patch_progress, &ppa, check_cancelled, NULL);
	print_patch_progress_stats(&ppa);
done:
	got_ref_list_free(&refs);
	free(keyword_idstr);
	free(commit_id);
	if (repo) {
		close_error = got_repo_close(repo);
		if (error == NULL)
			error = close_error;
	}
	if (worktree != NULL) {
		close_error = got_worktree_close(worktree);
		if (error == NULL)
			error = close_error;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(cwd);
	return error;
}

__dead static void
usage_revert(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s revert [-pR] [-F response-script] path ...\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
revert_progress(void *arg, unsigned char status, const char *path)
{
	if (status == GOT_STATUS_UNVERSIONED)
		return NULL;

	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
	return NULL;
}

struct choose_patch_arg {
	FILE *patch_script_file;
	const char *action;
};

static const struct got_error *
show_change(unsigned char status, const char *path, FILE *patch_file, int n,
    int nchanges, const char *action)
{
	const struct got_error *err;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	switch (status) {
	case GOT_STATUS_ADD:
		printf("A  %s\n%s this addition? [y/n] ", path, action);
		break;
	case GOT_STATUS_DELETE:
		printf("D  %s\n%s this deletion? [y/n] ", path, action);
		break;
	case GOT_STATUS_MODIFY:
		if (fseek(patch_file, 0L, SEEK_SET) == -1)
			return got_error_from_errno("fseek");
		printf(GOT_COMMIT_SEP_STR);
		while ((linelen = getline(&line, &linesize, patch_file)) != -1)
			printf("%s", line);
		if (linelen == -1 && ferror(patch_file)) {
			err = got_error_from_errno("getline");
			free(line);
			return err;
		}
		free(line);
		printf(GOT_COMMIT_SEP_STR);
		printf("M  %s (change %d of %d)\n%s this change? [y/n/q] ",
		    path, n, nchanges, action);
		break;
	default:
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	}

	fflush(stdout);
	return NULL;
}

#define CHOOSE_PATCH_VALID_RESPONSES	"ynq"

static const struct got_error *
choose_patch(int *choice, void *arg, unsigned char status, const char *path,
    FILE *patch_file, int n, int nchanges)
{
	const struct got_error *err = NULL;
	char *nl, *line = NULL;
	FILE *fp = stdin;
	size_t linesize = 0;
	ssize_t linelen;
	int interactive = 1;
	struct choose_patch_arg *a = arg;

	*choice = GOT_PATCH_CHOICE_NONE;

	if (a->patch_script_file) {
		interactive = 0;
		fp = a->patch_script_file;
	}

	for (;;) {
		err = show_change(status, path, patch_file, n, nchanges,
		    a->action);
		if (err)
			return err;

		linelen = getline(&line, &linesize, fp);
		if (linelen == -1) {
			free(line);
			if (ferror(fp))
				return got_error_from_errno("getline");
			if (feof(fp))
				return got_error(GOT_ERR_EOF);
			return NULL;
		}

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		if (strlen(line) != 1 ||
		    !strchr(CHOOSE_PATCH_VALID_RESPONSES, line[0])) {
			printf("invalid response '%s'\n", line);
			if (interactive)
				continue;
		}

		/* ADD and DELETE do not accept 'q' response currently. */
		if (status != GOT_STATUS_MODIFY && line[0] == 'q') {
			printf("invalid response '%s'\n", line);
			continue;
		}

		break;
	}

	switch (line[0]) {
	case 'y':
		*choice = GOT_PATCH_CHOICE_YES;
		break;
	case 'n':
		*choice = GOT_PATCH_CHOICE_NO;
		break;
	case 'q':
		if (status == GOT_STATUS_MODIFY)
			*choice = GOT_PATCH_CHOICE_QUIT;
		break;
	default:
		printf("invalid response '%s'\n", line);
		free(line);
		return NULL;
	}

	if (!interactive)
		printf("%c\n", line[0]);

	free(line);
	return NULL;
}

struct wt_commitable_path_arg {
	struct got_pathlist_head	*commit_paths;
	int				*has_changes;
};

/*
 * Shortcut work tree status callback to determine if the set of paths scanned
 * has at least one versioned path that is being modified and, if not NULL, is
 * in the arg->commit_paths list.  Set arg and return GOT_ERR_FILE_MODIFIED as
 * soon as a path is passed with a status that satisfies this criteria.
 */
static const struct got_error *
worktree_has_commitable_path(void *arg, unsigned char status,
    unsigned char staged_status, const char *path,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	struct wt_commitable_path_arg *a = arg;

	if (status == staged_status && (status == GOT_STATUS_DELETE))
		status = GOT_STATUS_NO_CHANGE;

	if (!(status == GOT_STATUS_NO_CHANGE ||
	    status == GOT_STATUS_UNVERSIONED) ||
	    staged_status != GOT_STATUS_NO_CHANGE) {
		if (a->commit_paths != NULL) {
			struct got_pathlist_entry *pe;

			RB_FOREACH(pe, got_pathlist_head, a->commit_paths) {
				if (strncmp(path, pe->path,
				    pe->path_len) == 0) {
					*a->has_changes = 1;
					break;
				}
			}
		} else
			*a->has_changes = 1;

		if (*a->has_changes)
			return got_error(GOT_ERR_FILE_MODIFIED);
	}

	return NULL;
}

/*
 * Check that the changeset of the commit identified by id is
 * comprised of at least one modified path that is being committed.
 */
static const struct got_error *
commit_path_changed_in_worktree(struct wt_commitable_path_arg *wcpa,
    struct got_object_id *id, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_pathlist_head	 paths;
	struct got_commit_object	*commit = NULL, *pcommit = NULL;
	struct got_tree_object		*tree = NULL, *ptree = NULL;
	struct got_object_qid		*pid;

	RB_INIT(&paths);

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo,
	    got_object_commit_get_tree_id(commit));
	if (err)
		goto done;

	pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (pid != NULL) {
		err = got_object_open_as_commit(&pcommit, repo, &pid->id);
		if (err)
			goto done;

		err = got_object_open_as_tree(&ptree, repo,
		    got_object_commit_get_tree_id(pcommit));
		if (err)
			goto done;
	}

	err = got_diff_tree(ptree, tree, NULL, NULL, -1, -1, "", "", repo,
	    got_diff_tree_collect_changed_paths, &paths, 0);
	if (err)
		goto done;

	err = got_worktree_status(worktree, &paths, repo, 0,
	    worktree_has_commitable_path, wcpa, check_cancelled, NULL);
	if (err && err->code == GOT_ERR_FILE_MODIFIED) {
		/*
		 * At least one changed path in the referenced commit is
		 * modified in the work tree, that's all we need to know!
		 */
		err = NULL;
	}

done:
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_ALL);
	if (commit)
		got_object_commit_close(commit);
	if (pcommit)
		got_object_commit_close(pcommit);
	if (tree)
		got_object_tree_close(tree);
	if (ptree)
		got_object_tree_close(ptree);
	return err;
}

/*
 * Remove any "logmsg" reference comprised entirely of paths that have
 * been reverted in this work tree. If any path in the logmsg ref changeset
 * remains in a changed state in the worktree, do not remove the reference.
 */
static const struct got_error *
rm_logmsg_ref(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_reflist_head		 refs;
	struct got_reflist_entry	*re;
	struct got_commit_object	*commit = NULL;
	struct got_object_id		*commit_id = NULL;
	struct wt_commitable_path_arg	 wcpa;
	char				*uuidstr = NULL;

	TAILQ_INIT(&refs);

	err = got_worktree_get_uuid(&uuidstr, worktree);
	if (err)
		goto done;

	err = got_ref_list(&refs, repo, "refs/got/worktree",
	    got_ref_cmp_by_name, repo);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		const char	*refname;
		int		 has_changes = 0;

		refname = got_ref_get_name(re->ref);

		if (!strncmp(refname, GOT_WORKTREE_CHERRYPICK_REF_PREFIX,
		    GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN))
			refname += GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN + 1;
		else if (!strncmp(refname, GOT_WORKTREE_BACKOUT_REF_PREFIX,
		    GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN))
			refname += GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN + 1;
		else
			continue;

		if (strncmp(refname, uuidstr, GOT_WORKTREE_UUID_STRLEN) == 0)
			refname += GOT_WORKTREE_UUID_STRLEN + 1; /* skip '-' */
		else
			continue;

		err = got_repo_match_object_id(&commit_id, NULL, refname,
		    GOT_OBJ_TYPE_COMMIT, NULL, repo);
		if (err)
			goto done;

		err = got_object_open_as_commit(&commit, repo, commit_id);
		if (err)
			goto done;

		wcpa.commit_paths = NULL;
		wcpa.has_changes = &has_changes;

		err = commit_path_changed_in_worktree(&wcpa, commit_id,
		    worktree, repo);
		if (err)
			goto done;

		if (!has_changes) {
			err = got_ref_delete(re->ref, repo);
			if (err)
				goto done;
		}

		got_object_commit_close(commit);
		commit = NULL;
		free(commit_id);
		commit_id = NULL;
	}

done:
	free(uuidstr);
	free(commit_id);
	got_ref_list_free(&refs);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
cmd_revert(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *path = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, can_recurse = 0, pflag = 0;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "F:pR")) != -1) {
		switch (ch) {
		case 'F':
			patch_script_path = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'R':
			can_recurse = 1;
			break;
		default:
			usage_revert(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_revert(1);
	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "revert", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "re");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}

	/*
	 * XXX "c" perm needed on repo dir to delete merge references.
	 */
	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "reverting directories requires -R option");
				goto done;
			}
		}
	}

	cpa.patch_script_file = patch_script_file;
	cpa.action = "revert";
	error = got_worktree_revert(worktree, &paths, revert_progress, NULL,
	    pflag ? choose_patch : NULL, &cpa, repo);

	error = rm_logmsg_ref(worktree, repo);
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(path);
	free(cwd);
	return error;
}

__dead static void
usage_commit(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s commit [-CNnS] [-A author] [-F path] "
	    "[-m message] [path ...]\n", getprogname());
	exit(status);
}

struct collect_commit_logmsg_arg {
	const char *cmdline_log;
	const char *prepared_log;
	const char *merged_log;
	int non_interactive;
	const char *editor;
	const char *worktree_path;
	const char *branch_name;
	const char *repo_path;
	char *logmsg_path;

};

static const struct got_error *
read_prepared_logmsg(char **logmsg, const char *path)
{
	const struct got_error *err = NULL;
	FILE *f = NULL;
	struct stat sb;
	size_t r;

	*logmsg = NULL;
	memset(&sb, 0, sizeof(sb));

	f = fopen(path, "re");
	if (f == NULL)
		return got_error_from_errno2("fopen", path);

	if (fstat(fileno(f), &sb) == -1) {
		err = got_error_from_errno2("fstat", path);
		goto done;
	}
	if (sb.st_size == 0) {
		err = got_error(GOT_ERR_COMMIT_MSG_EMPTY);
		goto done;
	}

	*logmsg = malloc(sb.st_size + 1);
	if (*logmsg == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}

	r = fread(*logmsg, 1, sb.st_size, f);
	if (r != sb.st_size) {
		if (ferror(f))
			err = got_error_from_errno2("fread", path);
		else
			err = got_error(GOT_ERR_IO);
		goto done;
	}
	(*logmsg)[sb.st_size] = '\0';
done:
	if (fclose(f) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path);
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

static const struct got_error *
collect_commit_logmsg(struct got_pathlist_head *commitable_paths,
    const char *diff_path, char **logmsg, void *arg)
{
	char *initial_content = NULL;
	struct got_pathlist_entry *pe;
	const struct got_error *err = NULL;
	char *template = NULL;
	char *prepared_msg = NULL, *merged_msg = NULL;
	struct collect_commit_logmsg_arg *a = arg;
	int initial_content_len;
	int fd = -1;
	size_t len;

	/* if a message was specified on the command line, just use it */
	if (a->cmdline_log != NULL && *a->cmdline_log != '\0') {
		len = strlen(a->cmdline_log) + 1;
		*logmsg = malloc(len + 1);
		if (*logmsg == NULL)
			return got_error_from_errno("malloc");
		strlcpy(*logmsg, a->cmdline_log, len);
		return NULL;
	} else if (a->prepared_log != NULL && a->non_interactive)
		return read_prepared_logmsg(logmsg, a->prepared_log);

	if (asprintf(&template, "%s/logmsg", a->worktree_path) == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(&a->logmsg_path, &fd, template, "");
	if (err)
		goto done;

	if (a->prepared_log) {
		err = read_prepared_logmsg(&prepared_msg, a->prepared_log);
		if (err)
			goto done;
	} else if (a->merged_log) {
		err = read_prepared_logmsg(&merged_msg, a->merged_log);
		if (err)
			goto done;
	}

	initial_content_len = asprintf(&initial_content,
	    "%s%s\n# changes to be committed on branch %s:\n",
	    prepared_msg ? prepared_msg : "",
	    merged_msg ? merged_msg : "", a->branch_name);
	if (initial_content_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", a->logmsg_path);
		goto done;
	}

	RB_FOREACH(pe, got_pathlist_head, commitable_paths) {
		struct got_commitable *ct = pe->data;
		dprintf(fd, "#  %c  %s\n",
		    got_commitable_get_status(ct),
		    got_commitable_get_path(ct));
	}

	if (diff_path) {
		dprintf(fd, "# detailed changes can be viewed in %s\n",
		    diff_path);
	}

	if (close(fd) == -1) {
		err = got_error_from_errno2("close", a->logmsg_path);
		goto done;
	}
	fd = -1;

	err = edit_logmsg(logmsg, a->editor, a->logmsg_path, initial_content,
	    initial_content_len, a->prepared_log ? 0 : 1);
done:
	free(initial_content);
	free(template);
	free(prepared_msg);
	free(merged_msg);

	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", a->logmsg_path);
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

static const struct got_error *
cat_logmsg(FILE *f, struct got_commit_object *commit, const char *idstr,
    const char *type, int has_content)
{
	const struct got_error	*err = NULL;
	char			*logmsg = NULL;

	err = got_object_commit_get_logmsg(&logmsg, commit);
	if (err)
		return err;

	if (fprintf(f, "%s# log message of %s commit %s:%s",
	    has_content ? "\n" : "", type, idstr, logmsg) < 0)
		err = got_ferror(f, GOT_ERR_IO);

	free(logmsg);
	return err;
}

/*
 * Lookup "logmsg" references of backed-out and cherrypicked commits
 * belonging to the current work tree. If found, and the worktree has
 * at least one modified file that was changed in the referenced commit,
 * add its log message to a new temporary file at *logmsg_path.
 * Add all refs found to matched_refs to be scheduled for removal on
 * successful commit.
 */
static const struct got_error *
lookup_logmsg_ref(char **logmsg_path, struct got_pathlist_head *paths,
    struct got_reflist_head *matched_refs, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_commit_object	*commit = NULL;
	struct got_object_id		*id = NULL;
	struct got_reflist_head		 refs;
	struct got_reflist_entry	*re, *re_match;
	FILE				*f = NULL;
	char				*uuidstr = NULL;
	int				 added_logmsg = 0;

	TAILQ_INIT(&refs);

	*logmsg_path = NULL;

	err = got_worktree_get_uuid(&uuidstr, worktree);
	if (err)
		goto done;

	err = got_ref_list(&refs, repo, "refs/got/worktree",
	    got_ref_cmp_by_name, repo);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		const char			*refname, *type;
		struct wt_commitable_path_arg	 wcpa;
		int				 add_logmsg = 0;

		refname = got_ref_get_name(re->ref);

		if (strncmp(refname, GOT_WORKTREE_CHERRYPICK_REF_PREFIX,
		    GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN) == 0) {
			refname += GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN + 1;
			type = "cherrypicked";
		} else if (strncmp(refname, GOT_WORKTREE_BACKOUT_REF_PREFIX,
		    GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN) == 0) {
			refname += GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN + 1;
			type = "backed-out";
		} else
			continue;

		if (strncmp(refname, uuidstr, GOT_WORKTREE_UUID_STRLEN) == 0)
			refname += GOT_WORKTREE_UUID_STRLEN + 1; /* skip '-' */
		else
			continue;

		err = got_repo_match_object_id(&id, NULL, refname,
		    GOT_OBJ_TYPE_COMMIT, NULL, repo);
		if (err)
			goto done;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			goto done;

		wcpa.commit_paths = paths;
		wcpa.has_changes = &add_logmsg;

		err = commit_path_changed_in_worktree(&wcpa, id,
		    worktree, repo);
		if (err)
			goto done;

		if (add_logmsg) {
			if (f == NULL) {
				err = got_opentemp_named(logmsg_path, &f,
				    "got-commit-logmsg", "");
				if (err)
					goto done;
			}
			err = cat_logmsg(f, commit, refname, type,
			    added_logmsg);
			if (err)
				goto done;
			if (!added_logmsg)
				++added_logmsg;

			err = got_reflist_entry_dup(&re_match, re);
			if (err)
				goto done;
			TAILQ_INSERT_HEAD(matched_refs, re_match, entry);
		}

		got_object_commit_close(commit);
		commit = NULL;
		free(id);
		id = NULL;
	}

done:
	free(id);
	free(uuidstr);
	got_ref_list_free(&refs);
	if (commit)
		got_object_commit_close(commit);
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (!added_logmsg) {
		if (*logmsg_path && unlink(*logmsg_path) != 0 && err == NULL)
			err = got_error_from_errno2("unlink", *logmsg_path);
		*logmsg_path = NULL;
	}
	return err;
}

static const struct got_error *
cmd_commit(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *id_str = NULL;
	struct got_object_id *id = NULL;
	const char *logmsg = NULL;
	char *prepared_logmsg = NULL, *merged_logmsg = NULL;
	struct collect_commit_logmsg_arg cl_arg;
	const char *author = NULL;
	char *gitconfig_path = NULL, *editor = NULL, *committer = NULL;
	int ch, rebase_in_progress, histedit_in_progress, preserve_logmsg = 0;
	int allow_bad_symlinks = 0, non_interactive = 0, merge_in_progress = 0;
	int show_diff = 1, commit_conflicts = 0;
	struct got_pathlist_head paths;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	int *pack_fds = NULL;

	TAILQ_INIT(&refs);
	RB_INIT(&paths);
	cl_arg.logmsg_path = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "A:CF:m:NnS")) != -1) {
		switch (ch) {
		case 'A':
			author = optarg;
			error = valid_author(author);
			if (error)
				return error;
			break;
		case 'C':
			commit_conflicts = 1;
			break;
		case 'F':
			if (logmsg != NULL)
				option_conflict('F', 'm');
			prepared_logmsg = realpath(optarg, NULL);
			if (prepared_logmsg == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			break;
		case 'm':
			if (prepared_logmsg)
				option_conflict('m', 'F');
			logmsg = optarg;
			break;
		case 'N':
			non_interactive = 1;
			break;
		case 'n':
			show_diff = 0;
			break;
		case 'S':
			allow_bad_symlinks = 1;
			break;
		default:
			usage_commit(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "commit", cwd);
		goto done;
	}

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;
	if (rebase_in_progress) {
		error = got_error(GOT_ERR_REBASING);
		goto done;
	}

	error = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (error)
		goto done;

	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    gitconfig_path, pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_merge_in_progress(&merge_in_progress, worktree, repo);
	if (error)
		goto done;
	if (merge_in_progress) {
		error = got_error(GOT_ERR_MERGE_BUSY);
		goto done;
	}

	error = get_author(&committer, repo, worktree);
	if (error)
		goto done;

	if (author == NULL)
		author = committer;

	if (logmsg == NULL || strlen(logmsg) == 0) {
		error = get_editor(&editor);
		if (error)
			goto done;
		if (unveil(editor, "x") != 0) {
			error = got_error_from_errno2("unveil", editor);
			goto done;
		}
	}
	if (prepared_logmsg) {
		if (unveil(prepared_logmsg, "r") != 0) {
			error = got_error_from_errno2("unveil",
			    prepared_logmsg);
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (prepared_logmsg == NULL) {
		error = lookup_logmsg_ref(&merged_logmsg,
		    argc > 0 ? &paths : NULL, &refs, worktree, repo);
		if (error)
			goto done;
	}

	cl_arg.editor = editor;
	cl_arg.cmdline_log = logmsg;
	cl_arg.prepared_log = prepared_logmsg;
	cl_arg.merged_log = merged_logmsg;
	cl_arg.non_interactive = non_interactive;
	cl_arg.worktree_path = got_worktree_get_root_path(worktree);
	cl_arg.branch_name = got_worktree_get_head_ref_name(worktree);
	if (!histedit_in_progress) {
		if (strncmp(cl_arg.branch_name, "refs/heads/", 11) != 0) {
			error = got_error(GOT_ERR_COMMIT_BRANCH);
			goto done;
		}
		cl_arg.branch_name += 11;
	}
	cl_arg.repo_path = got_repo_get_path(repo);
	error = got_worktree_commit(&id, worktree, &paths, author, 0,
	    committer, allow_bad_symlinks, show_diff, commit_conflicts,
	    collect_commit_logmsg, &cl_arg, print_status, NULL, repo);
	if (error) {
		if (error->code != GOT_ERR_COMMIT_MSG_EMPTY &&
		    cl_arg.logmsg_path != NULL)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_object_id_str(&id_str, id);
	if (error)
		goto done;
	printf("Created commit %s\n", id_str);

	TAILQ_FOREACH(re, &refs, entry) {
		error = got_ref_delete(re->ref, repo);
		if (error)
			goto done;
	}

done:
	if (preserve_logmsg) {
		fprintf(stderr, "%s: log message preserved in %s\n",
		    getprogname(), cl_arg.logmsg_path);
	} else if (cl_arg.logmsg_path && unlink(cl_arg.logmsg_path) == -1 &&
	    error == NULL)
		error = got_error_from_errno2("unlink", cl_arg.logmsg_path);
	free(cl_arg.logmsg_path);
	if (merged_logmsg && unlink(merged_logmsg) == -1 && error == NULL)
		error = got_error_from_errno2("unlink", merged_logmsg);
	free(merged_logmsg);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_ref_list_free(&refs);
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	free(id_str);
	free(gitconfig_path);
	free(editor);
	free(committer);
	free(prepared_logmsg);
	return error;
}

__dead static void
usage_send(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s send [-afqTv] [-b branch] [-d branch] "
	    "[-i identity-file] [-J jumphost] [-r repository-path] [-t tag] "
	    "[remote-repository]\n", getprogname());
	exit(status);
}

static void
print_load_info(int print_colored, int print_found, int print_trees,
    int ncolored, int nfound, int ntrees)
{
	if (print_colored) {
		printf("%d commit%s colored", ncolored,
		    ncolored == 1 ? "" : "s");
	}
	if (print_found) {
		printf("%s%d object%s found",
		    ncolored > 0 ? "; " : "",
		    nfound, nfound == 1 ? "" : "s");
	}
	if (print_trees) {
		printf("; %d tree%s scanned", ntrees,
		    ntrees == 1 ? "" : "s");
	}
}

struct got_send_progress_arg {
	char last_scaled_packsize[FMT_SCALED_STRSIZE];
	int verbosity;
	int last_ncolored;
	int last_nfound;
	int last_ntrees;
	int loading_done;
	int last_ncommits;
	int last_nobj_total;
	int last_p_deltify;
	int last_p_written;
	int last_p_sent;
	int printed_something;
	int sent_something;
	struct got_pathlist_head *delete_branches;
};

static const struct got_error *
send_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written, off_t bytes_sent, const char *refname,
    const char *errmsg, int success)
{
	struct got_send_progress_arg *a = arg;
	char scaled_packsize[FMT_SCALED_STRSIZE];
	char scaled_sent[FMT_SCALED_STRSIZE];
	int p_deltify = 0, p_written = 0, p_sent = 0;
	int print_colored = 0, print_found = 0, print_trees = 0;
	int print_searching = 0, print_total = 0;
	int print_deltify = 0, print_written = 0, print_sent = 0;

	if (a->verbosity < 0)
		return NULL;

	if (refname) {
		const char *status = success ? "accepted" : "rejected";

		if (success) {
			struct got_pathlist_entry *pe;
			RB_FOREACH(pe, got_pathlist_head, a->delete_branches) {
				const char *branchname = pe->path;
				if (got_path_cmp(branchname, refname,
				    strlen(branchname), strlen(refname)) == 0) {
					status = "deleted";
					a->sent_something = 1;
					break;
				}
			}
		}

		if (a->printed_something)
			putchar('\n');
		printf("Server has %s %s", status, refname);
		if (errmsg)
			printf(": %s", errmsg);
		a->printed_something = 1;
		return NULL;
	}

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
		printf("\r");
		print_load_info(print_colored, print_found, print_trees,
		    ncolored, nfound, ntrees);
		a->printed_something = 1;
		fflush(stdout);
		return NULL;
	} else if (!a->loading_done) {
		printf("\r");
		print_load_info(1, 1, 1, ncolored, nfound, ntrees);
		printf("\n");
		a->loading_done = 1;
	}

	if (fmt_scaled(packfile_size, scaled_packsize) == -1)
		return got_error_from_errno("fmt_scaled");
	if (fmt_scaled(bytes_sent, scaled_sent) == -1)
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

	if (packfile_size > 0 && (a->last_scaled_packsize[0] == '\0' ||
	    strcmp(scaled_packsize, a->last_scaled_packsize)) != 0) {
		if (strlcpy(a->last_scaled_packsize, scaled_packsize,
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

	if (bytes_sent > 0) {
		p_sent = (bytes_sent * 100) / packfile_size;
		if (p_sent != a->last_p_sent) {
			a->last_p_sent = p_sent;
			print_searching = 1;
			print_total = 1;
			print_deltify = 1;
			print_written = 1;
			print_sent = 1;
		}
		a->sent_something = 1;
	}

	if (print_searching || print_total || print_deltify || print_written ||
	    print_sent)
		printf("\r");
	if (print_searching)
		printf("packing %d reference%s", ncommits,
		    ncommits == 1 ? "" : "s");
	if (print_total)
		printf("; %d object%s", nobj_total,
		    nobj_total == 1 ? "" : "s");
	if (print_deltify)
		printf("; deltify: %d%%", p_deltify);
	if (print_sent)
		printf("; uploading pack: %*s %d%%", FMT_SCALED_STRSIZE - 2,
		    scaled_packsize, p_sent);
	else if (print_written)
		printf("; writing pack: %*s %d%%", FMT_SCALED_STRSIZE - 2,
		    scaled_packsize, p_written);
	if (print_searching || print_total || print_deltify ||
	    print_written || print_sent) {
		a->printed_something = 1;
		fflush(stdout);
	}
	return NULL;
}

static const struct got_error *
cmd_send(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *cwd = NULL, *repo_path = NULL;
	const char *remote_name;
	char *proto = NULL, *host = NULL, *port = NULL;
	char *repo_name = NULL, *server_path = NULL;
	const struct got_remote_repo *remotes;
	struct got_remote_repo *remote = NULL;
	int nremotes, nbranches = 0, ndelete_branches = 0;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	const struct got_gotconfig *repo_conf = NULL, *worktree_conf = NULL;
	struct got_pathlist_head branches;
	struct got_pathlist_head tags;
	struct got_reflist_head all_branches;
	struct got_reflist_head all_tags;
	struct got_pathlist_head delete_args;
	struct got_pathlist_head delete_branches;
	struct got_reflist_entry *re;
	struct got_pathlist_entry *pe;
	int i, ch, sendfd = -1, sendstatus;
	pid_t sendpid = -1;
	struct got_send_progress_arg spa;
	int verbosity = 0, overwrite_refs = 0;
	int send_all_branches = 0, send_all_tags = 0;
	struct got_reference *ref = NULL;
	int *pack_fds = NULL;
	const char *jumphost = NULL, *identity_file = NULL;

	RB_INIT(&branches);
	RB_INIT(&tags);
	TAILQ_INIT(&all_branches);
	TAILQ_INIT(&all_tags);
	RB_INIT(&delete_args);
	RB_INIT(&delete_branches);

	while ((ch = getopt(argc, argv, "ab:d:fi:J:qr:Tt:v")) != -1) {
		switch (ch) {
		case 'a':
			send_all_branches = 1;
			break;
		case 'b':
			error = got_pathlist_insert(NULL, &branches, optarg, NULL);
			if (error)
				return error;
			nbranches++;
			break;
		case 'd':
			error = got_pathlist_insert(NULL, &delete_args, optarg, NULL);
			if (error)
				return error;
			break;
		case 'f':
			overwrite_refs = 1;
			break;
		case 'i':
			identity_file = optarg;
			break;
		case 'J':
			jumphost = optarg;
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
		case 'T':
			send_all_tags = 1;
			break;
		case 't':
			error = got_pathlist_insert(NULL, &tags, optarg, NULL);
			if (error)
				return error;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		default:
			usage_send(1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (send_all_branches && !RB_EMPTY(&branches))
		option_conflict('a', 'b');
	if (send_all_tags && !RB_EMPTY(&tags))
		option_conflict('T', 't');


	if (argc == 0)
		remote_name = GOT_SEND_DEFAULT_REMOTE_NAME;
	else if (argc == 1)
		remote_name = argv[0];
	else
		usage_send(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	if (worktree) {
		worktree_conf = got_worktree_get_gotconfig(worktree);
		if (worktree_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    worktree_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					error = got_repo_remote_repo_dup(&remote,
					    &remotes[i]);
					if (error)
						goto done;
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		repo_conf = got_repo_get_gotconfig(repo);
		if (repo_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    repo_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					error = got_repo_remote_repo_dup(&remote,
					    &remotes[i]);
					if (error)
						goto done;
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		got_repo_get_gitconfig_remotes(&nremotes, &remotes, repo);
		for (i = 0; i < nremotes; i++) {
			if (strcmp(remotes[i].name, remote_name) == 0) {
				error = got_repo_remote_repo_dup(&remote,
				    &remotes[i]);
				if (error)
					goto done;
				break;
			}
		}
	}
	if (remote == NULL) {
		error = got_error_path(remote_name, GOT_ERR_NO_REMOTE);
		goto done;
	}

	error = got_dial_parse_uri(&proto, &host, &port, &server_path,
	    &repo_name, remote->send_url);
	if (error)
		goto done;

	if (strcmp(proto, "git") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd dns inet unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "git+ssh") == 0 ||
	    strcmp(proto, "ssh") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+http") == 0) {
		error = got_error_path(proto, GOT_ERR_NOT_IMPL);
		goto done;
	} else {
		error = got_error_path(proto, GOT_ERR_BAD_PROTO);
		goto done;
	}

	error = got_dial_apply_unveil(proto);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0, NULL);
	if (error)
		goto done;

	if (send_all_branches) {
		error = got_ref_list(&all_branches, repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
		if (error)
			goto done;
		TAILQ_FOREACH(re, &all_branches, entry) {
			const char *branchname = got_ref_get_name(re->ref);
			error = got_pathlist_insert(NULL, &branches,
			    branchname, NULL);
			if (error)
				goto done;
			nbranches++;
		}
	} else if (nbranches == 0) {
		for (i = 0; i < remote->nsend_branches; i++) {
			error = got_pathlist_insert(NULL, &branches,
			    remote->send_branches[i], NULL);
			if (error)
				goto done;
		}
	}

	if (send_all_tags) {
		error = got_ref_list(&all_tags, repo, "refs/tags",
		    got_ref_cmp_by_name, NULL);
		if (error)
			goto done;
		TAILQ_FOREACH(re, &all_tags, entry) {
			const char *tagname = got_ref_get_name(re->ref);
			error = got_pathlist_insert(NULL, &tags,
			    tagname, NULL);
			if (error)
				goto done;
		}
	}

	/*
	 * To prevent accidents only branches in refs/heads/ can be deleted
	 * with 'got send -d'.
	 * Deleting anything else requires local repository access or Git.
	 */
	RB_FOREACH(pe, got_pathlist_head, &delete_args) {
		const char *branchname = pe->path;
		char *s;
		struct got_pathlist_entry *new;
		if (strncmp(branchname, "refs/heads/", 11) == 0) {
			s = strdup(branchname);
			if (s == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		} else {
			if (asprintf(&s, "refs/heads/%s", branchname) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
		error = got_pathlist_insert(&new, &delete_branches, s, NULL);
		if (error || new == NULL /* duplicate */)
			free(s);
		if (error)
			goto done;
		ndelete_branches++;
	}

	if (nbranches == 0 && ndelete_branches == 0) {
		struct got_reference *head_ref;
		if (worktree)
			error = got_ref_open(&head_ref, repo,
			    got_worktree_get_head_ref_name(worktree), 0);
		else
			error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
		if (error)
			goto done;
		if (got_ref_is_symbolic(head_ref)) {
			error = got_ref_resolve_symbolic(&ref, repo, head_ref);
			got_ref_close(head_ref);
			if (error)
				goto done;
		} else
			ref = head_ref;
		error = got_pathlist_insert(NULL, &branches, got_ref_get_name(ref),
		    NULL);
		if (error)
			goto done;
		nbranches++;
	}

	if (worktree) {
		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	if (verbosity >= 0) {
		printf("Connecting to \"%s\" %s://%s%s%s%s%s\n",
		    remote->name, proto, host,
		    port ? ":" : "", port ? port : "",
		    *server_path == '/' ? "" : "/", server_path);
	}

	error = got_send_connect(&sendpid, &sendfd, proto, host, port,
	    server_path, jumphost, identity_file, verbosity);
	if (error)
		goto done;

	memset(&spa, 0, sizeof(spa));
	spa.last_scaled_packsize[0] = '\0';
	spa.last_p_deltify = -1;
	spa.last_p_written = -1;
	spa.verbosity = verbosity;
	spa.delete_branches = &delete_branches;
	error = got_send_pack(remote_name, &branches, &tags, &delete_branches,
	    verbosity, overwrite_refs, sendfd, repo, send_progress, &spa,
	    check_cancelled, NULL);
	if (spa.printed_something)
		putchar('\n');
	if (error)
		goto done;
	if (!spa.sent_something && verbosity >= 0)
		printf("Already up-to-date\n");
done:
	if (sendpid > 0) {
		if (kill(sendpid, SIGTERM) == -1)
			error = got_error_from_errno("kill");
		if (waitpid(sendpid, &sendstatus, 0) == -1 && error == NULL)
			error = got_error_from_errno("waitpid");
	}
	if (sendfd != -1 && close(sendfd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	if (ref)
		got_ref_close(ref);
	got_repo_free_remote_repo_data(remote);
	free(remote);
	got_pathlist_free(&branches, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&tags, GOT_PATHLIST_FREE_NONE);
	got_ref_list_free(&all_branches);
	got_ref_list_free(&all_tags);
	got_pathlist_free(&delete_args, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&delete_branches, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	free(repo_path);
	free(proto);
	free(host);
	free(port);
	free(server_path);
	free(repo_name);
	return error;
}

/*
 * Print and if delete is set delete all ref_prefix references.
 * If wanted_ref is not NULL, only print or delete this reference.
 */
static const struct got_error *
process_logmsg_refs(const char *ref_prefix, size_t prefix_len,
    const char *wanted_ref, int delete, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error			*err;
	struct got_pathlist_head		 paths;
	struct got_reflist_head			 refs;
	struct got_reflist_entry		*re;
	struct got_reflist_object_id_map	*refs_idmap = NULL;
	struct got_commit_object		*commit = NULL;
	struct got_object_id			*id = NULL;
	const char				*header_prefix;
	char					*uuidstr = NULL;
	int					 found = 0;

	TAILQ_INIT(&refs);
	RB_INIT(&paths);

	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, repo);
	if (err)
		goto done;

	err = got_reflist_object_id_map_create(&refs_idmap, &refs, repo);
	if (err)
		goto done;

	if (worktree != NULL) {
		err = got_worktree_get_uuid(&uuidstr, worktree);
		if (err)
			goto done;
	}

	if (wanted_ref) {
		if (strncmp(wanted_ref, "refs/heads/", 11) == 0)
			wanted_ref += 11;
	}

	if (strcmp(ref_prefix, GOT_WORKTREE_BACKOUT_REF_PREFIX) == 0)
		header_prefix = "backout";
	else
		header_prefix = "cherrypick";

	TAILQ_FOREACH(re, &refs, entry) {
		const char *refname, *wt;

		refname = got_ref_get_name(re->ref);

		err = check_cancelled(NULL);
		if (err)
			goto done;

		if (strncmp(refname, ref_prefix, prefix_len) == 0)
			refname += prefix_len + 1;  /* skip '-' delimiter */
		else
			continue;

		wt = refname;

		if (worktree == NULL || strncmp(refname, uuidstr,
		    GOT_WORKTREE_UUID_STRLEN) == 0)
			refname += GOT_WORKTREE_UUID_STRLEN + 1; /* skip '-' */
		else
			continue;

		err = got_repo_match_object_id(&id, NULL, refname,
		    GOT_OBJ_TYPE_COMMIT, NULL, repo);
		if (err)
			goto done;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			goto done;

		if (wanted_ref)
			found = strncmp(wanted_ref, refname,
			    strlen(wanted_ref)) == 0;
		if (wanted_ref && !found) {
			struct got_reflist_head	*ci_refs;

			ci_refs = got_reflist_object_id_map_lookup(refs_idmap,
			    id);

			if (ci_refs) {
				char		*refs_str = NULL;
				char const	*r = NULL;

				err = build_refs_str(&refs_str, ci_refs, id,
				    repo, 1);
				if (err)
					goto done;

				r = refs_str;
				while (r) {
					if (strncmp(r, wanted_ref,
					    strlen(wanted_ref)) == 0) {
						found = 1;
						break;
					}
					r = strchr(r, ' ');
					if (r)
						++r;
				}
				free(refs_str);
			}
		}

		if (wanted_ref == NULL || found) {
			if (delete) {
				err = got_ref_delete(re->ref, repo);
				if (err)
					goto done;
				printf("Deleted: ");
				err = print_commit_oneline(commit, id, repo,
				    refs_idmap);
			} else {
				/*
				 * Print paths modified by commit to help
				 * associate commits with worktree changes.
				 */
				err = get_changed_paths(&paths, commit,
				    repo, NULL);
				if (err)
					goto done;

				err = print_commit(commit, id, repo, NULL,
				    &paths, NULL, 0, 0, refs_idmap, NULL,
				    header_prefix);
				got_pathlist_free(&paths,
				    GOT_PATHLIST_FREE_ALL);

				if (worktree == NULL)
					printf("work tree: %.*s\n\n",
					    GOT_WORKTREE_UUID_STRLEN, wt);
			}
			if (err || found)
				goto done;
		}

		got_object_commit_close(commit);
		commit = NULL;
		free(id);
		id = NULL;
	}

	if (wanted_ref != NULL && !found)
		err = got_error_fmt(GOT_ERR_NOT_REF, "%s", wanted_ref);

done:
	free(id);
	free(uuidstr);
	got_ref_list_free(&refs);
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_ALL);
	if (refs_idmap)
		got_reflist_object_id_map_free(refs_idmap);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

/*
 * Create new temp "logmsg" ref of the backed-out or cherrypicked commit
 * identified by id for log messages to prepopulate the editor on commit.
 */
static const struct got_error *
logmsg_ref(struct got_object_id *id, const char *prefix,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error	*err = NULL;
	char			*idstr, *ref = NULL, *refname = NULL;
	int			 histedit_in_progress;
	int			 rebase_in_progress, merge_in_progress;

	/*
	 * Silently refuse to create merge reference if any histedit, merge,
	 * or rebase operation is in progress.
	 */
	err = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (err)
		return err;
	if (histedit_in_progress)
		return NULL;

	err = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (err)
		return err;
	if (rebase_in_progress)
		return NULL;

	err = got_worktree_merge_in_progress(&merge_in_progress, worktree,
	    repo);
	if (err)
		return err;
	if (merge_in_progress)
		return NULL;

	err = got_object_id_str(&idstr, id);
	if (err)
		return err;

	err = got_worktree_get_logmsg_ref_name(&refname, worktree, prefix);
	if (err)
		goto done;

	if (asprintf(&ref, "%s-%s", refname, idstr) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = create_ref(ref, got_worktree_get_base_commit_id(worktree),
	    -1, repo);
done:
	free(ref);
	free(idstr);
	free(refname);
	return err;
}

__dead static void
usage_cherrypick(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s cherrypick [-lX] [commit-id]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
cmd_cherrypick(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *commit_id_str = NULL, *keyword_idstr = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid;
	int ch, list_refs = 0, remove_refs = 0;
	struct got_update_progress_arg upa;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "lX")) != -1) {
		switch (ch) {
		case 'l':
			list_refs = 1;
			break;
		case 'X':
			remove_refs = 1;
			break;
		default:
			usage_cherrypick(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (list_refs || remove_refs) {
		if (argc != 0 && argc != 1)
			usage_cherrypick(1);
	} else if (argc != 1)
		usage_cherrypick(1);
	if (list_refs && remove_refs)
		option_conflict('l', 'X');

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (list_refs || remove_refs) {
			if (error->code != GOT_ERR_NOT_WORKTREE)
				goto done;
		} else {
			if (error->code == GOT_ERR_NOT_WORKTREE)
				error = wrap_not_worktree_error(error,
				    "cherrypick", cwd);
			goto done;
		}
	}

	error = got_repo_open(&repo,
	    worktree ? got_worktree_get_repo_path(worktree) : cwd,
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (list_refs || remove_refs) {
		error = process_logmsg_refs(GOT_WORKTREE_CHERRYPICK_REF_PREFIX,
		    GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN,
		    argc == 1 ? argv[0] : NULL, remove_refs, worktree, repo);
		goto done;
	}

	error = got_keyword_to_idstr(&keyword_idstr, argv[0], repo, worktree);
	if (error != NULL)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL,
	    keyword_idstr != NULL ? keyword_idstr : argv[0],
	    GOT_OBJ_TYPE_COMMIT, NULL, repo);
	if (error)
		goto done;
	error = got_object_id_str(&commit_id_str, commit_id);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;
	pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	memset(&upa, 0, sizeof(upa));
	error = got_worktree_merge_files(worktree, pid ? &pid->id : NULL,
	    commit_id, repo, update_progress, &upa, check_cancelled,
	    NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something) {
		error = logmsg_ref(commit_id,
		    GOT_WORKTREE_CHERRYPICK_REF_PREFIX, worktree, repo);
		if (error)
			goto done;
		printf("Merged commit %s\n", commit_id_str);
	}
	print_merge_progress_stats(&upa);
done:
	free(cwd);
	free(keyword_idstr);
	if (commit)
		got_object_commit_close(commit);
	free(commit_id_str);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}

	return error;
}

__dead static void
usage_backout(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s backout [-lX] [commit-id]\n", getprogname());
	exit(status);
}

static const struct got_error *
cmd_backout(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *commit_id_str = NULL, *keyword_idstr = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid;
	int ch, list_refs = 0, remove_refs = 0;
	struct got_update_progress_arg upa;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "lX")) != -1) {
		switch (ch) {
		case 'l':
			list_refs = 1;
			break;
		case 'X':
			remove_refs = 1;
			break;
		default:
			usage_backout(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (list_refs || remove_refs) {
		if (argc != 0 && argc != 1)
			usage_backout(1);
	} else if (argc != 1)
		usage_backout(1);
	if (list_refs && remove_refs)
		option_conflict('l', 'X');

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (list_refs || remove_refs) {
			if (error->code != GOT_ERR_NOT_WORKTREE)
				goto done;
		} else {
			if (error->code == GOT_ERR_NOT_WORKTREE)
				error = wrap_not_worktree_error(error,
				    "backout", cwd);
			goto done;
		}
	}

	error = got_repo_open(&repo,
	    worktree ? got_worktree_get_repo_path(worktree) : cwd,
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (list_refs || remove_refs) {
		error = process_logmsg_refs(GOT_WORKTREE_BACKOUT_REF_PREFIX,
		    GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN,
		    argc == 1 ? argv[0] : NULL, remove_refs, worktree, repo);
		goto done;
	}

	error = got_keyword_to_idstr(&keyword_idstr, argv[0], repo, worktree);
	if (error != NULL)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL,
	    keyword_idstr != NULL ? keyword_idstr : argv[0],
	    GOT_OBJ_TYPE_COMMIT, NULL, repo);
	if (error)
		goto done;
	error = got_object_id_str(&commit_id_str, commit_id);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;
	pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (pid == NULL) {
		error = got_error(GOT_ERR_ROOT_COMMIT);
		goto done;
	}

	memset(&upa, 0, sizeof(upa));
	error = got_worktree_merge_files(worktree, commit_id, &pid->id,
	    repo, update_progress, &upa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something) {
		error = logmsg_ref(commit_id, GOT_WORKTREE_BACKOUT_REF_PREFIX,
		    worktree, repo);
		if (error)
			goto done;
		printf("Backed out commit %s\n", commit_id_str);
	}
	print_merge_progress_stats(&upa);
done:
	free(cwd);
	free(keyword_idstr);
	if (commit)
		got_object_commit_close(commit);
	free(commit_id_str);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	return error;
}

__dead static void
usage_rebase(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s rebase [-aCclX] [branch]\n", getprogname());
	exit(status);
}

static void
trim_logmsg(char *logmsg, int limit)
{
	char *nl;
	size_t len;

	len = strlen(logmsg);
	if (len > limit)
		len = limit;
	logmsg[len] = '\0';
	nl = strchr(logmsg, '\n');
	if (nl)
		*nl = '\0';
}

static const struct got_error *
get_short_logmsg(char **logmsg, int limit, struct got_commit_object *commit)
{
	const struct got_error *err;
	char *logmsg0 = NULL;
	const char *s;

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		return err;

	s = logmsg0;
	while (isspace((unsigned char)s[0]))
		s++;

	*logmsg = strdup(s);
	if (*logmsg == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	trim_logmsg(*logmsg, limit);
done:
	free(logmsg0);
	return err;
}

static const struct got_error *
show_rebase_merge_conflict(struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *commit = NULL;
	char *id_str = NULL, *logmsg = NULL;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, id);
	if (err)
		goto done;

	id_str[12] = '\0';

	err = get_short_logmsg(&logmsg, 42, commit);
	if (err)
		goto done;

	printf("%s -> merge conflict: %s\n", id_str, logmsg);
done:
	free(id_str);
	got_object_commit_close(commit);
	free(logmsg);
	return err;
}

static const struct got_error *
show_rebase_progress(struct got_commit_object *commit,
    struct got_object_id *old_id, struct got_object_id *new_id)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL, *logmsg = NULL;

	err = got_object_id_str(&old_id_str, old_id);
	if (err)
		goto done;

	if (new_id) {
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
	}

	old_id_str[12] = '\0';
	if (new_id_str)
		new_id_str[12] = '\0';

	err = get_short_logmsg(&logmsg, 42, commit);
	if (err)
		goto done;

	printf("%s -> %s: %s\n", old_id_str,
	    new_id_str ? new_id_str : "no-op change", logmsg);
done:
	free(old_id_str);
	free(new_id_str);
	free(logmsg);
	return err;
}

static const struct got_error *
rebase_complete(struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *branch, struct got_reference *tmp_branch,
    struct got_repository *repo, int create_backup)
{
	printf("Switching work tree to %s\n", got_ref_get_name(branch));
	return got_worktree_rebase_complete(worktree, fileindex,
	    tmp_branch, branch, repo, create_backup);
}

static const struct got_error *
rebase_commit(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *tmp_branch, const char *committer,
    struct got_object_id *commit_id, int allow_conflict,
    struct got_repository *repo)
{
	const struct got_error *error;
	struct got_commit_object *commit;
	struct got_object_id *new_commit_id;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		return error;

	error = got_worktree_rebase_commit(&new_commit_id, merged_paths,
	    worktree, fileindex, tmp_branch, committer, commit, commit_id,
	    allow_conflict, repo);
	if (error) {
		if (error->code != GOT_ERR_COMMIT_NO_CHANGES)
			goto done;
		error = show_rebase_progress(commit, commit_id, NULL);
	} else {
		error = show_rebase_progress(commit, commit_id, new_commit_id);
		free(new_commit_id);
	}
done:
	got_object_commit_close(commit);
	return error;
}

struct check_path_prefix_arg {
	const char *path_prefix;
	size_t len;
	int errcode;
};

static const struct got_error *
check_path_prefix_in_diff(void *arg, struct got_blob_object *blob1,
    struct got_blob_object *blob2, FILE *f1, FILE *f2,
    struct got_object_id *id1, struct got_object_id *id2,
    const char *path1, const char *path2,
    mode_t mode1, mode_t mode2, struct got_repository *repo)
{
	struct check_path_prefix_arg *a = arg;

	if ((path1 && !got_path_is_child(path1, a->path_prefix, a->len)) ||
	    (path2 && !got_path_is_child(path2, a->path_prefix, a->len)))
		return got_error(a->errcode);

	return NULL;
}

static const struct got_error *
check_path_prefix(struct got_object_id *parent_id,
    struct got_object_id *commit_id, const char *path_prefix,
    int errcode, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_commit_object *commit = NULL, *parent_commit = NULL;
	struct check_path_prefix_arg cpp_arg;

	if (got_path_is_root_dir(path_prefix))
		return NULL;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	err = got_object_open_as_commit(&parent_commit, repo, parent_id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree1, repo,
	    got_object_commit_get_tree_id(parent_commit));
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree2, repo,
	    got_object_commit_get_tree_id(commit));
	if (err)
		goto done;

	cpp_arg.path_prefix = path_prefix;
	while (cpp_arg.path_prefix[0] == '/')
		cpp_arg.path_prefix++;
	cpp_arg.len = strlen(cpp_arg.path_prefix);
	cpp_arg.errcode = errcode;
	err = got_diff_tree(tree1, tree2, NULL, NULL, -1, -1, "", "", repo,
	    check_path_prefix_in_diff, &cpp_arg, 0);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (commit)
		got_object_commit_close(commit);
	if (parent_commit)
		got_object_commit_close(parent_commit);
	return err;
}

static const struct got_error *
collect_commits(struct got_object_id_queue *commits,
    struct got_object_id *initial_commit_id,
    struct got_object_id *iter_start_id, struct got_object_id *iter_stop_id,
    const char *path_prefix, int path_prefix_errcode,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_object_id parent_id, commit_id;
	struct got_object_qid *qid;

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		return err;

	err = got_commit_graph_bfsort(graph, iter_start_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;

	memcpy(&commit_id, initial_commit_id, sizeof(commit_id));
	while (got_object_id_cmp(&commit_id, iter_stop_id) != 0) {
		err = got_commit_graph_iter_next(&parent_id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = got_error_msg(GOT_ERR_ANCESTRY,
				    "ran out of commits to rebase before "
				    "youngest common ancestor commit has "
				    "been reached?!?");
			}
			goto done;
		} else {
			err = check_path_prefix(&parent_id, &commit_id,
			    path_prefix, path_prefix_errcode, repo);
			if (err)
				goto done;

			err = got_object_qid_alloc(&qid, &commit_id);
			if (err)
				goto done;
			STAILQ_INSERT_HEAD(commits, qid, entry);

			memcpy(&commit_id, &parent_id, sizeof(commit_id));
		}
	}
done:
	got_commit_graph_close(graph);
	return err;
}

static const struct got_error *
get_commit_brief_str(char **brief_str, struct got_commit_object *commit)
{
	const struct got_error *err = NULL;
	time_t committer_time;
	struct tm tm;
	char datebuf[11]; /* YYYY-MM-DD + NUL */
	char *author0 = NULL, *author, *smallerthan;
	char *logmsg0 = NULL, *logmsg, *newline;

	committer_time = got_object_commit_get_committer_time(commit);
	if (gmtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(datebuf, sizeof(datebuf), "%F", &tm) == 0)
		return got_error(GOT_ERR_NO_SPACE);

	author0 = strdup(got_object_commit_get_author(commit));
	if (author0 == NULL)
		return got_error_from_errno("strdup");
	author = author0;
	smallerthan = strchr(author, '<');
	if (smallerthan && smallerthan[1] != '\0')
		author = smallerthan + 1;
	author[strcspn(author, "@>")] = '\0';

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;
	logmsg = logmsg0;
	while (*logmsg == '\n')
		logmsg++;
	newline = strchr(logmsg, '\n');
	if (newline)
		*newline = '\0';

	if (asprintf(brief_str, "%s %s  %s",
	    datebuf, author, logmsg) == -1)
		err = got_error_from_errno("asprintf");
done:
	free(author0);
	free(logmsg0);
	return err;
}

static const struct got_error *
delete_backup_ref(struct got_reference *ref, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_ref_delete(ref, repo);
	if (err)
		goto done;

	printf("Deleted %s: %s\n", got_ref_get_name(ref), id_str);
done:
	free(id_str);
	return err;
}

static const struct got_error *
print_backup_ref(const char *branch_name, const char *new_id_str,
    struct got_object_id *old_commit_id, struct got_commit_object *old_commit,
    struct got_reflist_object_id_map *refs_idmap,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reflist_head *refs;
	char *refs_str = NULL;
	struct got_object_id *new_commit_id = NULL;
	struct got_commit_object *new_commit = NULL;
	char *new_commit_brief_str = NULL;
	struct got_object_id *yca_id = NULL;
	struct got_commit_object *yca_commit = NULL;
	char *yca_id_str = NULL, *yca_brief_str = NULL;
	char *custom_refs_str;

	if (asprintf(&custom_refs_str, "formerly %s", branch_name) == -1)
		return got_error_from_errno("asprintf");

	err = print_commit(old_commit, old_commit_id, repo, NULL, NULL, NULL,
	    0, 0, refs_idmap, custom_refs_str, NULL);
	if (err)
		goto done;

	err = got_object_resolve_id_str(&new_commit_id, repo, new_id_str);
	if (err)
		goto done;

	refs = got_reflist_object_id_map_lookup(refs_idmap, new_commit_id);
	if (refs) {
		err = build_refs_str(&refs_str, refs, new_commit_id, repo, 0);
		if (err)
			goto done;
	}

	err = got_object_open_as_commit(&new_commit, repo, new_commit_id);
	if (err)
		goto done;

	err = get_commit_brief_str(&new_commit_brief_str, new_commit);
	if (err)
		goto done;

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    old_commit_id, new_commit_id, 1, 0, repo, check_cancelled, NULL);
	if (err)
		goto done;

	printf("has become commit %s%s%s%s\n %s\n", new_id_str,
	    refs_str ? " (" : "", refs_str ? refs_str : "",
	    refs_str ? ")" : "", new_commit_brief_str);
	if (yca_id && got_object_id_cmp(yca_id, new_commit_id) != 0 &&
	    got_object_id_cmp(yca_id, old_commit_id) != 0) {
		free(refs_str);
		refs_str = NULL;

		err = got_object_open_as_commit(&yca_commit, repo, yca_id);
		if (err)
			goto done;

		err = get_commit_brief_str(&yca_brief_str, yca_commit);
		if (err)
			goto done;

		err = got_object_id_str(&yca_id_str, yca_id);
		if (err)
			goto done;

		refs = got_reflist_object_id_map_lookup(refs_idmap, yca_id);
		if (refs) {
			err = build_refs_str(&refs_str, refs, yca_id, repo, 0);
			if (err)
				goto done;
		}
		printf("history forked at %s%s%s%s\n %s\n",
		    yca_id_str,
		    refs_str ? " (" : "", refs_str ? refs_str : "",
		    refs_str ? ")" : "", yca_brief_str);
	}
done:
	free(custom_refs_str);
	free(new_commit_id);
	free(refs_str);
	free(yca_id);
	free(yca_id_str);
	free(yca_brief_str);
	if (new_commit)
		got_object_commit_close(new_commit);
	if (yca_commit)
		got_object_commit_close(yca_commit);

	return err;
}

static const struct got_error *
worktree_has_logmsg_ref(const char *caller, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error		*err;
	struct got_reflist_head		 refs;
	struct got_reflist_entry	*re;
	char				*uuidstr = NULL;
	static char			 msg[160];

	TAILQ_INIT(&refs);

	err = got_worktree_get_uuid(&uuidstr, worktree);
	if (err)
		goto done;

	err = got_ref_list(&refs, repo, "refs/got/worktree",
	    got_ref_cmp_by_name, repo);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		const char *cmd, *refname, *type;

		refname = got_ref_get_name(re->ref);

		if (strncmp(refname, GOT_WORKTREE_CHERRYPICK_REF_PREFIX,
		    GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN) == 0) {
			refname += GOT_WORKTREE_CHERRYPICK_REF_PREFIX_LEN + 1;
			cmd = "cherrypick";
			type = "cherrypicked";
		} else if (strncmp(refname, GOT_WORKTREE_BACKOUT_REF_PREFIX,
		    GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN) == 0) {
			refname += GOT_WORKTREE_BACKOUT_REF_PREFIX_LEN + 1;
			cmd = "backout";
			type = "backed-out";
		} else
			continue;

		if (strncmp(refname, uuidstr, GOT_WORKTREE_UUID_STRLEN) != 0)
			continue;

		snprintf(msg, sizeof(msg),
		    "work tree has references created by %s commits which "
		    "must be removed with 'got %s -X' before running the %s "
		    "command", type, cmd, caller);
		err = got_error_msg(GOT_ERR_WORKTREE_META, msg);
		goto done;
	}

done:
	free(uuidstr);
	got_ref_list_free(&refs);
	return err;
}

static const struct got_error *
process_backup_refs(const char *backup_ref_prefix,
    const char *wanted_branch_name,
    int delete, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reflist_head refs, backup_refs;
	struct got_reflist_entry *re;
	const size_t backup_ref_prefix_len = strlen(backup_ref_prefix);
	struct got_object_id *old_commit_id = NULL;
	char *branch_name = NULL;
	struct got_commit_object *old_commit = NULL;
	struct got_reflist_object_id_map *refs_idmap = NULL;
	int wanted_branch_found = 0;

	TAILQ_INIT(&refs);
	TAILQ_INIT(&backup_refs);

	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	err = got_reflist_object_id_map_create(&refs_idmap, &refs, repo);
	if (err)
		goto done;

	if (wanted_branch_name) {
		if (strncmp(wanted_branch_name, "refs/heads/", 11) == 0)
			wanted_branch_name += 11;
	}

	err = got_ref_list(&backup_refs, repo, backup_ref_prefix,
	    got_ref_cmp_by_commit_timestamp_descending, repo);
	if (err)
		goto done;

	TAILQ_FOREACH(re, &backup_refs, entry) {
		const char *refname = got_ref_get_name(re->ref);
		char *slash;

		err = check_cancelled(NULL);
		if (err)
			break;

		err = got_ref_resolve(&old_commit_id, repo, re->ref);
		if (err)
			break;

		err = got_object_open_as_commit(&old_commit, repo,
		    old_commit_id);
		if (err)
			break;

		if (strncmp(backup_ref_prefix, refname,
		    backup_ref_prefix_len) == 0)
			refname += backup_ref_prefix_len;

		while (refname[0] == '/')
			refname++;

		branch_name = strdup(refname);
		if (branch_name == NULL) {
			err = got_error_from_errno("strdup");
			break;
		}
		slash = strrchr(branch_name, '/');
		if (slash) {
			*slash = '\0';
			refname += strlen(branch_name) + 1;
		}

		if (wanted_branch_name == NULL ||
		    strcmp(wanted_branch_name, branch_name) == 0) {
			wanted_branch_found = 1;
			if (delete) {
				err = delete_backup_ref(re->ref,
				    old_commit_id, repo);
			} else {
				err = print_backup_ref(branch_name, refname,
				    old_commit_id, old_commit, refs_idmap,
				    repo);
			}
			if (err)
				break;
		}

		free(old_commit_id);
		old_commit_id = NULL;
		free(branch_name);
		branch_name = NULL;
		got_object_commit_close(old_commit);
		old_commit = NULL;
	}

	if (wanted_branch_name && !wanted_branch_found) {
		err = got_error_fmt(GOT_ERR_NOT_REF,
		    "%s/%s/", backup_ref_prefix, wanted_branch_name);
	}
done:
	if (refs_idmap)
		got_reflist_object_id_map_free(refs_idmap);
	got_ref_list_free(&refs);
	got_ref_list_free(&backup_refs);
	free(old_commit_id);
	free(branch_name);
	if (old_commit)
		got_object_commit_close(old_commit);
	return err;
}

static const struct got_error *
abort_progress(void *arg, unsigned char status, const char *path)
{
	/*
	 * Unversioned files should not clutter progress output when
	 * an operation is aborted.
	 */
	if (status == GOT_STATUS_UNVERSIONED)
		return NULL;

	return update_progress(arg, status, path);
}

static const struct got_error *
find_merge_commit_yca(struct got_object_id **new_yca_id,
    struct got_object_id *branch_head_commit_id,
    struct got_object_id *yca_id,
    struct got_object_id *base_commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;

	*new_yca_id = NULL;

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		return err;

	err = got_commit_graph_bfsort(graph, base_commit_id,
	    repo, check_cancelled, NULL);
	if (err)
		goto done;

	for (;;) {
		struct got_object_id id;

		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		err = got_object_open_as_commit(&commit, repo, &id);
		if (err)
			break;

		if (got_object_commit_get_nparents(commit) > 1) {
			/* Search for a better YCA using toposort. */
			err = got_commit_graph_find_youngest_common_ancestor(
			    new_yca_id, base_commit_id, branch_head_commit_id,
			    0, 1, repo, check_cancelled, NULL);
			break;
		}

		if (got_object_id_cmp(&id, yca_id) == 0)
			break;
		got_object_commit_close(commit);
		commit = NULL;
	}
done:
	got_commit_graph_close(graph);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
cmd_rebase(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	struct got_fileindex *fileindex = NULL;
	char *cwd = NULL, *committer = NULL, *gitconfig_path = NULL;
	struct got_reference *branch = NULL;
	struct got_reference *new_base_branch = NULL, *tmp_branch = NULL;
	struct got_object_id *commit_id = NULL, *parent_id = NULL;
	struct got_object_id *resume_commit_id = NULL;
	struct got_object_id *branch_head_commit_id = NULL, *yca_id = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct got_reference *head_ref = NULL;
	struct got_commit_object *commit = NULL;
	int ch, rebase_in_progress = 0, abort_rebase = 0, continue_rebase = 0;
	int histedit_in_progress = 0, merge_in_progress = 0;
	int create_backup = 1, list_backups = 0, delete_backups = 0;
	int allow_conflict = 0;
	struct got_object_id_queue commits;
	struct got_pathlist_head merged_paths;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *qid, *pid;
	struct got_update_progress_arg upa;
	int *pack_fds = NULL;

	STAILQ_INIT(&commits);
	RB_INIT(&merged_paths);
	memset(&upa, 0, sizeof(upa));

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aCclX")) != -1) {
		switch (ch) {
		case 'a':
			abort_rebase = 1;
			break;
		case 'C':
			allow_conflict = 1;
			break;
		case 'c':
			continue_rebase = 1;
			break;
		case 'l':
			list_backups = 1;
			break;
		case 'X':
			delete_backups = 1;
			break;
		default:
			usage_rebase(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (list_backups) {
		if (abort_rebase)
			option_conflict('l', 'a');
		if (allow_conflict)
			option_conflict('l', 'C');
		if (continue_rebase)
			option_conflict('l', 'c');
		if (delete_backups)
			option_conflict('l', 'X');
		if (argc != 0 && argc != 1)
			usage_rebase(1);
	} else if (delete_backups) {
		if (abort_rebase)
			option_conflict('X', 'a');
		if (allow_conflict)
			option_conflict('X', 'C');
		if (continue_rebase)
			option_conflict('X', 'c');
		if (list_backups)
			option_conflict('l', 'X');
		if (argc != 0 && argc != 1)
			usage_rebase(1);
	} else if (allow_conflict) {
		if (abort_rebase)
			option_conflict('C', 'a');
		if (!continue_rebase)
			errx(1, "-C option requires -c");
	} else {
		if (abort_rebase && continue_rebase)
			usage_rebase(1);
		else if (abort_rebase || continue_rebase) {
			if (argc != 0)
				usage_rebase(1);
		} else if (argc != 1)
			usage_rebase(1);
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (list_backups || delete_backups) {
			if (error->code != GOT_ERR_NOT_WORKTREE)
				goto done;
		} else {
			if (error->code == GOT_ERR_NOT_WORKTREE)
				error = wrap_not_worktree_error(error,
				    "rebase", cwd);
			goto done;
		}
	}

	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo,
	    worktree ? got_worktree_get_repo_path(worktree) : cwd,
	    gitconfig_path, pack_fds);
	if (error != NULL)
		goto done;

	if (worktree != NULL && !list_backups && !delete_backups) {
		error = worktree_has_logmsg_ref("rebase", worktree, repo);
		if (error)
			goto done;
	}

	error = get_author(&committer, repo, worktree);
	if (error && error->code != GOT_ERR_COMMIT_NO_AUTHOR)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (list_backups || delete_backups) {
		error = process_backup_refs(
		    GOT_WORKTREE_REBASE_BACKUP_REF_PREFIX,
		    argc == 1 ? argv[0] : NULL, delete_backups, repo);
		goto done; /* nothing else to do */
	}

	error = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (error)
		goto done;
	if (histedit_in_progress) {
		error = got_error(GOT_ERR_HISTEDIT_BUSY);
		goto done;
	}

	error = got_worktree_merge_in_progress(&merge_in_progress,
	    worktree, repo);
	if (error)
		goto done;
	if (merge_in_progress) {
		error = got_error(GOT_ERR_MERGE_BUSY);
		goto done;
	}

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;

	if (abort_rebase) {
		if (!rebase_in_progress) {
			error = got_error(GOT_ERR_NOT_REBASING);
			goto done;
		}
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, &fileindex,
		    worktree, repo);
		if (error)
			goto done;
		printf("Switching work tree to %s\n",
		    got_ref_get_symref_target(new_base_branch));
		error = got_worktree_rebase_abort(worktree, fileindex, repo,
		    new_base_branch, abort_progress, &upa);
		if (error)
			goto done;
		printf("Rebase of %s aborted\n", got_ref_get_name(branch));
		print_merge_progress_stats(&upa);
		goto done; /* nothing else to do */
	}

	if (continue_rebase) {
		if (!rebase_in_progress) {
			error = got_error(GOT_ERR_NOT_REBASING);
			goto done;
		}
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, &fileindex,
		    worktree, repo);
		if (error)
			goto done;

		error = rebase_commit(NULL, worktree, fileindex, tmp_branch,
		    committer, resume_commit_id, allow_conflict, repo);
		if (error)
			goto done;

		yca_id = got_object_id_dup(resume_commit_id);
		if (yca_id == NULL) {
			error = got_error_from_errno("got_object_id_dup");
			goto done;
		}
	} else {
		error = got_ref_open(&branch, repo, argv[0], 0);
		if (error != NULL)
			goto done;
		if (strncmp(got_ref_get_name(branch), "refs/heads/", 11) != 0) {
			error = got_error_msg(GOT_ERR_COMMIT_BRANCH,
			    "will not rebase a branch which lives outside "
			    "the \"refs/heads/\" reference namespace");
			goto done;
		}
	}

	error = got_ref_resolve(&branch_head_commit_id, repo, branch);
	if (error)
		goto done;

	if (!continue_rebase) {
		struct got_object_id *base_commit_id;

		error = got_ref_open(&head_ref, repo,
		    got_worktree_get_head_ref_name(worktree), 0);
		if (error)
			goto done;
		error = got_ref_resolve(&head_commit_id, repo, head_ref);
		if (error)
			goto done;
		base_commit_id = got_worktree_get_base_commit_id(worktree);
		if (got_object_id_cmp(base_commit_id, head_commit_id) != 0) {
			error = got_error(GOT_ERR_REBASE_OUT_OF_DATE);
			goto done;
		}

		error = got_commit_graph_find_youngest_common_ancestor(&yca_id,
		    base_commit_id, branch_head_commit_id, 1, 0,
		    repo, check_cancelled, NULL);
		if (error) {
			if (error->code == GOT_ERR_ANCESTRY) {
				error = got_error_msg(GOT_ERR_ANCESTRY,
				    "specified branch shares no common "
				    "ancestry with work tree's branch");
			}
			goto done;
		}

		/*
		 * If a merge commit appears between the new base branch tip
		 * and a YCA found via first-parent traversal then we might
		 * find a better YCA using topologically sorted commits.
		 */
		if (got_object_id_cmp(base_commit_id, yca_id) != 0) {
			struct got_object_id *better_yca_id;
			error = find_merge_commit_yca(&better_yca_id,
			    branch_head_commit_id, yca_id,
			    base_commit_id, repo);
			if (error)
				goto done;
			if (better_yca_id) {
				free(yca_id);
				yca_id = better_yca_id;
			}
		}

		if (got_object_id_cmp(base_commit_id, yca_id) == 0) {
			struct got_pathlist_head paths;
			const char *branch_name = got_ref_get_name(branch);
			const char *base =
			    got_worktree_get_head_ref_name(worktree);

			if (strcmp(branch_name, base) == 0) {
				error = got_error_fmt(GOT_ERR_WRONG_BRANCH,
				    "cannot rebase %s onto itself",
				    branch_name);
				goto done;
			} else {
				printf("%s is already based on %s\n",
				    branch_name, base);
			}
			error = switch_head_ref(branch, branch_head_commit_id,
			    worktree, repo);
			if (error)
				goto done;
			error = got_worktree_set_base_commit_id(worktree, repo,
			    branch_head_commit_id);
			if (error)
				goto done;
			RB_INIT(&paths);
			error = got_pathlist_insert(NULL, &paths, "", NULL);
			if (error)
				goto done;
			error = got_worktree_checkout_files(worktree,
			    &paths, repo, update_progress, &upa,
			    check_cancelled, NULL);
			got_pathlist_free(&paths, GOT_PATHLIST_FREE_NONE);
			if (error)
				goto done;
			if (upa.did_something) {
				char *id_str;
				error = got_object_id_str(&id_str,
				    branch_head_commit_id);
				if (error)
					goto done;
				printf("Updated to %s: %s\n",
				    got_worktree_get_head_ref_name(worktree),
				    id_str);
				free(id_str);
			} else
				printf("Already up-to-date\n");
			print_update_progress_stats(&upa);
			goto done;
		}
	}

	commit_id = branch_head_commit_id;
	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	parent_ids = got_object_commit_get_parent_ids(commit);
	pid = STAILQ_FIRST(parent_ids);
	if (pid) {
		error = collect_commits(&commits, commit_id, &pid->id,
		    yca_id, got_worktree_get_path_prefix(worktree),
		    GOT_ERR_REBASE_PATH, repo);
		if (error)
			goto done;
	}

	got_object_commit_close(commit);
	commit = NULL;

	if (!continue_rebase) {
		error = got_worktree_rebase_prepare(&new_base_branch,
		    &tmp_branch, &fileindex, worktree, branch, repo);
		if (error)
			goto done;
	}

	if (STAILQ_EMPTY(&commits)) {
		if (continue_rebase) {
			error = rebase_complete(worktree, fileindex,
			    branch, tmp_branch, repo, create_backup);
			goto done;
		} else {
			/* Fast-forward the reference of the branch. */
			struct got_object_id *new_head_commit_id;
			char *id_str;
			error = got_ref_resolve(&new_head_commit_id, repo,
			    new_base_branch);
			if (error)
				goto done;
			error = got_object_id_str(&id_str, new_head_commit_id);
			if (error)
				goto done;
			printf("Forwarding %s to commit %s\n",
			    got_ref_get_name(branch), id_str);
			free(id_str);
			error = got_ref_change_ref(branch,
			    new_head_commit_id);
			if (error)
				goto done;
			/* No backup needed since objects did not change. */
			create_backup = 0;
		}
	}

	pid = NULL;
	STAILQ_FOREACH(qid, &commits, entry) {

		commit_id = &qid->id;
		parent_id = pid ? &pid->id : yca_id;
		pid = qid;

		memset(&upa, 0, sizeof(upa));
		error = got_worktree_rebase_merge_files(&merged_paths,
		    worktree, fileindex, parent_id, commit_id, repo,
		    update_progress, &upa, check_cancelled, NULL);
		if (error)
			goto done;

		print_merge_progress_stats(&upa);
		if (upa.conflicts > 0 || upa.missing > 0 ||
		    upa.not_deleted > 0 || upa.unversioned > 0) {
			if (upa.conflicts > 0) {
				error = show_rebase_merge_conflict(&qid->id,
				    repo);
				if (error)
					goto done;
			}
			got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_PATH);
			break;
		}

		error = rebase_commit(&merged_paths, worktree, fileindex,
		    tmp_branch, committer, commit_id, 0, repo);
		got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_PATH);
		if (error)
			goto done;
	}

	if (upa.conflicts > 0 || upa.missing > 0 ||
	    upa.not_deleted > 0 || upa.unversioned > 0) {
		error = got_worktree_rebase_postpone(worktree, fileindex);
		if (error)
			goto done;
		if (upa.conflicts > 0 && upa.missing == 0 &&
		    upa.not_deleted == 0 && upa.unversioned == 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before rebasing "
			    "can continue");
		} else if (upa.conflicts > 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before rebasing "
			    "can continue; changes destined for some "
			    "files were not yet merged and should be "
			    "merged manually if required before the "
			    "rebase operation is continued");
		} else {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "changes destined for some files were not "
			    "yet merged and should be merged manually "
			    "if required before the rebase operation "
			    "is continued");
		}
	} else
		error = rebase_complete(worktree, fileindex, branch,
		    tmp_branch, repo, create_backup);
done:
	free(cwd);
	free(committer);
	free(gitconfig_path);
	got_object_id_queue_free(&commits);
	free(branch_head_commit_id);
	free(resume_commit_id);
	free(head_commit_id);
	free(yca_id);
	if (commit)
		got_object_commit_close(commit);
	if (branch)
		got_ref_close(branch);
	if (new_base_branch)
		got_ref_close(new_base_branch);
	if (tmp_branch)
		got_ref_close(tmp_branch);
	if (head_ref)
		got_ref_close(head_ref);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	return error;
}

__dead static void
usage_histedit(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s histedit [-aCcdeflmX] [-F histedit-script] "
	    "[branch]\n", getprogname());
	exit(status);
}

#define GOT_HISTEDIT_PICK 'p'
#define GOT_HISTEDIT_EDIT 'e'
#define GOT_HISTEDIT_FOLD 'f'
#define GOT_HISTEDIT_DROP 'd'
#define GOT_HISTEDIT_MESG 'm'

static const struct got_histedit_cmd {
	unsigned char code;
	const char *name;
	const char *desc;
} got_histedit_cmds[] = {
	{ GOT_HISTEDIT_PICK, "pick", "use commit" },
	{ GOT_HISTEDIT_EDIT, "edit", "use commit but stop for amending" },
	{ GOT_HISTEDIT_FOLD, "fold", "combine with next commit that will "
	    "be used" },
	{ GOT_HISTEDIT_DROP, "drop", "remove commit from history" },
	{ GOT_HISTEDIT_MESG, "mesg", "open editor to edit the log message" },
};

struct got_histedit_list_entry {
	TAILQ_ENTRY(got_histedit_list_entry) entry;
	struct got_object_id *commit_id;
	const struct got_histedit_cmd *cmd;
	char *logmsg;
};
TAILQ_HEAD(got_histedit_list, got_histedit_list_entry);

static const struct got_error *
histedit_write_commit(struct got_object_id *commit_id, const char *cmdname,
    FILE *f, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *logmsg = NULL, *id_str = NULL;
	struct got_commit_object *commit = NULL;
	int n;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	err = get_short_logmsg(&logmsg, 34, commit);
	if (err)
		goto done;

	err = got_object_id_str(&id_str, commit_id);
	if (err)
		goto done;

	n = fprintf(f, "%s %s %s\n", cmdname, id_str, logmsg);
	if (n < 0)
		err = got_ferror(f, GOT_ERR_IO);
done:
	if (commit)
		got_object_commit_close(commit);
	free(id_str);
	free(logmsg);
	return err;
}

static const struct got_error *
histedit_write_commit_list(struct got_object_id_queue *commits,
    FILE *f, int edit_logmsg_only, int fold_only, int drop_only,
    int edit_only, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;
	const char *histedit_cmd = NULL;

	if (STAILQ_EMPTY(commits))
		return got_error(GOT_ERR_EMPTY_HISTEDIT);

	STAILQ_FOREACH(qid, commits, entry) {
		histedit_cmd = got_histedit_cmds[0].name;
		if (drop_only)
			histedit_cmd = "drop";
		else if (edit_only)
			histedit_cmd = "edit";
		else if (fold_only && STAILQ_NEXT(qid, entry) != NULL)
			histedit_cmd = "fold";
		else if (edit_logmsg_only)
			histedit_cmd = "mesg";
		err = histedit_write_commit(&qid->id, histedit_cmd, f, repo);
		if (err)
			break;
	}

	return err;
}

static const struct got_error *
write_cmd_list(FILE *f, const char *branch_name,
    struct got_object_id_queue *commits)
{
	const struct got_error *err = NULL;
	size_t i;
	int n;
	char *id_str;
	struct got_object_qid *qid;

	qid = STAILQ_FIRST(commits);
	err = got_object_id_str(&id_str, &qid->id);
	if (err)
		return err;

	n = fprintf(f,
	    "# Editing the history of branch '%s' starting at\n"
	    "# commit %s\n"
	    "# Commits will be processed in order from top to "
	    "bottom of this file.\n", branch_name, id_str);
	if (n < 0) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	n = fprintf(f, "# Available histedit commands:\n");
	if (n < 0) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	for (i = 0; i < nitems(got_histedit_cmds); i++) {
		const struct got_histedit_cmd *cmd = &got_histedit_cmds[i];
		n = fprintf(f, "#   %s (%c): %s\n", cmd->name, cmd->code,
		    cmd->desc);
		if (n < 0) {
			err = got_ferror(f, GOT_ERR_IO);
			break;
		}
	}
done:
	free(id_str);
	return err;
}

static const struct got_error *
histedit_syntax_error(int lineno)
{
	static char msg[42];
	int ret;

	ret = snprintf(msg, sizeof(msg), "histedit syntax error on line %d",
	    lineno);
	if (ret < 0 || (size_t)ret >= sizeof(msg))
		return got_error(GOT_ERR_HISTEDIT_SYNTAX);

	return got_error_msg(GOT_ERR_HISTEDIT_SYNTAX, msg);
}

static const struct got_error *
append_folded_commit_msg(char **new_msg, struct got_histedit_list_entry *hle,
    char *logmsg, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *folded_commit = NULL;
	char *id_str, *folded_logmsg = NULL;

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		return err;

	err = got_object_open_as_commit(&folded_commit, repo, hle->commit_id);
	if (err)
		goto done;

	err = got_object_commit_get_logmsg(&folded_logmsg, folded_commit);
	if (err)
		goto done;
	if (asprintf(new_msg, "%s%s# log message of folded commit %s: %s",
	    logmsg ? logmsg : "", logmsg ? "\n" : "", id_str,
	    folded_logmsg) == -1) {
		err = got_error_from_errno("asprintf");
	}
done:
	if (folded_commit)
		got_object_commit_close(folded_commit);
	free(id_str);
	free(folded_logmsg);
	return err;
}

static struct got_histedit_list_entry *
get_folded_commits(struct got_histedit_list_entry *hle)
{
	struct got_histedit_list_entry *prev, *folded = NULL;

	prev = TAILQ_PREV(hle, got_histedit_list, entry);
	while (prev && (prev->cmd->code == GOT_HISTEDIT_FOLD ||
	    prev->cmd->code == GOT_HISTEDIT_DROP)) {
		if (prev->cmd->code == GOT_HISTEDIT_FOLD)
			folded = prev;
		prev = TAILQ_PREV(prev, got_histedit_list, entry);
	}

	return folded;
}

static const struct got_error *
histedit_edit_logmsg(struct got_histedit_list_entry *hle,
    const char *editor, struct got_repository *repo)
{
	char *logmsg_path = NULL, *id_str = NULL, *orig_logmsg = NULL;
	char *logmsg = NULL, *new_msg = NULL;
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	int logmsg_len;
	int fd = -1;
	struct got_histedit_list_entry *folded = NULL;

	err = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (err)
		return err;

	folded = get_folded_commits(hle);
	if (folded) {
		while (folded != hle) {
			if (folded->cmd->code == GOT_HISTEDIT_DROP) {
				folded = TAILQ_NEXT(folded, entry);
				continue;
			}
			err = append_folded_commit_msg(&new_msg, folded,
			    logmsg, repo);
			if (err)
				goto done;
			free(logmsg);
			logmsg = new_msg;
			folded = TAILQ_NEXT(folded, entry);
		}
	}

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		goto done;
	err = got_object_commit_get_logmsg(&orig_logmsg, commit);
	if (err)
		goto done;
	logmsg_len = asprintf(&new_msg,
	    "%s\n# original log message of commit %s: %s",
	    logmsg ? logmsg : "", id_str, orig_logmsg);
	if (logmsg_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	free(logmsg);
	logmsg = new_msg;

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		goto done;

	err = got_opentemp_named_fd(&logmsg_path, &fd,
	    GOT_TMPDIR_STR "/got-logmsg", "");
	if (err)
		goto done;

	if (write(fd, logmsg, logmsg_len) == -1) {
		err = got_error_from_errno2("write", logmsg_path);
		goto done;
	}
	if (close(fd) == -1) {
		err = got_error_from_errno2("close", logmsg_path);
		goto done;
	}
	fd = -1;

	err = edit_logmsg(&hle->logmsg, editor, logmsg_path, logmsg,
	    logmsg_len, 0);
	if (err) {
		if (err->code != GOT_ERR_COMMIT_MSG_EMPTY)
			goto done;
		err = NULL;
		hle->logmsg = strdup(new_msg);
		if (hle->logmsg == NULL)
			err = got_error_from_errno("strdup");
	}
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", logmsg_path);
	if (logmsg_path && unlink(logmsg_path) != 0 && err == NULL)
		err = got_error_from_errno2("unlink", logmsg_path);
	free(logmsg_path);
	free(logmsg);
	free(orig_logmsg);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
histedit_parse_list(struct got_histedit_list *histedit_cmds,
    FILE *f, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *line = NULL, *p, *end;
	size_t i, linesize = 0;
	ssize_t linelen;
	int lineno = 0;
	const struct got_histedit_cmd *cmd;
	struct got_object_id *commit_id = NULL;
	struct got_histedit_list_entry *hle = NULL;

	for (;;) {
		linelen = getline(&line, &linesize, f);
		if (linelen == -1) {
			const struct got_error *getline_err;
			if (feof(f))
				break;
			getline_err = got_error_from_errno("getline");
			err = got_ferror(f, getline_err->code);
			break;
		}
		lineno++;
		p = line;
		while (isspace((unsigned char)p[0]))
			p++;
		if (p[0] == '#' || p[0] == '\0')
			continue;
		cmd = NULL;
		for (i = 0; i < nitems(got_histedit_cmds); i++) {
			cmd = &got_histedit_cmds[i];
			if (strncmp(cmd->name, p, strlen(cmd->name)) == 0 &&
			    isspace((unsigned char)p[strlen(cmd->name)])) {
				p += strlen(cmd->name);
				break;
			}
			if (p[0] == cmd->code && isspace((unsigned char)p[1])) {
				p++;
				break;
			}
		}
		if (i == nitems(got_histedit_cmds)) {
			err = histedit_syntax_error(lineno);
			break;
		}
		while (isspace((unsigned char)p[0]))
			p++;
		end = p;
		while (end[0] && !isspace((unsigned char)end[0]))
			end++;
		*end = '\0';
		err = got_object_resolve_id_str(&commit_id, repo, p);
		if (err) {
			/* override error code */
			err = histedit_syntax_error(lineno);
			break;
		}
		hle = malloc(sizeof(*hle));
		if (hle == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		hle->cmd = cmd;
		hle->commit_id = commit_id;
		hle->logmsg = NULL;
		commit_id = NULL;
		TAILQ_INSERT_TAIL(histedit_cmds, hle, entry);
	}

	free(line);
	free(commit_id);
	return err;
}

static const struct got_error *
histedit_check_script(struct got_histedit_list *histedit_cmds,
    struct got_object_id_queue *commits, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;
	struct got_histedit_list_entry *hle;
	static char msg[128];
	char *id_str;

	if (TAILQ_EMPTY(histedit_cmds))
		return got_error_msg(GOT_ERR_EMPTY_HISTEDIT,
		    "histedit script contains no commands");
	if (STAILQ_EMPTY(commits))
		return got_error(GOT_ERR_EMPTY_HISTEDIT);

	TAILQ_FOREACH(hle, histedit_cmds, entry) {
		struct got_histedit_list_entry *hle2;
		TAILQ_FOREACH(hle2, histedit_cmds, entry) {
			if (hle == hle2)
				continue;
			if (got_object_id_cmp(hle->commit_id,
			    hle2->commit_id) != 0)
				continue;
			err = got_object_id_str(&id_str, hle->commit_id);
			if (err)
				return err;
			snprintf(msg, sizeof(msg), "commit %s is listed "
			    "more than once in histedit script", id_str);
			free(id_str);
			return got_error_msg(GOT_ERR_HISTEDIT_CMD, msg);
		}
	}

	STAILQ_FOREACH(qid, commits, entry) {
		TAILQ_FOREACH(hle, histedit_cmds, entry) {
			if (got_object_id_cmp(&qid->id, hle->commit_id) == 0)
				break;
		}
		if (hle == NULL) {
			err = got_object_id_str(&id_str, &qid->id);
			if (err)
				return err;
			snprintf(msg, sizeof(msg),
			    "commit %s missing from histedit script", id_str);
			free(id_str);
			return got_error_msg(GOT_ERR_HISTEDIT_CMD, msg);
		}
	}

	hle = TAILQ_LAST(histedit_cmds, got_histedit_list);
	if (hle && hle->cmd->code == GOT_HISTEDIT_FOLD)
		return got_error_msg(GOT_ERR_HISTEDIT_CMD,
		    "last commit in histedit script cannot be folded");

	return NULL;
}

static const struct got_error *
histedit_run_editor(struct got_histedit_list *histedit_cmds,
    const char *editor, const char *path,
    struct got_object_id_queue *commits, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct stat st, st2;
	struct timespec timeout;
	FILE *f = NULL;

	if (stat(path, &st) == -1) {
		err = got_error_from_errno2("stat", path);
		goto done;
	}

	if (spawn_editor(editor, path) == -1) {
		err = got_error_from_errno("failed spawning editor");
		goto done;
	}

	timeout.tv_sec = 0;
	timeout.tv_nsec = 1;
	nanosleep(&timeout,  NULL);

	if (stat(path, &st2) == -1) {
		err = got_error_from_errno2("stat", path);
		goto done;
	}

	if (st.st_size == st2.st_size &&
	    timespeccmp(&st.st_mtim, &st2.st_mtim, ==)) {
		err = got_error_msg(GOT_ERR_EMPTY_HISTEDIT,
                    "no changes made to histedit script, aborting");
		goto done;
	}

	f = fopen(path, "re");
	if (f == NULL) {
		err = got_error_from_errno("fopen");
		goto done;
	}
	err = histedit_parse_list(histedit_cmds, f, repo);
	if (err)
		goto done;

	err = histedit_check_script(histedit_cmds, commits, repo);
done:
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
histedit_edit_list_retry(struct got_histedit_list *, const struct got_error *,
    struct got_object_id_queue *, const char *, const char *, const char *,
    struct got_repository *);

static const struct got_error *
histedit_edit_script(struct got_histedit_list *histedit_cmds,
    struct got_object_id_queue *commits, const char *branch_name,
    int edit_logmsg_only, int fold_only, int drop_only, int edit_only,
    const char *editor, struct got_repository *repo)
{
	const struct got_error *err;
	FILE *f = NULL;
	char *path = NULL;

	err = got_opentemp_named(&path, &f, "got-histedit", "");
	if (err)
		return err;

	err = write_cmd_list(f, branch_name, commits);
	if (err)
		goto done;

	err = histedit_write_commit_list(commits, f, edit_logmsg_only,
	    fold_only, drop_only, edit_only, repo);
	if (err)
		goto done;

	if (drop_only || edit_logmsg_only || fold_only || edit_only) {
		rewind(f);
		err = histedit_parse_list(histedit_cmds, f, repo);
	} else {
		if (fclose(f) == EOF) {
			err = got_error_from_errno("fclose");
			goto done;
		}
		f = NULL;
		err = histedit_run_editor(histedit_cmds, editor, path,
		    commits, repo);
		if (err) {
			if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
			    err->code != GOT_ERR_HISTEDIT_CMD)
				goto done;
			err = histedit_edit_list_retry(histedit_cmds, err,
			    commits, editor, path, branch_name, repo);
		}
	}
done:
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (path && unlink(path) != 0 && err == NULL)
		err = got_error_from_errno2("unlink", path);
	free(path);
	return err;
}

static const struct got_error *
histedit_save_list(struct got_histedit_list *histedit_cmds,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path = NULL;
	FILE *f = NULL;
	struct got_histedit_list_entry *hle;

	err = got_worktree_get_histedit_script_path(&path, worktree);
	if (err)
		return err;

	f = fopen(path, "we");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", path);
		goto done;
	}
	TAILQ_FOREACH(hle, histedit_cmds, entry) {
		err = histedit_write_commit(hle->commit_id, hle->cmd->name, f,
		    repo);
		if (err)
			break;
	}
done:
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(path);
	return err;
}

static void
histedit_free_list(struct got_histedit_list *histedit_cmds)
{
	struct got_histedit_list_entry *hle;

	while ((hle = TAILQ_FIRST(histedit_cmds))) {
		TAILQ_REMOVE(histedit_cmds, hle, entry);
		free(hle);
	}
}

static const struct got_error *
histedit_load_list(struct got_histedit_list *histedit_cmds,
    const char *path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	FILE *f = NULL;

	f = fopen(path, "re");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", path);
		goto done;
	}

	err = histedit_parse_list(histedit_cmds, f, repo);
done:
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
histedit_edit_list_retry(struct got_histedit_list *histedit_cmds,
    const struct got_error *edit_err, struct got_object_id_queue *commits,
    const char *editor, const char *path, const char *branch_name,
    struct got_repository *repo)
{
	const struct got_error *err = NULL, *prev_err = edit_err;
	int resp = ' ';

	while (resp != 'c' && resp != 'r' && resp != 'a') {
		printf("%s: %s\n(c)ontinue editing, (r)estart editing, "
		    "or (a)bort: ", getprogname(), prev_err->msg);
		resp = getchar();
		if (resp == '\n')
			resp = getchar();
		if (resp == 'c') {
			histedit_free_list(histedit_cmds);
			err = histedit_run_editor(histedit_cmds, editor, path,
			    commits, repo);
			if (err) {
				if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
				    err->code != GOT_ERR_HISTEDIT_CMD)
					break;
				prev_err = err;
				resp = ' ';
				continue;
			}
			break;
		} else if (resp == 'r') {
			histedit_free_list(histedit_cmds);
			err = histedit_edit_script(histedit_cmds,
			    commits, branch_name, 0, 0, 0, 0, editor, repo);
			if (err) {
				if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
				    err->code != GOT_ERR_HISTEDIT_CMD)
					break;
				prev_err = err;
				resp = ' ';
				continue;
			}
			break;
		} else if (resp == 'a') {
			err = got_error(GOT_ERR_HISTEDIT_CANCEL);
			break;
		} else
			printf("invalid response '%c'\n", resp);
	}

	return err;
}

static const struct got_error *
histedit_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    struct got_reference *branch, struct got_repository *repo)
{
	printf("Switching work tree to %s\n",
	    got_ref_get_symref_target(branch));
	return got_worktree_histedit_complete(worktree, fileindex, tmp_branch,
	    branch, repo);
}

static const struct got_error *
show_histedit_progress(struct got_commit_object *commit,
    struct got_histedit_list_entry *hle, struct got_object_id *new_id)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL, *logmsg = NULL;

	err = got_object_id_str(&old_id_str, hle->commit_id);
	if (err)
		goto done;

	if (new_id) {
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
	}

	old_id_str[12] = '\0';
	if (new_id_str)
		new_id_str[12] = '\0';

	if (hle->logmsg) {
		logmsg = strdup(hle->logmsg);
		if (logmsg == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		trim_logmsg(logmsg, 42);
	} else {
		err = get_short_logmsg(&logmsg, 42, commit);
		if (err)
			goto done;
	}

	switch (hle->cmd->code) {
	case GOT_HISTEDIT_PICK:
	case GOT_HISTEDIT_EDIT:
	case GOT_HISTEDIT_MESG:
		printf("%s -> %s: %s\n", old_id_str,
		    new_id_str ? new_id_str : "no-op change", logmsg);
		break;
	case GOT_HISTEDIT_DROP:
	case GOT_HISTEDIT_FOLD:
		printf("%s ->  %s commit: %s\n", old_id_str, hle->cmd->name,
		    logmsg);
		break;
	default:
		break;
	}
done:
	free(old_id_str);
	free(new_id_str);
	return err;
}

static const struct got_error *
histedit_commit(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *tmp_branch, struct got_histedit_list_entry *hle,
    const char *committer, int allow_conflict, const char *editor,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *commit;
	struct got_object_id *new_commit_id;

	if ((hle->cmd->code == GOT_HISTEDIT_EDIT || get_folded_commits(hle))
	    && hle->logmsg == NULL) {
		err = histedit_edit_logmsg(hle, editor, repo);
		if (err)
			return err;
	}

	err = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (err)
		return err;

	err = got_worktree_histedit_commit(&new_commit_id, merged_paths,
	    worktree, fileindex, tmp_branch, committer, commit, hle->commit_id,
	    hle->logmsg, allow_conflict, repo);
	if (err) {
		if (err->code != GOT_ERR_COMMIT_NO_CHANGES)
			goto done;
		err = show_histedit_progress(commit, hle, NULL);
	} else {
		err = show_histedit_progress(commit, hle, new_commit_id);
		free(new_commit_id);
	}
done:
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
histedit_skip_commit(struct got_histedit_list_entry *hle,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *error;
	struct got_commit_object *commit;

	error = got_worktree_histedit_skip_commit(worktree, hle->commit_id,
	    repo);
	if (error)
		return error;

	error = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (error)
		return error;

	error = show_histedit_progress(commit, hle, NULL);
	got_object_commit_close(commit);
	return error;
}

static const struct got_error *
check_local_changes(void *arg, unsigned char status,
    unsigned char staged_status, const char *path,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	int *have_local_changes = arg;

	switch (status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
	case GOT_STATUS_CONFLICT:
		*have_local_changes = 1;
		return got_error(GOT_ERR_CANCELLED);
	default:
		break;
	}

	switch (staged_status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
		*have_local_changes = 1;
		return got_error(GOT_ERR_CANCELLED);
	default:
		break;
	}

	return NULL;
}

static const struct got_error *
cmd_histedit(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *committer = NULL, *gitconfig_path = NULL;
	struct got_reference *branch = NULL;
	struct got_reference *tmp_branch = NULL;
	struct got_object_id *resume_commit_id = NULL;
	struct got_object_id *base_commit_id = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct got_commit_object *commit = NULL;
	int ch, rebase_in_progress = 0, merge_in_progress = 0;
	struct got_update_progress_arg upa;
	int edit_in_progress = 0, abort_edit = 0, continue_edit = 0;
	int drop_only = 0, edit_logmsg_only = 0, fold_only = 0, edit_only = 0;
	int allow_conflict = 0, list_backups = 0, delete_backups = 0;
	const char *edit_script_path = NULL;
	char *editor = NULL;
	struct got_object_id_queue commits;
	struct got_pathlist_head merged_paths;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *pid;
	struct got_histedit_list histedit_cmds;
	struct got_histedit_list_entry *hle;
	int *pack_fds = NULL;

	STAILQ_INIT(&commits);
	TAILQ_INIT(&histedit_cmds);
	RB_INIT(&merged_paths);
	memset(&upa, 0, sizeof(upa));

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aCcdeF:flmX")) != -1) {
		switch (ch) {
		case 'a':
			abort_edit = 1;
			break;
		case 'C':
			allow_conflict = 1;
			break;
		case 'c':
			continue_edit = 1;
			break;
		case 'd':
			drop_only = 1;
			break;
		case 'e':
			edit_only = 1;
			break;
		case 'F':
			edit_script_path = optarg;
			break;
		case 'f':
			fold_only = 1;
			break;
		case 'l':
			list_backups = 1;
			break;
		case 'm':
			edit_logmsg_only = 1;
			break;
		case 'X':
			delete_backups = 1;
			break;
		default:
			usage_histedit(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (abort_edit && allow_conflict)
		option_conflict('a', 'C');
	if (abort_edit && continue_edit)
		option_conflict('a', 'c');
	if (edit_script_path && allow_conflict)
		option_conflict('F', 'C');
	if (edit_script_path && edit_logmsg_only)
		option_conflict('F', 'm');
	if (abort_edit && edit_logmsg_only)
		option_conflict('a', 'm');
	if (edit_logmsg_only && allow_conflict)
		option_conflict('m', 'C');
	if (continue_edit && edit_logmsg_only)
		option_conflict('c', 'm');
	if (abort_edit && fold_only)
		option_conflict('a', 'f');
	if (fold_only && allow_conflict)
		option_conflict('f', 'C');
	if (continue_edit && fold_only)
		option_conflict('c', 'f');
	if (fold_only && edit_logmsg_only)
		option_conflict('f', 'm');
	if (edit_script_path && fold_only)
		option_conflict('F', 'f');
	if (abort_edit && edit_only)
		option_conflict('a', 'e');
	if (continue_edit && edit_only)
		option_conflict('c', 'e');
	if (edit_only && edit_logmsg_only)
		option_conflict('e', 'm');
	if (edit_script_path && edit_only)
		option_conflict('F', 'e');
	if (fold_only && edit_only)
		option_conflict('f', 'e');
	if (drop_only && abort_edit)
		option_conflict('d', 'a');
	if (drop_only && allow_conflict)
		option_conflict('d', 'C');
	if (drop_only && continue_edit)
		option_conflict('d', 'c');
	if (drop_only && edit_logmsg_only)
		option_conflict('d', 'm');
	if (drop_only && edit_only)
		option_conflict('d', 'e');
	if (drop_only && edit_script_path)
		option_conflict('d', 'F');
	if (drop_only && fold_only)
		option_conflict('d', 'f');
	if (list_backups) {
		if (abort_edit)
			option_conflict('l', 'a');
		if (allow_conflict)
			option_conflict('l', 'C');
		if (continue_edit)
			option_conflict('l', 'c');
		if (edit_script_path)
			option_conflict('l', 'F');
		if (edit_logmsg_only)
			option_conflict('l', 'm');
		if (drop_only)
			option_conflict('l', 'd');
		if (fold_only)
			option_conflict('l', 'f');
		if (edit_only)
			option_conflict('l', 'e');
		if (delete_backups)
			option_conflict('l', 'X');
		if (argc != 0 && argc != 1)
			usage_histedit(1);
	} else if (delete_backups) {
		if (abort_edit)
			option_conflict('X', 'a');
		if (allow_conflict)
			option_conflict('X', 'C');
		if (continue_edit)
			option_conflict('X', 'c');
		if (drop_only)
			option_conflict('X', 'd');
		if (edit_script_path)
			option_conflict('X', 'F');
		if (edit_logmsg_only)
			option_conflict('X', 'm');
		if (fold_only)
			option_conflict('X', 'f');
		if (edit_only)
			option_conflict('X', 'e');
		if (list_backups)
			option_conflict('X', 'l');
		if (argc != 0 && argc != 1)
			usage_histedit(1);
	} else if (allow_conflict && !continue_edit)
		errx(1, "-C option requires -c");
	else if (argc != 0)
		usage_histedit(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (list_backups || delete_backups) {
			if (error->code != GOT_ERR_NOT_WORKTREE)
				goto done;
		} else {
			if (error->code == GOT_ERR_NOT_WORKTREE)
				error = wrap_not_worktree_error(error,
				    "histedit", cwd);
			goto done;
		}
	}

	if (list_backups || delete_backups) {
		error = got_repo_open(&repo,
		    worktree ? got_worktree_get_repo_path(worktree) : cwd,
		    NULL, pack_fds);
		if (error != NULL)
			goto done;
		error = apply_unveil(got_repo_get_path(repo), 0,
		    worktree ? got_worktree_get_root_path(worktree) : NULL);
		if (error)
			goto done;
		error = process_backup_refs(
		    GOT_WORKTREE_HISTEDIT_BACKUP_REF_PREFIX,
		    argc == 1 ? argv[0] : NULL, delete_backups, repo);
		goto done; /* nothing else to do */
	} else {
		error = get_gitconfig_path(&gitconfig_path);
		if (error)
			goto done;
		error = got_repo_open(&repo,
		    got_worktree_get_repo_path(worktree), gitconfig_path,
		    pack_fds);
		if (error != NULL)
			goto done;
		error = get_editor(&editor);
		if (error)
			goto done;
		if (unveil(editor, "x") != 0) {
			error = got_error_from_errno2("unveil", editor);
			goto done;
		}
		if (edit_script_path) {
			if (unveil(edit_script_path, "r") != 0) {
				error = got_error_from_errno2("unveil",
				    edit_script_path);
				goto done;
			}
		}
		error = apply_unveil(got_repo_get_path(repo), 0,
		    got_worktree_get_root_path(worktree));
		if (error)
			goto done;
	}

	if (worktree != NULL && !list_backups && !delete_backups) {
		error = worktree_has_logmsg_ref("histedit", worktree, repo);
		if (error)
			goto done;
	}

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;
	if (rebase_in_progress) {
		error = got_error(GOT_ERR_REBASING);
		goto done;
	}

	error = got_worktree_merge_in_progress(&merge_in_progress, worktree,
	    repo);
	if (error)
		goto done;
	if (merge_in_progress) {
		error = got_error(GOT_ERR_MERGE_BUSY);
		goto done;
	}

	error = got_worktree_histedit_in_progress(&edit_in_progress, worktree);
	if (error)
		goto done;

	if (edit_in_progress && edit_logmsg_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -m option can be used");
		goto done;
	}
	if (edit_in_progress && drop_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -d option can be used");
		goto done;
	}
	if (edit_in_progress && fold_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -f option can be used");
		goto done;
	}
	if (edit_in_progress && edit_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -e option can be used");
		goto done;
	}

	if (edit_in_progress && abort_edit) {
		error = got_worktree_histedit_continue(&resume_commit_id,
		    &tmp_branch, &branch, &base_commit_id, &fileindex,
		    worktree, repo);
		if (error)
			goto done;
		printf("Switching work tree to %s\n",
		    got_ref_get_symref_target(branch));
		error = got_worktree_histedit_abort(worktree, fileindex, repo,
		    branch, base_commit_id, abort_progress, &upa, 1);
		if (error)
			goto done;
		printf("Histedit of %s aborted\n",
		    got_ref_get_symref_target(branch));
		print_merge_progress_stats(&upa);
		goto done; /* nothing else to do */
	} else if (abort_edit) {
		error = got_error(GOT_ERR_NOT_HISTEDIT);
		goto done;
	}

	error = get_author(&committer, repo, worktree);
	if (error)
		goto done;

	if (continue_edit) {
		char *path;

		if (!edit_in_progress) {
			error = got_error(GOT_ERR_NOT_HISTEDIT);
			goto done;
		}

		error = got_worktree_get_histedit_script_path(&path, worktree);
		if (error)
			goto done;

		error = histedit_load_list(&histedit_cmds, path, repo);
		free(path);
		if (error)
			goto done;

		error = got_worktree_histedit_continue(&resume_commit_id,
		    &tmp_branch, &branch, &base_commit_id, &fileindex,
		    worktree, repo);
		if (error)
			goto done;

		error = got_ref_resolve(&head_commit_id, repo, branch);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo,
		    head_commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = STAILQ_FIRST(parent_ids);
		if (pid == NULL) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}
		error = collect_commits(&commits, head_commit_id, &pid->id,
		    base_commit_id, got_worktree_get_path_prefix(worktree),
		    GOT_ERR_HISTEDIT_PATH, repo);
		got_object_commit_close(commit);
		commit = NULL;
		if (error)
			goto done;
	} else {
		if (edit_in_progress) {
			error = got_error(GOT_ERR_HISTEDIT_BUSY);
			goto done;
		}

		error = got_ref_open(&branch, repo,
		    got_worktree_get_head_ref_name(worktree), 0);
		if (error != NULL)
			goto done;

		if (strncmp(got_ref_get_name(branch), "refs/heads/", 11) != 0) {
			error = got_error_msg(GOT_ERR_COMMIT_BRANCH,
			    "will not edit commit history of a branch outside "
			    "the \"refs/heads/\" reference namespace");
			goto done;
		}

		error = got_ref_resolve(&head_commit_id, repo, branch);
		got_ref_close(branch);
		branch = NULL;
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo,
		    head_commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = STAILQ_FIRST(parent_ids);
		if (pid == NULL) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}
		error = collect_commits(&commits, head_commit_id, &pid->id,
		    got_worktree_get_base_commit_id(worktree),
		    got_worktree_get_path_prefix(worktree),
		    GOT_ERR_HISTEDIT_PATH, repo);
		got_object_commit_close(commit);
		commit = NULL;
		if (error)
			goto done;

		if (STAILQ_EMPTY(&commits)) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}

		error = got_worktree_histedit_prepare(&tmp_branch, &branch,
		    &base_commit_id, &fileindex, worktree, repo);
		if (error)
			goto done;

		if (edit_script_path) {
			error = histedit_load_list(&histedit_cmds,
			    edit_script_path, repo);
			if (error) {
				got_worktree_histedit_abort(worktree, fileindex,
				    repo, branch, base_commit_id,
				    abort_progress, &upa, 0);
				print_merge_progress_stats(&upa);
				goto done;
			}
		} else {
			const char *branch_name;
			branch_name = got_ref_get_symref_target(branch);
			if (strncmp(branch_name, "refs/heads/", 11) == 0)
				branch_name += 11;
			error = histedit_edit_script(&histedit_cmds, &commits,
			    branch_name, edit_logmsg_only, fold_only,
			    drop_only, edit_only, editor, repo);
			if (error) {
				got_worktree_histedit_abort(worktree, fileindex,
				    repo, branch, base_commit_id,
				    abort_progress, &upa, 0);
				print_merge_progress_stats(&upa);
				goto done;
			}

		}

		error = histedit_save_list(&histedit_cmds, worktree,
		    repo);
		if (error) {
			got_worktree_histedit_abort(worktree, fileindex,
			    repo, branch, base_commit_id,
			    abort_progress, &upa, 0);
			print_merge_progress_stats(&upa);
			goto done;
		}

	}

	error = histedit_check_script(&histedit_cmds, &commits, repo);
	if (error)
		goto done;

	TAILQ_FOREACH(hle, &histedit_cmds, entry) {
		if (resume_commit_id) {
			if (got_object_id_cmp(hle->commit_id,
			    resume_commit_id) != 0)
				continue;

			resume_commit_id = NULL;
			if (hle->cmd->code == GOT_HISTEDIT_DROP ||
			    hle->cmd->code == GOT_HISTEDIT_FOLD) {
				error = histedit_skip_commit(hle, worktree,
				    repo);
				if (error)
					goto done;
			} else {
				struct got_pathlist_head paths;
				int have_changes = 0;

				RB_INIT(&paths);
				error = got_pathlist_insert(NULL, &paths, "", NULL);
				if (error)
					goto done;
				error = got_worktree_status(worktree, &paths,
				    repo, 0, check_local_changes, &have_changes,
				    check_cancelled, NULL);
				got_pathlist_free(&paths,
				    GOT_PATHLIST_FREE_NONE);
				if (error) {
					if (error->code != GOT_ERR_CANCELLED)
						goto done;
					if (sigint_received || sigpipe_received)
						goto done;
				}
				if (have_changes) {
					error = histedit_commit(NULL, worktree,
					    fileindex, tmp_branch, hle,
					    committer, allow_conflict, editor,
					    repo);
					if (error)
						goto done;
				} else {
					error = histedit_skip_commit(hle,
					    worktree, repo);
					if (error)
						goto done;
				}
			}
			continue;
		}

		if (hle->cmd->code == GOT_HISTEDIT_DROP) {
			error = histedit_skip_commit(hle, worktree, repo);
			if (error)
				goto done;
			continue;
		}
		error = got_object_open_as_commit(&commit, repo,
		    hle->commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = STAILQ_FIRST(parent_ids);

		error = got_worktree_histedit_merge_files(&merged_paths,
		    worktree, fileindex, &pid->id, hle->commit_id, repo,
		    update_progress, &upa, check_cancelled, NULL);
		if (error)
			goto done;
		got_object_commit_close(commit);
		commit = NULL;

		print_merge_progress_stats(&upa);
		if (upa.conflicts > 0 || upa.missing > 0 ||
		    upa.not_deleted > 0 || upa.unversioned > 0) {
			if (upa.conflicts > 0) {
				error = show_rebase_merge_conflict(
				    hle->commit_id, repo);
				if (error)
					goto done;
			}
			got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_PATH);
			break;
		}

		if (hle->cmd->code == GOT_HISTEDIT_EDIT) {
			char *id_str;
			error = got_object_id_str(&id_str, hle->commit_id);
			if (error)
				goto done;
			printf("Stopping histedit for amending commit %s\n",
			    id_str);
			free(id_str);
			got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_PATH);
			error = got_worktree_histedit_postpone(worktree,
			    fileindex);
			goto done;
		} else if (hle->cmd->code == GOT_HISTEDIT_FOLD) {
			error = histedit_skip_commit(hle, worktree, repo);
			if (error)
				goto done;
			continue;
		} else if (hle->cmd->code == GOT_HISTEDIT_MESG) {
			error = histedit_edit_logmsg(hle, editor, repo);
			if (error)
				goto done;
		}

		error = histedit_commit(&merged_paths, worktree, fileindex,
		    tmp_branch, hle, committer, allow_conflict, editor, repo);
		got_pathlist_free(&merged_paths, GOT_PATHLIST_FREE_PATH);
		if (error)
			goto done;
	}

	if (upa.conflicts > 0 || upa.missing > 0 ||
	    upa.not_deleted > 0 || upa.unversioned > 0) {
		error = got_worktree_histedit_postpone(worktree, fileindex);
		if (error)
			goto done;
		if (upa.conflicts > 0 && upa.missing == 0 &&
		    upa.not_deleted == 0 && upa.unversioned == 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before histedit "
			    "can continue");
		} else if (upa.conflicts > 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before histedit "
			    "can continue; changes destined for some "
			    "files were not yet merged and should be "
			    "merged manually if required before the "
			    "histedit operation is continued");
		} else {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "changes destined for some files were not "
			    "yet merged and should be merged manually "
			    "if required before the histedit operation "
			    "is continued");
		}
	} else
		error = histedit_complete(worktree, fileindex, tmp_branch,
		    branch, repo);
done:
	free(cwd);
	free(editor);
	free(committer);
	free(gitconfig_path);
	got_object_id_queue_free(&commits);
	histedit_free_list(&histedit_cmds);
	free(head_commit_id);
	free(base_commit_id);
	free(resume_commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (branch)
		got_ref_close(branch);
	if (tmp_branch)
		got_ref_close(tmp_branch);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	return error;
}

__dead static void
usage_integrate(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s integrate branch\n", getprogname());
	exit(status);
}

static const struct got_error *
cmd_integrate(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *refname = NULL, *base_refname = NULL;
	const char *branch_arg = NULL;
	struct got_reference *branch_ref = NULL, *base_branch_ref = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_object_id *commit_id = NULL, *base_commit_id = NULL;
	int ch;
	struct got_update_progress_arg upa;
	int *pack_fds = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_integrate(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_integrate(1);
	branch_arg = argv[0];

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "integrate",
			    cwd);
		goto done;
	}

	error = check_rebase_or_histedit_in_progress(worktree);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = check_merge_in_progress(worktree, repo);
	if (error)
		goto done;

	if (asprintf(&refname, "refs/heads/%s", branch_arg) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_worktree_integrate_prepare(&fileindex, &branch_ref,
	    &base_branch_ref, worktree, refname, repo);
	if (error)
		goto done;

	refname = strdup(got_ref_get_name(branch_ref));
	if (refname == NULL) {
		error = got_error_from_errno("strdup");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}
	base_refname = strdup(got_ref_get_name(base_branch_ref));
	if (base_refname == NULL) {
		error = got_error_from_errno("strdup");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}
	if (strncmp(base_refname, "refs/heads/", 11) != 0) {
		error = got_error(GOT_ERR_INTEGRATE_BRANCH);
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	error = got_ref_resolve(&commit_id, repo, branch_ref);
	if (error)
		goto done;

	error = got_ref_resolve(&base_commit_id, repo, base_branch_ref);
	if (error)
		goto done;

	if (got_object_id_cmp(commit_id, base_commit_id) == 0) {
		error = got_error_msg(GOT_ERR_SAME_BRANCH,
		    "specified branch has already been integrated");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	error = check_linear_ancestry(commit_id, base_commit_id, 1, repo);
	if (error) {
		if (error->code == GOT_ERR_ANCESTRY)
			error = got_error(GOT_ERR_REBASE_REQUIRED);
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	memset(&upa, 0, sizeof(upa));
	error = got_worktree_integrate_continue(worktree, fileindex, repo,
	    branch_ref, base_branch_ref, update_progress, &upa,
	    check_cancelled, NULL);
	if (error)
		goto done;

	printf("Integrated %s into %s\n", refname, base_refname);
	print_update_progress_stats(&upa);
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(cwd);
	free(base_commit_id);
	free(commit_id);
	free(refname);
	free(base_refname);
	return error;
}

__dead static void
usage_merge(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s merge [-aCcn] [branch]\n", getprogname());
	exit(status);
}

static const struct got_error *
cmd_merge(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	struct got_fileindex *fileindex = NULL;
	char *cwd = NULL, *id_str = NULL, *author = NULL;
	char *gitconfig_path = NULL;
	struct got_reference *branch = NULL, *wt_branch = NULL;
	struct got_object_id *branch_tip = NULL, *yca_id = NULL;
	struct got_object_id *wt_branch_tip = NULL;
	int ch, merge_in_progress = 0, abort_merge = 0, continue_merge = 0;
	int allow_conflict = 0, prefer_fast_forward = 1, interrupt_merge = 0;
	struct got_update_progress_arg upa;
	struct got_object_id *merge_commit_id = NULL;
	char *branch_name = NULL;
	int *pack_fds = NULL;

	memset(&upa, 0, sizeof(upa));

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aCcMn")) != -1) {
		switch (ch) {
		case 'a':
			abort_merge = 1;
			break;
		case 'C':
			allow_conflict = 1;
			break;
		case 'c':
			continue_merge = 1;
			break;
		case 'M':
			prefer_fast_forward = 0;
			break;
		case 'n':
			interrupt_merge = 1;
			break;
		default:
			usage_merge(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (abort_merge) {
		if (continue_merge)
			option_conflict('a', 'c');
		if (!prefer_fast_forward)
			option_conflict('a', 'M');
		if (interrupt_merge)
			option_conflict('a', 'n');
	} else if (continue_merge) {
		if (!prefer_fast_forward)
			option_conflict('c', 'M');
		if (interrupt_merge)
			option_conflict('c', 'n');
	}
	if (allow_conflict) {
		if (!continue_merge)
			errx(1, "-C option requires -c");
	}
	if (abort_merge || continue_merge) {
		if (argc != 0)
			usage_merge(1);
	} else if (argc != 1)
		usage_merge(1);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error,
			    "merge", cwd);
		goto done;
	}

	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo,
	    worktree ? got_worktree_get_repo_path(worktree) : cwd,
	    gitconfig_path, pack_fds);
	if (error != NULL)
		goto done;

	if (worktree != NULL) {
		error = worktree_has_logmsg_ref("merge", worktree, repo);
		if (error)
			goto done;
	}

	error = apply_unveil(got_repo_get_path(repo), 0,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	error = check_rebase_or_histedit_in_progress(worktree);
	if (error)
		goto done;

	error = got_worktree_merge_in_progress(&merge_in_progress, worktree,
	    repo);
	if (error)
		goto done;

	if (merge_in_progress && !(abort_merge || continue_merge)) {
		error = got_error(GOT_ERR_MERGE_BUSY);
		goto done;
	}

	if (!merge_in_progress && (abort_merge || continue_merge)) {
		error = got_error(GOT_ERR_NOT_MERGING);
		goto done;
	}

	if (abort_merge) {
		error = got_worktree_merge_continue(&branch_name,
		    &branch_tip, &fileindex, worktree, repo);
		if (error)
			goto done;
		error = got_worktree_merge_abort(worktree, fileindex, repo,
		    abort_progress, &upa);
		if (error)
			goto done;
		printf("Merge of %s aborted\n", branch_name);
		goto done; /* nothing else to do */
	}

	if (strncmp(got_worktree_get_head_ref_name(worktree),
	    "refs/heads/", 11) != 0) {
		error = got_error_fmt(GOT_ERR_COMMIT_BRANCH,
		    "work tree's current branch %s is outside the "
		    "\"refs/heads/\" reference namespace; "
		    "update -b required",
		    got_worktree_get_head_ref_name(worktree));
		goto done;
	}

	error = get_author(&author, repo, worktree);
	if (error)
		goto done;

	error = got_ref_open(&wt_branch, repo,
	    got_worktree_get_head_ref_name(worktree), 0);
	if (error)
		goto done;
	error = got_ref_resolve(&wt_branch_tip, repo, wt_branch);
	if (error)
		goto done;

	if (continue_merge) {
		struct got_object_id *base_commit_id;
		base_commit_id = got_worktree_get_base_commit_id(worktree);
		if (got_object_id_cmp(wt_branch_tip, base_commit_id) != 0) {
			error = got_error(GOT_ERR_MERGE_COMMIT_OUT_OF_DATE);
			goto done;
		}
		error = got_worktree_merge_continue(&branch_name,
		    &branch_tip, &fileindex, worktree, repo);
		if (error)
			goto done;
	} else {
		error = got_ref_open(&branch, repo, argv[0], 0);
		if (error != NULL)
			goto done;
		branch_name = strdup(got_ref_get_name(branch));
		if (branch_name == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		error = got_ref_resolve(&branch_tip, repo, branch);
		if (error)
			goto done;
	}

	error = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    wt_branch_tip, branch_tip, 0, 0, repo,
	    check_cancelled, NULL);
	if (error && error->code != GOT_ERR_ANCESTRY)
		goto done;

	if (!continue_merge) {
		error = check_path_prefix(wt_branch_tip, branch_tip,
		    got_worktree_get_path_prefix(worktree),
		    GOT_ERR_MERGE_PATH, repo);
		if (error)
			goto done;
		error = got_worktree_merge_prepare(&fileindex, worktree, repo);
		if (error)
			goto done;
		if (prefer_fast_forward && yca_id &&
		    got_object_id_cmp(wt_branch_tip, yca_id) == 0) {
			struct got_pathlist_head paths;
			if (interrupt_merge) {
				error = got_error_fmt(GOT_ERR_BAD_OPTION,
				    "there are no changes to merge since %s "
				    "is already based on %s; merge cannot be "
				    "interrupted for amending; -n",
				    branch_name, got_ref_get_name(wt_branch));
				goto done;
			}
			printf("Forwarding %s to %s\n",
				got_ref_get_name(wt_branch), branch_name);
			error = got_ref_change_ref(wt_branch, branch_tip);
			if (error)
				goto done;
			error = got_ref_write(wt_branch, repo);
			if (error)
				goto done;
			error = got_worktree_set_base_commit_id(worktree, repo,
			    branch_tip);
			if (error)
				goto done;
			RB_INIT(&paths);
			error = got_pathlist_insert(NULL, &paths, "", NULL);
			if (error)
				goto done;
			error = got_worktree_checkout_files(worktree,
			    &paths, repo, update_progress, &upa,
			    check_cancelled, NULL);
			got_pathlist_free(&paths, GOT_PATHLIST_FREE_NONE);
			if (error)
				goto done;
			if (upa.did_something) {
				char *id_str;
				error = got_object_id_str(&id_str, branch_tip);
				if (error)
					goto done;
				printf("Updated to commit %s\n", id_str);
				free(id_str);
			} else
				printf("Already up-to-date\n");
			print_update_progress_stats(&upa);
			goto done;
		}
		error = got_worktree_merge_write_refs(worktree, branch, repo);
		if (error)
			goto done;

		error = got_worktree_merge_branch(worktree, fileindex,
		    yca_id, branch_tip, repo, update_progress, &upa,
		    check_cancelled, NULL);
		if (error)
			goto done;
		print_merge_progress_stats(&upa);
		if (!upa.did_something) {
			error = got_worktree_merge_abort(worktree, fileindex,
			    repo, abort_progress, &upa);
			if (error)
				goto done;
			printf("Already up-to-date\n");
			goto done;
		}
	}

	if (interrupt_merge) {
		error = got_worktree_merge_postpone(worktree, fileindex);
		if (error)
			goto done;
		printf("Merge of %s interrupted on request\n", branch_name);
	} else if (upa.conflicts > 0 || upa.missing > 0 ||
	    upa.not_deleted > 0 || upa.unversioned > 0) {
		error = got_worktree_merge_postpone(worktree, fileindex);
		if (error)
			goto done;
		if (upa.conflicts > 0 && upa.missing == 0 &&
		    upa.not_deleted == 0 && upa.unversioned == 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before merging "
			    "can continue");
		} else if (upa.conflicts > 0) {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "conflicts must be resolved before merging "
			    "can continue; changes destined for some "
			    "files were not yet merged and "
			    "should be merged manually if required before the "
			    "merge operation is continued");
		} else {
			error = got_error_msg(GOT_ERR_CONFLICTS,
			    "changes destined for some "
			    "files were not yet merged and should be "
			    "merged manually if required before the "
			    "merge operation is continued");
		}
		goto done;
	} else {
		error = got_worktree_merge_commit(&merge_commit_id, worktree,
		    fileindex, author, 0, NULL, 1, branch_tip, branch_name,
		    allow_conflict, repo, continue_merge ? print_status : NULL,
		    NULL);
		if (error)
			goto done;
		error = got_worktree_merge_complete(worktree, fileindex, repo);
		if (error)
			goto done;
		error = got_object_id_str(&id_str, merge_commit_id);
		if (error)
			goto done;
		printf("Merged %s into %s: %s\n", branch_name,
		    got_worktree_get_head_ref_name(worktree),
		    id_str);

	}
done:
	free(cwd);
	free(gitconfig_path);
	free(id_str);
	free(merge_commit_id);
	free(author);
	free(branch_tip);
	free(branch_name);
	free(yca_id);
	if (branch)
		got_ref_close(branch);
	if (wt_branch)
		got_ref_close(wt_branch);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	return error;
}

__dead static void
usage_stage(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s stage [-lpS] [-F response-script] "
	    "[path ...]\n", getprogname());
	exit(status);
}

static const struct got_error *
print_stage(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	const struct got_error *err = NULL;
	char *id_str = NULL;

	if (staged_status != GOT_STATUS_ADD &&
	    staged_status != GOT_STATUS_MODIFY &&
	    staged_status != GOT_STATUS_DELETE)
		return NULL;

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY)
		err = got_object_id_str(&id_str, staged_blob_id);
	else
		err = got_object_id_str(&id_str, blob_id);
	if (err)
		return err;

	printf("%s %c %s\n", id_str, staged_status, path);
	free(id_str);
	return NULL;
}

static const struct got_error *
cmd_stage(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	int ch, list_stage = 0, pflag = 0, allow_bad_symlinks = 0;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "F:lpS")) != -1) {
		switch (ch) {
		case 'F':
			patch_script_path = optarg;
			break;
		case 'l':
			list_stage = 1;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'S':
			allow_bad_symlinks = 1;
			break;
		default:
			usage_stage(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (list_stage && (pflag || patch_script_path))
		errx(1, "-l option cannot be used with other options");
	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "stage", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "re");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}
	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = check_merge_in_progress(worktree, repo);
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (list_stage)
		error = got_worktree_status(worktree, &paths, repo, 0,
		    print_stage, NULL, check_cancelled, NULL);
	else {
		cpa.patch_script_file = patch_script_file;
		cpa.action = "stage";
		error = got_worktree_stage(worktree, &paths,
		    pflag ? NULL : print_status, NULL,
		    pflag ? choose_patch : NULL, &cpa,
		    allow_bad_symlinks, repo);
	}
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	return error;
}

__dead static void
usage_unstage(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s unstage [-p] [-F response-script] "
	    "[path ...]\n", getprogname());
	exit(status);
}


static const struct got_error *
cmd_unstage(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	int ch, pflag = 0;
	struct got_update_progress_arg upa;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;
	int *pack_fds = NULL;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "F:p")) != -1) {
		switch (ch) {
		case 'F':
			patch_script_path = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		default:
			usage_unstage(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "unstage", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL, pack_fds);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "re");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	cpa.patch_script_file = patch_script_file;
	cpa.action = "unstage";
	memset(&upa, 0, sizeof(upa));
	error = got_worktree_unstage(worktree, &paths, update_progress,
	    &upa, pflag ? choose_patch : NULL, &cpa, repo);
	if (!error)
		print_merge_progress_stats(&upa);
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	return error;
}

__dead static void
usage_cat(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s cat [-P] [-c commit] [-r repository-path] "
	    "arg ...\n", getprogname());
	exit(status);
}

static const struct got_error *
cat_blob(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object *blob;
	int fd = -1;

	fd = got_opentempfd();
	if (fd == -1)
		return got_error_from_errno("got_opentempfd");

	err = got_object_open_as_blob(&blob, repo, id, 8192, fd);
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, outfile, blob);
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	return err;
}

static const struct got_error *
cat_tree(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	int nentries, i;

	err = got_object_open_as_tree(&tree, repo, id);
	if (err)
		return err;

	nentries = got_object_tree_get_nentries(tree);
	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		char *id_str;
		if (sigint_received || sigpipe_received)
			break;
		te = got_object_tree_get_entry(tree, i);
		err = got_object_id_str(&id_str, got_tree_entry_get_id(te));
		if (err)
			break;
		fprintf(outfile, "%s %.7o %s\n", id_str,
		    got_tree_entry_get_mode(te),
		    got_tree_entry_get_name(te));
		free(id_str);
	}

	got_object_tree_close(tree);
	return err;
}

static const struct got_error *
cat_commit(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_commit_object *commit;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *pid;
	char *id_str = NULL;
	const char *logmsg = NULL;
	char gmtoff[6];

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, got_object_commit_get_tree_id(commit));
	if (err)
		goto done;

	fprintf(outfile, "%s%s\n", GOT_COMMIT_LABEL_TREE, id_str);
	parent_ids = got_object_commit_get_parent_ids(commit);
	fprintf(outfile, "numparents %d\n",
	    got_object_commit_get_nparents(commit));
	STAILQ_FOREACH(pid, parent_ids, entry) {
		char *pid_str;
		err = got_object_id_str(&pid_str, &pid->id);
		if (err)
			goto done;
		fprintf(outfile, "%s%s\n", GOT_COMMIT_LABEL_PARENT, pid_str);
		free(pid_str);
	}
	got_date_format_gmtoff(gmtoff, sizeof(gmtoff),
	    got_object_commit_get_author_gmtoff(commit));
	fprintf(outfile, "%s%s %lld %s\n", GOT_COMMIT_LABEL_AUTHOR,
	    got_object_commit_get_author(commit),
	    (long long)got_object_commit_get_author_time(commit),
	    gmtoff);

	got_date_format_gmtoff(gmtoff, sizeof(gmtoff),
	    got_object_commit_get_committer_gmtoff(commit));
	fprintf(outfile, "%s%s %lld %s\n", GOT_COMMIT_LABEL_COMMITTER,
	    got_object_commit_get_committer(commit),
	    (long long)got_object_commit_get_committer_time(commit),
	    gmtoff);

	logmsg = got_object_commit_get_logmsg_raw(commit);
	fprintf(outfile, "messagelen %zd\n", strlen(logmsg));
	fprintf(outfile, "%s", logmsg);
done:
	free(id_str);
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
cat_tag(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tag_object *tag;
	char *id_str = NULL;
	const char *tagmsg = NULL;
	char gmtoff[6];

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, got_object_tag_get_object_id(tag));
	if (err)
		goto done;

	fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_OBJECT, id_str);

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_BLOB:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_BLOB);
		break;
	case GOT_OBJ_TYPE_TREE:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_TREE);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_COMMIT);
		break;
	case GOT_OBJ_TYPE_TAG:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_TAG);
		break;
	default:
		break;
	}

	fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TAG,
	    got_object_tag_get_name(tag));

	got_date_format_gmtoff(gmtoff, sizeof(gmtoff),
	    got_object_tag_get_tagger_gmtoff(tag));
	fprintf(outfile, "%s%s %lld %s\n", GOT_TAG_LABEL_TAGGER,
	    got_object_tag_get_tagger(tag),
	    (long long)got_object_tag_get_tagger_time(tag),
	    gmtoff);

	tagmsg = got_object_tag_get_message(tag);
	fprintf(outfile, "messagelen %zd\n", strlen(tagmsg));
	fprintf(outfile, "%s", tagmsg);
done:
	free(id_str);
	got_object_tag_close(tag);
	return err;
}

static const struct got_error *
cmd_cat(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *label = NULL;
	char *keyword_idstr = NULL;
	const char *commit_id_str = NULL;
	struct got_object_id *id = NULL, *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	int ch, obj_type, i, force_path = 0;
	struct got_reflist_head refs;
	int *pack_fds = NULL;

	TAILQ_INIT(&refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:Pr:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'P':
			force_path = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_cat(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree) {
			repo_path = strdup(
			    got_worktree_get_repo_path(worktree));
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}

			if (commit_id_str == NULL) {
				/* Release work tree lock. */
				got_worktree_close(worktree);
				worktree = NULL;
			}
		}
	}

	if (repo_path == NULL) {
		repo_path = strdup(cwd);
		if (repo_path == NULL)
			return got_error_from_errno("strdup");
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	free(repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1, NULL);
	if (error)
		goto done;

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	if (commit_id_str != NULL) {
		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			commit_id_str = keyword_idstr;
		if (worktree != NULL) {
			got_worktree_close(worktree);
			worktree = NULL;
		}
	} else
		commit_id_str = GOT_REF_HEAD;
	error = got_repo_match_object_id(&commit_id, NULL,
	    commit_id_str, GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	for (i = 0; i < argc; i++) {
		if (force_path) {
			error = got_object_id_by_path(&id, repo, commit,
			    argv[i]);
			if (error)
				break;
		} else {
			error = got_repo_match_object_id(&id, &label, argv[i],
			    GOT_OBJ_TYPE_ANY, NULL /* do not resolve tags */,
			    repo);
			if (error) {
				if (error->code != GOT_ERR_BAD_OBJ_ID_STR &&
				    error->code != GOT_ERR_NOT_REF)
					break;
				error = got_object_id_by_path(&id, repo,
				    commit, argv[i]);
				if (error)
					break;
			}
		}

		error = got_object_get_type(&obj_type, repo, id);
		if (error)
			break;

		switch (obj_type) {
		case GOT_OBJ_TYPE_BLOB:
			error = cat_blob(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_TREE:
			error = cat_tree(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_COMMIT:
			error = cat_commit(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_TAG:
			error = cat_tag(id, repo, stdout);
			break;
		default:
			error = got_error(GOT_ERR_OBJ_TYPE);
			break;
		}
		if (error)
			break;
		free(label);
		label = NULL;
		free(id);
		id = NULL;
	}
done:
	free(cwd);
	free(label);
	free(id);
	free(commit_id);
	free(keyword_idstr);
	if (commit)
		got_object_commit_close(commit);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}

	got_ref_list_free(&refs);
	return error;
}

__dead static void
usage_info(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	fprintf(fp, "usage: %s info [path ...]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
print_path_info(void *arg, const char *path, mode_t mode, time_t mtime,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id)
{
	const struct got_error *err = NULL;
	char *id_str = NULL;
	char datebuf[128];
	struct tm mytm, *tm;
	struct got_pathlist_head *paths = arg;
	struct got_pathlist_entry *pe;

	/*
	 * Clear error indication from any of the path arguments which
	 * would cause this file index entry to be displayed.
	 */
	RB_FOREACH(pe, got_pathlist_head, paths) {
		if (got_path_cmp(path, pe->path, strlen(path),
		    pe->path_len) == 0 ||
		    got_path_is_child(path, pe->path, pe->path_len))
			pe->data = NULL; /* no error */
	}

	printf(GOT_COMMIT_SEP_STR);
	if (S_ISLNK(mode))
		printf("symlink: %s\n", path);
	else if (S_ISREG(mode)) {
		printf("file: %s\n", path);
		printf("mode: %o\n", mode & (S_IRWXU | S_IRWXG | S_IRWXO));
	} else if (S_ISDIR(mode))
		printf("directory: %s\n", path);
	else
		printf("something: %s\n", path);

	tm = localtime_r(&mtime, &mytm);
	if (tm == NULL)
		return NULL;
	if (strftime(datebuf, sizeof(datebuf), "%c %Z", tm) == 0)
		return got_error(GOT_ERR_NO_SPACE);
	printf("timestamp: %s\n", datebuf);

	if (blob_id) {
		err = got_object_id_str(&id_str, blob_id);
		if (err)
			return err;
		printf("based on blob: %s\n", id_str);
		free(id_str);
	}

	if (staged_blob_id) {
		err = got_object_id_str(&id_str, staged_blob_id);
		if (err)
			return err;
		printf("based on staged blob: %s\n", id_str);
		free(id_str);
	}

	if (commit_id) {
		err = got_object_id_str(&id_str, commit_id);
		if (err)
			return err;
		printf("based on commit: %s\n", id_str);
		free(id_str);
	}

	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_fileindex *fileindex = NULL;
	char *cwd = NULL, *id_str = NULL;
	struct got_pathlist_head paths;
	char *uuidstr = NULL;
	int ch, show_files = 0;

	RB_INIT(&paths);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_info(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd, GOT_WORKTREE_GOT_DIR);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "info", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree), NULL,
	    NULL);
	if (error)
		goto done;

#ifndef PROFILE
	/* Remove "wpath cpath proc exec sendfd" promises. */
	if (pledge("stdio rpath flock unveil", NULL) == -1)
		err(1, "pledge");
#endif
	error = apply_unveil(NULL, 0, got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	if (argc >= 1) {
		error = get_worktree_paths_from_argv(&paths, argc, argv,
		    worktree);
		if (error)
			goto done;
		show_files = 1;
	}

	error = got_worktree_path_info_prepare(&fileindex, worktree, repo);
	if (error)
		goto done;

	error = got_object_id_str(&id_str,
	    got_worktree_get_base_commit_id(worktree));
	if (error)
		goto done;

	error = got_worktree_get_uuid(&uuidstr, worktree);
	if (error)
		goto done;

	printf("work tree: %s\n", got_worktree_get_root_path(worktree));
	printf("work tree base commit: %s\n", id_str);
	printf("work tree path prefix: %s\n",
	    got_worktree_get_path_prefix(worktree));
	printf("work tree branch reference: %s\n",
	    got_worktree_get_head_ref_name(worktree));
	printf("work tree UUID: %s\n", uuidstr);
	printf("work tree format version: %d\n",
	    got_worktree_get_format_version(worktree));
	printf("file index version: %u\n",
	    got_worktree_get_fileindex_version(fileindex));
	printf("repository: %s\n", got_worktree_get_repo_path(worktree));

	if (show_files) {
		struct got_pathlist_entry *pe;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (pe->path_len == 0)
				continue;
			/*
			 * Assume this path will fail. This will be corrected
			 * in print_path_info() in case the path does suceeed.
			 */
			pe->data = (void *)got_error(GOT_ERR_BAD_PATH);
		}
		error = got_worktree_path_info(worktree, fileindex, &paths,
		    print_path_info, &paths, check_cancelled, NULL);
		if (error)
			goto done;
		RB_FOREACH(pe, got_pathlist_head, &paths) {
			if (pe->data != NULL) {
				const struct got_error *perr;

				perr = pe->data;
				error = got_error_path(pe->path, perr->code);
				break;
			}
		}
	}
done:
	if (worktree) {
		const struct got_error *cerr;

		cerr = got_worktree_path_info_complete(fileindex, worktree);
		if (error == NULL)
			error = cerr;
		got_worktree_close(worktree);
	}
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(cwd);
	free(id_str);
	free(uuidstr);
	return error;
}
