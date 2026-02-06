/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#define _XOPEN_SOURCE_EXTENDED /* for ncurses wide-character functions */
#endif
#include <curses.h>
#include <panel.h>
#include <locale.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <limits.h>
#include <wchar.h>
#include <time.h>
#include <pthread.h>
#include <libgen.h>
#include <regex.h>
#include <sched.h>

#include "got_version.h"
#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_gotconfig.h"
#include "got_diff.h"
#include "got_opentemp.h"
#include "got_utf8.h"
#include "got_cancel.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_path.h"
#include "got_worktree.h"
#include "got_keyword.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef MAX
#define	MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif

#ifndef CTRL
#define CTRL(x)		((x) & 0x1f)
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct tog_cmd {
	const char *name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void (*cmd_usage)(int);
};

__dead static void	usage(int, int);
__dead static void	usage_log(int);
__dead static void	usage_diff(int);
__dead static void	usage_blame(int);
__dead static void	usage_tree(int);
__dead static void	usage_ref(int);

static const struct got_error*	cmd_log(int, char *[]);
static const struct got_error*	cmd_diff(int, char *[]);
static const struct got_error*	cmd_blame(int, char *[]);
static const struct got_error*	cmd_tree(int, char *[]);
static const struct got_error*	cmd_ref(int, char *[]);

static const struct tog_cmd tog_commands[] = {
	{ "log",	cmd_log,	usage_log },
	{ "diff",	cmd_diff,	usage_diff },
	{ "blame",	cmd_blame,	usage_blame },
	{ "tree",	cmd_tree,	usage_tree },
	{ "ref",	cmd_ref,	usage_ref },
};

enum tog_view_type {
	TOG_VIEW_DIFF,
	TOG_VIEW_LOG,
	TOG_VIEW_BLAME,
	TOG_VIEW_TREE,
	TOG_VIEW_REF,
	TOG_VIEW_HELP
};

/* Match _DIFF to _HELP with enum tog_view_type TOG_VIEW_* counterparts. */
enum tog_keymap_type {
	TOG_KEYMAP_KEYS = -2,
	TOG_KEYMAP_GLOBAL,
	TOG_KEYMAP_DIFF,
	TOG_KEYMAP_LOG,
	TOG_KEYMAP_BLAME,
	TOG_KEYMAP_TREE,
	TOG_KEYMAP_REF,
	TOG_KEYMAP_HELP
};

enum tog_view_mode {
	TOG_VIEW_SPLIT_NONE,
	TOG_VIEW_SPLIT_VERT,
	TOG_VIEW_SPLIT_HRZN
};

#define HSPLIT_SCALE	0.3f  /* default horizontal split scale */

#define TOG_EOF_STRING	"(END)"

struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
	int worktree_entry;
	int idx;
};
TAILQ_HEAD(commit_queue_head, commit_queue_entry);
struct commit_queue {
	int ncommits;
	struct commit_queue_head head;
};

struct tog_color {
	STAILQ_ENTRY(tog_color) entry;
	regex_t regex;
	short colorpair;
};
STAILQ_HEAD(tog_colors, tog_color);

static struct got_reflist_head tog_refs = TAILQ_HEAD_INITIALIZER(tog_refs);
static struct got_reflist_object_id_map *tog_refs_idmap;
static struct {
	struct got_object_id	*id;
	int			 idx;
	char			 marker;
} tog_base_commit;
static enum got_diff_algorithm tog_diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;

static const struct got_error *
tog_ref_cmp_by_name(void *arg, int *cmp, struct got_reference *re1,
    struct got_reference* re2)
{
	const char *name1 = got_ref_get_name(re1);
	const char *name2 = got_ref_get_name(re2);
	int isbackup1, isbackup2;

	/* Sort backup refs towards the bottom of the list. */
	isbackup1 = strncmp(name1, "refs/got/backup/", 16) == 0;
	isbackup2 = strncmp(name2, "refs/got/backup/", 16) == 0;
	if (!isbackup1 && isbackup2) {
		*cmp = -1;
		return NULL;
	} else if (isbackup1 && !isbackup2) {
		*cmp = 1;
		return NULL;
	}

	*cmp = got_path_cmp(name1, name2, strlen(name1), strlen(name2));
	return NULL;
}

static const struct got_error *
tog_load_refs(struct got_repository *repo, int sort_by_date)
{
	const struct got_error *err;

	err = got_ref_list(&tog_refs, repo, NULL, sort_by_date ?
	    got_ref_cmp_by_commit_timestamp_descending : tog_ref_cmp_by_name,
	    repo);
	if (err)
		return err;

	return got_reflist_object_id_map_create(&tog_refs_idmap, &tog_refs,
	    repo);
}

static void
tog_free_refs(void)
{
	if (tog_refs_idmap) {
		got_reflist_object_id_map_free(tog_refs_idmap);
		tog_refs_idmap = NULL;
	}
	got_ref_list_free(&tog_refs);
}

static const struct got_error *
add_color(struct tog_colors *colors, const char *pattern,
    int idx, short color)
{
	const struct got_error *err = NULL;
	struct tog_color *tc;
	int regerr = 0;

	if (idx < 1 || idx > COLOR_PAIRS - 1)
		return NULL;

	init_pair(idx, color, -1);

	tc = calloc(1, sizeof(*tc));
	if (tc == NULL)
		return got_error_from_errno("calloc");
	regerr = regcomp(&tc->regex, pattern,
	    REG_EXTENDED | REG_NOSUB | REG_NEWLINE);
	if (regerr) {
		static char regerr_msg[512];
		static char err_msg[512];
		regerror(regerr, &tc->regex, regerr_msg,
		    sizeof(regerr_msg));
		snprintf(err_msg, sizeof(err_msg), "regcomp: %s",
		    regerr_msg);
		err = got_error_msg(GOT_ERR_REGEX, err_msg);
		free(tc);
		return err;
	}
	tc->colorpair = idx;
	STAILQ_INSERT_HEAD(colors, tc, entry);
	return NULL;
}

static void
free_colors(struct tog_colors *colors)
{
	struct tog_color *tc;

	while (!STAILQ_EMPTY(colors)) {
		tc = STAILQ_FIRST(colors);
		STAILQ_REMOVE_HEAD(colors, entry);
		regfree(&tc->regex);
		free(tc);
	}
}

static struct tog_color *
get_color(struct tog_colors *colors, int colorpair)
{
	struct tog_color *tc = NULL;

	STAILQ_FOREACH(tc, colors, entry) {
		if (tc->colorpair == colorpair)
			return tc;
	}

	return NULL;
}

static int
default_color_value(const char *envvar)
{
	if (strcmp(envvar, "TOG_COLOR_DIFF_MINUS") == 0)
		return COLOR_MAGENTA;
	if (strcmp(envvar, "TOG_COLOR_DIFF_PLUS") == 0)
		return COLOR_CYAN;
	if (strcmp(envvar, "TOG_COLOR_DIFF_CHUNK_HEADER") == 0)
		return COLOR_YELLOW;
	if (strcmp(envvar, "TOG_COLOR_DIFF_META") == 0)
		return COLOR_GREEN;
	if (strcmp(envvar, "TOG_COLOR_TREE_SUBMODULE") == 0)
		return COLOR_MAGENTA;
	if (strcmp(envvar, "TOG_COLOR_TREE_SYMLINK") == 0)
		return COLOR_MAGENTA;
	if (strcmp(envvar, "TOG_COLOR_TREE_DIRECTORY") == 0)
		return COLOR_CYAN;
	if (strcmp(envvar, "TOG_COLOR_TREE_EXECUTABLE") == 0)
		return COLOR_GREEN;
	if (strcmp(envvar, "TOG_COLOR_COMMIT") == 0)
		return COLOR_GREEN;
	if (strcmp(envvar, "TOG_COLOR_AUTHOR") == 0)
		return COLOR_CYAN;
	if (strcmp(envvar, "TOG_COLOR_DATE") == 0)
		return COLOR_YELLOW;
	if (strcmp(envvar, "TOG_COLOR_REFS_HEADS") == 0)
		return COLOR_GREEN;
	if (strcmp(envvar, "TOG_COLOR_REFS_TAGS") == 0)
		return COLOR_MAGENTA;
	if (strcmp(envvar, "TOG_COLOR_REFS_REMOTES") == 0)
		return COLOR_YELLOW;
	if (strcmp(envvar, "TOG_COLOR_REFS_BACKUP") == 0)
		return COLOR_CYAN;

	return -1;
}

static int
get_color_value(const char *envvar)
{
	const char *val = getenv(envvar);

	if (val == NULL)
		return default_color_value(envvar);

	if (strcasecmp(val, "black") == 0)
		return COLOR_BLACK;
	if (strcasecmp(val, "red") == 0)
		return COLOR_RED;
	if (strcasecmp(val, "green") == 0)
		return COLOR_GREEN;
	if (strcasecmp(val, "yellow") == 0)
		return COLOR_YELLOW;
	if (strcasecmp(val, "blue") == 0)
		return COLOR_BLUE;
	if (strcasecmp(val, "magenta") == 0)
		return COLOR_MAGENTA;
	if (strcasecmp(val, "cyan") == 0)
		return COLOR_CYAN;
	if (strcasecmp(val, "white") == 0)
		return COLOR_WHITE;
	if (strcasecmp(val, "default") == 0)
		return -1;

	return default_color_value(envvar);
}

struct diff_worktree_arg {
	struct got_repository		 *repo;
	struct got_worktree		 *worktree;
	struct got_diff_line		**lines;
	struct got_diffstat_cb_arg	 *diffstat;
	FILE				 *outfile;
	FILE				 *f1;
	FILE				 *f2;
	const char			 *id_str;
	size_t				 *nlines;
	int				  diff_context;
	int				  header_shown;
	int				  diff_staged;
	int				  ignore_whitespace;
	int				  force_text_diff;
	enum got_diff_algorithm		  diff_algo;
};

struct tog_diff_view_state {
	struct got_object_id *id1, *id2;
	const char *label1, *label2;
	const char *worktree_root;
	char *action;
	FILE *f, *f1, *f2;
	int fd1, fd2;
	int lineno;
	int first_displayed_line;
	int last_displayed_line;
	int eof;
	int diff_context;
	int ignore_whitespace;
	int force_text_diff;
	int diff_worktree;
	int diff_staged;
	struct got_repository *repo;
	struct got_pathlist_head *paths;
	struct got_diff_line *lines;
	size_t nlines;
	int matched_line;
	int selected_line;

	/* passed from log or blame view; may be NULL */
	struct tog_view *parent_view;
};

#define TOG_WORKTREE_CHANGES_LOCAL_MSG		"work tree changes"
#define TOG_WORKTREE_CHANGES_STAGED_MSG		"staged work tree changes"

#define TOG_WORKTREE_CHANGES_LOCAL	(1 << 0)
#define TOG_WORKTREE_CHANGES_STAGED	(1 << 1)
#define TOG_WORKTREE_CHANGES_ALL	\
	(TOG_WORKTREE_CHANGES_LOCAL | TOG_WORKTREE_CHANGES_STAGED)

struct tog_worktree_ctx {
	char		*wt_ref;
	char		*wt_author;
	char		*wt_root;
	int		 wt_state;
	int		 active;
};

pthread_mutex_t tog_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t tog_thread_error;

struct tog_log_thread_args {
	pthread_cond_t need_commits;
	pthread_cond_t commit_loaded;
	int commits_needed;
	int load_all;
	struct got_commit_graph *graph;
	struct commit_queue *real_commits;
	struct tog_worktree_ctx wctx;
	const char *in_repo_path;
	struct got_object_id *start_id;
	struct got_repository *repo;
	int *pack_fds;
	int log_complete;
	pthread_cond_t log_loaded;
	sig_atomic_t *quit;
	struct commit_queue_entry **first_displayed_entry;
	struct commit_queue_entry **last_displayed_entry;
	struct commit_queue_entry **selected_entry;
	int *selected;
	int *searching;
	int *search_next_done;
	regex_t *regex;
	int *limiting;
	int limit_match;
	regex_t *limit_regex;
	struct commit_queue *limit_commits;
	struct got_worktree *worktree;
	int need_commit_marker;
	int need_wt_status;
	int *view_nlines;
};

struct tog_log_view_state {
	struct commit_queue *commits;
	struct commit_queue_entry *first_displayed_entry;
	struct commit_queue_entry *last_displayed_entry;
	struct commit_queue_entry *selected_entry;
	struct commit_queue_entry *marked_entry;
	struct commit_queue real_commits;
	int selected;
	char *in_repo_path;
	char *head_ref_name;
	int log_branches;
	struct got_repository *repo;
	struct got_object_id *start_id;
	sig_atomic_t quit;
	pthread_t thread;
	struct tog_log_thread_args thread_args;
	struct commit_queue_entry *matched_entry;
	struct commit_queue_entry *search_entry;
	struct tog_colors colors;
	int use_committer;
	int limit_view;
	regex_t limit_regex;
	struct commit_queue limit_commits;
};

#define TOG_COLOR_DIFF_MINUS		1
#define TOG_COLOR_DIFF_PLUS		2
#define TOG_COLOR_DIFF_CHUNK_HEADER	3
#define TOG_COLOR_DIFF_META		4
#define TOG_COLOR_TREE_SUBMODULE	5
#define TOG_COLOR_TREE_SYMLINK		6
#define TOG_COLOR_TREE_DIRECTORY	7
#define TOG_COLOR_TREE_EXECUTABLE	8
#define TOG_COLOR_COMMIT		9
#define TOG_COLOR_AUTHOR		10
#define TOG_COLOR_DATE			11
#define TOG_COLOR_REFS_HEADS		12
#define TOG_COLOR_REFS_TAGS		13
#define TOG_COLOR_REFS_REMOTES		14
#define TOG_COLOR_REFS_BACKUP		15

struct tog_blame_cb_args {
	struct tog_blame_line *lines; /* one per line */
	int nlines;

	struct tog_view *view;
	struct got_object_id *commit_id;
	int *quit;
};

struct tog_blame_thread_args {
	const char *path;
	struct got_repository *repo;
	struct tog_blame_cb_args *cb_args;
	int *complete;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
	pthread_cond_t blame_complete;
};

struct tog_blame {
	FILE *f;
	off_t filesize;
	struct tog_blame_line *lines;
	int nlines;
	off_t *line_offsets;
	pthread_t thread;
	struct tog_blame_thread_args thread_args;
	struct tog_blame_cb_args cb_args;
	const char *path;
	int *pack_fds;
};

struct tog_blame_view_state {
	int first_displayed_line;
	int last_displayed_line;
	int selected_line;
	int last_diffed_line;
	int blame_complete;
	int eof;
	int done;
	struct got_object_id_queue blamed_commits;
	struct got_object_qid *blamed_commit;
	char *path;
	struct got_repository *repo;
	struct got_object_id *commit_id;
	struct got_object_id *id_to_log;
	struct tog_blame blame;
	int matched_line;
	struct tog_colors colors;
};

struct tog_parent_tree {
	TAILQ_ENTRY(tog_parent_tree) entry;
	struct got_tree_object *tree;
	struct got_tree_entry *first_displayed_entry;
	struct got_tree_entry *selected_entry;
	int selected;
};

TAILQ_HEAD(tog_parent_trees, tog_parent_tree);

struct tog_tree_view_state {
	char *tree_label;
	struct got_object_id *commit_id;/* commit which this tree belongs to */
	struct got_tree_object *root;	/* the commit's root tree entry */
	struct got_tree_object *tree;	/* currently displayed (sub-)tree */
	struct got_tree_entry *first_displayed_entry;
	struct got_tree_entry *last_displayed_entry;
	struct got_tree_entry *selected_entry;
	int ndisplayed, selected, show_ids;
	struct tog_parent_trees parents; /* parent trees of current sub-tree */
	char *head_ref_name;
	struct got_repository *repo;
	struct got_tree_entry *matched_entry;
	struct tog_colors colors;
};

struct tog_reflist_entry {
	TAILQ_ENTRY(tog_reflist_entry) entry;
	struct got_reference *ref;
	int idx;
};

TAILQ_HEAD(tog_reflist_head, tog_reflist_entry);

struct tog_ref_view_state {
	struct tog_reflist_head refs;
	struct tog_reflist_entry *first_displayed_entry;
	struct tog_reflist_entry *last_displayed_entry;
	struct tog_reflist_entry *selected_entry;
	int nrefs, ndisplayed, selected, show_date, show_ids, sort_by_date;
	struct got_repository *repo;
	struct tog_reflist_entry *matched_entry;
	struct tog_colors colors;
};

struct tog_help_view_state {
	FILE			*f;
	off_t			*line_offsets;
	size_t			 nlines;
	int			 lineno;
	int			 first_displayed_line;
	int			 last_displayed_line;
	int			 eof;
	int			 matched_line;
	int			 selected_line;
	int			 all;
	enum tog_keymap_type	 type;
};

#define GENERATE_HELP \
	KEYMAP_("Global", TOG_KEYMAP_GLOBAL), \
	KEY_("H F1", "Open view-specific help (double tap for all help)"), \
	KEY_("k C-p Up", "Move cursor or page up one line"), \
	KEY_("j C-n Down", "Move cursor or page down one line"), \
	KEY_("C-b b PgUp", "Scroll the view up one page"), \
	KEY_("C-f f PgDn Space", "Scroll the view down one page"), \
	KEY_("C-u u", "Scroll the view up one half page"), \
	KEY_("C-d d", "Scroll the view down one half page"), \
	KEY_("g", "Go to line N (default: first line)"), \
	KEY_("Home =", "Go to the first line"), \
	KEY_("G", "Go to line N (default: last line)"), \
	KEY_("End *", "Go to the last line"), \
	KEY_("l Right", "Scroll the view right"), \
	KEY_("h Left", "Scroll the view left"), \
	KEY_("$", "Scroll view to the rightmost position"), \
	KEY_("0", "Scroll view to the leftmost position"), \
	KEY_("-", "Decrease size of the focussed split"), \
	KEY_("+", "Increase size of the focussed split"), \
	KEY_("Tab", "Switch focus between views"), \
	KEY_("F", "Toggle fullscreen mode"), \
	KEY_("S", "Switch split-screen layout"), \
	KEY_("/", "Open prompt to enter search term"), \
	KEY_("n", "Find next line/token matching the current search term"), \
	KEY_("N", "Find previous line/token matching the current search term"),\
	KEY_("q", "Quit the focussed view; Quit help screen"), \
	KEY_("Q", "Quit tog"), \
	\
	KEYMAP_("Log view", TOG_KEYMAP_LOG), \
	KEY_("< ,", "Move cursor up one commit"), \
	KEY_("> .", "Move cursor down one commit"), \
	KEY_("Enter", "Open diff view of the selected commit"), \
	KEY_("B", "Reload the log view and toggle display of merged commits"), \
	KEY_("R", "Open ref view of all repository references"), \
	KEY_("T", "Display tree view of the repository from the selected" \
	    " commit"), \
	KEY_("m", "Mark or unmark the selected entry for diffing with the " \
	    "next selected commit"), \
	KEY_("@", "Toggle between displaying author and committer name"), \
	KEY_("&", "Open prompt to enter term to limit commits displayed"), \
	KEY_("C-g Backspace", "Cancel current search or log operation"), \
	KEY_("C-l", "Reload the log view with new repository commits or " \
	    "work tree changes"), \
	\
	KEYMAP_("Diff view", TOG_KEYMAP_DIFF), \
	KEY_("K < ,", "Display diff of next line in the file/log entry"), \
	KEY_("J > .", "Display diff of previous line in the file/log entry"), \
	KEY_("A", "Toggle between Myers and Patience diff algorithm"), \
	KEY_("a", "Toggle treatment of file as ASCII irrespective of binary" \
	    " data"), \
	KEY_("p", "Write diff to a patch file in /tmp"), \
	KEY_("(", "Go to the previous file in the diff"), \
	KEY_(")", "Go to the next file in the diff"), \
	KEY_("{", "Go to the previous hunk in the diff"), \
	KEY_("}", "Go to the next hunk in the diff"), \
	KEY_("[", "Decrease the number of context lines"), \
	KEY_("]", "Increase the number of context lines"), \
	KEY_("w", "Toggle ignore whitespace-only changes in the diff"), \
	\
	KEYMAP_("Blame view", TOG_KEYMAP_BLAME), \
	KEY_("Enter", "Display diff view of the selected line's commit"), \
	KEY_("A", "Toggle diff algorithm between Myers and Patience"), \
	KEY_("L", "Open log view for the currently selected annotated line"), \
	KEY_("C", "Reload view with the previously blamed commit"), \
	KEY_("c", "Reload view with the version of the file found in the" \
	    " selected line's commit"), \
	KEY_("p", "Reload view with the version of the file found in the" \
	    " selected line's parent commit"), \
	\
	KEYMAP_("Tree view", TOG_KEYMAP_TREE), \
	KEY_("Enter", "Enter selected directory or open blame view of the" \
	    " selected file"), \
	KEY_("L", "Open log view for the selected entry"), \
	KEY_("R", "Open ref view of all repository references"), \
	KEY_("i", "Show object IDs for all tree entries"), \
	KEY_("Backspace", "Return to the parent directory"), \
	\
	KEYMAP_("Ref view", TOG_KEYMAP_REF), \
	KEY_("Enter", "Display log view of the selected reference"), \
	KEY_("T", "Display tree view of the selected reference"), \
	KEY_("i", "Toggle display of IDs for all non-symbolic references"), \
	KEY_("m", "Toggle display of last modified date for each reference"), \
	KEY_("o", "Toggle reference sort order (name -> timestamp)"), \
	KEY_("C-l", "Reload view with all repository references")

struct tog_key_map {
	const char		*keys;
	const char		*info;
	enum tog_keymap_type	 type;
};

/* curses io for tog regress */
struct tog_io {
	FILE	*cin;
	FILE	*cout;
	FILE	*f;
	FILE	*sdump;
	char	*input_str;
	int	 wait_for_ui;
} tog_io;
static int using_mock_io;

#define TOG_KEY_SCRDUMP	SHRT_MIN

/*
 * We implement two types of views: parent views and child views.
 *
 * The 'Tab' key switches focus between a parent view and its child view.
 * Child views are shown side-by-side to their parent view, provided
 * there is enough screen estate.
 *
 * When a new view is opened from within a parent view, this new view
 * becomes a child view of the parent view, replacing any existing child.
 *
 * When a new view is opened from within a child view, this new view
 * becomes a parent view which will obscure the views below until the
 * user quits the new parent view by typing 'q'.
 *
 * This list of views contains parent views only.
 * Child views are only pointed to by their parent view.
 */
TAILQ_HEAD(tog_view_list_head, tog_view);

struct tog_view {
	TAILQ_ENTRY(tog_view) entry;
	WINDOW *window;
	PANEL *panel;
	int nlines, ncols, begin_y, begin_x; /* based on split height/width */
	int resized_y, resized_x; /* begin_y/x based on user resizing */
	int maxx, x; /* max column and current start column */
	int lines, cols; /* copies of LINES and COLS */
	int nscrolled, offset; /* lines scrolled and hsplit line offset */
	int gline, hiline; /* navigate to and highlight this nG line */
	int ch, count; /* current keymap and count prefix */
	int resized; /* set when in a resize event */
	int focussed; /* Only set on one parent or child view at a time. */
	int dying;
	struct tog_view *parent;
	struct tog_view *child;

	/*
	 * This flag is initially set on parent views when a new child view
	 * is created. It gets toggled when the 'Tab' key switches focus
	 * between parent and child.
	 * The flag indicates whether focus should be passed on to our child
	 * view if this parent view gets picked for focus after another parent
	 * view was closed. This prevents child views from losing focus in such
	 * situations.
	 */
	int focus_child;

	enum tog_view_mode mode;
	/* type-specific state */
	enum tog_view_type type;
	union {
		struct tog_diff_view_state diff;
		struct tog_log_view_state log;
		struct tog_blame_view_state blame;
		struct tog_tree_view_state tree;
		struct tog_ref_view_state ref;
		struct tog_help_view_state help;
	} state;

	const struct got_error *(*show)(struct tog_view *);
	const struct got_error *(*input)(struct tog_view **,
	    struct tog_view *, int);
	const struct got_error *(*reset)(struct tog_view *);
	const struct got_error *(*resize)(struct tog_view *, int);
	const struct got_error *(*close)(struct tog_view *);

	const struct got_error *(*search_start)(struct tog_view *);
	const struct got_error *(*search_next)(struct tog_view *);
	void (*search_setup)(struct tog_view *, FILE **, off_t **, size_t *,
	    int **, int **, int **, int **);
	int search_started;
	int searching;
#define TOG_SEARCH_FORWARD	1
#define TOG_SEARCH_BACKWARD	2
	int search_next_done;
#define TOG_SEARCH_HAVE_MORE	1
#define TOG_SEARCH_NO_MORE	2
#define TOG_SEARCH_HAVE_NONE	3
	regex_t regex;
	regmatch_t regmatch;
	const char *action;
};

static const struct got_error *open_diff_view(struct tog_view *,
    struct got_object_id *, struct got_object_id *, const char *, const char *,
    int, int, int, int, int, const char *, struct tog_view *,
    struct got_repository *, struct got_pathlist_head *);
static const struct got_error *show_diff_view(struct tog_view *);
static const struct got_error *input_diff_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *reset_diff_view(struct tog_view *);
static const struct got_error* close_diff_view(struct tog_view *);
static const struct got_error *search_start_diff_view(struct tog_view *);
static void search_setup_diff_view(struct tog_view *, FILE **, off_t **,
    size_t *, int **, int **, int **, int **);
static const struct got_error *search_next_view_match(struct tog_view *);

static const struct got_error *open_log_view(struct tog_view *,
    struct got_object_id *, struct got_repository *,
    const char *, const char *, int, struct got_worktree *);
static const struct got_error * show_log_view(struct tog_view *);
static const struct got_error *input_log_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *resize_log_view(struct tog_view *, int);
static const struct got_error *close_log_view(struct tog_view *);
static const struct got_error *search_start_log_view(struct tog_view *);
static const struct got_error *search_next_log_view(struct tog_view *);

static const struct got_error *open_blame_view(struct tog_view *, char *,
    struct got_object_id *, struct got_repository *);
static const struct got_error *show_blame_view(struct tog_view *);
static const struct got_error *input_blame_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *reset_blame_view(struct tog_view *);
static const struct got_error *close_blame_view(struct tog_view *);
static const struct got_error *search_start_blame_view(struct tog_view *);
static void search_setup_blame_view(struct tog_view *, FILE **, off_t **,
    size_t *, int **, int **, int **, int **);

static const struct got_error *open_tree_view(struct tog_view *,
    struct got_object_id *, const char *, struct got_repository *);
static const struct got_error *show_tree_view(struct tog_view *);
static const struct got_error *input_tree_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *close_tree_view(struct tog_view *);
static const struct got_error *search_start_tree_view(struct tog_view *);
static const struct got_error *search_next_tree_view(struct tog_view *);

static const struct got_error *open_ref_view(struct tog_view *,
    struct got_repository *);
static const struct got_error *show_ref_view(struct tog_view *);
static const struct got_error *input_ref_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *close_ref_view(struct tog_view *);
static const struct got_error *search_start_ref_view(struct tog_view *);
static const struct got_error *search_next_ref_view(struct tog_view *);

static const struct got_error *open_help_view(struct tog_view *,
    struct tog_view *);
static const struct got_error *show_help_view(struct tog_view *);
static const struct got_error *input_help_view(struct tog_view **,
    struct tog_view *, int);
static const struct got_error *reset_help_view(struct tog_view *);
static const struct got_error* close_help_view(struct tog_view *);
static const struct got_error *search_start_help_view(struct tog_view *);
static void search_setup_help_view(struct tog_view *, FILE **, off_t **,
    size_t *, int **, int **, int **, int **);

static volatile sig_atomic_t tog_sigwinch_received;
static volatile sig_atomic_t tog_sigpipe_received;
static volatile sig_atomic_t tog_sigcont_received;
static volatile sig_atomic_t tog_sigint_received;
static volatile sig_atomic_t tog_sigterm_received;

static void
tog_sigwinch(int signo)
{
	tog_sigwinch_received = 1;
}

static void
tog_sigpipe(int signo)
{
	tog_sigpipe_received = 1;
}

static void
tog_sigcont(int signo)
{
	tog_sigcont_received = 1;
}

static void
tog_sigint(int signo)
{
	tog_sigint_received = 1;
}

static void
tog_sigterm(int signo)
{
	tog_sigterm_received = 1;
}

static int
tog_fatal_signal_received(void)
{
	return (tog_sigpipe_received ||
	    tog_sigint_received || tog_sigterm_received);
}

static const struct got_error *
view_close(struct tog_view *view)
{
	const struct got_error *err = NULL, *child_err = NULL;

	if (view->child) {
		child_err = view_close(view->child);
		view->child = NULL;
	}
	if (view->close)
		err = view->close(view);
	if (view->panel) {
		del_panel(view->panel);
		view->panel = NULL;
	}
	if (view->window) {
		delwin(view->window);
		view->window = NULL;
	}
	free(view);
	return err ? err : child_err;
}

static struct tog_view *
view_open(int nlines, int ncols, int begin_y, int begin_x,
    enum tog_view_type type)
{
	struct tog_view *view = calloc(1, sizeof(*view));

	if (view == NULL)
		return NULL;

	view->type = type;
	view->lines = LINES;
	view->cols = COLS;
	view->nlines = nlines ? nlines : LINES - begin_y;
	view->ncols = ncols ? ncols : COLS - begin_x;
	view->begin_y = begin_y;
	view->begin_x = begin_x;
	view->window = newwin(nlines, ncols, begin_y, begin_x);
	if (view->window == NULL) {
		view_close(view);
		return NULL;
	}
	view->panel = new_panel(view->window);
	if (view->panel == NULL ||
	    set_panel_userptr(view->panel, view) != OK) {
		view_close(view);
		return NULL;
	}

	keypad(view->window, TRUE);
	return view;
}

static int
view_split_begin_x(int begin_x)
{
	if (begin_x > 0 || COLS < 120)
		return 0;
	return (COLS - MAX(COLS / 2, 80));
}

/* XXX Stub till we decide what to do. */
static int
view_split_begin_y(int lines)
{
	return lines * HSPLIT_SCALE;
}

static const struct got_error *view_resize(struct tog_view *);

static const struct got_error *
view_splitscreen(struct tog_view *view)
{
	const struct got_error *err = NULL;

	if (!view->resized && view->mode == TOG_VIEW_SPLIT_HRZN) {
		if (view->resized_y && view->resized_y < view->lines)
			view->begin_y = view->resized_y;
		else
			view->begin_y = view_split_begin_y(view->nlines);
		view->begin_x = 0;
	} else if (!view->resized) {
		if (view->resized_x && view->resized_x < view->cols - 1 &&
		    view->cols > 119)
			view->begin_x = view->resized_x;
		else
			view->begin_x = view_split_begin_x(0);
		view->begin_y = 0;
	}
	view->nlines = LINES - view->begin_y;
	view->ncols = COLS - view->begin_x;
	view->lines = LINES;
	view->cols = COLS;
	err = view_resize(view);
	if (err)
		return err;

	if (view->parent && view->mode == TOG_VIEW_SPLIT_HRZN)
		view->parent->nlines = view->begin_y;

	if (mvwin(view->window, view->begin_y, view->begin_x) == ERR)
		return got_error_from_errno("mvwin");

	return NULL;
}

static const struct got_error *
view_fullscreen(struct tog_view *view)
{
	const struct got_error *err = NULL;

	view->begin_x = 0;
	view->begin_y = view->resized ? view->begin_y : 0;
	view->nlines = view->resized ? view->nlines : LINES;
	view->ncols = COLS;
	view->lines = LINES;
	view->cols = COLS;
	err = view_resize(view);
	if (err)
		return err;

	if (mvwin(view->window, view->begin_y, view->begin_x) == ERR)
		return got_error_from_errno("mvwin");

	return NULL;
}

static int
view_is_parent_view(struct tog_view *view)
{
	return view->parent == NULL;
}

static int
view_is_splitscreen(struct tog_view *view)
{
	return view->begin_x > 0 || view->begin_y > 0;
}

static int
view_is_fullscreen(struct tog_view *view)
{
	return view->nlines == LINES && view->ncols == COLS;
}

static int
view_is_hsplit_top(struct tog_view *view)
{
	return view->mode == TOG_VIEW_SPLIT_HRZN && view->child &&
	    view_is_splitscreen(view->child);
}

static void
view_border(struct tog_view *view)
{
	PANEL *panel;
	const struct tog_view *view_above;

	if (view->parent)
		return view_border(view->parent);

	panel = panel_above(view->panel);
	if (panel == NULL)
		return;

	view_above = panel_userptr(panel);
	if (view->mode == TOG_VIEW_SPLIT_HRZN)
		mvwhline(view->window, view_above->begin_y - 1,
		    view->begin_x, ACS_HLINE, view->ncols);
	else
		mvwvline(view->window, view->begin_y, view_above->begin_x - 1,
		    ACS_VLINE, view->nlines);
}

static const struct got_error *view_init_hsplit(struct tog_view *, int);
static const struct got_error *request_log_commits(struct tog_view *);
static const struct got_error *offset_selection_down(struct tog_view *);
static void offset_selection_up(struct tog_view *);
static void view_get_split(struct tog_view *, int *, int *);

static const struct got_error *
view_resize(struct tog_view *view)
{
	const struct got_error	*err = NULL;
	int			 dif, nlines, ncols;

	dif = LINES - view->lines;  /* line difference */

	if (view->lines > LINES)
		nlines = view->nlines - (view->lines - LINES);
	else
		nlines = view->nlines + (LINES - view->lines);
	if (view->cols > COLS)
		ncols = view->ncols - (view->cols - COLS);
	else
		ncols = view->ncols + (COLS - view->cols);

	if (view->child) {
		int hs = view->child->begin_y;

		if (!view_is_fullscreen(view))
			view->child->begin_x = view_split_begin_x(view->begin_x);
		if (view->mode == TOG_VIEW_SPLIT_HRZN ||
		    view->child->begin_x == 0) {
			ncols = COLS;

			view_fullscreen(view->child);
			if (view->child->focussed)
				show_panel(view->child->panel);
			else
				show_panel(view->panel);
		} else {
			ncols = view->child->begin_x;

			view_splitscreen(view->child);
			show_panel(view->child->panel);
		}
		/*
		 * XXX This is ugly and needs to be moved into the above
		 * logic but "works" for now and my attempts at moving it
		 * break either 'tab' or 'F' key maps in horizontal splits.
		 */
		if (hs) {
			err = view_splitscreen(view->child);
			if (err)
				return err;
			if (dif < 0) { /* top split decreased */
				err = offset_selection_down(view);
				if (err)
					return err;
			}
			view_border(view);
			update_panels();
			doupdate();
			show_panel(view->child->panel);
			nlines = view->nlines;
		}
	} else if (view->parent == NULL)
		ncols = COLS;

	if (view->resize && dif > 0) {
		err = view->resize(view, dif);
		if (err)
			return err;
	}

	if (wresize(view->window, nlines, ncols) == ERR)
		return got_error_from_errno("wresize");
	if (replace_panel(view->panel, view->window) == ERR)
		return got_error_from_errno("replace_panel");
	wclear(view->window);

	view->nlines = nlines;
	view->ncols = ncols;
	view->lines = LINES;
	view->cols = COLS;

	return NULL;
}

static const struct got_error *
resize_log_view(struct tog_view *view, int increase)
{
	struct tog_log_view_state	*s = &view->state.log;
	const struct got_error		*err = NULL;
	int				 n = 0;

	if (s->selected_entry)
		n = s->selected_entry->idx + view->lines - s->selected;

	/*
	 * Request commits to account for the increased
	 * height so we have enough to populate the view.
	 */
	if (s->commits->ncommits < n) {
		view->nscrolled = n - s->commits->ncommits + increase + 1;
		err = request_log_commits(view);
	}

	return err;
}

static void
view_adjust_offset(struct tog_view *view, int n)
{
	if (n == 0)
		return;

	if (view->parent && view->parent->offset) {
		if (view->parent->offset + n >= 0)
			view->parent->offset += n;
		else
			view->parent->offset = 0;
	} else if (view->offset) {
		if (view->offset - n >= 0)
			view->offset -= n;
		else
			view->offset = 0;
	}
}

static const struct got_error *
view_resize_split(struct tog_view *view, int resize)
{
	const struct got_error	*err = NULL;
	struct tog_view		*v = NULL;

	if (view->parent)
		v = view->parent;
	else
		v = view;

	if (!v->child || !view_is_splitscreen(v->child))
		return NULL;

	v->resized = v->child->resized = resize;  /* lock for resize event */

	if (view->mode == TOG_VIEW_SPLIT_HRZN) {
		if (v->child->resized_y)
			v->child->begin_y = v->child->resized_y;
		if (view->parent)
			v->child->begin_y -= resize;
		else
			v->child->begin_y += resize;
		if (v->child->begin_y < 3) {
			view->count = 0;
			v->child->begin_y = 3;
		} else if (v->child->begin_y > LINES - 1) {
			view->count = 0;
			v->child->begin_y = LINES - 1;
		}
		v->ncols = COLS;
		v->child->ncols = COLS;
		view_adjust_offset(view, resize);
		err = view_init_hsplit(v, v->child->begin_y);
		if (err)
			return err;
		v->child->resized_y = v->child->begin_y;
	} else {
		if (v->child->resized_x)
			v->child->begin_x = v->child->resized_x;
		if (view->parent)
			v->child->begin_x -= resize;
		else
			v->child->begin_x += resize;
		if (v->child->begin_x < 11) {
			view->count = 0;
			v->child->begin_x = 11;
		} else if (v->child->begin_x > COLS - 1) {
			view->count = 0;
			v->child->begin_x = COLS - 1;
		}
		v->child->resized_x = v->child->begin_x;
	}

	v->child->mode = v->mode;
	v->child->nlines = v->lines - v->child->begin_y;
	v->child->ncols = v->cols - v->child->begin_x;
	v->focus_child = 1;

	err = view_fullscreen(v);
	if (err)
		return err;
	err = view_splitscreen(v->child);
	if (err)
		return err;

	if (v->mode == TOG_VIEW_SPLIT_HRZN) {
		err = offset_selection_down(v->child);
		if (err)
			return err;
	}

	if (v->resize)
		err = v->resize(v, 0);
	else if (v->child->resize)
		err = v->child->resize(v->child, 0);

	v->resized = v->child->resized = 0;

	return err;
}

static void
view_transfer_size(struct tog_view *dst, struct tog_view *src)
{
	struct tog_view *v = src->child ? src->child : src;

	dst->resized_x = v->resized_x;
	dst->resized_y = v->resized_y;
}

static const struct got_error *
view_close_child(struct tog_view *view)
{
	const struct got_error *err = NULL;

	if (view->child == NULL)
		return NULL;

	err = view_close(view->child);
	view->child = NULL;
	return err;
}

static const struct got_error *
view_set_child(struct tog_view *view, struct tog_view *child)
{
	const struct got_error *err = NULL;

	view->child = child;
	child->parent = view;

	err = view_resize(view);
	if (err)
		return err;

	if (view->child->resized_x || view->child->resized_y)
		err = view_resize_split(view, 0);

	return err;
}

static const struct got_error *view_dispatch_request(struct tog_view **,
    struct tog_view *, enum tog_view_type, int, int);

static const struct got_error *
view_request_new(struct tog_view **requested, struct tog_view *view,
    enum tog_view_type request)
{
	struct tog_view		*new_view = NULL;
	const struct got_error	*err;
	int			 y = 0, x = 0;

	*requested = NULL;

	if (view_is_parent_view(view) && request != TOG_VIEW_HELP)
		view_get_split(view, &y, &x);

	err = view_dispatch_request(&new_view, view, request, y, x);
	if (err) {
		/*
		 * The ref view expects its selected entry to resolve to
		 * a commit object id to open either a log or tree view.
		 */
		if (err->code != GOT_ERR_OBJ_TYPE)
			return err;
		view->action = "commit reference required";
		return NULL;
	}

	if (view_is_parent_view(view) && view->mode == TOG_VIEW_SPLIT_HRZN &&
	    request != TOG_VIEW_HELP) {
		err = view_init_hsplit(view, y);
		if (err)
			return err;
	}

	view->focussed = 0;
	new_view->focussed = 1;
	new_view->mode = view->mode;
	new_view->nlines = request == TOG_VIEW_HELP ?
	    view->lines : view->lines - y;

	if (view_is_parent_view(view) && request != TOG_VIEW_HELP) {
		view_transfer_size(new_view, view);
		err = view_close_child(view);
		if (err)
			return err;
		err = view_set_child(view, new_view);
		if (err)
			return err;
		view->focus_child = 1;
	} else
		*requested = new_view;

	return NULL;
}

static void
tog_resizeterm(void)
{
	int cols, lines;
	struct winsize size;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) < 0) {
		cols = 80;     /* Default */
		lines = 24;
	} else {
		cols = size.ws_col;
		lines = size.ws_row;
	}
	resize_term(lines, cols);
}

static const struct got_error *
view_search_start(struct tog_view *view, int fast_refresh)
{
	const struct got_error *err = NULL;
	struct tog_view *v = view;
	char pattern[1024];
	int ret;

	if (view->search_started) {
		regfree(&view->regex);
		view->searching = 0;
		memset(&view->regmatch, 0, sizeof(view->regmatch));
	}
	view->search_started = 0;

	if (view->nlines < 1)
		return NULL;

	if (view_is_hsplit_top(view))
		v = view->child;
	else if (view->mode == TOG_VIEW_SPLIT_VERT && view->parent)
		v = view->parent;

	if (tog_io.input_str != NULL) {
		if (strlcpy(pattern, tog_io.input_str, sizeof(pattern)) >=
		    sizeof(pattern))
			return got_error(GOT_ERR_NO_SPACE);
	} else {
		mvwaddstr(v->window, v->nlines - 1, 0, "/");
		wclrtoeol(v->window);
		nodelay(v->window, FALSE);  /* block for search term input */
		nocbreak();
		echo();
		ret = wgetnstr(v->window, pattern, sizeof(pattern));
		wrefresh(v->window);
		cbreak();
		noecho();
		nodelay(v->window, TRUE);
		if (!fast_refresh && !using_mock_io)
			halfdelay(10);
		if (ret == ERR)
			return NULL;
	}

	if (regcomp(&view->regex, pattern, REG_EXTENDED | REG_NEWLINE) == 0) {
		err = view->search_start(view);
		if (err) {
			regfree(&view->regex);
			return err;
		}
		view->search_started = 1;
		view->searching = TOG_SEARCH_FORWARD;
		view->search_next_done = 0;
		view->search_next(view);
	}

	return NULL;
}

/* Switch split mode. If view is a parent or child, draw the new splitscreen. */
static const struct got_error *
switch_split(struct tog_view *view)
{
	const struct got_error	*err = NULL;
	struct tog_view		*v = NULL;

	if (view->parent)
		v = view->parent;
	else
		v = view;

	if (v->mode == TOG_VIEW_SPLIT_HRZN)
		v->mode = TOG_VIEW_SPLIT_VERT;
	else
		v->mode = TOG_VIEW_SPLIT_HRZN;

	if (!v->child)
		return NULL;
	else if (v->mode == TOG_VIEW_SPLIT_VERT && v->cols < 120)
		v->mode = TOG_VIEW_SPLIT_NONE;

	view_get_split(v, &v->child->begin_y, &v->child->begin_x);
	if (v->mode == TOG_VIEW_SPLIT_HRZN && v->child->resized_y)
		v->child->begin_y = v->child->resized_y;
	else if (v->mode == TOG_VIEW_SPLIT_VERT && v->child->resized_x)
		v->child->begin_x = v->child->resized_x;


	if (v->mode == TOG_VIEW_SPLIT_HRZN) {
		v->ncols = COLS;
		v->child->ncols = COLS;
		v->child->nscrolled = LINES - v->child->nlines;

		err = view_init_hsplit(v, v->child->begin_y);
		if (err)
			return err;
	}
	v->child->mode = v->mode;
	v->child->nlines = v->lines - v->child->begin_y;
	v->focus_child = 1;

	err = view_fullscreen(v);
	if (err)
		return err;
	err = view_splitscreen(v->child);
	if (err)
		return err;

	if (v->mode == TOG_VIEW_SPLIT_NONE)
		v->mode = TOG_VIEW_SPLIT_VERT;
	if (v->mode == TOG_VIEW_SPLIT_HRZN) {
		err = offset_selection_down(v);
		if (err)
			return err;
		err = offset_selection_down(v->child);
		if (err)
			return err;
	} else {
		offset_selection_up(v);
		offset_selection_up(v->child);
	}
	if (v->resize)
		err = v->resize(v, 0);
	else if (v->child->resize)
		err = v->child->resize(v->child, 0);

	return err;
}

/*
 * Strip trailing whitespace from str starting at byte *n;
 * if *n < 0, use strlen(str). Return new str length in *n.
 */
static void
strip_trailing_ws(char *str, int *n)
{
	size_t x = *n;

	if (str == NULL || *str == '\0')
		return;

	if (x < 0)
		x = strlen(str);

	while (x-- > 0 && isspace((unsigned char)str[x]))
		str[x] = '\0';

	*n = x + 1;
}

/*
 * Extract visible substring of line y from the curses screen
 * and strip trailing whitespace. If vline is set, overwrite
 * line[vline] with '|' because the ACS_VLINE character is
 * written out as 'x'. Write the line to file f.
 */
static const struct got_error *
view_write_line(FILE *f, int y, int vline)
{
	char	line[COLS * MB_LEN_MAX];  /* allow for multibyte chars */
	int	r, w;

	r = mvwinnstr(curscr, y, 0, line, sizeof(line));
	if (r == ERR)
		return got_error_fmt(GOT_ERR_RANGE,
		    "failed to extract line %d", y);

	/*
	 * In some views, lines are padded with blanks to COLS width.
	 * Strip them so we can diff without the -b flag when testing.
	 */
	strip_trailing_ws(line, &r);

	if (vline > 0)
		line[vline] = '|';

	w = fprintf(f, "%s\n", line);
	if (w != r + 1)		/* \n */
		return got_ferror(f, GOT_ERR_IO);

	return NULL;
}

/*
 * Capture the visible curses screen by writing each line to the
 * file at the path set via the TOG_SCR_DUMP environment variable.
 */
static const struct got_error *
screendump(struct tog_view *view)
{
	const struct got_error	*err;
	int			 i;

	err = got_opentemp_truncate(tog_io.sdump);
	if (err)
		return err;

	if ((view->child && view->child->begin_x) ||
	    (view->parent && view->begin_x)) {
		int ncols = view->child ? view->ncols : view->parent->ncols;

		/* vertical splitscreen */
		for (i = 0; i < view->nlines; ++i) {
			err = view_write_line(tog_io.sdump, i, ncols - 1);
			if (err)
				goto done;
		}
	} else {
		int hline = 0;

		/* fullscreen or horizontal splitscreen */
		if ((view->child && view->child->begin_y) ||
		    (view->parent && view->begin_y))	/* hsplit */
			hline = view->child ?
			    view->child->begin_y : view->begin_y;

		for (i = 0; i < view->lines; i++) {
			if (hline && i == hline - 1) {
				int c;

				/* ACS_HLINE writes out as 'q', overwrite it */
				for (c = 0; c < view->cols; ++c)
					fputc('-', tog_io.sdump);
				fputc('\n', tog_io.sdump);
				continue;
			}

			err = view_write_line(tog_io.sdump, i, 0);
			if (err)
				goto done;
		}
	}

done:
	return err;
}

/*
 * Compute view->count from numeric input. Assign total to view->count and
 * return first non-numeric key entered.
 */
static int
get_compound_key(struct tog_view *view, int c)
{
	struct tog_view	*v = view;
	int		 x, n = 0;

	if (view_is_hsplit_top(view))
		v = view->child;
	else if (view->mode == TOG_VIEW_SPLIT_VERT && view->parent)
		v = view->parent;

	view->count = 0;
	cbreak();  /* block for input */
	nodelay(view->window, FALSE);
	wmove(v->window, v->nlines - 1, 0);
	wclrtoeol(v->window);
	waddch(v->window, ':');

	do {
		x = getcurx(v->window);
		if (x != ERR && x < view->ncols) {
			waddch(v->window, c);
			wrefresh(v->window);
		}

		/*
		 * Don't overflow. Max valid request should be the greatest
		 * between the longest and total lines; cap at 10 million.
		 */
		if (n >= 9999999)
			n = 9999999;
		else
			n = n * 10 + (c - '0');
	} while (((c = wgetch(view->window))) >= '0' && c <= '9' && c != ERR);

	if (c == 'G' || c == 'g') {	/* nG key map */
		view->gline = view->hiline = n;
		n = 0;
		c = 0;
	}

	/* Massage excessive or inapplicable values at the input handler. */
	view->count = n;

	return c;
}

static void
action_report(struct tog_view *view)
{
	struct tog_view *v = view;

	if (view_is_hsplit_top(view))
		v = view->child;
	else if (view->mode == TOG_VIEW_SPLIT_VERT && view->parent)
		v = view->parent;

	wmove(v->window, v->nlines - 1, 0);
	wclrtoeol(v->window);
	wprintw(v->window, ":%s", view->action);
	wrefresh(v->window);

	/*
	 * Clear action status report. Only clear in blame view
	 * once annotating is complete, otherwise it's too fast.
	 * In diff view, let its state control view->action lifetime.
	 */
	if (view->type == TOG_VIEW_BLAME) {
		if (view->state.blame.blame_complete)
			view->action = NULL;
	} else if (view->type == TOG_VIEW_DIFF) {
		view->action = view->state.diff.action;
	} else
		view->action = NULL;
}

/*
 * Read the next line from the test script and assign
 * key instruction to *ch. If at EOF, set the *done flag.
 */
static const struct got_error *
tog_read_script_key(FILE *script, struct tog_view *view, int *ch, int *done)
{
	const struct got_error	*err = NULL;
	char			*line = NULL;
	size_t			 linesz = 0;
	ssize_t			 n;


	if (view->count && --view->count) {
		*ch = view->ch;
		return NULL;
	} else
		*ch = -1;

	if ((n = getline(&line, &linesz, script)) == -1) {
		if (feof(script)) {
			*done = 1;
			goto done;
		} else {
			err = got_ferror(script, GOT_ERR_IO);
			goto done;
		}
	}

	if (strncasecmp(line, "WAIT_FOR_UI", 11) == 0)
		tog_io.wait_for_ui = 1;
	else if (strncasecmp(line, "KEY_ENTER", 9) == 0)
		*ch = KEY_ENTER;
	else if (strncasecmp(line, "KEY_RIGHT", 9) == 0)
		*ch = KEY_RIGHT;
	else if (strncasecmp(line, "KEY_LEFT", 8) == 0)
		*ch = KEY_LEFT;
	else if (strncasecmp(line, "KEY_DOWN", 8) == 0)
		*ch = KEY_DOWN;
	else if (strncasecmp(line, "KEY_UP", 6) == 0)
		*ch = KEY_UP;
	else if (strncasecmp(line, "TAB", 3) == 0)
		*ch = '\t';
	else if (strncasecmp(line, "SCREENDUMP", 10) == 0)
		*ch = TOG_KEY_SCRDUMP;
	else if (isdigit((unsigned char)*line)) {
		char *t = line;

		while (isdigit((unsigned char)*t))
			++t;
		view->ch = *ch = *t;
		*t = '\0';
		/* ignore error, view->count is 0 if instruction is invalid */
		view->count = strtonum(line, 0, INT_MAX, NULL);
	} else {
		*ch = *line;
		if (n > 2 && (*ch == '/' || *ch == '&')) {
			/* skip leading keymap and trim trailing newline */
			tog_io.input_str = strndup(line + 1, n - 2);
			if (tog_io.input_str == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
		}
	}

done:
	free(line);
	return err;
}

static void
log_mark_clear(struct tog_log_view_state *s)
{
	s->marked_entry = NULL;
}

static const struct got_error *
view_input(struct tog_view **new, int *done, struct tog_view *view,
    struct tog_view_list_head *views, int fast_refresh)
{
	const struct got_error *err = NULL;
	struct tog_view *v;
	int ch, errcode;

	*new = NULL;

	if (view->action)
		action_report(view);

	/* Clear "no matches" indicator. */
	if (view->search_next_done == TOG_SEARCH_NO_MORE ||
	    view->search_next_done == TOG_SEARCH_HAVE_NONE) {
		view->search_next_done = TOG_SEARCH_HAVE_MORE;
		view->count = 0;
	}

	if (view->searching && !view->search_next_done) {
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_unlock");
		sched_yield();
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_lock");
		view->search_next(view);
		return NULL;
	}

	/* Allow threads to make progress while we are waiting for input. */
	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_unlock");

	if (using_mock_io) {
		err = tog_read_script_key(tog_io.f, view, &ch, done);
		if (err) {
			errcode = pthread_mutex_lock(&tog_mutex);
			return err;
		}
	} else if (view->count && --view->count) {
		cbreak();
		nodelay(view->window, TRUE);
		ch = wgetch(view->window);
		/* let C-g or backspace abort unfinished count */
		if (ch == CTRL('g') || ch == KEY_BACKSPACE)
			view->count = 0;
		else
			ch = view->ch;
	} else {
		ch = wgetch(view->window);
		if (ch >= '1' && ch  <= '9')
			view->ch = ch = get_compound_key(view, ch);
	}
	if (view->hiline && ch != ERR && ch != 0)
		view->hiline = 0;  /* key pressed, clear line highlight */
	wtimeout(view->window, fast_refresh ? 100 : 1000);  /* milliseconds */
	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_lock");

	if (tog_sigwinch_received || tog_sigcont_received) {
		tog_resizeterm();
		tog_sigwinch_received = 0;
		tog_sigcont_received = 0;
		TAILQ_FOREACH(v, views, entry) {
			err = view_resize(v);
			if (err)
				return err;
			err = v->input(new, v, KEY_RESIZE);
			if (err)
				return err;
			if (v->child) {
				err = view_resize(v->child);
				if (err)
					return err;
				err = v->child->input(new, v->child,
				    KEY_RESIZE);
				if (err)
					return err;
				if (v->child->resized_x || v->child->resized_y) {
					err = view_resize_split(v, 0);
					if (err)
						return err;
				}
			}
		}
	}

	switch (ch) {
	case '?':
	case 'H':
	case KEY_F(1):
		view->count = 0;
		if (view->type == TOG_VIEW_HELP)
			err = view->reset(view);
		else
			err = view_request_new(new, view, TOG_VIEW_HELP);
		break;
	case '\t':
		view->count = 0;
		if (view->child) {
			view->focussed = 0;
			view->child->focussed = 1;
			view->focus_child = 1;
		} else if (view->parent) {
			view->focussed = 0;
			view->parent->focussed = 1;
			view->parent->focus_child = 0;
			if (!view_is_splitscreen(view)) {
				if (view->parent->resize) {
					err = view->parent->resize(view->parent,
					    0);
					if (err)
						return err;
				}
				offset_selection_up(view->parent);
				err = view_fullscreen(view->parent);
				if (err)
					return err;
			}
		}
		break;
	case 'q':
		if (view->parent != NULL) {
			if (view->parent->type == TOG_VIEW_LOG)
				log_mark_clear(&view->parent->state.log);

			if (view->mode == TOG_VIEW_SPLIT_HRZN) {
				if (view->parent->resize) {
					/*
					 * Might need more commits
					 * to fill fullscreen.
					 */
					err = view->parent->resize(
					    view->parent, 0);
					if (err)
						break;
				}
				offset_selection_up(view->parent);
			}
		}
		err = view->input(new, view, ch);
		view->dying = 1;
		break;
	case 'Q':
		*done = 1;
		break;
	case 'F':
		view->count = 0;
		if (view_is_parent_view(view)) {
			if (view->child == NULL)
				break;
			if (view_is_splitscreen(view->child)) {
				view->focussed = 0;
				view->child->focussed = 1;
				err = view_fullscreen(view->child);
			} else {
				err = view_splitscreen(view->child);
				if (!err)
					err = view_resize_split(view, 0);
			}
			if (err)
				break;
			err = view->child->input(new, view->child,
			    KEY_RESIZE);
		} else {
			if (view_is_splitscreen(view)) {
				view->parent->focussed = 0;
				view->focussed = 1;
				err = view_fullscreen(view);
			} else {
				err = view_splitscreen(view);
				if (!err && view->mode != TOG_VIEW_SPLIT_HRZN)
					err = view_resize(view->parent);
				if (!err)
					err = view_resize_split(view, 0);
			}
			if (err)
				break;
			err = view->input(new, view, KEY_RESIZE);
		}
		if (err)
			break;
		if (view->resize) {
			err = view->resize(view, 0);
			if (err)
				break;
		}
		if (view->parent) {
			if (view->parent->resize) {
				err = view->parent->resize(view->parent, 0);
				if (err != NULL)
					break;
			}
			err = offset_selection_down(view->parent);
			if (err != NULL)
				break;
		}
		err = offset_selection_down(view);
		break;
	case 'S':
		view->count = 0;
		err = switch_split(view);
		break;
	case '-':
		err = view_resize_split(view, -1);
		break;
	case '+':
		err = view_resize_split(view, 1);
		break;
	case KEY_RESIZE:
		break;
	case '/':
		view->count = 0;
		if (view->search_start)
			view_search_start(view, fast_refresh);
		else
			err = view->input(new, view, ch);
		break;
	case 'N':
	case 'n':
		if (view->search_started && view->search_next) {
			view->searching = (ch == 'n' ?
			    TOG_SEARCH_FORWARD : TOG_SEARCH_BACKWARD);
			view->search_next_done = 0;
			view->search_next(view);
		} else
			err = view->input(new, view, ch);
		break;
	case 'A':
		if (tog_diff_algo == GOT_DIFF_ALGORITHM_MYERS) {
			tog_diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;
			view->action = "Patience diff algorithm";
		} else {
			tog_diff_algo = GOT_DIFF_ALGORITHM_MYERS;
			view->action = "Myers diff algorithm";
		}
		TAILQ_FOREACH(v, views, entry) {
			if (v->reset) {
				err = v->reset(v);
				if (err)
					return err;
			}
			if (v->child && v->child->reset) {
				err = v->child->reset(v->child);
				if (err)
					return err;
			}
		}
		break;
	case TOG_KEY_SCRDUMP:
		err = screendump(view);
		break;
	default:
		err = view->input(new, view, ch);
		break;
	}

	return err;
}

static int
view_needs_focus_indication(struct tog_view *view)
{
	if (view_is_parent_view(view)) {
		if (view->child == NULL || view->child->focussed)
			return 0;
		if (!view_is_splitscreen(view->child))
			return 0;
	} else if (!view_is_splitscreen(view))
		return 0;

	return view->focussed;
}

static const struct got_error *
tog_io_close(void)
{
	const struct got_error *err = NULL;

	if (tog_io.cin && fclose(tog_io.cin) == EOF)
		err = got_ferror(tog_io.cin, GOT_ERR_IO);
	if (tog_io.cout && fclose(tog_io.cout) == EOF && err == NULL)
		err = got_ferror(tog_io.cout, GOT_ERR_IO);
	if (tog_io.f && fclose(tog_io.f) == EOF && err == NULL)
		err = got_ferror(tog_io.f, GOT_ERR_IO);
	if (tog_io.sdump && fclose(tog_io.sdump) == EOF && err == NULL)
		err = got_ferror(tog_io.sdump, GOT_ERR_IO);
	if (tog_io.input_str != NULL)
		free(tog_io.input_str);

	return err;
}

static const struct got_error *
view_loop(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_view_list_head views;
	struct tog_view *new_view;
	char *mode;
	int fast_refresh = 10;
	int done = 0, errcode;

	mode = getenv("TOG_VIEW_SPLIT_MODE");
	if (!mode || !(*mode == 'h' || *mode == 'H'))
		view->mode = TOG_VIEW_SPLIT_VERT;
	else
		view->mode = TOG_VIEW_SPLIT_HRZN;

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_lock");

	TAILQ_INIT(&views);
	TAILQ_INSERT_HEAD(&views, view, entry);

	view->focussed = 1;
	err = view->show(view);
	if (err)
		return err;
	update_panels();
	doupdate();
	while (!TAILQ_EMPTY(&views) && !done && !tog_thread_error &&
	    !tog_fatal_signal_received()) {
		/* Refresh fast during initialization, then become slower. */
		if (fast_refresh && --fast_refresh == 0 && !using_mock_io)
			halfdelay(10); /* switch to once per second */

		err = view_input(&new_view, &done, view, &views, fast_refresh);
		if (err)
			break;

		if (view->dying && view == TAILQ_FIRST(&views) &&
		    TAILQ_NEXT(view, entry) == NULL)
			done = 1;
		if (done) {
			struct tog_view *v;

			/*
			 * When we quit, scroll the screen up a single line
			 * so we don't lose any information.
			 */
			TAILQ_FOREACH(v, &views, entry) {
				wmove(v->window, 0, 0);
				wdeleteln(v->window);
				wnoutrefresh(v->window);
				if (v->child && !view_is_fullscreen(v)) {
					wmove(v->child->window, 0, 0);
					wdeleteln(v->child->window);
					wnoutrefresh(v->child->window);
				}
			}
			doupdate();
		}

		if (view->dying) {
			struct tog_view *v, *prev = NULL;

			if (view_is_parent_view(view))
				prev = TAILQ_PREV(view, tog_view_list_head,
				    entry);
			else if (view->parent)
				prev = view->parent;

			if (view->parent) {
				view->parent->child = NULL;
				view->parent->focus_child = 0;
				/* Restore fullscreen line height. */
				view->parent->nlines = view->parent->lines;
				err = view_resize(view->parent);
				if (err)
					break;
				/* Make resized splits persist. */
				view_transfer_size(view->parent, view);
			} else
				TAILQ_REMOVE(&views, view, entry);

			err = view_close(view);
			if (err)
				goto done;

			view = NULL;
			TAILQ_FOREACH(v, &views, entry) {
				if (v->focussed)
					break;
			}
			if (view == NULL && new_view == NULL) {
				/* No view has focus. Try to pick one. */
				if (prev)
					view = prev;
				else if (!TAILQ_EMPTY(&views)) {
					view = TAILQ_LAST(&views,
					    tog_view_list_head);
				}
				if (view) {
					if (view->focus_child) {
						view->child->focussed = 1;
						view = view->child;
					} else
						view->focussed = 1;
				}
			}
		}
		if (new_view) {
			struct tog_view *v, *t;
			/* Only allow one parent view per type. */
			TAILQ_FOREACH_SAFE(v, &views, entry, t) {
				if (v->type != new_view->type)
					continue;
				TAILQ_REMOVE(&views, v, entry);
				err = view_close(v);
				if (err)
					goto done;
				break;
			}
			TAILQ_INSERT_TAIL(&views, new_view, entry);
			view = new_view;
		}
		if (view && !done) {
			if (view_is_parent_view(view)) {
				if (view->child && view->child->focussed)
					view = view->child;
			} else {
				if (view->parent && view->parent->focussed)
					view = view->parent;
			}
			show_panel(view->panel);
			if (view->child && view_is_splitscreen(view->child))
				show_panel(view->child->panel);
			if (view->parent && view_is_splitscreen(view)) {
				err = view->parent->show(view->parent);
				if (err)
					goto done;
			}
			err = view->show(view);
			if (err)
				goto done;
			if (view->child) {
				err = view->child->show(view->child);
				if (err)
					goto done;
			}
			update_panels();
			doupdate();
		}
	}
done:
	while (!TAILQ_EMPTY(&views)) {
		const struct got_error *close_err;
		view = TAILQ_FIRST(&views);
		TAILQ_REMOVE(&views, view, entry);
		close_err = view_close(view);
		if (close_err && err == NULL)
			err = close_err;
	}

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode, "pthread_mutex_unlock");

	return err;
}

__dead static void
usage_log(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	endwin();
	fprintf(fp,
	    "usage: %s log [-b] [-c commit] [-r repository-path] [path]\n",
	    getprogname());
	exit(status);
}

/* Create newly allocated wide-character string equivalent to a byte string. */
static const struct got_error *
mbs2ws(wchar_t **ws, size_t *wlen, const char *s)
{
	char *vis = NULL;
	const struct got_error *err = NULL;

	*ws = NULL;
	*wlen = mbstowcs(NULL, s, 0);
	if (*wlen == (size_t)-1) {
		int vislen;
		if (errno != EILSEQ)
			return got_error_from_errno("mbstowcs");

		/* byte string invalid in current encoding; try to "fix" it */
		err = got_mbsavis(&vis, &vislen, s);
		if (err)
			return err;
		*wlen = mbstowcs(NULL, vis, 0);
		if (*wlen == (size_t)-1) {
			err = got_error_from_errno("mbstowcs"); /* give up */
			goto done;
		}
	}

	*ws = calloc(*wlen + 1, sizeof(**ws));
	if (*ws == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (mbstowcs(*ws, vis ? vis : s, *wlen) != *wlen)
		err = got_error_from_errno("mbstowcs");
done:
	free(vis);
	if (err) {
		free(*ws);
		*ws = NULL;
		*wlen = 0;
	}
	return err;
}

static const struct got_error *
expand_tab(char **ptr, const char *src)
{
	char	*dst;
	size_t	 len, n, idx = 0, sz = 0;

	*ptr = NULL;
	n = len = strlen(src);
	dst = malloc(n + 1);
	if (dst == NULL)
		return got_error_from_errno("malloc");

	while (idx < len && src[idx]) {
		const char c = src[idx];

		if (c == '\t') {
			size_t nb = TABSIZE - sz % TABSIZE;
			char *p;

			p = realloc(dst, n + nb);
			if (p == NULL) {
				free(dst);
				return got_error_from_errno("realloc");

			}
			dst = p;
			n += nb;
			memset(dst + sz, ' ', nb);
			sz += nb;
		} else
			dst[sz++] = src[idx];
		++idx;
	}

	dst[sz] = '\0';
	*ptr = dst;
	return NULL;
}

/*
 * Advance at most n columns from wline starting at offset off.
 * Return the index to the first character after the span operation.
 * Return the combined column width of all spanned wide characters in
 * *rcol.
 */
static int
span_wline(int *rcol, int off, wchar_t *wline, int n, int col_tab_align)
{
	int width, i, cols = 0;

	if (n == 0) {
		*rcol = cols;
		return off;
	}

	for (i = off; wline[i] != L'\0'; ++i) {
		if (wline[i] == L'\t')
			width = TABSIZE - ((cols + col_tab_align) % TABSIZE);
		else
			width = wcwidth(wline[i]);

		if (width == -1) {
			width = 1;
			wline[i] = L'.';
		}

		if (cols + width > n)
			break;
		cols += width;
	}

	*rcol = cols;
	return i;
}

/*
 * Format a line for display, ensuring that it won't overflow a width limit.
 * With scrolling, the width returned refers to the scrolled version of the
 * line, which starts at (*wlinep)[*scrollxp]. The caller must free *wlinep.
 */
static const struct got_error *
format_line(wchar_t **wlinep, int *widthp, int *scrollxp,
    const char *line, int nscroll, int wlimit, int col_tab_align, int expand)
{
	const struct got_error *err = NULL;
	int cols;
	wchar_t *wline = NULL;
	char *exstr = NULL;
	size_t wlen;
	int i, scrollx;

	*wlinep = NULL;
	*widthp = 0;

	if (expand) {
		err = expand_tab(&exstr, line);
		if (err)
			return err;
	}

	err = mbs2ws(&wline, &wlen, expand ? exstr : line);
	free(exstr);
	if (err)
		return err;

	if (wlen > 0 && wline[wlen - 1] == L'\n') {
		wline[wlen - 1] = L'\0';
		wlen--;
	}
	if (wlen > 0 && wline[wlen - 1] == L'\r') {
		wline[wlen - 1] = L'\0';
		wlen--;
	}

	scrollx = span_wline(&cols, 0, wline, nscroll, col_tab_align);

	i = span_wline(&cols, scrollx, wline, wlimit, col_tab_align);
	wline[i] = L'\0';

	if (widthp)
		*widthp = cols;
	if (scrollxp)
		*scrollxp = scrollx;
	if (err)
		free(wline);
	else
		*wlinep = wline;
	return err;
}

static const struct got_error*
build_refs_str(char **refs_str, struct got_reflist_head *refs,
    struct got_object_id *id, struct got_repository *repo)
{
	static const struct got_error *err = NULL;
	struct got_reflist_entry *re;
	char *s;
	const char *name;

	*refs_str = NULL;

	if (refs == NULL)
		return NULL;

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
format_author(wchar_t **wauthor, int *author_width, char *author, int limit,
    int col_tab_align)
{
	char *smallerthan;

	smallerthan = strchr(author, '<');
	if (smallerthan && smallerthan[1] != '\0')
		author = smallerthan + 1;
	author[strcspn(author, "@>")] = '\0';
	return format_line(wauthor, author_width, NULL, author, 0, limit,
	    col_tab_align, 0);
}

static const struct got_error *
draw_commit_marker(struct tog_view *view, char c)
{
	struct tog_color *tc;

	if (view->type != TOG_VIEW_LOG)
		return got_error_msg(GOT_ERR_NOT_IMPL, "view not supported");

	tc = get_color(&view->state.log.colors, TOG_COLOR_COMMIT);
	if (tc != NULL)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	if (waddch(view->window, c) == ERR)
		return got_error_msg(GOT_ERR_IO, "waddch");
	if (tc != NULL)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);

	return NULL;
}

static void
tog_waddwstr(struct tog_view *view, wchar_t *wstr, int width,
    int *col, int color, int toeol)
{
	struct tog_color	*tc;
	int			 x;

	x = col != NULL ? *col : getcurx(view->window);
	tc = color > 0 ? get_color(&view->state.log.colors, color) : NULL;

	if (tc != NULL)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	waddwstr(view->window, wstr);
	x += MAX(width, 0);
	if (toeol) {
		while (x < view->ncols) {
			waddch(view->window, ' ');
			++x;
		}
	}
	if (tc != NULL)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);
	if (col != NULL)
		*col = x;
}

static void
tog_waddnstr(struct tog_view *view, const char *str, int limit, int color)
{
	struct tog_color *tc;

	if (limit == 0)
		limit = view->ncols - getcurx(view->window);

	tc = get_color(&view->state.log.colors, color);
	if (tc != NULL)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	waddnstr(view->window, str, limit);
	if (tc != NULL)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);
}

static const struct got_error *
draw_author(struct tog_view *view, char *author, int author_display_cols,
    int limit, int *col, int color, int marker_column,
    struct commit_queue_entry *entry)
{
	const struct got_error		*err;
	struct tog_log_view_state	*s = &view->state.log;
	struct tog_color		*tc;
	wchar_t				*wauthor;
	int				 author_width;

	err = format_author(&wauthor, &author_width, author, limit, *col);
	if (err != NULL)
		return err;
	if ((tc = get_color(&s->colors, color)) != NULL)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	waddwstr(view->window, wauthor);
	free(wauthor);

	*col += author_width;
	while (*col < limit && author_width < author_display_cols + 2) {
		if (entry != NULL && s->marked_entry == entry &&
		    author_width == marker_column) {
			err = draw_commit_marker(view, '>');
			if (err != NULL)
				return err;
		} else if (entry != NULL &&
		    tog_base_commit.marker != GOT_WORKTREE_STATE_UNKNOWN &&
		    author_width == marker_column &&
		    entry->idx == tog_base_commit.idx && !s->limit_view) {
			err = draw_commit_marker(view, tog_base_commit.marker);
			if (err != NULL)
				return err;
		} else
			waddch(view->window, ' ');
		++(*col);
		++(author_width);
	}
	if (tc != NULL)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);

	return NULL;
}

static const struct got_error *
draw_idstr(struct tog_view *view, const char *id_str, int color)
{
	char *str = NULL;

	if (strlen(id_str) > 9 && asprintf(&str, "%.8s ", id_str) == -1)
		return got_error_from_errno("asprintf");

	tog_waddnstr(view, str != NULL ? str : id_str, 0, color);
	free(str);
	return NULL;
}

static const struct got_error *
draw_ymd(struct tog_view *view, time_t t, int *limit, int avail,
    int date_display_cols)
{
	struct	tm tm;
	char	datebuf[12];	/* YYYY-MM-DD + SPACE + NUL */

	if (gmtime_r(&t, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(datebuf, sizeof(datebuf), "%F ", &tm) == 0)
		return got_error(GOT_ERR_NO_SPACE);

	if (avail <= date_display_cols)
		*limit = MIN(sizeof(datebuf) - 1, avail);
	else
		*limit = MIN(date_display_cols, sizeof(datebuf) - 1);

	tog_waddnstr(view, datebuf, *limit, TOG_COLOR_DATE);
	return NULL;
}

static const struct got_error *
draw_worktree_entry(struct tog_view *view, int wt_entry,
    const size_t date_display_cols, int author_display_cols)
{
	const struct got_error		*err = NULL;
	struct tog_log_view_state	*s = &view->state.log;
	wchar_t				*wmsg = NULL;
	char				*author, *msg = NULL;
	char				*base_commit_id = NULL;
	const char			*p = TOG_WORKTREE_CHANGES_LOCAL_MSG;
	int				 col, limit, scrollx, width;
	const int			 avail = view->ncols;

	err = draw_ymd(view, time(NULL), &col, avail, date_display_cols);
	if (err != NULL)
		return err;
	if (col > avail)
		return NULL;
	if (avail >= 120) {
		err = draw_idstr(view, "........ ", TOG_COLOR_COMMIT);
		if (err != NULL)
			return err;
		col += 9;
		if (col > avail)
			return NULL;
	}

	author = strdup(s->thread_args.wctx.wt_author);
	if (author == NULL)
		return got_error_from_errno("strdup");

	err = draw_author(view, author, author_display_cols, avail - col,
	    &col, TOG_COLOR_AUTHOR, 0, NULL);
	if (err != NULL)
		goto done;
	if (col > avail)
		goto done;

	err = got_object_id_str(&base_commit_id, tog_base_commit.id);
	if (err != NULL)
		goto done;
	if (wt_entry & TOG_WORKTREE_CHANGES_STAGED)
		p = TOG_WORKTREE_CHANGES_STAGED_MSG;
	if (asprintf(&msg, "%s based on [%.10s]", p, base_commit_id) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	limit = avail - col;
	if (view->child != NULL && !view_is_hsplit_top(view) && limit > 0)
		limit--;	/* for the border */

	err = format_line(&wmsg, &width, &scrollx, msg, view->x, limit, col, 1);
	if (err != NULL)
		goto done;
	tog_waddwstr(view, &wmsg[scrollx], width, &col, 0, 1);

done:
	free(msg);
	free(wmsg);
	free(author);
	free(base_commit_id);
	return err;
}

static const struct got_error *
draw_commit(struct tog_view *view, struct commit_queue_entry *entry,
    const size_t date_display_cols, int author_display_cols)
{
	struct tog_log_view_state *s = &view->state.log;
	const struct got_error *err = NULL;
	struct got_commit_object *commit = entry->commit;
	struct got_object_id *id = entry->id;
	char *author, *newline, *logmsg, *logmsg0 = NULL, *refs_str = NULL;
	wchar_t *wrefstr = NULL, *wlogmsg = NULL;
	int refstr_width, logmsg_width, col, limit, scrollx, logmsg_x;
	const int avail = view->ncols, marker_column = author_display_cols + 1;
	time_t committer_time;
	struct got_reflist_head *refs;

	if (tog_base_commit.id != NULL && tog_base_commit.idx == -1 &&
	    got_object_id_cmp(id, tog_base_commit.id) == 0)
		tog_base_commit.idx = entry->idx;
	if (tog_io.wait_for_ui && s->thread_args.need_commit_marker) {
		int rc;

		rc = pthread_cond_wait(&s->thread_args.log_loaded, &tog_mutex);
		if (rc)
			return got_error_set_errno(rc, "pthread_cond_wait");
	}

	committer_time = got_object_commit_get_committer_time(commit);
	err = draw_ymd(view, committer_time, &col, avail, date_display_cols);
	if (err != NULL)
		return err;
	if (col > avail)
		return NULL;

	if (avail >= 120) {
		char *id_str;

		err = got_object_id_str(&id_str, id);
		if (err)
			return err;
		err = draw_idstr(view, id_str, TOG_COLOR_COMMIT);
		free(id_str);
		if (err != NULL)
			return err;
		col += 9;
		if (col > avail)
			return NULL;
	}

	if (s->use_committer)
		author = strdup(got_object_commit_get_committer(commit));
	else
		author = strdup(got_object_commit_get_author(commit));
	if (author == NULL)
		return got_error_from_errno("strdup");

	err = draw_author(view, author, author_display_cols,
	    avail - col, &col, TOG_COLOR_AUTHOR, marker_column, entry);
	if (err != NULL)
		goto done;
	if (col > avail)
		goto done;

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		goto done;
	logmsg = logmsg0;
	while (*logmsg == '\n')
		logmsg++;
	newline = strchr(logmsg, '\n');
	if (newline)
		*newline = '\0';

	limit = avail - col;
	if (view->child && !view_is_hsplit_top(view) && limit > 0)
		limit--;	/* for the border */

	/* Prepend reference labels to log message if possible .*/
	refs = got_reflist_object_id_map_lookup(tog_refs_idmap, id);
	err = build_refs_str(&refs_str, refs, id, s->repo);
	if (err)
		goto done;
	if (refs_str) {
		char *rs;

		if (asprintf(&rs, "[%s]", refs_str) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = format_line(&wrefstr, &refstr_width,
		    &scrollx, rs, view->x, limit, col, 1);
		free(rs);
		if (err)
			goto done;
		tog_waddwstr(view, &wrefstr[scrollx], refstr_width,
		    &col, TOG_COLOR_COMMIT, 0);
		if (col > avail)
			goto done;

		if (col < avail) {
			waddch(view->window, ' ');
			col++;
		}

		if (refstr_width > 0)
			logmsg_x = 0;
		else {
			int unscrolled_refstr_width;
			size_t len = wcslen(wrefstr);

			/*
			 * No need to check for -1 return value here since
			 * unprintables have been replaced by span_wline().
			 */
			unscrolled_refstr_width = wcswidth(wrefstr, len);
			unscrolled_refstr_width += 1; /* trailing space */
			logmsg_x = view->x - unscrolled_refstr_width;
		}

		limit = avail - col;
		if (view->child && !view_is_hsplit_top(view) && limit > 0)
			limit--;	/* for the border */
	} else
		logmsg_x = view->x;

	err = format_line(&wlogmsg, &logmsg_width, &scrollx, logmsg, logmsg_x,
	    limit, col, 1);
	if (err)
		goto done;
	tog_waddwstr(view, &wlogmsg[scrollx], logmsg_width, &col, 0, 1);

done:
	free(logmsg0);
	free(wlogmsg);
	free(wrefstr);
	free(refs_str);
	free(author);
	return err;
}

static struct commit_queue_entry *
alloc_commit_queue_entry(struct got_commit_object *commit,
    struct got_object_id *id)
{
	struct commit_queue_entry *entry;
	struct got_object_id *dup;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	dup = got_object_id_dup(id);
	if (dup == NULL) {
		free(entry);
		return NULL;
	}

	entry->id = dup;
	entry->commit = commit;
	return entry;
}

static void
pop_commit(struct commit_queue *commits)
{
	struct commit_queue_entry *entry;

	entry = TAILQ_FIRST(&commits->head);
	TAILQ_REMOVE(&commits->head, entry, entry);
	if (entry->worktree_entry == 0)
		got_object_commit_close(entry->commit);
	commits->ncommits--;
	free(entry->id);
	free(entry);
}

static void
free_commits(struct commit_queue *commits)
{
	while (!TAILQ_EMPTY(&commits->head))
		pop_commit(commits);
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

static const struct got_error *
queue_commits(struct tog_log_thread_args *a)
{
	const struct got_error *err = NULL;

	/*
	 * We keep all commits open throughout the lifetime of the log
	 * view in order to avoid having to re-fetch commits from disk
	 * while updating the display.
	 */
	do {
		struct got_object_id id;
		struct got_commit_object *commit;
		struct commit_queue_entry *entry;
		int limit_match = 0;
		int errcode;

		err = got_commit_graph_iter_next(&id, a->graph, a->repo,
		    NULL, NULL);
		if (err)
			break;

		err = got_object_open_as_commit(&commit, a->repo, &id);
		if (err)
			break;
		entry = alloc_commit_queue_entry(commit, &id);
		if (entry == NULL) {
			err = got_error_from_errno("alloc_commit_queue_entry");
			break;
		}

		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode) {
			err = got_error_set_errno(errcode,
			    "pthread_mutex_lock");
			break;
		}

		entry->idx = a->real_commits->ncommits;
		TAILQ_INSERT_TAIL(&a->real_commits->head, entry, entry);
		a->real_commits->ncommits++;

		if (*a->limiting) {
			err = match_commit(&limit_match, &id, commit,
			    a->limit_regex);
			if (err)
				break;

			if (limit_match) {
				struct commit_queue_entry *matched;

				matched = alloc_commit_queue_entry(
				    entry->commit, entry->id);
				if (matched == NULL) {
					err = got_error_from_errno(
					    "alloc_commit_queue_entry");
					break;
				}
				matched->commit = entry->commit;
				got_object_commit_retain(entry->commit);

				matched->idx = a->limit_commits->ncommits;
				TAILQ_INSERT_TAIL(&a->limit_commits->head,
				    matched, entry);
				a->limit_commits->ncommits++;
			}

			/*
			 * This is how we signal log_thread() that we
			 * have found a match, and that it should be
			 * counted as a new entry for the view.
			 */
			a->limit_match = limit_match;
		}

		if (*a->searching == TOG_SEARCH_FORWARD &&
		    !*a->search_next_done) {
			int have_match;
			err = match_commit(&have_match, &id, commit, a->regex);
			if (err)
				break;

			if (*a->limiting) {
				if (limit_match && have_match)
					*a->search_next_done =
					    TOG_SEARCH_HAVE_MORE;
			} else if (have_match)
				*a->search_next_done = TOG_SEARCH_HAVE_MORE;
		}

		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode,
			    "pthread_mutex_unlock");
		if (err)
			break;
	} while (*a->searching == TOG_SEARCH_FORWARD && !*a->search_next_done);

	return err;
}

static void
select_commit(struct tog_log_view_state *s)
{
	struct commit_queue_entry *entry;
	int ncommits = 0;

	entry = s->first_displayed_entry;
	while (entry) {
		if (ncommits == s->selected) {
			s->selected_entry = entry;
			break;
		}
		entry = TAILQ_NEXT(entry, entry);
		ncommits++;
	}
}

/* lifted from got.c:652 (TODO make lib routine) */
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
		err = got_error_from_errno("strdup");
	return err;
}

static const struct got_error *
push_worktree_entry(struct tog_log_thread_args *ta, int wt_entry,
    struct got_worktree *worktree)
{
	struct commit_queue_entry	*e, *entry;
	int				 rc;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return got_error_from_errno("calloc");

	entry->idx = 0;
	entry->worktree_entry = wt_entry;

	rc = pthread_mutex_lock(&tog_mutex);
	if (rc != 0) {
		free(entry);
		return got_error_set_errno(rc, "pthread_mutex_lock");
	}

	TAILQ_FOREACH(e, &ta->real_commits->head, entry)
		++e->idx;

	TAILQ_INSERT_HEAD(&ta->real_commits->head, entry, entry);
	ta->wctx.wt_state |= wt_entry;
	++ta->real_commits->ncommits;
	++tog_base_commit.idx;

	rc = pthread_mutex_unlock(&tog_mutex);
	if (rc != 0)
		return got_error_set_errno(rc, "pthread_mutex_unlock");

	return NULL;
}

static const struct got_error *
check_cancelled(void *arg)
{
	int rc, quit = 0;

	if ((rc = pthread_mutex_lock(&tog_mutex)) != 0)
		return got_error_set_errno(rc, "pthread_mutex_lock");
	if (tog_sigint_received || tog_sigpipe_received || *((int *)arg))
		quit = 1;
	if ((rc = pthread_mutex_unlock(&tog_mutex)) != 0)
		return got_error_set_errno(rc, "pthread_mutex_unlock");
	if (quit)
		return got_error(GOT_ERR_CANCELLED);
	return NULL;
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
		*have_local_changes |= TOG_WORKTREE_CHANGES_LOCAL;
	default:
		break;
	}

	switch (staged_status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
		*have_local_changes |= TOG_WORKTREE_CHANGES_STAGED;
	default:
		break;
	}

	return NULL;
}

static const struct got_error *
tog_worktree_status(struct tog_log_thread_args *ta)
{
	const struct got_error		*err, *close_err;
	struct tog_worktree_ctx		*wctx = &ta->wctx;
	struct got_worktree		*wt = ta->worktree;
	struct got_pathlist_head	 paths;
	char				*cwd = NULL;
	int				 wt_state = 0;

	RB_INIT(&paths);

	if (wt == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno("getcwd");

		err = got_worktree_open(&wt, cwd, NULL);
		if (err != NULL) {
			if (err->code == GOT_ERR_NOT_WORKTREE) {
				/*
				 * Shouldn't happen; this routine should only
				 * be called if tog is invoked in a worktree.
				 */
				wctx->active = 0;
				err = NULL;
			} else if (err->code == GOT_ERR_WORKTREE_BUSY)
				err = NULL;	/* retry next redraw */
			goto done;
		}
	}

	err = got_pathlist_insert(NULL, &paths, "", NULL);
	if (err != NULL)
		goto done;

	err = got_worktree_status(wt, &paths, ta->repo, 0,
	    check_local_changes, &wt_state, check_cancelled, ta->quit);
	if (err != NULL)
		goto done;

	if (wt_state != 0) {
		err = get_author(&wctx->wt_author, ta->repo, wt);
		if (err != NULL) {
			if (err->code != GOT_ERR_COMMIT_NO_AUTHOR)
				goto done;
			if ((wctx->wt_author = strdup("")) == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}

		wctx->wt_root = strdup(got_worktree_get_root_path(wt));
		if (wctx->wt_root == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}

		wctx->wt_ref = strdup(got_worktree_get_head_ref_name(wt));
		if (wctx->wt_ref == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	/*
	 * Push staged entry first so it's the second log entry
	 * if there are both staged and unstaged work tree changes.
	 */
	if (wt_state & TOG_WORKTREE_CHANGES_STAGED &&
	    (wctx->wt_state & TOG_WORKTREE_CHANGES_STAGED) == 0) {
		err = push_worktree_entry(ta, TOG_WORKTREE_CHANGES_STAGED, wt);
		if (err != NULL)
			goto done;
	}
	if (wt_state & TOG_WORKTREE_CHANGES_LOCAL &&
	    (wctx->wt_state & TOG_WORKTREE_CHANGES_LOCAL) == 0) {
		err = push_worktree_entry(ta, TOG_WORKTREE_CHANGES_LOCAL, wt);
		if (err != NULL)
			goto done;
	}

done:
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_NONE);
	if (ta->worktree == NULL && wt != NULL) {
		close_err = got_worktree_close(wt);
		if (close_err != NULL && err == NULL)
			err = close_err;
	}
	free(cwd);
	return err;
}

static const struct got_error *
worktree_headref_str(char **ret, const char *ref)
{
	if (strncmp(ref, "refs/heads/", 11) == 0)
		*ret = strdup(ref + 11);
	else
		*ret = strdup(ref);
	if (*ret == NULL)
		return got_error_from_errno("strdup");

	return NULL;
}

static const struct got_error *
fmtindex(char **index, int *ncommits, int wt_state,
    struct commit_queue_entry *entry, int limit_view)
{
	int idx = 0;

	if (!limit_view) {
		if (*ncommits > 0 && wt_state & TOG_WORKTREE_CHANGES_LOCAL)
			--(*ncommits);
		if (*ncommits > 0 && wt_state & TOG_WORKTREE_CHANGES_STAGED)
			--(*ncommits);
	}

	if (entry != NULL && entry->worktree_entry == 0) {
		/*
		 * Display 1-based index of selected commit entries only.
		 * If a work tree entry is selected, show an index of 0.
		 */
		idx = entry->idx;
		if (wt_state == 0 || limit_view)
			++idx;
		else if (wt_state > TOG_WORKTREE_CHANGES_STAGED)
			--idx;
	}
	if (asprintf(index, " [%d/%d] ", idx, *ncommits) == -1) {
		*index = NULL;
		return got_error_from_errno("asprintf");
	}

	return NULL;
}

static const struct got_error *
fmtheader(char **header, int *ncommits, struct commit_queue_entry *entry,
    struct tog_view *view)
{
	const struct got_error		*err;
	struct tog_log_view_state	*s = &view->state.log;
	struct tog_worktree_ctx		*wctx = &s->thread_args.wctx;
	struct got_reflist_head		*refs;
	char				*id_str = NULL, *index = NULL;
	char				*wthdr = NULL, *ncommits_str = NULL;
	char				*refs_str = NULL;
	int				 wt_entry;

	*header = NULL;
	wt_entry = entry != NULL ? entry->worktree_entry : 0;

	if (entry && !(view->searching && view->search_next_done == 0)) {
		if (entry->worktree_entry == 0) {
			err = got_object_id_str(&id_str, entry->id);
			if (err != NULL)
				return err;
			refs = got_reflist_object_id_map_lookup(tog_refs_idmap,
			    entry->id);
			err = build_refs_str(&refs_str, refs,
			    entry->id, s->repo);
			if (err != NULL)
				goto done;
		} else {
			err = worktree_headref_str(&refs_str, wctx->wt_ref);
			if (err != NULL)
				return err;
		}
	}

	err = fmtindex(&index, ncommits, wctx->wt_state, entry, s->limit_view);
	if (err != NULL)
		goto done;

	if (s->thread_args.commits_needed > 0 || s->thread_args.load_all) {
		if (asprintf(&ncommits_str, "%s%s", index,
		    (view->searching && !view->search_next_done) ?
		    "searching..." : "loading...") == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	} else {
		const char *search_str = NULL;
		const char *limit_str = NULL;

		if (view->searching) {
			if (view->search_next_done == TOG_SEARCH_NO_MORE)
				search_str = "no more matches";
			else if (view->search_next_done == TOG_SEARCH_HAVE_NONE)
				search_str = "no matches found";
			else if (!view->search_next_done)
				search_str = "searching...";
		}

		if (s->limit_view && ncommits == 0)
			limit_str = "no matches found";

		if (asprintf(&ncommits_str, "%s%s %s", index,
		    search_str ? search_str : (refs_str ? refs_str : ""),
		    limit_str ? limit_str : "") == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}

	if (wt_entry != 0) {
		const char *t = "", *p = TOG_WORKTREE_CHANGES_LOCAL_MSG;

		if (wt_entry == TOG_WORKTREE_CHANGES_STAGED) {
			p = TOG_WORKTREE_CHANGES_STAGED_MSG;
			t = "-s ";
		}
		if (asprintf(&wthdr, "%s%s (%s)", t, wctx->wt_root, p) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}

	if (s->in_repo_path != NULL && strcmp(s->in_repo_path, "/") != 0) {
		if (asprintf(header, "%s%s %s%s",
		    wt_entry == 0 ? "commit " : "diff ",
		    wt_entry == 0 ? id_str ? id_str :
		    "........................................" :
		    wthdr != NULL ? wthdr : "", s->in_repo_path,
		    ncommits_str) == -1)
			err = got_error_from_errno("asprintf");
	} else if (asprintf(header, "%s%s%s",
	    wt_entry == 0 ? "commit " : "diff ",
	    wt_entry == 0 ? id_str ? id_str :
	    "........................................" :
	    wthdr != NULL ? wthdr : "", ncommits_str) == -1)
		err = got_error_from_errno("asprintf");
	if (err != NULL)
		*header = NULL;

done:
	free(wthdr);
	free(index);
	free(id_str);
	free(refs_str);
	free(ncommits_str);
	return err;
}

static const struct got_error *
draw_commits(struct tog_view *view)
{
	const struct got_error *err;
	struct tog_log_view_state *s = &view->state.log;
	struct commit_queue_entry *entry = s->selected_entry;
	int width, limit = view->nlines;
	int ncommits = s->commits->ncommits, author_cols = 4, refstr_cols;
	char *header;
	wchar_t *wline;
	static const size_t date_display_cols = 12;

	if (view_is_hsplit_top(view))
		--limit;  /* account for border */

	if (s->thread_args.commits_needed == 0 &&
	    s->thread_args.need_wt_status == 0 &&
	    s->thread_args.need_commit_marker == 0 && !using_mock_io)
		halfdelay(10); /* disable fast refresh */

	err = fmtheader(&header, &ncommits, entry, view);
	if (err != NULL)
		return err;

	err = format_line(&wline, &width, NULL, header, 0, view->ncols, 0, 0);
	free(header);
	if (err)
		return err;

	werase(view->window);

	if (view_needs_focus_indication(view))
		wstandout(view->window);
	tog_waddwstr(view, wline, width, NULL, TOG_COLOR_COMMIT, 1);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	if (limit <= 1)
		return NULL;

	/* Grow author column size if necessary, and set view->maxx. */
	entry = s->first_displayed_entry;
	ncommits = 0;
	view->maxx = 0;
	while (entry) {
		struct got_reflist_head *refs;
		struct got_commit_object *c = entry->commit;
		char *author, *eol, *msg, *msg0, *refs_str;
		wchar_t *wauthor, *wmsg;
		int width;

		if (ncommits >= limit - 1)
			break;
		if (entry->worktree_entry != 0)
			author = strdup(s->thread_args.wctx.wt_author);
		else if (s->use_committer)
			author = strdup(got_object_commit_get_committer(c));
		else
			author = strdup(got_object_commit_get_author(c));
		if (author == NULL)
			return got_error_from_errno("strdup");

		err = format_author(&wauthor, &width, author, COLS,
		    date_display_cols);
		if (author_cols < width)
			author_cols = width;
		free(wauthor);
		free(author);
		if (err)
			return err;
		if (entry->worktree_entry != 0) {
			if (entry->worktree_entry == TOG_WORKTREE_CHANGES_LOCAL)
				width = sizeof(TOG_WORKTREE_CHANGES_LOCAL_MSG);
			else
				width = sizeof(TOG_WORKTREE_CHANGES_STAGED_MSG);
			view->maxx = MAX(view->maxx, width - 1);
			entry = TAILQ_NEXT(entry, entry);
			++ncommits;
			continue;
		}
		refs = got_reflist_object_id_map_lookup(tog_refs_idmap,
		    entry->id);
		err = build_refs_str(&refs_str, refs, entry->id, s->repo);
		if (err)
			return err;
		if (refs_str) {
			wchar_t *ws;

			err = format_line(&ws, &width, NULL, refs_str,
			    0, INT_MAX, date_display_cols + author_cols, 0);
			free(ws);
			free(refs_str);
			refs_str = NULL;
			if (err)
				return err;
			refstr_cols = width + 3; /* account for [ ] + space */
		} else
			refstr_cols = 0;
		err = got_object_commit_get_logmsg(&msg0, c);
		if (err)
			return err;
		msg = msg0;
		while (*msg == '\n')
			++msg;
		if ((eol = strchr(msg, '\n')))
			*eol = '\0';
		err = format_line(&wmsg, &width, NULL, msg, 0, INT_MAX,
		    date_display_cols + author_cols + refstr_cols, 0);
		free(msg0);
		free(wmsg);
		if (err)
			return err;
		view->maxx = MAX(view->maxx, width + refstr_cols);
		ncommits++;
		entry = TAILQ_NEXT(entry, entry);
	}

	entry = s->first_displayed_entry;
	s->last_displayed_entry = s->first_displayed_entry;
	ncommits = 0;
	while (entry) {
		if (ncommits >= limit - 1)
			break;
		if (ncommits == s->selected)
			wstandout(view->window);
		if (entry->worktree_entry == 0)
			err = draw_commit(view, entry,
			    date_display_cols, author_cols);
		else
			err = draw_worktree_entry(view, entry->worktree_entry,
			    date_display_cols, author_cols);
		if (ncommits == s->selected)
			wstandend(view->window);
		if (err)
			return err;
		ncommits++;
		s->last_displayed_entry = entry;
		entry = TAILQ_NEXT(entry, entry);
	}

	view_border(view);
	return NULL;
}

static void
log_scroll_up(struct tog_log_view_state *s, int maxscroll)
{
	struct commit_queue_entry *entry;
	int nscrolled = 0;

	entry = TAILQ_FIRST(&s->commits->head);
	if (s->first_displayed_entry == entry)
		return;

	entry = s->first_displayed_entry;
	while (entry && nscrolled < maxscroll) {
		entry = TAILQ_PREV(entry, commit_queue_head, entry);
		if (entry) {
			s->first_displayed_entry = entry;
			nscrolled++;
		}
	}
}

static const struct got_error *
trigger_log_thread(struct tog_view *view, int wait)
{
	const struct got_error *err;
	struct tog_log_thread_args *ta = &view->state.log.thread_args;
	int errcode;

	if (!using_mock_io)
		halfdelay(1); /* fast refresh while loading commits */

	while (!ta->log_complete && !tog_thread_error &&
	    (ta->commits_needed > 0 || ta->load_all)) {
		/* Wake the log thread. */
		errcode = pthread_cond_signal(&ta->need_commits);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_cond_signal");

		/*
		 * The mutex will be released while the view loop waits
		 * in wgetch(), at which time the log thread will run.
		 */
		if (!wait)
			break;

		/* Display progress update in log view. */
		err = show_log_view(view);
		if (err != NULL)
			return err;
		update_panels();
		doupdate();

		/* Wait right here while next commit is being loaded. */
		errcode = pthread_cond_wait(&ta->commit_loaded, &tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_cond_wait");

		/* Display progress update in log view. */
		err = show_log_view(view);
		if (err != NULL)
			return err;
		update_panels();
		doupdate();
	}

	return NULL;
}

static const struct got_error *
request_log_commits(struct tog_view *view)
{
	struct tog_log_view_state	*state = &view->state.log;
	const struct got_error		*err = NULL;

	if (state->thread_args.log_complete)
		return NULL;

	state->thread_args.commits_needed += view->nscrolled;
	err = trigger_log_thread(view, 1);
	view->nscrolled = 0;

	return err;
}

static const struct got_error *
log_scroll_down(struct tog_view *view, int maxscroll)
{
	struct tog_log_view_state *s = &view->state.log;
	const struct got_error *err = NULL;
	struct commit_queue_entry *pentry;
	int nscrolled = 0, ncommits_needed;

	if (s->last_displayed_entry == NULL)
		return NULL;

	ncommits_needed = s->last_displayed_entry->idx + 2 + maxscroll;
	if (s->commits->ncommits < ncommits_needed &&
	    !s->thread_args.log_complete) {
		/*
		 * Ask the log thread for required amount of commits.
		 */
		s->thread_args.commits_needed +=
		    ncommits_needed - s->commits->ncommits;
		err = trigger_log_thread(view, 1);
		if (err)
			return err;
	}

	do {
		pentry = TAILQ_NEXT(s->last_displayed_entry, entry);
		if (pentry == NULL && view->mode != TOG_VIEW_SPLIT_HRZN)
			break;

		s->last_displayed_entry = pentry ?
		    pentry : s->last_displayed_entry;

		pentry = TAILQ_NEXT(s->first_displayed_entry, entry);
		if (pentry == NULL)
			break;
		s->first_displayed_entry = pentry;
	} while (++nscrolled < maxscroll);

	if (view->mode == TOG_VIEW_SPLIT_HRZN && !s->thread_args.log_complete)
		view->nscrolled += nscrolled;
	else
		view->nscrolled = 0;

	return err;
}

static const struct got_error *
open_diff_view_for_commit(struct tog_view **new_view, int begin_y, int begin_x,
    struct commit_queue_entry *entry, struct tog_view *log_view,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *p;
	struct got_object_id *parent_id;
	struct tog_view *diff_view;
	struct tog_log_view_state *ls = NULL;
	const char *worktree_root = NULL;

	diff_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_DIFF);
	if (diff_view == NULL)
		return got_error_from_errno("view_open");

	if (log_view != NULL) {
		ls = &log_view->state.log;
		worktree_root = ls->thread_args.wctx.wt_root;
	}

	if (ls != NULL && ls->marked_entry != NULL &&
	    ls->marked_entry != ls->selected_entry)
		parent_id = ls->marked_entry->id;
	else if (entry->worktree_entry == 0 &&
	    (p = STAILQ_FIRST(got_object_commit_get_parent_ids(entry->commit))))
		parent_id = &p->id;
	else
		parent_id = NULL;

	err = open_diff_view(diff_view, parent_id, entry->id, NULL, NULL, 3, 0,
	    0, 0, entry->worktree_entry, worktree_root, log_view, repo, NULL);
	if (err == NULL)
		*new_view = diff_view;
	return err;
}

static const struct got_error *
tree_view_visit_subtree(struct tog_tree_view_state *s,
    struct got_tree_object *subtree)
{
	struct tog_parent_tree *parent;

	parent = calloc(1, sizeof(*parent));
	if (parent == NULL)
		return got_error_from_errno("calloc");

	parent->tree = s->tree;
	parent->first_displayed_entry = s->first_displayed_entry;
	parent->selected_entry = s->selected_entry;
	parent->selected = s->selected;
	TAILQ_INSERT_HEAD(&s->parents, parent, entry);
	s->tree = subtree;
	s->selected = 0;
	s->first_displayed_entry = NULL;
	return NULL;
}

static const struct got_error *
tree_view_walk_path(struct tog_tree_view_state *s,
    struct got_commit_object *commit, const char *path)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree = NULL;
	const char *p;
	char *slash, *subpath = NULL;

	/* Walk the path and open corresponding tree objects. */
	p = path;
	while (*p) {
		struct got_tree_entry *te;
		struct got_object_id *tree_id;
		char *te_name;

		while (p[0] == '/')
			p++;

		/* Ensure the correct subtree entry is selected. */
		slash = strchr(p, '/');
		if (slash == NULL)
			te_name = strdup(p);
		else
			te_name = strndup(p, slash - p);
		if (te_name == NULL) {
			err = got_error_from_errno("strndup");
			break;
		}
		te = got_object_tree_find_entry(s->tree, te_name);
		if (te == NULL) {
			err = got_error_path(te_name, GOT_ERR_NO_TREE_ENTRY);
			free(te_name);
			break;
		}
		free(te_name);
		s->first_displayed_entry = s->selected_entry = te;

		if (!S_ISDIR(got_tree_entry_get_mode(s->selected_entry)))
			break; /* jump to this file's entry */

		slash = strchr(p, '/');
		if (slash)
			subpath = strndup(path, slash - path);
		else
			subpath = strdup(path);
		if (subpath == NULL) {
			err = got_error_from_errno("strdup");
			break;
		}

		err = got_object_id_by_path(&tree_id, s->repo, commit,
		    subpath);
		if (err)
			break;

		err = got_object_open_as_tree(&tree, s->repo, tree_id);
		free(tree_id);
		if (err)
			break;

		err = tree_view_visit_subtree(s, tree);
		if (err) {
			got_object_tree_close(tree);
			break;
		}
		if (slash == NULL)
			break;
		free(subpath);
		subpath = NULL;
		p = slash;
	}

	free(subpath);
	return err;
}

static const struct got_error *
browse_commit_tree(struct tog_view **new_view, int begin_y, int begin_x,
    struct commit_queue_entry *entry, const char *path,
    const char *head_ref_name, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s;
	struct tog_view *tree_view;
	struct got_commit_object *commit = NULL;
	struct got_object_id *commit_id;

	*new_view = NULL;

	if (entry->id != NULL)
		commit_id = entry->id;
	else if (entry->worktree_entry)
		commit_id = tog_base_commit.id;
	else /* cannot happen */
		return got_error(GOT_ERR_NOT_WORKTREE);

	tree_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_TREE);
	if (tree_view == NULL)
		return got_error_from_errno("view_open");

	err = open_tree_view(tree_view, commit_id, head_ref_name, repo);
	if (err)
		return err;
	s = &tree_view->state.tree;

	*new_view = tree_view;

	if (got_path_is_root_dir(path))
		return NULL;

	if (entry->worktree_entry) {
		err = got_object_open_as_commit(&commit, repo, commit_id);
		if (err != NULL)
			goto done;
	}

	err = tree_view_walk_path(s, commit ? commit : entry->commit, path);

done:
	if (commit != NULL)
		got_object_commit_close(commit);
	if (err != NULL) {
		view_close(tree_view);
		*new_view = NULL;
	}
	return err;
}

/*
 * If work tree entries have been pushed onto the commit queue and the
 * first commit entry is still displayed, scroll the view so the new
 * work tree entries are visible. If the selection cursor is still on
 * the first commit entry, keep the cursor in place such that the first
 * work tree entry is selected, otherwise move the selection cursor so
 * the currently selected commit stays selected if it remains on screen.
 */
static void
worktree_entries_reveal(struct tog_log_thread_args *a)
{
	struct commit_queue_entry	**first = a->first_displayed_entry;
	struct commit_queue_entry	**select = a->selected_entry;
	int				 *cursor = a->selected;
	int				  wts = a->wctx.wt_state;

#define select_worktree_entry(_first, _selected) do {			\
	*_first = TAILQ_FIRST(&a->real_commits->head);			\
	*_selected = *_first;						\
} while (0)

	if (first == NULL)
		select_worktree_entry(first, select);
	else if (*select == *first) {
		if (wts == TOG_WORKTREE_CHANGES_LOCAL && (*first)->idx == 1)
			select_worktree_entry(first, select);
		else if (wts == TOG_WORKTREE_CHANGES_STAGED &&
		    (*first)->idx == 1)
			select_worktree_entry(first, select);
		else if (wts & TOG_WORKTREE_CHANGES_ALL && (*first)->idx == 2)
			select_worktree_entry(first, select);
	} else if (wts & TOG_WORKTREE_CHANGES_ALL && (*first)->idx == 2) {
		*first = TAILQ_FIRST(&a->real_commits->head);
		if (*cursor + 2 < *a->view_nlines - 1)
			(*cursor) += 2;
		else if (*cursor + 1 < *a->view_nlines - 1) {
			*select = TAILQ_PREV(*select, commit_queue_head, entry);
			++(*cursor);
		} else {
			*select = TAILQ_PREV(*select, commit_queue_head, entry);
			*select = TAILQ_PREV(*select, commit_queue_head, entry);
		}
	} else if (wts != 0 && (*first)->idx == 1) {
		*first = TAILQ_FIRST(&a->real_commits->head);
		if (*cursor + 1 < *a->view_nlines - 1)
			++(*cursor);
		else
			*select = TAILQ_PREV(*select, commit_queue_head, entry);
	}
#undef select_worktree_entry
}

static const struct got_error *
block_signals_used_by_main_thread(void)
{
	sigset_t sigset;
	int errcode;

	if (sigemptyset(&sigset) == -1)
		return got_error_from_errno("sigemptyset");

	/* tog handles SIGWINCH, SIGCONT, SIGINT, SIGTERM */
	if (sigaddset(&sigset, SIGWINCH) == -1)
		return got_error_from_errno("sigaddset");
	if (sigaddset(&sigset, SIGCONT) == -1)
		return got_error_from_errno("sigaddset");
	if (sigaddset(&sigset, SIGINT) == -1)
		return got_error_from_errno("sigaddset");
	if (sigaddset(&sigset, SIGTERM) == -1)
		return got_error_from_errno("sigaddset");

	/* ncurses handles SIGTSTP */
	if (sigaddset(&sigset, SIGTSTP) == -1)
		return got_error_from_errno("sigaddset");

	errcode = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_sigmask");

	return NULL;
}

static void *
log_thread(void *arg)
{
	const struct got_error *err = NULL;
	int errcode = 0;
	struct tog_log_thread_args *a = arg;
	int done = 0;

	/*
	 * Sync startup with main thread such that we begin our
	 * work once view_input() has released the mutex.
	 */
	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode) {
		err = got_error_set_errno(errcode, "pthread_mutex_lock");
		return (void *)err;
	}

	err = block_signals_used_by_main_thread();
	if (err) {
		pthread_mutex_unlock(&tog_mutex);
		goto done;
	}

	while (!done && !err && !tog_fatal_signal_received()) {
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode) {
			err = got_error_set_errno(errcode,
			    "pthread_mutex_unlock");
			goto done;
		}
		err = queue_commits(a);
		if (err) {
			if (err->code != GOT_ERR_ITER_COMPLETED)
				goto done;
			err = NULL;
			done = 1;
			a->commits_needed = 0;
		} else if (a->commits_needed > 0 && !a->load_all) {
			if (*a->limiting) {
				if (a->limit_match)
					a->commits_needed--;
			} else
				a->commits_needed--;
		}

		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode) {
			err = got_error_set_errno(errcode,
			    "pthread_mutex_lock");
			goto done;
		} else if (*a->quit)
			done = 1;
		else if (*a->limiting && *a->first_displayed_entry == NULL) {
			*a->first_displayed_entry =
			    TAILQ_FIRST(&a->limit_commits->head);
			*a->selected_entry = *a->first_displayed_entry;
		} else if (*a->first_displayed_entry == NULL) {
			*a->first_displayed_entry =
			    TAILQ_FIRST(&a->real_commits->head);
			*a->selected_entry = *a->first_displayed_entry;
		}
		if (done)
			a->log_complete = 1;

		errcode = pthread_cond_signal(&a->commit_loaded);
		if (errcode) {
			err = got_error_set_errno(errcode,
			    "pthread_cond_signal");
			pthread_mutex_unlock(&tog_mutex);
			goto done;
		}

		if (a->commits_needed == 0 && a->need_wt_status) {
			errcode = pthread_mutex_unlock(&tog_mutex);
			if (errcode) {
				err = got_error_set_errno(errcode,
				    "pthread_mutex_unlock");
				goto done;
			}
			err = tog_worktree_status(a);
			if (err != NULL) {
				if (err->code == GOT_ERR_CANCELLED)
					err = NULL;
				goto done;
			}
			errcode = pthread_mutex_lock(&tog_mutex);
			if (errcode) {
				err = got_error_set_errno(errcode,
				    "pthread_mutex_lock");
				goto done;
			}
			if (a->wctx.wt_state != 0)
				worktree_entries_reveal(a);
			a->need_wt_status = 0;
		}

		if (a->commits_needed == 0 &&
		    a->need_commit_marker && a->worktree) {
			errcode = pthread_mutex_unlock(&tog_mutex);
			if (errcode) {
				err = got_error_set_errno(errcode,
				    "pthread_mutex_unlock");
				goto done;
			}
			err = got_worktree_get_state(&tog_base_commit.marker,
			    a->repo, a->worktree, NULL, NULL);
			if (err)
				goto done;
			errcode = pthread_mutex_lock(&tog_mutex);
			if (errcode) {
				err = got_error_set_errno(errcode,
				    "pthread_mutex_lock");
				goto done;
			}
			a->need_commit_marker = 0;
			/*
			 * The main thread did not close this
			 * work tree yet. Close it now.
			 */
			got_worktree_close(a->worktree);
			a->worktree = NULL;

			if (*a->quit)
				done = 1;
		}

		if (done)
			a->commits_needed = 0;
		else {
			if (a->commits_needed == 0 && !a->load_all) {
				if (tog_io.wait_for_ui) {
					errcode = pthread_cond_signal(
					    &a->log_loaded);
					if (errcode) {
						err = got_error_set_errno(
						    errcode,
						    "pthread_cond_signal");
						pthread_mutex_unlock(
						    &tog_mutex);
						goto done;
					}
				}

				errcode = pthread_cond_wait(&a->need_commits,
				    &tog_mutex);
				if (errcode) {
					err = got_error_set_errno(errcode,
					    "pthread_cond_wait");
					pthread_mutex_unlock(&tog_mutex);
					goto done;
				}
				if (*a->quit)
					done = 1;
			}
		}
	}
	a->log_complete = 1;
	if (tog_io.wait_for_ui) {
		errcode = pthread_cond_signal(&a->log_loaded);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode,
			    "pthread_cond_signal");
	}

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		err = got_error_set_errno(errcode, "pthread_mutex_unlock");
done:
	if (err) {
		tog_thread_error = 1;
		pthread_cond_signal(&a->commit_loaded);
		if (a->worktree) {
			got_worktree_close(a->worktree);
			a->worktree = NULL;
		}
	}
	return (void *)err;
}

static const struct got_error *
stop_log_thread(struct tog_log_view_state *s)
{
	const struct got_error *err = NULL, *thread_err = NULL;
	int errcode;

	if (s->thread) {
		s->quit = 1;
		errcode = pthread_cond_signal(&s->thread_args.need_commits);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_cond_signal");
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_unlock");
		errcode = pthread_join(s->thread, (void **)&thread_err);
		if (errcode)
			return got_error_set_errno(errcode, "pthread_join");
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_lock");
		s->thread = 0; //NULL;
	}

	if (s->thread_args.repo) {
		err = got_repo_close(s->thread_args.repo);
		s->thread_args.repo = NULL;
	}

	if (s->thread_args.pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(s->thread_args.pack_fds);
		if (err == NULL)
			err = pack_err;
		s->thread_args.pack_fds = NULL;
	}

	if (s->thread_args.graph) {
		got_commit_graph_close(s->thread_args.graph);
		s->thread_args.graph = NULL;
	}

	return err ? err : thread_err;
}

static void
worktree_ctx_close(struct tog_log_thread_args *ta)
{
	struct tog_worktree_ctx *wctx = &ta->wctx;

	if (wctx->active) {
		free(wctx->wt_author);
		wctx->wt_author = NULL;
		free(wctx->wt_root);
		wctx->wt_root = NULL;
		free(wctx->wt_ref);
		wctx->wt_ref = NULL;
		wctx->wt_state = 0;
		ta->need_wt_status = 1;
	}
}

static const struct got_error *
close_log_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	int errcode;

	log_mark_clear(s);

	err = stop_log_thread(s);

	errcode = pthread_cond_destroy(&s->thread_args.need_commits);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode, "pthread_cond_destroy");

	errcode = pthread_cond_destroy(&s->thread_args.commit_loaded);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode, "pthread_cond_destroy");

	if (using_mock_io) {
		errcode = pthread_cond_destroy(&s->thread_args.log_loaded);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode,
			    "pthread_cond_destroy");
	}

	free_commits(&s->limit_commits);
	free_commits(&s->real_commits);
	free_colors(&s->colors);
	free(s->in_repo_path);
	s->in_repo_path = NULL;
	free(s->start_id);
	s->start_id = NULL;
	free(s->head_ref_name);
	s->head_ref_name = NULL;
	worktree_ctx_close(&s->thread_args);
	return err;
}

/*
 * We use two queues to implement the limit feature: first consists of
 * commits matching the current limit_regex; second is the real queue
 * of all known commits (real_commits). When the user starts limiting,
 * we swap queues such that all movement and displaying functionality
 * works with very slight change.
 */
static const struct got_error *
limit_log_view(struct tog_view *view)
{
	struct tog_log_view_state *s = &view->state.log;
	struct commit_queue_entry *entry;
	struct tog_view	*v = view;
	const struct got_error *err = NULL;
	char pattern[1024];
	int ret;

	if (view_is_hsplit_top(view))
		v = view->child;
	else if (view->mode == TOG_VIEW_SPLIT_VERT && view->parent)
		v = view->parent;

	if (tog_io.input_str != NULL) {
		if (strlcpy(pattern, tog_io.input_str, sizeof(pattern)) >=
		    sizeof(pattern))
			return got_error(GOT_ERR_NO_SPACE);
	} else {
		wmove(v->window, v->nlines - 1, 0);
		wclrtoeol(v->window);
		mvwaddstr(v->window, v->nlines - 1, 0, "&/");
		nodelay(v->window, FALSE);
		nocbreak();
		echo();
		ret = wgetnstr(v->window, pattern, sizeof(pattern));
		cbreak();
		noecho();
		nodelay(v->window, TRUE);
		if (ret == ERR)
			return NULL;
	}

	if (*pattern == '\0') {
		/*
		 * Safety measure for the situation where the user
		 * resets limit without previously limiting anything.
		 */
		if (!s->limit_view)
			return NULL;

		/*
		 * User could have pressed Ctrl+L, which refreshed the
		 * commit queues, it means we can't save previously
		 * (before limit took place) displayed entries,
		 * because they would point to already free'ed memory,
		 * so we are forced to always select first entry of
		 * the queue.
		 */
		s->commits = &s->real_commits;
		s->first_displayed_entry = TAILQ_FIRST(&s->real_commits.head);
		s->selected_entry = s->first_displayed_entry;
		s->selected = 0;
		s->limit_view = 0;

		return NULL;
	}

	if (regcomp(&s->limit_regex, pattern, REG_EXTENDED | REG_NEWLINE))
		return NULL;

	s->limit_view = 1;

	/* Clear the screen while loading limit view */
	s->first_displayed_entry = NULL;
	s->last_displayed_entry = NULL;
	s->selected_entry = NULL;
	s->commits = &s->limit_commits;

	/* Prepare limit queue for new search */
	free_commits(&s->limit_commits);
	s->limit_commits.ncommits = 0;

	/* First process commits, which are in queue already */
	TAILQ_FOREACH(entry, &s->real_commits.head, entry) {
		int have_match = 0;

		if (entry->worktree_entry == 0) {
			err = match_commit(&have_match, entry->id,
			    entry->commit, &s->limit_regex);
			if (err)
				return err;
		}

		if (have_match) {
			struct commit_queue_entry *matched;

			matched = alloc_commit_queue_entry(entry->commit,
			    entry->id);
			if (matched == NULL) {
				err = got_error_from_errno(
				    "alloc_commit_queue_entry");
				break;
			}
			matched->commit = entry->commit;
			got_object_commit_retain(entry->commit);

			matched->idx = s->limit_commits.ncommits;
			TAILQ_INSERT_TAIL(&s->limit_commits.head,
			    matched, entry);
			s->limit_commits.ncommits++;
		}
	}

	/* Second process all the commits, until we fill the screen */
	if (s->limit_commits.ncommits < view->nlines - 1 &&
	    !s->thread_args.log_complete) {
		s->thread_args.commits_needed +=
		    view->nlines - s->limit_commits.ncommits - 1;
		err = trigger_log_thread(view, 1);
		if (err)
			return err;
	}

	s->first_displayed_entry = TAILQ_FIRST(&s->commits->head);
	s->selected_entry = TAILQ_FIRST(&s->commits->head);
	s->selected = 0;

	return NULL;
}

static const struct got_error *
search_start_log_view(struct tog_view *view)
{
	struct tog_log_view_state *s = &view->state.log;

	s->matched_entry = NULL;
	s->search_entry = NULL;
	return NULL;
}

static const struct got_error *
search_next_log_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	struct commit_queue_entry *entry;

	/* Display progress update in log view. */
	err = show_log_view(view);
	if (err != NULL)
		return err;
	update_panels();
	doupdate();

	if (s->search_entry) {
		if (!using_mock_io) {
			int errcode, ch;

			errcode = pthread_mutex_unlock(&tog_mutex);
			if (errcode)
				return got_error_set_errno(errcode,
				    "pthread_mutex_unlock");
			ch = wgetch(view->window);
			errcode = pthread_mutex_lock(&tog_mutex);
			if (errcode)
				return got_error_set_errno(errcode,
				    "pthread_mutex_lock");
			if (ch == CTRL('g') || ch == KEY_BACKSPACE) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				return NULL;
			}
		}
		if (view->searching == TOG_SEARCH_FORWARD)
			entry = TAILQ_NEXT(s->search_entry, entry);
		else
			entry = TAILQ_PREV(s->search_entry,
			    commit_queue_head, entry);
	} else if (s->matched_entry) {
		/*
		 * If the user has moved the cursor after we hit a match,
		 * the position from where we should continue searching
		 * might have changed.
		 */
		if (view->searching == TOG_SEARCH_FORWARD)
			entry = TAILQ_NEXT(s->selected_entry, entry);
		else
			entry = TAILQ_PREV(s->selected_entry, commit_queue_head,
			    entry);
	} else {
		entry = s->selected_entry;
	}

	while (1) {
		int have_match = 0;

		if (entry == NULL) {
			if (s->thread_args.log_complete ||
			    view->searching == TOG_SEARCH_BACKWARD) {
				view->search_next_done =
				    (s->matched_entry == NULL ?
				    TOG_SEARCH_HAVE_NONE : TOG_SEARCH_NO_MORE);
				s->search_entry = NULL;
				return NULL;
			}
			/*
			 * Poke the log thread for more commits and return,
			 * allowing the main loop to make progress. Search
			 * will resume at s->search_entry once we come back.
			 */
			s->search_entry = s->selected_entry;
			s->thread_args.commits_needed++;
			return trigger_log_thread(view, 0);
		}

		if (entry->worktree_entry == 0) {
			err = match_commit(&have_match, entry->id,
			    entry->commit, &view->regex);
			if (err)
				break;
			if (have_match) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				s->matched_entry = entry;
				break;
			}
		}

		s->search_entry = entry;
		if (view->searching == TOG_SEARCH_FORWARD)
			entry = TAILQ_NEXT(entry, entry);
		else
			entry = TAILQ_PREV(entry, commit_queue_head, entry);
	}

	if (s->matched_entry) {
		int cur = s->selected_entry->idx;
		while (cur < s->matched_entry->idx) {
			err = input_log_view(NULL, view, KEY_DOWN);
			if (err)
				return err;
			cur++;
		}
		while (cur > s->matched_entry->idx) {
			err = input_log_view(NULL, view, KEY_UP);
			if (err)
				return err;
			cur--;
		}
	}

	s->search_entry = NULL;

	return NULL;
}

static const struct got_error *
open_log_view(struct tog_view *view, struct got_object_id *start_id,
    struct got_repository *repo, const char *head_ref_name,
    const char *in_repo_path, int log_branches,
    struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	struct got_repository *thread_repo = NULL;
	struct got_commit_graph *thread_graph = NULL;
	int errcode;

	if (in_repo_path != s->in_repo_path) {
		free(s->in_repo_path);
		s->in_repo_path = strdup(in_repo_path);
		if (s->in_repo_path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	/* The commit queue only contains commits being displayed. */
	TAILQ_INIT(&s->real_commits.head);
	s->real_commits.ncommits = 0;
	s->commits = &s->real_commits;

	TAILQ_INIT(&s->limit_commits.head);
	s->limit_view = 0;
	s->limit_commits.ncommits = 0;

	s->repo = repo;
	if (head_ref_name) {
		s->head_ref_name = strdup(head_ref_name);
		if (s->head_ref_name == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
	s->start_id = got_object_id_dup(start_id);
	if (s->start_id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}
	s->log_branches = log_branches;
	s->use_committer = 1;

	STAILQ_INIT(&s->colors);
	if (has_colors() && getenv("TOG_COLORS") != NULL) {
		err = add_color(&s->colors, "^$", TOG_COLOR_COMMIT,
		    get_color_value("TOG_COLOR_COMMIT"));
		if (err)
			goto done;
		err = add_color(&s->colors, "^$", TOG_COLOR_AUTHOR,
		    get_color_value("TOG_COLOR_AUTHOR"));
		if (err)
			goto done;
		err = add_color(&s->colors, "^$", TOG_COLOR_DATE,
		    get_color_value("TOG_COLOR_DATE"));
		if (err)
			goto done;
	}

	view->show = show_log_view;
	view->input = input_log_view;
	view->resize = resize_log_view;
	view->close = close_log_view;
	view->search_start = search_start_log_view;
	view->search_next = search_next_log_view;

	if (s->thread_args.pack_fds == NULL) {
		err = got_repo_pack_fds_open(&s->thread_args.pack_fds);
		if (err)
			goto done;
	}
	err = got_repo_open(&thread_repo, got_repo_get_path(repo), NULL,
	    s->thread_args.pack_fds);
	if (err)
		goto done;
	err = got_commit_graph_open(&thread_graph, s->in_repo_path,
	    !s->log_branches);
	if (err)
		goto done;
	err = got_commit_graph_bfsort(thread_graph, s->start_id,
	    s->repo, NULL, NULL);
	if (err)
		goto done;

	errcode = pthread_cond_init(&s->thread_args.need_commits, NULL);
	if (errcode) {
		err = got_error_set_errno(errcode, "pthread_cond_init");
		goto done;
	}
	errcode = pthread_cond_init(&s->thread_args.commit_loaded, NULL);
	if (errcode) {
		err = got_error_set_errno(errcode, "pthread_cond_init");
		goto done;
	}

	if (using_mock_io) {
		int rc;

		rc = pthread_cond_init(&s->thread_args.log_loaded, NULL);
		if (rc)
			return got_error_set_errno(rc, "pthread_cond_init");
	}

	s->thread_args.view_nlines = &view->nlines;
	s->thread_args.commits_needed = view->nlines;
	s->thread_args.graph = thread_graph;
	s->thread_args.real_commits = &s->real_commits;
	s->thread_args.limit_commits = &s->limit_commits;
	s->thread_args.in_repo_path = s->in_repo_path;
	s->thread_args.start_id = s->start_id;
	s->thread_args.repo = thread_repo;
	s->thread_args.log_complete = 0;
	s->thread_args.quit = &s->quit;
	s->thread_args.first_displayed_entry = &s->first_displayed_entry;
	s->thread_args.last_displayed_entry = &s->last_displayed_entry;
	s->thread_args.selected_entry = &s->selected_entry;
	s->thread_args.selected = &s->selected;
	s->thread_args.searching = &view->searching;
	s->thread_args.search_next_done = &view->search_next_done;
	s->thread_args.regex = &view->regex;
	s->thread_args.limiting = &s->limit_view;
	s->thread_args.limit_regex = &s->limit_regex;
	s->thread_args.limit_commits = &s->limit_commits;
	s->thread_args.worktree = worktree;
	if (worktree) {
		s->thread_args.wctx.active = 1;
		s->thread_args.need_wt_status = 1;
		s->thread_args.need_commit_marker = 1;
	}

done:
	if (err) {
		if (view->close == NULL)
			close_log_view(view);
		view_close(view);
	}
	return err;
}

static const struct got_error *
show_log_view(struct tog_view *view)
{
	const struct got_error *err;
	struct tog_log_view_state *s = &view->state.log;

	if (s->thread == 0) { //NULL) {
		int errcode = pthread_create(&s->thread, NULL, log_thread,
		    &s->thread_args);
		if (errcode)
			return got_error_set_errno(errcode, "pthread_create");
		if (s->thread_args.commits_needed > 0) {
			err = trigger_log_thread(view, 1);
			if (err)
				return err;
		}
	}

	return draw_commits(view);
}

static void
log_move_cursor_up(struct tog_view *view, int page, int home)
{
	struct tog_log_view_state *s = &view->state.log;

	if (s->first_displayed_entry == NULL)
		return;
	if (s->selected_entry->idx == 0)
		view->count = 0;

	if ((page && TAILQ_FIRST(&s->commits->head) == s->first_displayed_entry)
	    || home)
		s->selected = home ? 0 : MAX(0, s->selected - page - 1);

	if (!page && !home && s->selected > 0)
		--s->selected;
	else
		log_scroll_up(s, home ? s->commits->ncommits : MAX(page, 1));

	select_commit(s);
	return;
}

static const struct got_error *
log_move_cursor_down(struct tog_view *view, int page)
{
	struct tog_log_view_state	*s = &view->state.log;
	const struct got_error		*err = NULL;
	int				 eos = view->nlines - 2;

	if (s->first_displayed_entry == NULL)
		return NULL;

	if (s->thread_args.log_complete &&
	    s->selected_entry->idx >= s->commits->ncommits - 1)
		return NULL;

	if (view_is_hsplit_top(view))
		--eos;  /* border consumes the last line */

	if (!page) {
		if (s->selected < MIN(eos, s->commits->ncommits - 1))
			++s->selected;
		else
			err = log_scroll_down(view, 1);
	} else if (s->thread_args.load_all && s->thread_args.log_complete) {
		struct commit_queue_entry *entry;
		int n;

		s->selected = 0;
		entry = TAILQ_LAST(&s->commits->head, commit_queue_head);
		s->last_displayed_entry = entry;
		for (n = 0; n <= eos; n++) {
			if (entry == NULL)
				break;
			s->first_displayed_entry = entry;
			entry = TAILQ_PREV(entry, commit_queue_head, entry);
		}
		if (n > 0)
			s->selected = n - 1;
	} else {
		if (s->last_displayed_entry->idx == s->commits->ncommits - 1 &&
		    s->thread_args.log_complete)
			s->selected += MIN(page,
			    s->commits->ncommits - s->selected_entry->idx - 1);
		else
			err = log_scroll_down(view, page);
	}
	if (err)
		return err;

	/*
	 * We might necessarily overshoot in horizontal
	 * splits; if so, select the last displayed commit.
	 */
	if (view_is_hsplit_top(view) && s->first_displayed_entry &&
	    s->last_displayed_entry) {
		s->selected = MIN(s->selected,
		    s->last_displayed_entry->idx -
		    s->first_displayed_entry->idx);
	}

	select_commit(s);

	if (s->thread_args.log_complete &&
	    s->selected_entry->idx == s->commits->ncommits - 1)
		view->count = 0;

	return NULL;
}

static void
view_get_split(struct tog_view *view, int *y, int *x)
{
	*x = 0;
	*y = 0;

	if (view->mode == TOG_VIEW_SPLIT_HRZN) {
		if (view->child && view->child->resized_y)
			*y = view->child->resized_y;
		else if (view->resized_y)
			*y = view->resized_y;
		else
			*y = view_split_begin_y(view->lines);
	} else if (view->mode == TOG_VIEW_SPLIT_VERT) {
		if (view->child && view->child->resized_x)
			*x = view->child->resized_x;
		else if (view->resized_x)
			*x = view->resized_x;
		else
			*x = view_split_begin_x(view->begin_x);
	}
}

/* Split view horizontally at y and offset view->state->selected line. */
static const struct got_error *
view_init_hsplit(struct tog_view *view, int y)
{
	const struct got_error *err = NULL;

	view->nlines = y;
	view->ncols = COLS;
	err = view_resize(view);
	if (err)
		return err;

	err = offset_selection_down(view);

	return err;
}

static const struct got_error *
log_goto_line(struct tog_view *view, int nlines)
{
	const struct got_error		*err = NULL;
	struct tog_log_view_state	*s = &view->state.log;
	int				 g, idx = s->selected_entry->idx;

	if (s->first_displayed_entry == NULL || s->last_displayed_entry == NULL)
		return NULL;

	g = view->gline;
	view->gline = 0;

	if (g >= s->first_displayed_entry->idx + 1 &&
	    g <= s->last_displayed_entry->idx + 1 &&
	    g - s->first_displayed_entry->idx - 1 < nlines) {
		s->selected = g - s->first_displayed_entry->idx - 1;
		select_commit(s);
		return NULL;
	}

	if (idx + 1 < g) {
		err = log_move_cursor_down(view, g - idx - 1);
		if (!err && g > s->selected_entry->idx + 1)
			err = log_move_cursor_down(view,
			    g - s->first_displayed_entry->idx - 1);
		if (err)
			return err;
	} else if (idx + 1 > g)
		log_move_cursor_up(view, idx - g + 1, 0);

	if (g < nlines && s->first_displayed_entry->idx == 0)
		s->selected = g - 1;

	select_commit(s);
	return NULL;

}

static void
horizontal_scroll_input(struct tog_view *view, int ch)
{

	switch (ch) {
	case KEY_LEFT:
	case 'h':
		view->x -= MIN(view->x, 2);
		if (view->x <= 0)
			view->count = 0;
		break;
	case KEY_RIGHT:
	case 'l':
		if (view->x + view->ncols / 2 < view->maxx)
			view->x += 2;
		else
			view->count = 0;
		break;
	case '0':
		view->x = 0;
		break;
	case '$':
		view->x = MAX(view->maxx - view->ncols / 2, 0);
		view->count = 0;
		break;
	default:
		break;
	}
}

static void
log_mark_commit(struct tog_log_view_state *s)
{
	if (s->selected_entry == s->marked_entry)
		s->marked_entry = NULL;
	else
		s->marked_entry = s->selected_entry;
}

static const struct got_error *
input_log_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	int eos, nscroll;

	if (s->thread_args.load_all) {
		if (ch == CTRL('g') || ch == KEY_BACKSPACE)
			s->thread_args.load_all = 0;
		else if (s->thread_args.log_complete) {
			err = log_move_cursor_down(view, s->commits->ncommits);
			s->thread_args.load_all = 0;
		}
		if (err)
			return err;
	}

	eos = nscroll = view->nlines - 1;
	if (view_is_hsplit_top(view))
		--eos;  /* border */

	if (view->gline)
		return log_goto_line(view, eos);

	switch (ch) {
	case '&':
		view->count = 0;
		err = limit_log_view(view);
		break;
	case 'q':
		s->quit = 1;
		break;
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'k':
	case KEY_UP:
	case '<':
	case ',':
	case CTRL('p'):
		log_move_cursor_up(view, 0, 0);
		break;
	case 'g':
	case '=':
	case KEY_HOME:
		log_move_cursor_up(view, 0, 1);
		view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		log_move_cursor_up(view, nscroll, 0);
		break;
	case 'j':
	case KEY_DOWN:
	case '>':
	case '.':
	case CTRL('n'):
		err = log_move_cursor_down(view, 0);
		break;
	case '@':
		s->use_committer = !s->use_committer;
		view->action = s->use_committer ?
		    "show committer" : "show commit author";
		break;
	case 'G':
	case '*':
	case KEY_END: {
		/* We don't know yet how many commits, so we're forced to
		 * traverse them all. */
		view->count = 0;
		s->thread_args.load_all = 1;
		if (!s->thread_args.log_complete)
			return trigger_log_thread(view, 0);
		err = log_move_cursor_down(view, s->commits->ncommits);
		s->thread_args.load_all = 0;
		break;
	}
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		err = log_move_cursor_down(view, nscroll);
		break;
	case KEY_RESIZE:
		if (s->selected > view->nlines - 2)
			s->selected = view->nlines - 2;
		if (s->selected > s->commits->ncommits - 1)
			s->selected = s->commits->ncommits - 1;
		select_commit(s);
		if (s->commits->ncommits < view->nlines - 1 &&
		    !s->thread_args.log_complete) {
			s->thread_args.commits_needed += (view->nlines - 1) -
			    s->commits->ncommits;
			err = trigger_log_thread(view, 1);
		}
		break;
	case KEY_ENTER:
	case '\r':
		view->count = 0;
		if (s->selected_entry == NULL)
			break;
		err = view_request_new(new_view, view, TOG_VIEW_DIFF);
		break;
	case 'T':
		view->count = 0;
		if (s->selected_entry == NULL)
			break;
		err = view_request_new(new_view, view, TOG_VIEW_TREE);
		break;
	case KEY_BACKSPACE:
	case CTRL('l'):
	case 'B':
		view->count = 0;
		if (ch == KEY_BACKSPACE &&
		    got_path_is_root_dir(s->in_repo_path))
			break;
		err = stop_log_thread(s);
		if (err)
			return err;
		if (ch == KEY_BACKSPACE) {
			char *parent_path;
			err = got_path_dirname(&parent_path, s->in_repo_path);
			if (err)
				return err;
			free(s->in_repo_path);
			s->in_repo_path = parent_path;
			s->thread_args.in_repo_path = s->in_repo_path;
		} else if (ch == CTRL('l')) {
			struct got_object_id *start_id;
			err = got_repo_match_object_id(&start_id, NULL,
			    s->head_ref_name ? s->head_ref_name : GOT_REF_HEAD,
			    GOT_OBJ_TYPE_COMMIT, &tog_refs, s->repo);
			if (err) {
				if (s->head_ref_name == NULL ||
				    err->code != GOT_ERR_NOT_REF)
					return err;
				/* Try to cope with deleted references. */
				free(s->head_ref_name);
				s->head_ref_name = NULL;
				err = got_repo_match_object_id(&start_id,
				    NULL, GOT_REF_HEAD, GOT_OBJ_TYPE_COMMIT,
				    &tog_refs, s->repo);
				if (err)
					return err;
			}
			free(s->start_id);
			s->start_id = start_id;
			s->thread_args.start_id = s->start_id;
		} else /* 'B' */
			s->log_branches = !s->log_branches;

		if (s->thread_args.pack_fds == NULL) {
			err = got_repo_pack_fds_open(&s->thread_args.pack_fds);
			if (err)
				return err;
		}
		err = got_repo_open(&s->thread_args.repo,
		    got_repo_get_path(s->repo), NULL,
		    s->thread_args.pack_fds);
		if (err)
			return err;
		tog_free_refs();
		err = tog_load_refs(s->repo, 0);
		if (err)
			return err;
		err = got_commit_graph_open(&s->thread_args.graph,
		    s->in_repo_path, !s->log_branches);
		if (err)
			return err;
		err = got_commit_graph_bfsort(s->thread_args.graph,
		    s->start_id, s->repo, NULL, NULL);
		if (err)
			return err;
		free_commits(&s->real_commits);
		free_commits(&s->limit_commits);
		s->first_displayed_entry = NULL;
		s->last_displayed_entry = NULL;
		s->selected_entry = NULL;
		s->selected = 0;
		s->thread_args.log_complete = 0;
		s->quit = 0;
		s->thread_args.commits_needed = view->lines;
		s->matched_entry = NULL;
		s->search_entry = NULL;
		tog_base_commit.idx = -1;
		worktree_ctx_close(&s->thread_args);
		view->offset = 0;
		break;
	case 'm':
		if (s->selected_entry->worktree_entry == 0)
			log_mark_commit(s);
		break;
	case 'R':
		view->count = 0;
		err = view_request_new(new_view, view, TOG_VIEW_REF);
		break;
	default:
		view->count = 0;
		break;
	}

	return err;
}

static const struct got_error *
apply_unveil(const char *repo_path, const char *worktree_path)
{
	const struct got_error *error;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, "r") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (worktree_path && unveil(worktree_path, "rwc") != 0)
		return got_error_from_errno2("unveil", worktree_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

	error = got_privsep_unveil_exec_helpers();
	if (error != NULL)
		return error;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
init_mock_term(const char *test_script_path)
{
	const struct got_error	*err = NULL;
	const char *screen_dump_path;
	int in;

	if (test_script_path == NULL || *test_script_path == '\0')
		return got_error_msg(GOT_ERR_IO, "TOG_TEST_SCRIPT not defined");

	tog_io.f = fopen(test_script_path, "re");
	if (tog_io.f == NULL) {
		err = got_error_from_errno_fmt("fopen: %s",
		    test_script_path);
		goto done;
	}

	/* test mode, we don't want any output */
	tog_io.cout = fopen("/dev/null", "w+");
	if (tog_io.cout == NULL) {
		err = got_error_from_errno2("fopen", "/dev/null");
		goto done;
	}

	in = dup(fileno(tog_io.cout));
	if (in == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	tog_io.cin = fdopen(in, "r");
	if (tog_io.cin == NULL) {
		err = got_error_from_errno("fdopen");
		close(in);
		goto done;
	}

	screen_dump_path = getenv("TOG_SCR_DUMP");
	if (screen_dump_path == NULL || *screen_dump_path == '\0')
		return got_error_msg(GOT_ERR_IO, "TOG_SCR_DUMP not defined");
	tog_io.sdump = fopen(screen_dump_path, "we");
	if (tog_io.sdump == NULL) {
		err = got_error_from_errno2("fopen", screen_dump_path);
		goto done;
	}

	if (fseeko(tog_io.f, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	if (newterm(NULL, tog_io.cout, tog_io.cin) == NULL)
		err = got_error_msg(GOT_ERR_IO,
		    "newterm: failed to initialise curses");

	using_mock_io = 1;

done:
	if (err)
		tog_io_close();
	return err;
}

static void
init_curses(void)
{
	if (using_mock_io) /* In test mode we use a fake terminal */
		return;

	initscr();

	cbreak();
	halfdelay(1); /* Fast refresh while initial view is loading. */
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	curs_set(0);
	if (getenv("TOG_COLORS") != NULL) {
		start_color();
		use_default_colors();
	}

	return;
}

static const struct got_error *
set_tog_base_commit(struct got_repository *repo, struct got_worktree *worktree)
{
	tog_base_commit.id = got_object_id_dup(
	    got_worktree_get_base_commit_id(worktree));
	if (tog_base_commit.id == NULL)
		return got_error_from_errno( "got_object_id_dup");

	return NULL;
}

static const struct got_error *
get_in_repo_path_from_argv0(char **in_repo_path, int argc, char *argv[],
    struct got_repository *repo, struct got_worktree *worktree)
{
	const struct got_error *err = NULL;

	if (argc == 0) {
		*in_repo_path = strdup("/");
		if (*in_repo_path == NULL)
			return got_error_from_errno("strdup");
		return NULL;
	}

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p;

		err = got_worktree_resolve_path(&p, worktree, argv[0]);
		if (err)
			return err;
		if (asprintf(in_repo_path, "%s%s%s", prefix,
		    (p[0] != '\0' && !got_path_is_root_dir(prefix)) ? "/" : "",
		    p) == -1) {
			err = got_error_from_errno("asprintf");
			*in_repo_path = NULL;
		}
		free(p);
	} else
		err = got_repo_map_path(in_repo_path, repo, argv[0]);

	return err;
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_object_id *start_id = NULL;
	char *in_repo_path = NULL, *repo_path = NULL, *cwd = NULL;
	char *keyword_idstr = NULL, *start_commit = NULL, *label = NULL;
	struct got_reference *ref = NULL;
	const char *head_ref_name = NULL;
	int ch, log_branches = 0;
	struct tog_view *view;
	int *pack_fds = NULL;

	while ((ch = getopt(argc, argv, "bc:r:")) != -1) {
		switch (ch) {
		case 'b':
			log_branches = 1;
			break;
		case 'c':
			start_commit = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			break;
		default:
			usage_log(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage_log(1);

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL) {
			error = got_error_from_errno("getcwd");
			goto done;
		}
		error = got_worktree_open(&worktree, cwd, NULL);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree)
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
		else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = get_in_repo_path_from_argv0(&in_repo_path, argc, argv,
	    repo, worktree);
	if (error)
		goto done;

	init_curses();

	error = apply_unveil(got_repo_get_path(repo),
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	/* already loaded by tog_log_with_path()? */
	if (TAILQ_EMPTY(&tog_refs)) {
		error = tog_load_refs(repo, 0);
		if (error)
			goto done;
	}

	if (start_commit == NULL) {
		error = got_repo_match_object_id(&start_id, &label,
		    worktree ? got_worktree_get_head_ref_name(worktree) :
		    GOT_REF_HEAD, GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
		if (error)
			goto done;
		head_ref_name = label;
	} else {
		error = got_keyword_to_idstr(&keyword_idstr, start_commit,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			start_commit = keyword_idstr;

		error = got_ref_open(&ref, repo, start_commit, 0);
		if (error == NULL)
			head_ref_name = got_ref_get_name(ref);
		else if (error->code != GOT_ERR_NOT_REF)
			goto done;
		error = got_repo_match_object_id(&start_id, NULL,
		    start_commit, GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
		if (error)
			goto done;
	}

	view = view_open(0, 0, 0, 0, TOG_VIEW_LOG);
	if (view == NULL) {
		error = got_error_from_errno("view_open");
		goto done;
	}

	if (worktree) {
		error = set_tog_base_commit(repo, worktree);
		if (error != NULL)
			goto done;
	}

	error = open_log_view(view, start_id, repo, head_ref_name,
	    in_repo_path, log_branches, worktree);
	if (error)
		goto done;

	if (worktree) {
		/* The work tree will be closed by the log thread. */
		worktree = NULL;
	}

	error = view_loop(view);

done:
	free(tog_base_commit.id);
	free(keyword_idstr);
	free(in_repo_path);
	free(repo_path);
	free(cwd);
	free(start_id);
	free(label);
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
	tog_free_refs();
	return error;
}

__dead static void
usage_diff(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	endwin();
	fprintf(fp, "usage: %s diff [-asw] [-C number] [-c commit] "
	    "[-r repository-path] [object1 object2 | path ...]\n",
	    getprogname());
	exit(status);
}

static int
match_line(const char *line, regex_t *regex, size_t nmatch,
    regmatch_t *regmatch)
{
	return regexec(regex, line, nmatch, regmatch, 0) == 0;
}

static struct tog_color *
match_color(struct tog_colors *colors, const char *line)
{
	struct tog_color *tc = NULL;

	STAILQ_FOREACH(tc, colors, entry) {
		if (match_line(line, &tc->regex, 0, NULL))
			return tc;
	}

	return NULL;
}

static const struct got_error *
add_matched_line(int *wtotal, const char *line, int wlimit, int col_tab_align,
    WINDOW *window, int skipcol, regmatch_t *regmatch)
{
	const struct got_error *err = NULL;
	char *exstr = NULL;
	wchar_t *wline = NULL;
	int rme, rms, n, width, scrollx;
	int width0 = 0, width1 = 0, width2 = 0;
	char *seg0 = NULL, *seg1 = NULL, *seg2 = NULL;

	*wtotal = 0;

	rms = regmatch->rm_so;
	rme = regmatch->rm_eo;

	err = expand_tab(&exstr, line);
	if (err)
		return err;

	/* Split the line into 3 segments, according to match offsets. */
	seg0 = strndup(exstr, rms);
	if (seg0 == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	seg1 = strndup(exstr + rms, rme - rms);
	if (seg1 == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
	seg2 = strdup(exstr + rme);
	if (seg2 == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

	/* draw up to matched token if we haven't scrolled past it */
	err = format_line(&wline, &width0, NULL, seg0, 0, wlimit,
	    col_tab_align, 1);
	if (err)
		goto done;
	n = MAX(width0 - skipcol, 0);
	if (n) {
		free(wline);
		err = format_line(&wline, &width, &scrollx, seg0, skipcol,
		    wlimit, col_tab_align, 1);
		if (err)
			goto done;
		waddwstr(window, &wline[scrollx]);
		wlimit -= width;
		*wtotal += width;
	}

	if (wlimit > 0) {
		int i = 0, w = 0;
		size_t wlen;

		free(wline);
		err = format_line(&wline, &width1, NULL, seg1, 0, wlimit,
		    col_tab_align, 1);
		if (err)
			goto done;
		wlen = wcslen(wline);
		while (i < wlen) {
			width = wcwidth(wline[i]);
			if (width == -1) {
				/* should not happen, tabs are expanded */
				err = got_error(GOT_ERR_RANGE);
				goto done;
			}
			if (width0 + w + width > skipcol)
				break;
			w += width;
			i++;
		}
		/* draw (visible part of) matched token (if scrolled into it) */
		if (width1 - w > 0) {
			wattron(window, A_STANDOUT);
			waddwstr(window, &wline[i]);
			wattroff(window, A_STANDOUT);
			wlimit -= (width1 - w);
			*wtotal += (width1 - w);
		}
	}

	if (wlimit > 0) {  /* draw rest of line */
		free(wline);
		if (skipcol > width0 + width1) {
			err = format_line(&wline, &width2, &scrollx, seg2,
			    skipcol - (width0 + width1), wlimit,
			    col_tab_align, 1);
			if (err)
				goto done;
			waddwstr(window, &wline[scrollx]);
		} else {
			err = format_line(&wline, &width2, NULL, seg2, 0,
			    wlimit, col_tab_align, 1);
			if (err)
				goto done;
			waddwstr(window, wline);
		}
		*wtotal += width2;
	}
done:
	free(wline);
	free(exstr);
	free(seg0);
	free(seg1);
	free(seg2);
	return err;
}

static int
gotoline(struct tog_view *view, int *lineno, int *nprinted)
{
	FILE	*f = NULL;
	int	*eof, *first, *selected;

	if (view->type == TOG_VIEW_DIFF) {
		struct tog_diff_view_state *s = &view->state.diff;

		first = &s->first_displayed_line;
		selected = first;
		eof = &s->eof;
		f = s->f;
	} else if (view->type == TOG_VIEW_HELP) {
		struct tog_help_view_state *s = &view->state.help;

		first = &s->first_displayed_line;
		selected = first;
		eof = &s->eof;
		f = s->f;
	} else if (view->type == TOG_VIEW_BLAME) {
		struct tog_blame_view_state *s = &view->state.blame;

		first = &s->first_displayed_line;
		selected = &s->selected_line;
		eof = &s->eof;
		f = s->blame.f;
	} else
		return 0;

	/* Center gline in the middle of the page like vi(1). */
	if (*lineno < view->gline - (view->nlines - 3) / 2)
		return 0;
	if (*first != 1 && (*lineno > view->gline - (view->nlines - 3) / 2)) {
		rewind(f);
		*eof = 0;
		*first = 1;
		*lineno = 0;
		*nprinted = 0;
		return 0;
	}

	*selected = view->gline <= (view->nlines - 3) / 2 ?
		view->gline : (view->nlines - 3) / 2 + 1;
	view->gline = 0;

	return 1;
}

static const struct got_error *
draw_file(struct tog_view *view, const char *header)
{
	struct tog_diff_view_state *s = &view->state.diff;
	regmatch_t *regmatch = &view->regmatch;
	const struct got_error *err;
	int nprinted = 0;
	char *line;
	size_t linesize = 0;
	ssize_t linelen;
	wchar_t *wline;
	int width;
	int max_lines = view->nlines;
	int nlines = s->nlines;
	off_t line_offset;

	s->lineno = s->first_displayed_line - 1;
	line_offset = s->lines[s->first_displayed_line - 1].offset;
	if (fseeko(s->f, line_offset, SEEK_SET) == -1)
		return got_error_from_errno("fseek");

	werase(view->window);

	if (view->gline > s->nlines - 1)
		view->gline = s->nlines - 1;

	if (header) {
		int ln = view->gline ? view->gline <= (view->nlines - 3) / 2 ?
		    1 : view->gline - (view->nlines - 3) / 2 :
		    s->lineno + s->selected_line;

		if (asprintf(&line, "[%d/%d] %s", ln, nlines, header) == -1)
			return got_error_from_errno("asprintf");
		err = format_line(&wline, &width, NULL, line, 0, view->ncols,
		    0, 0);
		free(line);
		if (err)
			return err;

		if (view_needs_focus_indication(view))
			wstandout(view->window);
		waddwstr(view->window, wline);
		free(wline);
		wline = NULL;
		while (width++ < view->ncols)
			waddch(view->window, ' ');
		if (view_needs_focus_indication(view))
			wstandend(view->window);

		if (max_lines <= 1)
			return NULL;
		max_lines--;
	}

	s->eof = 0;
	view->maxx = 0;
	line = NULL;
	while (max_lines > 0 && nprinted < max_lines) {
		enum got_diff_line_type linetype;
		attr_t attr = 0;

		linelen = getline(&line, &linesize, s->f);
		if (linelen == -1) {
			if (feof(s->f)) {
				s->eof = 1;
				break;
			}
			free(line);
			return got_ferror(s->f, GOT_ERR_IO);
		}

		if (++s->lineno < s->first_displayed_line)
			continue;
		if (view->gline && !gotoline(view, &s->lineno, &nprinted))
			continue;
		if (s->lineno == view->hiline)
			attr = A_STANDOUT;

		/* Set view->maxx based on full line length. */
		err = format_line(&wline, &width, NULL, line, 0, INT_MAX, 0,
		    view->x ? 1 : 0);
		if (err) {
			free(line);
			return err;
		}
		view->maxx = MAX(view->maxx, width);
		free(wline);
		wline = NULL;

		linetype = s->lines[s->lineno].type;
		if (linetype > GOT_DIFF_LINE_LOGMSG &&
		    linetype < GOT_DIFF_LINE_CONTEXT)
			attr |= COLOR_PAIR(linetype);
		if (attr)
			wattron(view->window, attr);
		if (s->first_displayed_line + nprinted == s->matched_line &&
		    regmatch->rm_so >= 0 && regmatch->rm_so < regmatch->rm_eo) {
			err = add_matched_line(&width, line, view->ncols, 0,
			    view->window, view->x, regmatch);
			if (err) {
				free(line);
				return err;
			}
		} else {
			int skip;
			err = format_line(&wline, &width, &skip, line,
			    view->x, view->ncols, 0, view->x ? 1 : 0);
			if (err) {
				free(line);
				return err;
			}
			waddwstr(view->window, &wline[skip]);
			free(wline);
			wline = NULL;
		}
		if (s->lineno == view->hiline) {
			/* highlight full gline length */
			while (width++ < view->ncols)
				waddch(view->window, ' ');
		} else {
			if (width <= view->ncols - 1)
				waddch(view->window, '\n');
		}
		if (attr)
			wattroff(view->window, attr);
		if (++nprinted == 1)
			s->first_displayed_line = s->lineno;
	}
	free(line);
	if (nprinted >= 1)
		s->last_displayed_line = s->first_displayed_line +
		    (nprinted - 1);
	else
		s->last_displayed_line = s->first_displayed_line;

	view_border(view);

	if (s->eof) {
		while (nprinted < view->nlines) {
			waddch(view->window, '\n');
			nprinted++;
		}

		err = format_line(&wline, &width, NULL, TOG_EOF_STRING, 0,
		    view->ncols, 0, 0);
		if (err) {
			return err;
		}

		wstandout(view->window);
		waddwstr(view->window, wline);
		free(wline);
		wline = NULL;
		wstandend(view->window);
	}

	return NULL;
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
add_line_metadata(struct got_diff_line **lines, size_t *nlines,
    off_t off, uint8_t type)
{
	struct got_diff_line *p;

	p = reallocarray(*lines, *nlines + 1, sizeof(**lines));
	if (p == NULL)
		return got_error_from_errno("reallocarray");
	*lines = p;
	(*lines)[*nlines].offset = off;
	(*lines)[*nlines].type = type;
	(*nlines)++;

	return NULL;
}

static const struct got_error *
cat_diff(FILE *dst, FILE *src, struct got_diff_line **d_lines, size_t *d_nlines,
    struct got_diff_line *s_lines, size_t s_nlines)
{
	struct got_diff_line	*p;
	char			 buf[BUFSIZ];
	size_t			 i, r;

	if (fseeko(src, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	for (;;) {
		r = fread(buf, 1, sizeof(buf), src);
		if (r == 0) {
			if (ferror(src))
				return got_error_from_errno("fread");
			if (feof(src))
				break;
		}
		if (fwrite(buf, 1, r, dst) != r)
			return got_ferror(dst, GOT_ERR_IO);
	}

	if (s_nlines == 0 && *d_nlines == 0)
		return NULL;

	/*
	 * If commit info was in dst, increment line offsets
	 * of the appended diff content, but skip s_lines[0]
	 * because offset zero is already in *d_lines.
	 */
	if (*d_nlines > 0) {
		for (i = 1; i < s_nlines; ++i)
			s_lines[i].offset += (*d_lines)[*d_nlines - 1].offset;

		if (s_nlines > 0) {
			--s_nlines;
			++s_lines;
		}
	}

	p = reallocarray(*d_lines, *d_nlines + s_nlines, sizeof(*p));
	if (p == NULL) {
		/* d_lines is freed in close_diff_view() */
		return got_error_from_errno("reallocarray");
	}

	*d_lines = p;

	memcpy(*d_lines + *d_nlines, s_lines, s_nlines * sizeof(*s_lines));
	*d_nlines += s_nlines;

	return NULL;
}

static const struct got_error *
write_diffstat(FILE *outfile, struct got_diff_line **lines, size_t *nlines,
    struct got_diffstat_cb_arg *dsa)
{
	const struct got_error		*err;
	struct got_pathlist_entry	*pe;
	off_t				 offset;
	int				 n;

	if (*nlines == 0) {
		err = add_line_metadata(lines, nlines, 0, GOT_DIFF_LINE_NONE);
		if (err != NULL)
			return err;
		offset = 0;
	} else
		offset = (*lines)[*nlines - 1].offset;

	RB_FOREACH(pe, got_pathlist_head, dsa->paths) {
		struct got_diff_changed_path *cp = pe->data;
		int pad = dsa->max_path_len - pe->path_len + 1;

		n = fprintf(outfile, "%c  %s%*c | %*d+ %*d-\n", cp->status,
		    pe->path, pad, ' ', dsa->add_cols + 1, cp->add,
		    dsa->rm_cols + 1, cp->rm);
		if (n < 0)
			return got_error_from_errno("fprintf");

		offset += n;
		err = add_line_metadata(lines, nlines, offset,
		    GOT_DIFF_LINE_CHANGES);
		if (err != NULL)
			return err;
	}

	if (fputc('\n', outfile) == EOF)
		return got_error_from_errno("fputc");

	offset++;
	err = add_line_metadata(lines, nlines, offset, GOT_DIFF_LINE_NONE);
	if (err != NULL)
		return err;

	n = fprintf(outfile,
	    "%d file%s changed, %d insertion%s(+), %d deletion%s(-)\n",
	    dsa->nfiles, dsa->nfiles > 1 ? "s" : "", dsa->ins,
	    dsa->ins != 1 ? "s" : "", dsa->del, dsa->del != 1 ? "s" : "");
	if (n < 0)
		return got_error_from_errno("fprintf");

	offset += n;
	err = add_line_metadata(lines, nlines, offset, GOT_DIFF_LINE_NONE);
	if (err != NULL)
		return err;

	if (fputc('\n', outfile) == EOF)
		return got_error_from_errno("fputc");

	offset++;
	return add_line_metadata(lines, nlines, offset, GOT_DIFF_LINE_NONE);
}

static const struct got_error *
write_commit_info(struct got_diff_line **lines, size_t *nlines,
    struct got_object_id *commit_id, struct got_reflist_head *refs,
    struct got_repository *repo, int ignore_ws, int force_text_diff,
    struct got_diffstat_cb_arg *dsa, FILE *outfile)
{
	const struct got_error *err = NULL;
	char datebuf[26], *datestr;
	struct got_commit_object *commit;
	char *id_str = NULL, *logmsg = NULL, *s = NULL, *line;
	time_t committer_time;
	const char *author, *committer;
	char *refs_str = NULL;
	off_t outoff = 0;
	int n;

	err = build_refs_str(&refs_str, refs, commit_id, repo);
	if (err)
		return err;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, commit_id);
	if (err) {
		err = got_error_from_errno("got_object_id_str");
		goto done;
	}

	err = add_line_metadata(lines, nlines, 0, GOT_DIFF_LINE_NONE);
	if (err)
		goto done;

	n = fprintf(outfile, "commit %s%s%s%s\n", id_str, refs_str ? " (" : "",
	    refs_str ? refs_str : "", refs_str ? ")" : "");
	if (n < 0) {
		err = got_error_from_errno("fprintf");
		goto done;
	}
	outoff += n;
	err = add_line_metadata(lines, nlines, outoff, GOT_DIFF_LINE_META);
	if (err)
		goto done;

	n = fprintf(outfile, "from: %s\n",
	    got_object_commit_get_author(commit));
	if (n < 0) {
		err = got_error_from_errno("fprintf");
		goto done;
	}
	outoff += n;
	err = add_line_metadata(lines, nlines, outoff, GOT_DIFF_LINE_AUTHOR);
	if (err)
		goto done;

	author = got_object_commit_get_author(commit);
	committer = got_object_commit_get_committer(commit);
	if (strcmp(author, committer) != 0) {
		n = fprintf(outfile, "via: %s\n", committer);
		if (n < 0) {
			err = got_error_from_errno("fprintf");
			goto done;
		}
		outoff += n;
		err = add_line_metadata(lines, nlines, outoff,
		    GOT_DIFF_LINE_AUTHOR);
		if (err)
			goto done;
	}
	committer_time = got_object_commit_get_committer_time(commit);
	datestr = get_datestr(&committer_time, datebuf);
	if (datestr) {
		n = fprintf(outfile, "date: %s UTC\n", datestr);
		if (n < 0) {
			err = got_error_from_errno("fprintf");
			goto done;
		}
		outoff += n;
		err = add_line_metadata(lines, nlines, outoff,
		    GOT_DIFF_LINE_DATE);
		if (err)
			goto done;
	}
	if (got_object_commit_get_nparents(commit) > 1) {
		const struct got_object_id_queue *parent_ids;
		struct got_object_qid *qid;
		int pn = 1;
		parent_ids = got_object_commit_get_parent_ids(commit);
		STAILQ_FOREACH(qid, parent_ids, entry) {
			err = got_object_id_str(&id_str, &qid->id);
			if (err)
				goto done;
			n = fprintf(outfile, "parent %d: %s\n", pn++, id_str);
			if (n < 0) {
				err = got_error_from_errno("fprintf");
				goto done;
			}
			outoff += n;
			err = add_line_metadata(lines, nlines, outoff,
			    GOT_DIFF_LINE_META);
			if (err)
				goto done;
			free(id_str);
			id_str = NULL;
		}
	}

	err = got_object_commit_get_logmsg(&logmsg, commit);
	if (err)
		goto done;
	s = logmsg;
	while ((line = strsep(&s, "\n")) != NULL) {
		n = fprintf(outfile, " %s\n", line);
		if (n < 0) {
			err = got_error_from_errno("fprintf");
			goto done;
		}
		outoff += n;
		err = add_line_metadata(lines, nlines, outoff,
		    GOT_DIFF_LINE_LOGMSG);
		if (err)
			goto done;
	}

done:
	free(id_str);
	free(logmsg);
	free(refs_str);
	got_object_commit_close(commit);
	return err;
}

static void
evict_worktree_entry(struct tog_log_thread_args *ta, int victim)
{
	struct commit_queue_entry *e, *v = *ta->selected_entry;

	if (victim == 0)
		return;		/* paranoid check */

	if (v->worktree_entry != victim) {
		TAILQ_FOREACH(v, &ta->real_commits->head, entry) {
			if (v->worktree_entry == victim)
				break;
		}
		if (v == NULL)
			return;
	}

	ta->wctx.wt_state &= ~victim;

	if (*ta->selected_entry == v)
		*ta->selected_entry = TAILQ_NEXT(v, entry);
	if (*ta->first_displayed_entry == v)
		*ta->first_displayed_entry = TAILQ_NEXT(v, entry);
	if (*ta->last_displayed_entry == v)
		*ta->last_displayed_entry = TAILQ_NEXT(v, entry);

	for (e = TAILQ_NEXT(v, entry); e != NULL; e = TAILQ_NEXT(e, entry))
		--e->idx;

	--tog_base_commit.idx;
	--ta->real_commits->ncommits;

	TAILQ_REMOVE(&ta->real_commits->head, v, entry);
	free(v);
}

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
emit_base_commit_header(FILE *f, struct got_diff_line **lines, size_t *nlines,
    struct got_object_id *commit_id, struct got_worktree *worktree)
{
	const struct got_error	*err;
	struct got_object_id	*base_commit_id;
	char			*base_commit_idstr;
	int			 n;

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

	if ((n = fprintf(f, "commit - %s\n", base_commit_idstr)) < 0)
		err = got_error_from_errno("fprintf");
	free(base_commit_idstr);
	if (err != NULL)
		return err;

	return add_line_metadata(lines, nlines,
	    (*lines)[*nlines - 1].offset + n, GOT_DIFF_LINE_META);
}

static const struct got_error *
tog_worktree_diff(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	const struct got_error		*err = NULL;
	struct diff_worktree_arg	*a = arg;
	struct got_blob_object		*blob1 = NULL;
	struct stat			 sb;
	FILE				*f2 = NULL;
	char				*abspath = NULL, *label1 = NULL;
	off_t				 size1 = 0;
	off_t				 outoff = 0;
	int				 fd = -1, fd1 = -1, fd2 = -1;
	int				 n, f2_exists = 1;

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
	if (err != NULL)
		return got_error_from_errno("got_opentemp_truncate");
	err = got_opentemp_truncate(a->f2);
	if (err != NULL)
		return got_error_from_errno("got_opentemp_truncate");

	if (!a->header_shown) {
		n = fprintf(a->outfile, "path + %s%s\n",
		    got_worktree_get_root_path(a->worktree),
		    a->diff_staged ? " (staged changes)" : "");
		if (n < 0)
			return got_error_from_errno("fprintf");

		outoff += n;
		err = add_line_metadata(a->lines, a->nlines, outoff,
		    GOT_DIFF_LINE_META);
		if (err != NULL)
			return err;

		a->header_shown = 1;
	}

	err = emit_base_commit_header(a->outfile,
	    a->lines, a->nlines, commit_id, a->worktree);
	if (err != NULL)
		return err;

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
		if (fd1 == -1)
			return got_error_from_errno("got_opentempfd");

		fd2 = got_opentempfd();
		if (fd2 == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}

		err = got_diff_objects_as_blobs(a->lines, a->nlines,
		    a->f1, a->f2, fd1, fd2, blob_id, staged_blob_id,
		    label1, label2, a->diff_algo, a->diff_context,
		    a->ignore_whitespace, a->force_text_diff,
		    a->diffstat, a->repo, a->outfile);
		goto done;
	}

	fd1 = got_opentempfd();
	if (fd1 == -1)
		return got_error_from_errno("got_opentempfd");

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY) {
		char *id_str;

		err = got_object_open_as_blob(&blob1,
		    a->repo, staged_blob_id, 8192, fd1);
		if (err != NULL)
			goto done;
		err = got_object_id_str(&id_str, staged_blob_id);
		if (err != NULL)
			goto done;
		if (asprintf(&label1, "%s (staged)", id_str) == -1) {
			err = got_error_from_errno("asprintf");
			free(id_str);
			goto done;
		}
		free(id_str);
	} else if (status != GOT_STATUS_ADD) {
		err = got_object_open_as_blob(&blob1,
		    a->repo, blob_id, 8192, fd1);
		if (err != NULL)
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
				err = get_symlink_target_file(&fd,
				    dirfd, de_name, abspath);
				if (err != NULL)
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
				err = get_symlink_target_file(&fd,
				    dirfd, de_name, abspath);
				if (err != NULL)
					goto done;
			}
		}
		if (fstat(fd, &sb) == -1) {
			err = got_error_from_errno2("fstat", abspath);
			goto done;
		}
		f2 = fdopen(fd, "r");
		if (f2 == NULL) {
			err = got_error_from_errno2("fdopen", abspath);
			goto done;
		}
		fd = -1;
	} else {
		sb.st_size = 0;
		f2_exists = 0;
	}

	if (blob1 != NULL) {
		err = got_object_blob_dump_to_file(&size1,
		    NULL, NULL, a->f1, blob1);
		if (err != NULL)
			goto done;
	}

	err = got_diff_blob_file(a->lines, a->nlines, blob1, a->f1, size1,
	    label1, f2 != NULL ? f2 : a->f2, f2_exists, &sb, path,
	    tog_diff_algo, a->diff_context, a->ignore_whitespace,
	    a->force_text_diff, a->diffstat, a->outfile);

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob1 != NULL)
		got_object_blob_close(blob1);
	if (f2 != NULL && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(abspath);
	free(label1);
	return err;
}

static const struct got_error *
tog_diff_worktree(struct tog_diff_view_state *s, FILE *f,
    struct got_diff_line **lines, size_t *nlines,
    struct got_diffstat_cb_arg *dsa)
{
	const struct got_error		*close_err, *err;
	struct got_worktree		*worktree = NULL;
	struct diff_worktree_arg	 arg;
	struct got_pathlist_head	 pathlist;
	char				*cwd, *id_str = NULL;

	RB_INIT(&pathlist);

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno("getcwd");

	err = add_line_metadata(lines, nlines, 0, GOT_DIFF_LINE_NONE);
	if (err != NULL)
		goto done;

	err = got_worktree_open(&worktree, cwd, NULL);
	if (err != NULL) {
		if (err->code == GOT_ERR_WORKTREE_BUSY) {
			int n;

			if ((n = fprintf(f, "%s\n", err->msg)) < 0) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
			err = add_line_metadata(lines, nlines, n,
			    GOT_DIFF_LINE_META);
			if (err != NULL)
				goto done;
			err = got_error(GOT_ERR_DIFF_NOCHANGES);
		}
		goto done;
	}

	err = got_object_id_str(&id_str,
	    got_worktree_get_base_commit_id(worktree));
	if (err != NULL)
		goto done;

	err = got_repo_match_object_id(&s->id1, NULL, id_str,
	    GOT_OBJ_TYPE_ANY, &tog_refs, s->repo);
	if (err != NULL)
		goto done;

	arg.id_str = id_str;
	arg.diff_algo = tog_diff_algo;
	arg.repo = s->repo;
	arg.worktree = worktree;
	arg.diffstat = dsa;
	arg.diff_context = s->diff_context;
	arg.diff_staged = s->diff_staged;
	arg.ignore_whitespace = s->ignore_whitespace;
	arg.force_text_diff = s->force_text_diff;
	arg.header_shown = 0;
	arg.lines = lines;
	arg.nlines = nlines;
	arg.f1 = s->f1;
	arg.f2 = s->f2;
	arg.outfile = f;

	if (s->paths == NULL) {
		err = got_pathlist_insert(NULL, &pathlist, "", NULL);
		if (err != NULL)
			goto done;
	}

	err = got_worktree_status(worktree, s->paths ? s->paths : &pathlist,
	    s->repo, 0, tog_worktree_diff, &arg, NULL, NULL);
	if (err != NULL)
		goto done;

	if (*nlines == 1) {
		const char	*msg = TOG_WORKTREE_CHANGES_LOCAL_MSG;
		int		 n, victim = TOG_WORKTREE_CHANGES_LOCAL;

		if (s->diff_staged) {
			victim = TOG_WORKTREE_CHANGES_STAGED;
			msg = TOG_WORKTREE_CHANGES_STAGED_MSG;
		}
		if ((n = fprintf(f, "no %s\n", msg)) < 0) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
		err = add_line_metadata(lines, nlines, n, GOT_DIFF_LINE_META);
		if (err != NULL)
			goto done;
		if (s->parent_view && s->parent_view->type == TOG_VIEW_LOG)
			evict_worktree_entry(
			    &s->parent_view->state.log.thread_args, victim);
		err = got_error(GOT_ERR_DIFF_NOCHANGES);
	}

done:
	free(cwd);
	free(id_str);
	got_pathlist_free(&pathlist, GOT_PATHLIST_FREE_NONE);
	if (worktree != NULL) {
		if ((close_err = got_worktree_close(worktree)) != NULL) {
			if (err == NULL || err->code == GOT_ERR_DIFF_NOCHANGES)
				err = close_err;
		}
	}
	return err;
}

static const struct got_error *
tog_diff_objects(struct tog_diff_view_state *s, FILE *f,
    struct got_diff_line **lines, size_t *nlines,
    struct got_diffstat_cb_arg *dsa)
{
	const struct got_error	*err;
	int			 obj_type;

	if (s->id1)
		err = got_object_get_type(&obj_type, s->repo, s->id1);
	else
		err = got_object_get_type(&obj_type, s->repo, s->id2);
	if (err != NULL)
		return err;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		err = got_diff_objects_as_blobs(lines, nlines, s->f1, s->f2,
		    s->fd1, s->fd2, s->id1, s->id2, NULL, NULL, tog_diff_algo,
		    s->diff_context, s->ignore_whitespace, s->force_text_diff,
		    dsa, s->repo, f);
		if (err != NULL)
			return err;
		break;
	case GOT_OBJ_TYPE_TREE:
		err = got_diff_objects_as_trees(lines, nlines,
		    s->f1, s->f2, s->fd1, s->fd2, s->id1, s->id2,
		    s->paths, "", "", tog_diff_algo, s->diff_context,
		    s->ignore_whitespace, s->force_text_diff, dsa, s->repo, f);
		if (err != NULL)
			return err;
		break;
	case GOT_OBJ_TYPE_COMMIT: {
		const struct got_object_id_queue *parent_ids;
		struct got_commit_object *commit2;
		struct got_object_qid *pid;
		struct got_reflist_head *refs;

		err = got_diff_objects_as_commits(lines, nlines, s->f1, s->f2,
		    s->fd1, s->fd2, s->id1, s->id2, s->paths, tog_diff_algo,
		    s->diff_context, s->ignore_whitespace, s->force_text_diff,
		    dsa, s->repo, f);
		if (err != NULL)
			return err;

		refs = got_reflist_object_id_map_lookup(tog_refs_idmap, s->id2);
		/* Show commit info if we're diffing to a parent/root commit. */
		if (s->id1 == NULL)
			return write_commit_info(&s->lines, &s->nlines, s->id2,
			    refs, s->repo, s->ignore_whitespace,
			    s->force_text_diff, dsa, s->f);

		err = got_object_open_as_commit(&commit2, s->repo,
		    s->id2);
		if (err != NULL)
			return err;

		parent_ids = got_object_commit_get_parent_ids(commit2);
		STAILQ_FOREACH(pid, parent_ids, entry) {
			if (got_object_id_cmp(s->id1, &pid->id) == 0) {
				err = write_commit_info(&s->lines, &s->nlines,
				    s->id2, refs, s->repo, s->ignore_whitespace,
				    s->force_text_diff, dsa, s->f);
				break;
			}
		}
		if (commit2 != NULL)
			got_object_commit_close(commit2);
		if (err != NULL)
			return err;
		break;
	}
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	return NULL;
}

static const struct got_error *
create_diff(struct tog_diff_view_state *s)
{
	const struct got_error *err = NULL;
	FILE *tmp_diff_file = NULL;
	struct got_diff_line *lines = NULL;
	struct got_pathlist_head changed_paths;
	struct got_diffstat_cb_arg dsa;
	size_t nlines = 0;

	RB_INIT(&changed_paths);
	memset(&dsa, 0, sizeof(dsa));
	dsa.paths = &changed_paths;
	dsa.diff_algo = tog_diff_algo;
	dsa.force_text = s->force_text_diff;
	dsa.ignore_ws = s->ignore_whitespace;

	free(s->lines);
	s->lines = malloc(sizeof(*s->lines));
	if (s->lines == NULL)
		return got_error_from_errno("malloc");
	s->nlines = 0;

	if (s->f && fclose(s->f) == EOF) {
		s->f = NULL;
		return got_error_from_errno("fclose");
	}

	s->f = got_opentemp();
	if (s->f == NULL)
		return got_error_from_errno("got_opentemp");

	/*
	 * The diffstat requires the diff to be built first, but we want the
	 * diffstat to precede the diff when displayed. Build the diff first
	 * in the temporary file and write the diffstat and/or commit info to
	 * the persistent file (s->f) from which views are drawn, then append
	 * the diff from the temp file to the diffstat/commit info in s->f.
	 */
	tmp_diff_file = got_opentemp();
	if (tmp_diff_file == NULL)
		return got_error_from_errno("got_opentemp");

	lines = malloc(sizeof(*lines));
	if (lines == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}

	if (s->parent_view != NULL && s->parent_view->type == TOG_VIEW_LOG) {
		struct tog_log_view_state *ls = &s->parent_view->state.log;
		struct commit_queue_entry *cqe = ls->selected_entry;

		if (cqe->worktree_entry != 0) {
			if (cqe->worktree_entry == TOG_WORKTREE_CHANGES_STAGED)
				s->diff_staged = 1;
			s->diff_worktree = 1;
		}
	}

	if (s->diff_worktree)
		err = tog_diff_worktree(s, tmp_diff_file,
		    &lines, &nlines, &dsa);
	else
		err = tog_diff_objects(s, tmp_diff_file,
		    &lines, &nlines, &dsa);
	if (err != NULL) {
		if (err->code != GOT_ERR_DIFF_NOCHANGES)
			goto done;
	} else {
		err = write_diffstat(s->f, &s->lines, &s->nlines, &dsa);
		if (err != NULL)
			goto done;
	}

	err = cat_diff(s->f, tmp_diff_file, &s->lines, &s->nlines,
	    lines, nlines);

done:
	free(lines);
	got_pathlist_free(&changed_paths, GOT_PATHLIST_FREE_ALL);
	if (s->f && fflush(s->f) != 0 && err == NULL)
		err = got_error_from_errno("fflush");
	if (tmp_diff_file && fclose(tmp_diff_file) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static void
diff_view_indicate_progress(struct tog_view *view)
{
	mvwaddstr(view->window, 0, 0, "diffing...");
	update_panels();
	doupdate();
}

static const struct got_error *
search_start_diff_view(struct tog_view *view)
{
	struct tog_diff_view_state *s = &view->state.diff;

	s->matched_line = 0;
	return NULL;
}

static void
search_setup_diff_view(struct tog_view *view, FILE **f, off_t **line_offsets,
    size_t *nlines, int **first, int **last, int **match, int **selected)
{
	struct tog_diff_view_state *s = &view->state.diff;

	*f = s->f;
	*nlines = s->nlines;
	*line_offsets = NULL;
	*match = &s->matched_line;
	*first = &s->first_displayed_line;
	*last = &s->last_displayed_line;
	*selected = &s->selected_line;
}

static const struct got_error *
search_next_view_match(struct tog_view *view)
{
	const struct got_error *err = NULL;
	FILE *f;
	int lineno;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	off_t *line_offsets;
	size_t nlines = 0;
	int *first, *last, *match, *selected;

	if (!view->search_setup)
		return got_error_msg(GOT_ERR_NOT_IMPL,
		    "view search not supported");
	view->search_setup(view, &f, &line_offsets, &nlines, &first, &last,
	    &match, &selected);

	if (!view->searching) {
		view->search_next_done = TOG_SEARCH_HAVE_MORE;
		return NULL;
	}

	if (*match) {
		if (view->searching == TOG_SEARCH_FORWARD)
			lineno = *first + 1;
		else
			lineno = *first - 1;
	} else
		lineno = *first - 1 + *selected;

	while (1) {
		off_t offset;

		if (lineno <= 0 || lineno > nlines) {
			if (*match == 0) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				break;
			}

			if (view->searching == TOG_SEARCH_FORWARD)
				lineno = 1;
			else
				lineno = nlines;
		}

		offset = view->type == TOG_VIEW_DIFF ?
		    view->state.diff.lines[lineno - 1].offset :
		    line_offsets[lineno - 1];
		if (fseeko(f, offset, SEEK_SET) != 0) {
			free(line);
			return got_error_from_errno("fseeko");
		}
		linelen = getline(&line, &linesize, f);
		if (linelen != -1) {
			char *exstr;
			err = expand_tab(&exstr, line);
			if (err)
				break;
			if (match_line(exstr, &view->regex, 1,
			    &view->regmatch)) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				*match = lineno;
				free(exstr);
				break;
			}
			free(exstr);
		}
		if (view->searching == TOG_SEARCH_FORWARD)
			lineno++;
		else
			lineno--;
	}
	free(line);

	if (*match) {
		*first = *match;
		*selected = 1;
	}

	return err;
}

static const struct got_error *
close_diff_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_diff_view_state *s = &view->state.diff;

	free(s->id1);
	s->id1 = NULL;
	free(s->id2);
	s->id2 = NULL;
	free(s->action);
	s->action = NULL;
	if (s->f && fclose(s->f) == EOF)
		err = got_error_from_errno("fclose");
	s->f = NULL;
	if (s->f1 && fclose(s->f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	s->f1 = NULL;
	if (s->f2 && fclose(s->f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	s->f2 = NULL;
	if (s->fd1 != -1 && close(s->fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	s->fd1 = -1;
	if (s->fd2 != -1 && close(s->fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	s->fd2 = -1;
	free(s->lines);
	s->lines = NULL;
	s->nlines = 0;
	return err;
}

static const struct got_error *
open_diff_view(struct tog_view *view, struct got_object_id *id1,
    struct got_object_id *id2, const char *label1, const char *label2,
    int diff_context, int ignore_whitespace, int force_text_diff,
    int diff_staged, int diff_worktree, const char *worktree_root,
    struct tog_view *parent_view, struct got_repository *repo,
    struct got_pathlist_head *paths)
{
	const struct got_error *err;
	struct tog_diff_view_state *s = &view->state.diff;

	memset(s, 0, sizeof(*s));
	s->fd1 = -1;
	s->fd2 = -1;

	if (id1 != NULL && id2 != NULL) {
		int type1, type2;

		err = got_object_get_type(&type1, repo, id1);
		if (err)
			goto done;
		err = got_object_get_type(&type2, repo, id2);
		if (err)
			goto done;

		if (type1 != type2) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}
	}

	if (diff_worktree == 0) {
		if (id1) {
			s->id1 = got_object_id_dup(id1);
			if (s->id1 == NULL) {
				err = got_error_from_errno("got_object_id_dup");
				goto done;
			}
		} else
			s->id1 = NULL;

		s->id2 = got_object_id_dup(id2);
		if (s->id2 == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
	}

	s->f1 = got_opentemp();
	if (s->f1 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	s->f2 = got_opentemp();
	if (s->f2 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	s->fd1 = got_opentempfd();
	if (s->fd1 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	s->fd2 = got_opentempfd();
	if (s->fd2 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->selected_line = 1;
	s->label1 = label1;
	s->label2 = label2;
	s->diff_context = diff_context;
	s->ignore_whitespace = ignore_whitespace;
	s->force_text_diff = force_text_diff;
	s->diff_worktree = diff_worktree;
	s->diff_staged = diff_staged;
	s->parent_view = parent_view;
	s->paths = paths;
	s->repo = repo;
	s->worktree_root = worktree_root;

	if (has_colors() && getenv("TOG_COLORS") != NULL && !using_mock_io) {
		int rc;

		rc = init_pair(GOT_DIFF_LINE_MINUS,
		    get_color_value("TOG_COLOR_DIFF_MINUS"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_PLUS,
			    get_color_value("TOG_COLOR_DIFF_PLUS"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_HUNK,
			    get_color_value("TOG_COLOR_DIFF_CHUNK_HEADER"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_META,
			    get_color_value("TOG_COLOR_DIFF_META"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_CHANGES,
			    get_color_value("TOG_COLOR_DIFF_META"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_BLOB_MIN,
			    get_color_value("TOG_COLOR_DIFF_META"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_BLOB_PLUS,
			    get_color_value("TOG_COLOR_DIFF_META"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_AUTHOR,
			    get_color_value("TOG_COLOR_AUTHOR"), -1);
		if (rc != ERR)
			rc = init_pair(GOT_DIFF_LINE_DATE,
			    get_color_value("TOG_COLOR_DATE"), -1);
		if (rc == ERR) {
			err = got_error(GOT_ERR_RANGE);
			goto done;
		}
	}

	if (parent_view && parent_view->type == TOG_VIEW_LOG &&
	    view_is_splitscreen(view)) {
		err = show_log_view(parent_view); /* draw border */
		if (err != NULL)
			goto done;
	}
	diff_view_indicate_progress(view);

	err = create_diff(s);

	view->show = show_diff_view;
	view->input = input_diff_view;
	view->reset = reset_diff_view;
	view->close = close_diff_view;
	view->search_start = search_start_diff_view;
	view->search_setup = search_setup_diff_view;
	view->search_next = search_next_view_match;
done:
	if (err) {
		if (view->close == NULL)
			close_diff_view(view);
		view_close(view);
	}
	return err;
}

static const struct got_error *
show_diff_view(struct tog_view *view)
{
	const struct got_error *err;
	struct tog_diff_view_state *s = &view->state.diff;
	char *header;

	if (s->diff_worktree) {
		if (asprintf(&header, "diff %s%s",
		    s->diff_staged ? "-s " : "", s->worktree_root) == -1)
			return got_error_from_errno("asprintf");
	} else {
		char		*id_str2, *id_str1 = NULL;
		const char	*label1, *label2;

		if (s->id1) {
			err = got_object_id_str(&id_str1, s->id1);
			if (err)
				return err;
			label1 = s->label1 ? s->label1 : id_str1;
		} else
			label1 = "/dev/null";

		err = got_object_id_str(&id_str2, s->id2);
		if (err)
			return err;
		label2 = s->label2 ? s->label2 : id_str2;

		if (asprintf(&header, "diff %s %s", label1, label2) == -1) {
			err = got_error_from_errno("asprintf");
			free(id_str1);
			free(id_str2);
			return err;
		}
		free(id_str1);
		free(id_str2);
	}

	err = draw_file(view, header);
	free(header);
	return err;
}

static const struct got_error *
diff_write_patch(struct tog_view *view)
{
	const struct got_error		*err;
	struct tog_diff_view_state	*s = &view->state.diff;
	struct got_object_id		*id2 = s->id2;
	FILE				*f = NULL;
	char				 buf[BUFSIZ], pathbase[PATH_MAX];
	char				*idstr1, *idstr2 = NULL, *path = NULL;
	char				*repo_name = NULL;
	size_t				 r;
	off_t				 pos;
	int				 rc;

	if (s->action != NULL) {
		free(s->action);
		s->action = NULL;
	}

	pos = ftello(s->f);
	if (pos == -1)
		return got_error_from_errno("ftello");
	if (fseeko(s->f, 0L, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	if (s->id1 != NULL) {
		err = got_object_id_str(&idstr1, s->id1);
		if (err != NULL)
			return err;
	}
	if (id2 == NULL) {
		if (s->diff_worktree == 0 || tog_base_commit.id == NULL) {
			/* illegal state that should not be possible */
			err = got_error(GOT_ERR_NOT_WORKTREE);
			goto done;
		}
		id2 = tog_base_commit.id;
	}
	err = got_object_id_str(&idstr2, id2);
	if (err != NULL)
		goto done;

	err = got_path_basename(&repo_name, got_repo_get_path(s->repo));
	if (err)
		goto done;

	rc = snprintf(pathbase, sizeof(pathbase), "%s/tog-%s-%.8s-%.8s",
	    GOT_TMPDIR_STR, repo_name,
	    idstr1 != NULL ? idstr1 : "empty", idstr2);
	if (rc < 0 || (size_t)rc >= sizeof(pathbase)) {
		err = got_error(rc < 0 ? GOT_ERR_IO : GOT_ERR_NO_SPACE);
		goto done;
	}

	err = got_opentemp_named(&path, &f, pathbase, ".diff");
	if (err != NULL)
		goto done;

	while ((r = fread(buf, 1, sizeof(buf), s->f)) > 0) {
		if (fwrite(buf, 1, r, f) != r) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	}

	if (ferror(s->f)) {
		err = got_error_from_errno("fread");
		goto done;
	}
	if (fseeko(s->f, pos, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	if (fflush(f) == EOF) {
		err = got_error_from_errno2("fflush", path);
		goto done;
	}

	if (asprintf(&s->action, "patch file written to %s", path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	view->action = s->action;

done:
	if (f != NULL && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", path);
	free(path);
	free(idstr1);
	free(idstr2);
	free(repo_name);
	return err;
}

static const struct got_error *
set_selected_commit(struct tog_diff_view_state *s,
    struct commit_queue_entry *entry)
{
	const struct got_error *err;
	const struct got_object_id_queue *parent_ids;
	struct got_commit_object *selected_commit;
	struct got_object_qid *pid;

	free(s->id1);
	s->id1 = NULL;
	free(s->id2);
	s->id2 = NULL;

	if (entry->worktree_entry == 0) {
		s->id2 = got_object_id_dup(entry->id);
		if (s->id2 == NULL)
			return got_error_from_errno("got_object_id_dup");

		err = got_object_open_as_commit(&selected_commit,
		    s->repo, entry->id);
		if (err)
			return err;
		parent_ids = got_object_commit_get_parent_ids(selected_commit);
		pid = STAILQ_FIRST(parent_ids);
		s->id1 = pid ? got_object_id_dup(&pid->id) : NULL;
		got_object_commit_close(selected_commit);
	}

	return NULL;
}

static const struct got_error *
reset_diff_view(struct tog_view *view)
{
	struct tog_diff_view_state *s = &view->state.diff;

	view->count = 0;
	wclear(view->window);
	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->matched_line = 0;
	if (s->action != NULL) {
		free(s->action);
		s->action = NULL;
	}
	diff_view_indicate_progress(view);
	return create_diff(s);
}

static void
diff_prev_index(struct tog_diff_view_state *s, enum got_diff_line_type type)
{
	int start, i;

	i = start = s->first_displayed_line - 1;

	while (s->lines[i].type != type) {
		if (i == 0)
			i = s->nlines - 1;
		if (--i == start)
			return; /* do nothing, requested type not in file */
	}

	s->selected_line = 1;
	s->first_displayed_line = i;
}

static void
diff_next_index(struct tog_diff_view_state *s, enum got_diff_line_type type)
{
	int start, i;

	i = start = s->first_displayed_line + 1;

	while (s->lines[i].type != type) {
		if (i == s->nlines - 1)
			i = 0;
		if (++i == start)
			return; /* do nothing, requested type not in file */
	}

	s->selected_line = 1;
	s->first_displayed_line = i;
}

static struct got_object_id *get_selected_commit_id(struct tog_blame_line *,
    int, int, int);
static struct got_object_id *get_annotation_for_line(struct tog_blame_line *,
    int, int);

static const struct got_error *
input_diff_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_diff_view_state *s = &view->state.diff;
	struct tog_log_view_state *ls;
	struct commit_queue_entry *old_selected_entry;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int i, nscroll = view->nlines - 1, up = 0;

	s->lineno = s->first_displayed_line - 1 + s->selected_line;

	if (s->action != NULL && ch != ERR) {
		free(s->action);
		s->action = NULL;
		view->action = NULL;
	}

	switch (ch) {
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'a':
	case 'w':
		if (ch == 'a') {
			s->force_text_diff = !s->force_text_diff;
			view->action = s->force_text_diff ?
			    "force ASCII text enabled" :
			    "force ASCII text disabled";
		}
		else if (ch == 'w') {
			s->ignore_whitespace = !s->ignore_whitespace;
			view->action = s->ignore_whitespace ?
			    "ignore whitespace enabled" :
			    "ignore whitespace disabled";
		}
		err = reset_diff_view(view);
		break;
	case 'g':
	case KEY_HOME:
		s->first_displayed_line = 1;
		view->count = 0;
		break;
	case 'G':
	case KEY_END:
		view->count = 0;
		if (s->eof)
			break;

		s->first_displayed_line = (s->nlines - view->nlines) + 2;
		s->eof = 1;
		break;
	case 'k':
	case KEY_UP:
	case CTRL('p'):
		if (s->first_displayed_line > 1)
			s->first_displayed_line--;
		else
			view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		if (s->first_displayed_line == 1) {
			view->count = 0;
			break;
		}
		i = 0;
		while (i++ < nscroll && s->first_displayed_line > 1)
			s->first_displayed_line--;
		break;
	case 'j':
	case KEY_DOWN:
	case CTRL('n'):
		if (!s->eof)
			s->first_displayed_line++;
		else
			view->count = 0;
		break;
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		if (s->eof) {
			view->count = 0;
			break;
		}
		i = 0;
		while (!s->eof && i++ < nscroll) {
			linelen = getline(&line, &linesize, s->f);
			s->first_displayed_line++;
			if (linelen == -1) {
				if (feof(s->f)) {
					s->eof = 1;
				} else
					err = got_ferror(s->f, GOT_ERR_IO);
				break;
			}
		}
		free(line);
		break;
	case '(':
		diff_prev_index(s, GOT_DIFF_LINE_BLOB_MIN);
		break;
	case ')':
		diff_next_index(s, GOT_DIFF_LINE_BLOB_MIN);
		break;
	case '{':
		diff_prev_index(s, GOT_DIFF_LINE_HUNK);
		break;
	case '}':
		diff_next_index(s, GOT_DIFF_LINE_HUNK);
		break;
	case '[':
		if (s->diff_context > 0) {
			s->diff_context--;
			s->matched_line = 0;
			diff_view_indicate_progress(view);
			err = create_diff(s);
			if (s->first_displayed_line + view->nlines - 1 >
			    s->nlines) {
				s->first_displayed_line = 1;
				s->last_displayed_line = view->nlines;
			}
		} else
			view->count = 0;
		break;
	case ']':
		if (s->diff_context < GOT_DIFF_MAX_CONTEXT) {
			s->diff_context++;
			s->matched_line = 0;
			diff_view_indicate_progress(view);
			err = create_diff(s);
		} else
			view->count = 0;
		break;
	case '<':
	case ',':
	case 'K':
		up = 1;
		/* FALL THROUGH */
	case '>':
	case '.':
	case 'J':
		if (s->parent_view == NULL) {
			view->count = 0;
			break;
		}
		s->parent_view->count = view->count;

		if (s->parent_view->type == TOG_VIEW_LOG) {
			ls = &s->parent_view->state.log;
			old_selected_entry = ls->selected_entry;

			err = input_log_view(NULL, s->parent_view,
			    up ? KEY_UP : KEY_DOWN);
			if (err)
				break;
			view->count = s->parent_view->count;

			if (old_selected_entry == ls->selected_entry)
				break;

			log_mark_clear(ls);

			err = set_selected_commit(s, ls->selected_entry);
			if (err)
				break;

			if (s->worktree_root == NULL)
				s->worktree_root = ls->thread_args.wctx.wt_root;
		} else if (s->parent_view->type == TOG_VIEW_BLAME) {
			struct tog_blame_view_state *bs;
			struct got_object_id *id, *prev_id;

			bs = &s->parent_view->state.blame;
			prev_id = get_annotation_for_line(bs->blame.lines,
			    bs->blame.nlines, bs->last_diffed_line);

			err = input_blame_view(&view, s->parent_view,
			    up ? KEY_UP : KEY_DOWN);
			if (err)
				break;
			view->count = s->parent_view->count;

			if (prev_id == NULL)
				break;
			id = get_selected_commit_id(bs->blame.lines,
			    bs->blame.nlines, bs->first_displayed_line,
			    bs->selected_line);
			if (id == NULL)
				break;

			if (!got_object_id_cmp(prev_id, id))
				break;

			err = input_blame_view(&view, s->parent_view, KEY_ENTER);
			if (err)
				break;
		}
		s->diff_staged = 0;
		s->diff_worktree = 0;
		s->first_displayed_line = 1;
		s->last_displayed_line = view->nlines;
		s->matched_line = 0;
		view->x = 0;

		diff_view_indicate_progress(view);
		err = create_diff(s);
		break;
	case 'p':
		view->count = 0;
		err = diff_write_patch(view);
		break;
	default:
		view->count = 0;
		break;
	}

	return err;
}

 static const struct got_error *
get_worktree_paths_from_argv(struct got_pathlist_head *paths, int argc,
    char *argv[], struct got_worktree *worktree)
{
	const struct got_error		*err = NULL;
	char				*path;
	struct got_pathlist_entry	*new;
	int				 i;

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
		if (err != NULL || new == NULL) {
			free(path);
			if (err != NULL)
				break;
		}
	}

	return err;
}

static const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_pathlist_head paths;
	struct got_object_id *ids[2] = { NULL, NULL };
	const char *commit_args[2] = { NULL, NULL };
	char *labels[2] = { NULL, NULL };
	char *repo_path = NULL, *worktree_path = NULL, *cwd = NULL;
	int type1 = GOT_OBJ_TYPE_ANY, type2 = GOT_OBJ_TYPE_ANY;
	int i, ncommit_args = 0, diff_context = 3, ignore_whitespace = 0;
	int ch, diff_staged = 0, diff_worktree = 0, force_text_diff = 0;
	const char *errstr;
	struct tog_view *view;
	int *pack_fds = NULL;

	RB_INIT(&paths);

	while ((ch = getopt(argc, argv, "aC:c:r:sw")) != -1) {
		switch (ch) {
		case 'a':
			force_text_diff = 1;
			break;
		case 'C':
			diff_context = strtonum(optarg, 0, GOT_DIFF_MAX_CONTEXT,
			    &errstr);
			if (errstr != NULL)
				errx(1, "number of context lines is %s: %s",
				    errstr, errstr);
			break;
		case 'c':
			if (ncommit_args >= 2)
				errx(1, "too many -c options used");
			commit_args[ncommit_args++] = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
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

	error = got_repo_pack_fds_open(&pack_fds);
	if (error)
		goto done;

	if (repo_path == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno("getcwd");
		error = got_worktree_open(&worktree, cwd, NULL);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree)
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
		else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error)
		goto done;

	if (diff_staged && (worktree == NULL || ncommit_args > 0)) {
		error = got_error_msg(GOT_ERR_BAD_OPTION,
		    "-s can only be used when diffing a work tree");
		goto done;
	}

	init_curses();

	error = apply_unveil(got_repo_get_path(repo),
	    worktree != NULL ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (argc == 2 || ncommit_args > 0) {
		int obj_type = (ncommit_args > 0 ?
		    GOT_OBJ_TYPE_COMMIT : GOT_OBJ_TYPE_ANY);

		error = tog_load_refs(repo, 0);
		if (error != NULL)
			goto done;

		for (i = 0; i < (ncommit_args > 0 ? ncommit_args : argc); ++i) {
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
			    arg, obj_type, &tog_refs, repo);
			free(keyword_idstr);
			if (error != NULL) {
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

	if (diff_staged && ids[0] != NULL) {
		error = got_error_msg(GOT_ERR_BAD_OPTION,
		    "-s can only be used when diffing a work tree");
		goto done;
	}

	if (ncommit_args == 0 && (ids[0] == NULL || ids[1] == NULL)) {
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
		if (error != NULL)
			goto done;

		worktree_path = strdup(got_worktree_get_root_path(worktree));
		if (worktree_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		diff_worktree = 1;
	}

	if (ncommit_args == 1) {  /* diff commit against its first parent */
		struct got_commit_object *commit;

		error = got_object_open_as_commit(&commit, repo, ids[0]);
		if (error != NULL)
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
			if (error != NULL) {
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
		if (error != NULL)
			goto done;
	}

	if (diff_worktree == 0) {
		error = got_object_get_type(&type2, repo, ids[1]);
		if (error != NULL)
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
	}

	for (i = 0; ncommit_args > 0 && i < argc; i++) {
		char *in_repo_path;
		struct got_pathlist_entry *new;

		if (worktree) {
			const char *prefix;
			char *p;

			error = got_worktree_resolve_path(&p, worktree,
			    argv[i]);
			if (error != NULL)
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
			if (error != NULL)
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
		if (error != NULL || new == NULL)
			free(in_repo_path);
		if (error != NULL)
			goto done;
	}

	view = view_open(0, 0, 0, 0, TOG_VIEW_DIFF);
	if (view == NULL) {
		error = got_error_from_errno("view_open");
		goto done;
	}

	if (worktree) {
		error = set_tog_base_commit(repo, worktree);
		if (error != NULL)
			goto done;

		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = open_diff_view(view, ids[0], ids[1], labels[0], labels[1],
	    diff_context, ignore_whitespace, force_text_diff, diff_staged,
	    diff_worktree, worktree_path, NULL, repo, &paths);
	if (error)
		goto done;

	error = view_loop(view);

done:
	got_pathlist_free(&paths, GOT_PATHLIST_FREE_PATH);
	free(tog_base_commit.id);
	free(worktree_path);
	free(repo_path);
	free(labels[0]);
	free(labels[1]);
	free(ids[0]);
	free(ids[1]);
	free(cwd);
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
	tog_free_refs();
	return error;
}

__dead static void
usage_blame(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	endwin();
	fprintf(fp,
	    "usage: %s blame [-c commit] [-r repository-path] path\n",
	    getprogname());
	exit(status);
}

struct tog_blame_line {
	int annotated;
	struct got_object_id *id;
};

static const struct got_error *
draw_blame(struct tog_view *view)
{
	struct tog_blame_view_state *s = &view->state.blame;
	struct tog_blame *blame = &s->blame;
	regmatch_t *regmatch = &view->regmatch;
	const struct got_error *err;
	int lineno = 0, nprinted = 0;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	wchar_t *wline;
	int width;
	struct tog_blame_line *blame_line;
	struct got_object_id *prev_id = NULL;
	char *id_str;
	struct tog_color *tc;

	err = got_object_id_str(&id_str, &s->blamed_commit->id);
	if (err)
		return err;

	rewind(blame->f);
	werase(view->window);

	if (asprintf(&line, "commit %s", id_str) == -1) {
		err = got_error_from_errno("asprintf");
		free(id_str);
		return err;
	}

	err = format_line(&wline, &width, NULL, line, 0, view->ncols, 0, 0);
	free(line);
	line = NULL;
	if (err)
		return err;
	if (view_needs_focus_indication(view))
		wstandout(view->window);
	tc = get_color(&s->colors, TOG_COLOR_COMMIT);
	if (tc)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	waddwstr(view->window, wline);
	while (width++ < view->ncols)
		waddch(view->window, ' ');
	if (tc)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	wline = NULL;

	if (view->gline > blame->nlines)
		view->gline = blame->nlines;

	if (tog_io.wait_for_ui) {
		struct tog_blame_thread_args *bta = &s->blame.thread_args;
		int rc;

		rc = pthread_cond_wait(&bta->blame_complete, &tog_mutex);
		if (rc)
			return got_error_set_errno(rc, "pthread_cond_wait");
		tog_io.wait_for_ui = 0;
	}

	if (asprintf(&line, "[%d/%d] %s%s", view->gline ? view->gline :
	    s->first_displayed_line - 1 + s->selected_line, blame->nlines,
	    s->blame_complete ? "" : "annotating... ", s->path) == -1) {
		free(id_str);
		return got_error_from_errno("asprintf");
	}
	free(id_str);
	err = format_line(&wline, &width, NULL, line, 0, view->ncols, 0, 0);
	free(line);
	line = NULL;
	if (err)
		return err;
	waddwstr(view->window, wline);
	free(wline);
	wline = NULL;
	if (width < view->ncols - 1)
		waddch(view->window, '\n');

	s->eof = 0;
	view->maxx = 0;
	while (nprinted < view->nlines - 2) {
		linelen = getline(&line, &linesize, blame->f);
		if (linelen == -1) {
			if (feof(blame->f)) {
				s->eof = 1;
				break;
			}
			free(line);
			return got_ferror(blame->f, GOT_ERR_IO);
		}
		if (++lineno < s->first_displayed_line)
			continue;
		if (view->gline && !gotoline(view, &lineno, &nprinted))
			continue;

		/* Set view->maxx based on full line length. */
		err = format_line(&wline, &width, NULL, line, 0, INT_MAX, 9, 1);
		if (err) {
			free(line);
			return err;
		}
		free(wline);
		wline = NULL;
		view->maxx = MAX(view->maxx, width);

		if (nprinted == s->selected_line - 1)
			wstandout(view->window);

		if (blame->nlines > 0) {
			blame_line = &blame->lines[lineno - 1];
			if (blame_line->annotated && prev_id &&
			    got_object_id_cmp(prev_id, blame_line->id) == 0 &&
			    !(nprinted == s->selected_line - 1)) {
				waddstr(view->window, "        ");
			} else if (blame_line->annotated) {
				char *id_str;
				err = got_object_id_str(&id_str,
				    blame_line->id);
				if (err) {
					free(line);
					return err;
				}
				tc = get_color(&s->colors, TOG_COLOR_COMMIT);
				if (tc)
					wattr_on(view->window,
					    COLOR_PAIR(tc->colorpair), NULL);
				wprintw(view->window, "%.8s", id_str);
				if (tc)
					wattr_off(view->window,
					    COLOR_PAIR(tc->colorpair), NULL);
				free(id_str);
				prev_id = blame_line->id;
			} else {
				waddstr(view->window, "........");
				prev_id = NULL;
			}
		} else {
			waddstr(view->window, "........");
			prev_id = NULL;
		}

		if (nprinted == s->selected_line - 1)
			wstandend(view->window);
		waddstr(view->window, " ");

		if (view->ncols <= 9) {
			width = 9;
		} else if (s->first_displayed_line + nprinted ==
		    s->matched_line &&
		    regmatch->rm_so >= 0 && regmatch->rm_so < regmatch->rm_eo) {
			err = add_matched_line(&width, line, view->ncols - 9, 9,
			    view->window, view->x, regmatch);
			if (err) {
				free(line);
				return err;
			}
			width += 9;
		} else {
			int skip;
			err = format_line(&wline, &width, &skip, line,
			    view->x, view->ncols - 9, 9, 1);
			if (err) {
				free(line);
				return err;
			}
			waddwstr(view->window, &wline[skip]);
			width += 9;
			free(wline);
			wline = NULL;
		}

		if (width <= view->ncols - 1)
			waddch(view->window, '\n');
		if (++nprinted == 1)
			s->first_displayed_line = lineno;
	}
	free(line);
	s->last_displayed_line = lineno;

	view_border(view);

	return NULL;
}

static const struct got_error *
blame_cb(void *arg, int nlines, int lineno,
    struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct tog_blame_cb_args *a = arg;
	struct tog_blame_line *line;
	int errcode;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_lock");

	if (*a->quit) {	/* user has quit the blame view */
		err = got_error(GOT_ERR_ITER_COMPLETED);
		goto done;
	}

	if (lineno == -1)
		goto done; /* no change in this commit */

	line = &a->lines[lineno - 1];
	if (line->annotated)
		goto done;

	line->id = got_object_id_dup(id);
	if (line->id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}
	line->annotated = 1;
done:
	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		err = got_error_set_errno(errcode, "pthread_mutex_unlock");
	return err;
}

static void *
blame_thread(void *arg)
{
	const struct got_error *err, *close_err;
	struct tog_blame_thread_args *ta = arg;
	struct tog_blame_cb_args *a = ta->cb_args;
	int errcode, fd1 = -1, fd2 = -1;
	FILE *f1 = NULL, *f2 = NULL;

	fd1 = got_opentempfd();
	if (fd1 == -1)
		return (void *)got_error_from_errno("got_opentempfd");

	fd2 = got_opentempfd();
	if (fd2 == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	f1 = got_opentemp();
	if (f1 == NULL) {
		err = (void *)got_error_from_errno("got_opentemp");
		goto done;
	}
	f2 = got_opentemp();
	if (f2 == NULL) {
		err = (void *)got_error_from_errno("got_opentemp");
		goto done;
	}

	err = block_signals_used_by_main_thread();
	if (err)
		goto done;

	err = got_blame(ta->path, a->commit_id, ta->repo,
	    tog_diff_algo, blame_cb, ta->cb_args,
	    ta->cancel_cb, ta->cancel_arg, fd1, fd2, f1, f2);
	if (err && err->code == GOT_ERR_CANCELLED)
		err = NULL;

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode) {
		err = got_error_set_errno(errcode, "pthread_mutex_lock");
		goto done;
	}

	close_err = got_repo_close(ta->repo);
	if (err == NULL)
		err = close_err;
	ta->repo = NULL;
	*ta->complete = 1;

	if (tog_io.wait_for_ui) {
		errcode = pthread_cond_signal(&ta->blame_complete);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode,
			    "pthread_cond_signal");
	}

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode, "pthread_mutex_unlock");

done:
	if (fd1 != -1 && close(fd1) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (f1 && fclose(f1) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");

	return (void *)err;
}

static struct got_object_id *
get_selected_commit_id(struct tog_blame_line *lines, int nlines,
    int first_displayed_line, int selected_line)
{
	struct tog_blame_line *line;

	if (nlines <= 0)
		return NULL;

	line = &lines[first_displayed_line - 1 + selected_line - 1];
	if (!line->annotated)
		return NULL;

	return line->id;
}

static struct got_object_id *
get_annotation_for_line(struct tog_blame_line *lines, int nlines,
    int lineno)
{
	struct tog_blame_line *line;

	if (nlines <= 0 || lineno >= nlines)
		return NULL;

	line = &lines[lineno - 1];
	if (!line->annotated)
		return NULL;

	return line->id;
}

static const struct got_error *
stop_blame(struct tog_blame *blame)
{
	const struct got_error *err = NULL;
	int i;

	if (blame->thread) {
		int errcode;
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_unlock");
		errcode = pthread_join(blame->thread, (void **)&err);
		if (errcode)
			return got_error_set_errno(errcode, "pthread_join");
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode,
			    "pthread_mutex_lock");
		if (err && err->code == GOT_ERR_ITER_COMPLETED)
			err = NULL;
		blame->thread = 0; //NULL;
	}
	if (blame->thread_args.repo) {
		const struct got_error *close_err;
		close_err = got_repo_close(blame->thread_args.repo);
		if (err == NULL)
			err = close_err;
		blame->thread_args.repo = NULL;
	}
	if (blame->f) {
		if (fclose(blame->f) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
		blame->f = NULL;
	}
	if (blame->lines) {
		for (i = 0; i < blame->nlines; i++)
			free(blame->lines[i].id);
		free(blame->lines);
		blame->lines = NULL;
	}
	free(blame->cb_args.commit_id);
	blame->cb_args.commit_id = NULL;
	if (blame->pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(blame->pack_fds);
		if (err == NULL)
			err = pack_err;
		blame->pack_fds = NULL;
	}
	free(blame->line_offsets);
	blame->line_offsets = NULL;
	return err;
}

static const struct got_error *
cancel_blame_view(void *arg)
{
	const struct got_error *err = NULL;
	int *done = arg;
	int errcode;

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_lock");

	if (*done)
		err = got_error(GOT_ERR_CANCELLED);

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode, "pthread_mutex_unlock");

	return err;
}

static const struct got_error *
run_blame(struct tog_view *view)
{
	struct tog_blame_view_state *s = &view->state.blame;
	struct tog_blame *blame = &s->blame;
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_blob_object *blob = NULL;
	struct got_repository *thread_repo = NULL;
	struct got_object_id *obj_id = NULL;
	int obj_type, fd = -1;
	int *pack_fds = NULL;

	err = got_object_open_as_commit(&commit, s->repo,
	    &s->blamed_commit->id);
	if (err)
		return err;

	fd = got_opentempfd();
	if (fd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	err = got_object_id_by_path(&obj_id, s->repo, commit, s->path);
	if (err)
		goto done;

	err = got_object_get_type(&obj_type, s->repo, obj_id);
	if (err)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open_as_blob(&blob, s->repo, obj_id, 8192, fd);
	if (err)
		goto done;
	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(&blame->filesize, &blame->nlines,
	    &blame->line_offsets, blame->f, blob);
	if (err)
		goto done;
	if (blame->nlines == 0) {
		s->blame_complete = 1;
		goto done;
	}

	/* Don't include \n at EOF in the blame line count. */
	if (blame->line_offsets[blame->nlines - 1] == blame->filesize)
		blame->nlines--;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = got_repo_pack_fds_open(&pack_fds);
	if (err)
		goto done;
	err = got_repo_open(&thread_repo, got_repo_get_path(s->repo), NULL,
	    pack_fds);
	if (err)
		goto done;

	blame->pack_fds = pack_fds;
	blame->cb_args.view = view;
	blame->cb_args.lines = blame->lines;
	blame->cb_args.nlines = blame->nlines;
	blame->cb_args.commit_id = got_object_id_dup(&s->blamed_commit->id);
	if (blame->cb_args.commit_id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}
	blame->cb_args.quit = &s->done;

	blame->thread_args.path = s->path;
	blame->thread_args.repo = thread_repo;
	blame->thread_args.cb_args = &blame->cb_args;
	blame->thread_args.complete = &s->blame_complete;
	blame->thread_args.cancel_cb = cancel_blame_view;
	blame->thread_args.cancel_arg = &s->done;
	s->blame_complete = 0;

	if (s->first_displayed_line + view->nlines - 1 > blame->nlines) {
		s->first_displayed_line = 1;
		s->last_displayed_line = view->nlines;
		s->selected_line = 1;
	}
	s->matched_line = 0;

done:
	if (commit)
		got_object_commit_close(commit);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	free(obj_id);
	if (err)
		stop_blame(blame);
	return err;
}

static const struct got_error *
open_blame_view(struct tog_view *view, char *path,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;

	STAILQ_INIT(&s->blamed_commits);

	s->path = strdup(path);
	if (s->path == NULL)
		return got_error_from_errno("strdup");

	err = got_object_qid_alloc(&s->blamed_commit, commit_id);
	if (err) {
		free(s->path);
		return err;
	}

	STAILQ_INSERT_HEAD(&s->blamed_commits, s->blamed_commit, entry);
	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->selected_line = 1;
	s->blame_complete = 0;
	s->repo = repo;
	s->commit_id = commit_id;
	memset(&s->blame, 0, sizeof(s->blame));

	STAILQ_INIT(&s->colors);
	if (has_colors() && getenv("TOG_COLORS") != NULL) {
		err = add_color(&s->colors, "^", TOG_COLOR_COMMIT,
		    get_color_value("TOG_COLOR_COMMIT"));
		if (err)
			return err;
	}

	view->show = show_blame_view;
	view->input = input_blame_view;
	view->reset = reset_blame_view;
	view->close = close_blame_view;
	view->search_start = search_start_blame_view;
	view->search_setup = search_setup_blame_view;
	view->search_next = search_next_view_match;

	if (using_mock_io) {
		struct tog_blame_thread_args *bta = &s->blame.thread_args;
		int rc;

		rc = pthread_cond_init(&bta->blame_complete, NULL);
		if (rc)
			return got_error_set_errno(rc, "pthread_cond_init");
	}

	return run_blame(view);
}

static const struct got_error *
close_blame_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;

	if (s->blame.thread)
		err = stop_blame(&s->blame);

	got_object_id_queue_free(&s->blamed_commits);

	if (using_mock_io) {
		struct tog_blame_thread_args *bta = &s->blame.thread_args;
		int rc;

		rc = pthread_cond_destroy(&bta->blame_complete);
		if (rc && err == NULL)
			err = got_error_set_errno(rc, "pthread_cond_destroy");
	}

	free(s->path);
	free_colors(&s->colors);
	return err;
}

static const struct got_error *
search_start_blame_view(struct tog_view *view)
{
	struct tog_blame_view_state *s = &view->state.blame;

	s->matched_line = 0;
	return NULL;
}

static void
search_setup_blame_view(struct tog_view *view, FILE **f, off_t **line_offsets,
    size_t *nlines, int **first, int **last, int **match, int **selected)
{
	struct tog_blame_view_state *s = &view->state.blame;

	*f = s->blame.f;
	*nlines = s->blame.nlines;
	*line_offsets = s->blame.line_offsets;
	*match = &s->matched_line;
	*first = &s->first_displayed_line;
	*last = &s->last_displayed_line;
	*selected = &s->selected_line;
}

static const struct got_error *
show_blame_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;
	int errcode;

	if (s->blame.thread == 0 && !s->blame_complete) {
		errcode = pthread_create(&s->blame.thread, NULL, blame_thread,
		    &s->blame.thread_args);
		if (errcode)
			return got_error_set_errno(errcode, "pthread_create");

		if (!using_mock_io)
			halfdelay(1); /* fast refresh while annotating  */
	}

	if (s->blame_complete && !using_mock_io)
		halfdelay(10); /* disable fast refresh */

	err = draw_blame(view);

	view_border(view);
	return err;
}

static const struct got_error *
log_annotated_line(struct tog_view **new_view, int begin_y, int begin_x,
    struct got_repository *repo, struct got_object_id *id)
{
	struct tog_view		*log_view;
	const struct got_error	*err = NULL;

	*new_view = NULL;

	log_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_LOG);
	if (log_view == NULL)
		return got_error_from_errno("view_open");

	err = open_log_view(log_view, id, repo, GOT_REF_HEAD, "", 0, NULL);
	if (err)
		view_close(log_view);
	else
		*new_view = log_view;

	return err;
}

static const struct got_error *
input_blame_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL, *thread_err = NULL;
	struct tog_view *diff_view;
	struct tog_blame_view_state *s = &view->state.blame;
	int eos, nscroll, begin_y = 0, begin_x = 0;

	eos = nscroll = view->nlines - 2;
	if (view_is_hsplit_top(view))
		--eos;  /* border */

	switch (ch) {
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'q':
		s->done = 1;
		break;
	case 'g':
	case KEY_HOME:
		s->selected_line = 1;
		s->first_displayed_line = 1;
		view->count = 0;
		break;
	case 'G':
	case KEY_END:
		if (s->blame.nlines < eos) {
			s->selected_line = s->blame.nlines;
			s->first_displayed_line = 1;
		} else {
			s->selected_line = eos;
			s->first_displayed_line = s->blame.nlines - (eos - 1);
		}
		view->count = 0;
		break;
	case 'k':
	case KEY_UP:
	case CTRL('p'):
		if (s->selected_line > 1)
			s->selected_line--;
		else if (s->selected_line == 1 &&
		    s->first_displayed_line > 1)
			s->first_displayed_line--;
		else
			view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		if (s->first_displayed_line == 1) {
			if (view->count > 1)
				nscroll += nscroll;
			s->selected_line = MAX(1, s->selected_line - nscroll);
			view->count = 0;
			break;
		}
		if (s->first_displayed_line > nscroll)
			s->first_displayed_line -= nscroll;
		else
			s->first_displayed_line = 1;
		break;
	case 'j':
	case KEY_DOWN:
	case CTRL('n'):
		if (s->selected_line < eos && s->first_displayed_line +
		    s->selected_line <= s->blame.nlines)
			s->selected_line++;
		else if (s->first_displayed_line < s->blame.nlines - (eos - 1))
			s->first_displayed_line++;
		else
			view->count = 0;
		break;
	case 'c':
	case 'p': {
		struct got_object_id *id = NULL;

		view->count = 0;
		id = get_selected_commit_id(s->blame.lines, s->blame.nlines,
		    s->first_displayed_line, s->selected_line);
		if (id == NULL)
			break;
		if (ch == 'p') {
			struct got_commit_object *commit, *pcommit;
			struct got_object_qid *pid;
			struct got_object_id *blob_id = NULL;
			int obj_type;
			err = got_object_open_as_commit(&commit,
			    s->repo, id);
			if (err)
				break;
			pid = STAILQ_FIRST(
			    got_object_commit_get_parent_ids(commit));
			if (pid == NULL) {
				got_object_commit_close(commit);
				break;
			}
			/* Check if path history ends here. */
			err = got_object_open_as_commit(&pcommit,
			    s->repo, &pid->id);
			if (err)
				break;
			err = got_object_id_by_path(&blob_id, s->repo,
			    pcommit, s->path);
			got_object_commit_close(pcommit);
			if (err) {
				if (err->code == GOT_ERR_NO_TREE_ENTRY)
					err = NULL;
				got_object_commit_close(commit);
				break;
			}
			err = got_object_get_type(&obj_type, s->repo,
			    blob_id);
			free(blob_id);
			/* Can't blame non-blob type objects. */
			if (obj_type != GOT_OBJ_TYPE_BLOB) {
				got_object_commit_close(commit);
				break;
			}
			err = got_object_qid_alloc(&s->blamed_commit,
			    &pid->id);
			got_object_commit_close(commit);
		} else {
			if (got_object_id_cmp(id,
			    &s->blamed_commit->id) == 0)
				break;
			err = got_object_qid_alloc(&s->blamed_commit,
			    id);
		}
		if (err)
			break;
		s->done = 1;
		thread_err = stop_blame(&s->blame);
		s->done = 0;
		if (thread_err)
			break;
		STAILQ_INSERT_HEAD(&s->blamed_commits,
		    s->blamed_commit, entry);
		err = run_blame(view);
		if (err)
			break;
		break;
	}
	case 'C': {
		struct got_object_qid *first;

		view->count = 0;
		first = STAILQ_FIRST(&s->blamed_commits);
		if (!got_object_id_cmp(&first->id, s->commit_id))
			break;
		s->done = 1;
		thread_err = stop_blame(&s->blame);
		s->done = 0;
		if (thread_err)
			break;
		STAILQ_REMOVE_HEAD(&s->blamed_commits, entry);
		got_object_qid_free(s->blamed_commit);
		s->blamed_commit =
		    STAILQ_FIRST(&s->blamed_commits);
		err = run_blame(view);
		if (err)
			break;
		break;
	}
	case 'L':
		view->count = 0;
		s->id_to_log = get_selected_commit_id(s->blame.lines,
		    s->blame.nlines, s->first_displayed_line, s->selected_line);
		if (s->id_to_log)
			err = view_request_new(new_view, view, TOG_VIEW_LOG);
		break;
	case KEY_ENTER:
	case '\r': {
		struct got_object_id *id = NULL;
		struct got_object_qid *pid;
		struct got_commit_object *commit = NULL;

		view->count = 0;
		id = get_selected_commit_id(s->blame.lines, s->blame.nlines,
		    s->first_displayed_line, s->selected_line);
		if (id == NULL)
			break;
		err = got_object_open_as_commit(&commit, s->repo, id);
		if (err)
			break;
		pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
		if (*new_view) {
			/* traversed from diff view, release diff resources  */
			err = close_diff_view(*new_view);
			if (err)
				break;
			diff_view = *new_view;
		} else {
			if (view_is_parent_view(view))
				view_get_split(view, &begin_y, &begin_x);

			diff_view = view_open(0, 0, begin_y, begin_x,
			    TOG_VIEW_DIFF);
			if (diff_view == NULL) {
				got_object_commit_close(commit);
				err = got_error_from_errno("view_open");
				break;
			}
		}
		err = open_diff_view(diff_view, pid ? &pid->id : NULL,
		    id, NULL, NULL, 3, 0, 0, 0, 0, NULL, view, s->repo, NULL);
		got_object_commit_close(commit);
		if (err)
			break;
		s->last_diffed_line = s->first_displayed_line - 1 +
		    s->selected_line;
		if (*new_view)
			break;	/* still open from active diff view */
		if (view_is_parent_view(view) &&
		    view->mode == TOG_VIEW_SPLIT_HRZN) {
			err = view_init_hsplit(view, begin_y);
			if (err)
				break;
		}

		view->focussed = 0;
		diff_view->focussed = 1;
		diff_view->mode = view->mode;
		diff_view->nlines = view->lines - begin_y;
		if (view_is_parent_view(view)) {
			view_transfer_size(diff_view, view);
			err = view_close_child(view);
			if (err)
				break;
			err = view_set_child(view, diff_view);
			if (err)
				break;
			view->focus_child = 1;
		} else
			*new_view = diff_view;
		if (err)
			break;
		break;
	}
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		if (s->last_displayed_line >= s->blame.nlines &&
		    s->selected_line >= MIN(s->blame.nlines,
		    view->nlines - 2)) {
			view->count = 0;
			break;
		}
		if (s->last_displayed_line >= s->blame.nlines &&
		    s->selected_line < view->nlines - 2) {
			s->selected_line +=
			    MIN(nscroll, s->last_displayed_line -
			    s->first_displayed_line - s->selected_line + 1);
		}
		if (s->last_displayed_line + nscroll <= s->blame.nlines)
			s->first_displayed_line += nscroll;
		else
			s->first_displayed_line =
			    s->blame.nlines - (view->nlines - 3);
		break;
	case KEY_RESIZE:
		if (s->selected_line > view->nlines - 2) {
			s->selected_line = MIN(s->blame.nlines,
			    view->nlines - 2);
		}
		break;
	default:
		view->count = 0;
		break;
	}
	return thread_err ? thread_err : err;
}

static const struct got_error *
reset_blame_view(struct tog_view *view)
{
	const struct got_error *err;
	struct tog_blame_view_state *s = &view->state.blame;

	view->count = 0;
	s->done = 1;
	err = stop_blame(&s->blame);
	s->done = 0;
	if (err)
		return err;
	return run_blame(view);
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	char *link_target = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	char *keyword_idstr = NULL, *commit_id_str = NULL;
	int ch;
	struct tog_view *view = NULL;
	int *pack_fds = NULL;

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
			break;
		default:
			usage_blame(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_blame(1);

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno("getcwd");
		error = got_worktree_open(&worktree, cwd, NULL);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree)
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
		else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = get_in_repo_path_from_argv0(&in_repo_path, argc, argv, repo,
	    worktree);
	if (error)
		goto done;

	init_curses();

	error = apply_unveil(got_repo_get_path(repo), NULL);
	if (error)
		goto done;

	error = tog_load_refs(repo, 0);
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
	} else {
		error = got_keyword_to_idstr(&keyword_idstr, commit_id_str,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			commit_id_str = keyword_idstr;

		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
	}
	if (error != NULL)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_resolve_symlinks(&link_target, in_repo_path,
	    commit, repo);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_BLAME);
	if (view == NULL) {
		error = got_error_from_errno("view_open");
		goto done;
	}
	error = open_blame_view(view, link_target ? link_target : in_repo_path,
	    commit_id, repo);
	if (error != NULL) {
		if (view->close == NULL)
			close_blame_view(view);
		view_close(view);
		goto done;
	}

	if (worktree) {
		error = set_tog_base_commit(repo, worktree);
		if (error != NULL)
			goto done;

		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = view_loop(view);

done:
	free(tog_base_commit.id);
	free(repo_path);
	free(in_repo_path);
	free(link_target);
	free(cwd);
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
	tog_free_refs();
	return error;
}

static const struct got_error *
draw_tree_entries(struct tog_view *view, const char *parent_path)
{
	struct tog_tree_view_state *s = &view->state.tree;
	const struct got_error *err = NULL;
	struct got_tree_entry *te;
	wchar_t *wline;
	char *index = NULL;
	struct tog_color *tc;
	int width, n, nentries, scrollx, i = 1;
	int limit = view->nlines;

	s->ndisplayed = 0;
	if (view_is_hsplit_top(view))
		--limit;  /* border */

	werase(view->window);

	if (limit == 0)
		return NULL;

	err = format_line(&wline, &width, NULL, s->tree_label, 0, view->ncols,
	    0, 0);
	if (err)
		return err;
	if (view_needs_focus_indication(view))
		wstandout(view->window);
	tc = get_color(&s->colors, TOG_COLOR_COMMIT);
	if (tc)
		wattr_on(view->window, COLOR_PAIR(tc->colorpair), NULL);
	waddwstr(view->window, wline);
	free(wline);
	wline = NULL;
	while (width++ < view->ncols)
		waddch(view->window, ' ');
	if (tc)
		wattr_off(view->window, COLOR_PAIR(tc->colorpair), NULL);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	if (--limit <= 0)
		return NULL;

	i += s->selected;
	if (s->first_displayed_entry) {
		i += got_tree_entry_get_index(s->first_displayed_entry);
		if (s->tree != s->root)
			++i;  /* account for ".." entry */
	}
	nentries = got_object_tree_get_nentries(s->tree);
	if (asprintf(&index, "[%d/%d] %s",
	    i, nentries + (s->tree == s->root ? 0 : 1), parent_path) == -1)
		return got_error_from_errno("asprintf");
	err = format_line(&wline, &width, NULL, index, 0, view->ncols, 0, 0);
	free(index);
	if (err)
		return err;
	waddwstr(view->window, wline);
	free(wline);
	wline = NULL;
	if (width < view->ncols - 1)
		waddch(view->window, '\n');
	if (--limit <= 0)
		return NULL;
	waddch(view->window, '\n');
	if (--limit <= 0)
		return NULL;

	if (s->first_displayed_entry == NULL) {
		te = got_object_tree_get_first_entry(s->tree);
		if (s->selected == 0) {
			if (view->focussed)
				wstandout(view->window);
			s->selected_entry = NULL;
		}
		waddstr(view->window, "  ..\n");	/* parent directory */
		if (s->selected == 0 && view->focussed)
			wstandend(view->window);
		s->ndisplayed++;
		if (--limit <= 0)
			return NULL;
		n = 1;
	} else {
		n = 0;
		te = s->first_displayed_entry;
	}

	view->maxx = 0;
	for (i = got_tree_entry_get_index(te); i < nentries; i++) {
		char *line = NULL, *id_str = NULL, *link_target = NULL;
		const char *modestr = "";
		mode_t mode;

		te = got_object_tree_get_entry(s->tree, i);
		mode = got_tree_entry_get_mode(te);

		if (s->show_ids) {
			err = got_object_id_str(&id_str,
			    got_tree_entry_get_id(te));
			if (err)
				return got_error_from_errno(
				    "got_object_id_str");
		}
		if (got_object_tree_entry_is_submodule(te))
			modestr = "$";
		else if (S_ISLNK(mode)) {
			int i;

			err = got_tree_entry_get_symlink_target(&link_target,
			    te, s->repo);
			if (err) {
				free(id_str);
				return err;
			}
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
		if (asprintf(&line, "%s  %s%s%s%s", id_str ? id_str : "",
		    got_tree_entry_get_name(te), modestr,
		    link_target ? " -> ": "",
		    link_target ? link_target : "") == -1) {
			free(id_str);
			free(link_target);
			return got_error_from_errno("asprintf");
		}
		free(id_str);
		free(link_target);

		/* use full line width to determine view->maxx */
		err = format_line(&wline, &width, NULL, line, 0, INT_MAX, 0, 0);
		if (err) {
			free(line);
			break;
		}
		view->maxx = MAX(view->maxx, width);
		free(wline);
		wline = NULL;

		err = format_line(&wline, &width, &scrollx, line, view->x,
		    view->ncols, 0, 0);
		if (err) {
			free(line);
			break;
		}
		if (n == s->selected) {
			if (view->focussed)
				wstandout(view->window);
			s->selected_entry = te;
		}
		tc = match_color(&s->colors, line);
		if (tc)
			wattr_on(view->window,
			    COLOR_PAIR(tc->colorpair), NULL);
		waddwstr(view->window, &wline[scrollx]);
		if (tc)
			wattr_off(view->window,
			    COLOR_PAIR(tc->colorpair), NULL);
		if (width < view->ncols)
			waddch(view->window, '\n');
		if (n == s->selected && view->focussed)
			wstandend(view->window);
		free(line);
		free(wline);
		wline = NULL;
		n++;
		s->ndisplayed++;
		s->last_displayed_entry = te;
		if (--limit <= 0)
			break;
	}

	return err;
}

static void
tree_scroll_up(struct tog_tree_view_state *s, int maxscroll)
{
	struct got_tree_entry *te;
	int isroot = s->tree == s->root;
	int i = 0;

	if (s->first_displayed_entry == NULL)
		return;

	te = got_tree_entry_get_prev(s->tree, s->first_displayed_entry);
	while (i++ < maxscroll) {
		if (te == NULL) {
			if (!isroot)
				s->first_displayed_entry = NULL;
			break;
		}
		s->first_displayed_entry = te;
		te = got_tree_entry_get_prev(s->tree, te);
	}
}

static const struct got_error *
tree_scroll_down(struct tog_view *view, int maxscroll)
{
	struct tog_tree_view_state *s = &view->state.tree;
	struct got_tree_entry *next, *last;
	int n = 0;

	if (s->first_displayed_entry)
		next = got_tree_entry_get_next(s->tree,
		    s->first_displayed_entry);
	else
		next = got_object_tree_get_first_entry(s->tree);

	last = s->last_displayed_entry;
	while (next && n++ < maxscroll) {
		if (last) {
			s->last_displayed_entry = last;
			last = got_tree_entry_get_next(s->tree, last);
		}
		if (last || (view->mode == TOG_VIEW_SPLIT_HRZN && next)) {
			s->first_displayed_entry = next;
			next = got_tree_entry_get_next(s->tree, next);
		}
	}

	return NULL;
}

static const struct got_error *
tree_entry_path(char **path, struct tog_parent_trees *parents,
    struct got_tree_entry *te)
{
	const struct got_error *err = NULL;
	struct tog_parent_tree *pt;
	size_t len = 2; /* for leading slash and NUL */

	TAILQ_FOREACH(pt, parents, entry)
		len += strlen(got_tree_entry_get_name(pt->selected_entry))
		    + 1 /* slash */;
	if (te)
		len += strlen(got_tree_entry_get_name(te));

	*path = calloc(1, len);
	if (path == NULL)
		return got_error_from_errno("calloc");

	(*path)[0] = '/';
	pt = TAILQ_LAST(parents, tog_parent_trees);
	while (pt) {
		const char *name = got_tree_entry_get_name(pt->selected_entry);
		if (strlcat(*path, name, len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		if (strlcat(*path, "/", len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		pt = TAILQ_PREV(pt, tog_parent_trees, entry);
	}
	if (te) {
		if (strlcat(*path, got_tree_entry_get_name(te), len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
	}
done:
	if (err) {
		free(*path);
		*path = NULL;
	}
	return err;
}

static const struct got_error *
blame_tree_entry(struct tog_view **new_view, int begin_y, int begin_x,
    struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;
	struct tog_view *blame_view;

	*new_view = NULL;

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	blame_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_BLAME);
	if (blame_view == NULL) {
		err = got_error_from_errno("view_open");
		goto done;
	}

	err = open_blame_view(blame_view, path, commit_id, repo);
	if (err) {
		if (err->code == GOT_ERR_CANCELLED)
			err = NULL;
		view_close(blame_view);
	} else
		*new_view = blame_view;
done:
	free(path);
	return err;
}

static const struct got_error *
log_selected_tree_entry(struct tog_view **new_view, int begin_y, int begin_x,
    struct tog_tree_view_state *s)
{
	struct tog_view *log_view;
	const struct got_error *err = NULL;
	char *path;

	*new_view = NULL;

	log_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_LOG);
	if (log_view == NULL)
		return got_error_from_errno("view_open");

	err = tree_entry_path(&path, &s->parents, s->selected_entry);
	if (err)
		return err;

	err = open_log_view(log_view, s->commit_id, s->repo, s->head_ref_name,
	    path, 0, NULL);
	if (err)
		view_close(log_view);
	else
		*new_view = log_view;
	free(path);
	return err;
}

static const struct got_error *
open_tree_view(struct tog_view *view, struct got_object_id *commit_id,
    const char *head_ref_name, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *commit_id_str = NULL;
	struct tog_tree_view_state *s = &view->state.tree;
	struct got_commit_object *commit = NULL;

	TAILQ_INIT(&s->parents);
	STAILQ_INIT(&s->colors);

	s->commit_id = got_object_id_dup(commit_id);
	if (s->commit_id == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	/*
	 * The root is opened here and will be closed when the view is closed.
	 * Any visited subtrees and their path-wise parents are opened and
	 * closed on demand.
	 */
	err = got_object_open_as_tree(&s->root, repo,
	    got_object_commit_get_tree_id(commit));
	if (err)
		goto done;
	s->tree = s->root;

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err != NULL)
		goto done;

	if (asprintf(&s->tree_label, "commit %s", commit_id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	s->first_displayed_entry = got_object_tree_get_entry(s->tree, 0);
	s->selected_entry = got_object_tree_get_entry(s->tree, 0);
	if (head_ref_name) {
		s->head_ref_name = strdup(head_ref_name);
		if (s->head_ref_name == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
	s->repo = repo;

	if (has_colors() && getenv("TOG_COLORS") != NULL) {
		err = add_color(&s->colors, "\\$$",
		    TOG_COLOR_TREE_SUBMODULE,
		    get_color_value("TOG_COLOR_TREE_SUBMODULE"));
		if (err)
			goto done;
		err = add_color(&s->colors, "@$", TOG_COLOR_TREE_SYMLINK,
		    get_color_value("TOG_COLOR_TREE_SYMLINK"));
		if (err)
			goto done;
		err = add_color(&s->colors, "/$",
		    TOG_COLOR_TREE_DIRECTORY,
		    get_color_value("TOG_COLOR_TREE_DIRECTORY"));
		if (err)
			goto done;

		err = add_color(&s->colors, "\\*$",
		    TOG_COLOR_TREE_EXECUTABLE,
		    get_color_value("TOG_COLOR_TREE_EXECUTABLE"));
		if (err)
			goto done;

		err = add_color(&s->colors, "^$", TOG_COLOR_COMMIT,
		    get_color_value("TOG_COLOR_COMMIT"));
		if (err)
			goto done;
	}

	view->show = show_tree_view;
	view->input = input_tree_view;
	view->close = close_tree_view;
	view->search_start = search_start_tree_view;
	view->search_next = search_next_tree_view;
done:
	free(commit_id_str);
	if (commit)
		got_object_commit_close(commit);
	if (err) {
		if (view->close == NULL)
			close_tree_view(view);
		view_close(view);
	}
	return err;
}

static const struct got_error *
close_tree_view(struct tog_view *view)
{
	struct tog_tree_view_state *s = &view->state.tree;

	free_colors(&s->colors);
	free(s->tree_label);
	s->tree_label = NULL;
	free(s->commit_id);
	s->commit_id = NULL;
	free(s->head_ref_name);
	s->head_ref_name = NULL;
	while (!TAILQ_EMPTY(&s->parents)) {
		struct tog_parent_tree *parent;
		parent = TAILQ_FIRST(&s->parents);
		TAILQ_REMOVE(&s->parents, parent, entry);
		if (parent->tree != s->root)
			got_object_tree_close(parent->tree);
		free(parent);

	}
	if (s->tree != NULL && s->tree != s->root)
		got_object_tree_close(s->tree);
	if (s->root)
		got_object_tree_close(s->root);
	return NULL;
}

static const struct got_error *
search_start_tree_view(struct tog_view *view)
{
	struct tog_tree_view_state *s = &view->state.tree;

	s->matched_entry = NULL;
	return NULL;
}

static int
match_tree_entry(struct got_tree_entry *te, regex_t *regex)
{
	regmatch_t regmatch;

	return regexec(regex, got_tree_entry_get_name(te), 1, &regmatch,
	    0) == 0;
}

static const struct got_error *
search_next_tree_view(struct tog_view *view)
{
	struct tog_tree_view_state *s = &view->state.tree;
	struct got_tree_entry *te = NULL;

	if (!view->searching) {
		view->search_next_done = TOG_SEARCH_HAVE_MORE;
		return NULL;
	}

	if (s->matched_entry) {
		if (view->searching == TOG_SEARCH_FORWARD) {
			if (s->selected_entry)
				te = got_tree_entry_get_next(s->tree,
				    s->selected_entry);
			else
				te = got_object_tree_get_first_entry(s->tree);
		} else {
			if (s->selected_entry == NULL)
				te = got_object_tree_get_last_entry(s->tree);
			else
				te = got_tree_entry_get_prev(s->tree,
				    s->selected_entry);
		}
	} else {
		if (s->selected_entry)
			te = s->selected_entry;
		else if (view->searching == TOG_SEARCH_FORWARD)
			te = got_object_tree_get_first_entry(s->tree);
		else
			te = got_object_tree_get_last_entry(s->tree);
	}

	while (1) {
		if (te == NULL) {
			if (s->matched_entry == NULL) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				return NULL;
			}
			if (view->searching == TOG_SEARCH_FORWARD)
				te = got_object_tree_get_first_entry(s->tree);
			else
				te = got_object_tree_get_last_entry(s->tree);
		}

		if (match_tree_entry(te, &view->regex)) {
			view->search_next_done = TOG_SEARCH_HAVE_MORE;
			s->matched_entry = te;
			break;
		}

		if (view->searching == TOG_SEARCH_FORWARD)
			te = got_tree_entry_get_next(s->tree, te);
		else
			te = got_tree_entry_get_prev(s->tree, te);
	}

	if (s->matched_entry) {
		s->first_displayed_entry = s->matched_entry;
		s->selected = 0;
	}

	return NULL;
}

static const struct got_error *
show_tree_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s = &view->state.tree;
	char *parent_path;

	err = tree_entry_path(&parent_path, &s->parents, NULL);
	if (err)
		return err;

	err = draw_tree_entries(view, parent_path);
	free(parent_path);

	view_border(view);
	return err;
}

static const struct got_error *
tree_goto_line(struct tog_view *view, int nlines)
{
	const struct got_error		 *err = NULL;
	struct tog_tree_view_state	 *s = &view->state.tree;
	struct got_tree_entry		**fte, **lte, **ste;
	int				  g, last, first = 1, i = 1;
	int				  root = s->tree == s->root;
	int				  off = root ? 1 : 2;

	g = view->gline;
	view->gline = 0;

	if (g == 0)
		g = 1;
	else if (g > got_object_tree_get_nentries(s->tree))
		g = got_object_tree_get_nentries(s->tree) + (root ? 0 : 1);

	fte = &s->first_displayed_entry;
	lte = &s->last_displayed_entry;
	ste = &s->selected_entry;

	if (*fte != NULL) {
		first = got_tree_entry_get_index(*fte);
		first += off;  /* account for ".." */
	}
	last = got_tree_entry_get_index(*lte);
	last += off;

	if (g >= first && g <= last && g - first < nlines) {
		s->selected = g - first;
		return NULL;	/* gline is on the current page */
	}

	if (*ste != NULL) {
		i = got_tree_entry_get_index(*ste);
		i += off;
	}

	if (i < g) {
		err = tree_scroll_down(view, g - i);
		if (err)
			return err;
		if (got_tree_entry_get_index(*lte) >=
		    got_object_tree_get_nentries(s->tree) - 1 &&
		    first + s->selected < g &&
		    s->selected < s->ndisplayed - 1) {
			first = got_tree_entry_get_index(*fte);
			first += off;
			s->selected = g - first;
		}
	} else if (i > g)
		tree_scroll_up(s, i - g);

	if (g < nlines &&
	    (*fte == NULL || (root && !got_tree_entry_get_index(*fte))))
		s->selected = g - 1;

	return NULL;
}

static const struct got_error *
input_tree_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s = &view->state.tree;
	struct got_tree_entry *te;
	int n, nscroll = view->nlines - 3;

	if (view->gline)
		return tree_goto_line(view, nscroll);

	switch (ch) {
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'i':
		s->show_ids = !s->show_ids;
		view->count = 0;
		break;
	case 'L':
		view->count = 0;
		if (!s->selected_entry)
			break;
		err = view_request_new(new_view, view, TOG_VIEW_LOG);
		break;
	case 'R':
		view->count = 0;
		err = view_request_new(new_view, view, TOG_VIEW_REF);
		break;
	case 'g':
	case '=':
	case KEY_HOME:
		s->selected = 0;
		view->count = 0;
		if (s->tree == s->root)
			s->first_displayed_entry =
			    got_object_tree_get_first_entry(s->tree);
		else
			s->first_displayed_entry = NULL;
		break;
	case 'G':
	case '*':
	case KEY_END: {
		int eos = view->nlines - 3;

		if (view->mode == TOG_VIEW_SPLIT_HRZN)
			--eos;  /* border */
		s->selected = 0;
		view->count = 0;
		te = got_object_tree_get_last_entry(s->tree);
		for (n = 0; n < eos; n++) {
			if (te == NULL) {
				if (s->tree != s->root) {
					s->first_displayed_entry = NULL;
					n++;
				}
				break;
			}
			s->first_displayed_entry = te;
			te = got_tree_entry_get_prev(s->tree, te);
		}
		if (n > 0)
			s->selected = n - 1;
		break;
	}
	case 'k':
	case KEY_UP:
	case CTRL('p'):
		if (s->selected > 0) {
			s->selected--;
			break;
		}
		tree_scroll_up(s, 1);
		if (s->selected_entry == NULL ||
		    (s->tree == s->root && s->selected_entry ==
		     got_object_tree_get_first_entry(s->tree)))
			view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		if (s->tree == s->root) {
			if (got_object_tree_get_first_entry(s->tree) ==
			    s->first_displayed_entry)
				s->selected -= MIN(s->selected, nscroll);
		} else {
			if (s->first_displayed_entry == NULL)
				s->selected -= MIN(s->selected, nscroll);
		}
		tree_scroll_up(s, MAX(0, nscroll));
		if (s->selected_entry == NULL ||
		    (s->tree == s->root && s->selected_entry ==
		     got_object_tree_get_first_entry(s->tree)))
			view->count = 0;
		break;
	case 'j':
	case KEY_DOWN:
	case CTRL('n'):
		if (s->selected < s->ndisplayed - 1) {
			s->selected++;
			break;
		}
		if (s->last_displayed_entry == NULL ||
		    got_tree_entry_get_next(s->tree, s->last_displayed_entry)
		    == NULL) {
			/* can't scroll any further */
			view->count = 0;
			break;
		}
		tree_scroll_down(view, 1);
		break;
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		if (s->last_displayed_entry == NULL ||
		    got_tree_entry_get_next(s->tree, s->last_displayed_entry)
		    == NULL) {
			/* can't scroll any further; move cursor down */
			if (s->selected < s->ndisplayed - 1)
				s->selected += MIN(nscroll,
				    s->ndisplayed - s->selected - 1);
			else
				view->count = 0;
			break;
		}
		tree_scroll_down(view, nscroll);
		break;
	case KEY_ENTER:
	case '\r':
	case KEY_BACKSPACE:
		if (s->selected_entry == NULL || ch == KEY_BACKSPACE) {
			struct tog_parent_tree *parent;
			/* user selected '..' */
			if (s->tree == s->root) {
				view->count = 0;
				break;
			}
			parent = TAILQ_FIRST(&s->parents);
			TAILQ_REMOVE(&s->parents, parent,
			    entry);
			got_object_tree_close(s->tree);
			s->tree = parent->tree;
			s->first_displayed_entry =
			    parent->first_displayed_entry;
			s->selected_entry =
			    parent->selected_entry;
			s->selected = parent->selected;
			if (s->selected > view->nlines - 3) {
				err = offset_selection_down(view);
				if (err)
					break;
			}
			free(parent);
		} else if (S_ISDIR(got_tree_entry_get_mode(
		    s->selected_entry))) {
			struct got_tree_object *subtree;
			view->count = 0;
			err = got_object_open_as_tree(&subtree, s->repo,
			    got_tree_entry_get_id(s->selected_entry));
			if (err)
				break;
			err = tree_view_visit_subtree(s, subtree);
			if (err) {
				got_object_tree_close(subtree);
				break;
			}
		} else if (S_ISREG(got_tree_entry_get_mode(s->selected_entry)))
			err = view_request_new(new_view, view, TOG_VIEW_BLAME);
		break;
	case KEY_RESIZE:
		if (view->nlines >= 4 && s->selected >= view->nlines - 3)
			s->selected = view->nlines - 4;
		view->count = 0;
		break;
	default:
		view->count = 0;
		break;
	}

	return err;
}

__dead static void
usage_tree(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	endwin();
	fprintf(fp,
	    "usage: %s tree [-c commit] [-r repository-path] [path]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
cmd_tree(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	const char *commit_id_arg = NULL;
	char *keyword_idstr = NULL, *label = NULL;
	struct got_reference *ref = NULL;
	const char *head_ref_name = NULL;
	int ch;
	struct tog_view *view;
	int *pack_fds = NULL;

	while ((ch = getopt(argc, argv, "c:r:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			break;
		default:
			usage_tree(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage_tree(1);

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno("getcwd");
		error = got_worktree_open(&worktree, cwd, NULL);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree)
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
		else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = get_in_repo_path_from_argv0(&in_repo_path, argc, argv,
	    repo, worktree);
	if (error)
		goto done;

	init_curses();

	error = apply_unveil(got_repo_get_path(repo), NULL);
	if (error)
		goto done;

	error = tog_load_refs(repo, 0);
	if (error)
		goto done;

	if (commit_id_arg == NULL) {
		error = got_repo_match_object_id(&commit_id, &label,
		    worktree ? got_worktree_get_head_ref_name(worktree) :
		    GOT_REF_HEAD, GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
		if (error)
			goto done;
		head_ref_name = label;
	} else {
		error = got_keyword_to_idstr(&keyword_idstr, commit_id_arg,
		    repo, worktree);
		if (error != NULL)
			goto done;
		if (keyword_idstr != NULL)
			commit_id_arg = keyword_idstr;

		error = got_ref_open(&ref, repo, commit_id_arg, 0);
		if (error == NULL)
			head_ref_name = got_ref_get_name(ref);
		else if (error->code != GOT_ERR_NOT_REF)
			goto done;
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_arg, GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
		if (error)
			goto done;
	}

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_TREE);
	if (view == NULL) {
		error = got_error_from_errno("view_open");
		goto done;
	}
	error = open_tree_view(view, commit_id, head_ref_name, repo);
	if (error)
		goto done;
	if (!got_path_is_root_dir(in_repo_path)) {
		error = tree_view_walk_path(&view->state.tree, commit,
		    in_repo_path);
		if (error)
			goto done;
	}

	if (worktree) {
		error = set_tog_base_commit(repo, worktree);
		if (error != NULL)
			goto done;

		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = view_loop(view);

done:
	free(tog_base_commit.id);
	free(keyword_idstr);
	free(repo_path);
	free(cwd);
	free(commit_id);
	free(label);
	if (commit != NULL)
		got_object_commit_close(commit);
	if (ref)
		got_ref_close(ref);
	if (worktree != NULL)
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
	tog_free_refs();
	return error;
}

static const struct got_error *
ref_view_load_refs(struct tog_ref_view_state *s)
{
	struct got_reflist_entry *sre;
	struct tog_reflist_entry *re;

	s->nrefs = 0;
	TAILQ_FOREACH(sre, &tog_refs, entry) {
		if (strncmp(got_ref_get_name(sre->ref),
		    "refs/got/", 9) == 0 &&
		    strncmp(got_ref_get_name(sre->ref),
		    "refs/got/backup/", 16) != 0)
			continue;

		re = malloc(sizeof(*re));
		if (re == NULL)
			return got_error_from_errno("malloc");

		re->ref = got_ref_dup(sre->ref);
		if (re->ref == NULL)
			return got_error_from_errno("got_ref_dup");
		re->idx = s->nrefs++;
		TAILQ_INSERT_TAIL(&s->refs, re, entry);
	}

	s->first_displayed_entry = TAILQ_FIRST(&s->refs);
	return NULL;
}

static void
ref_view_free_refs(struct tog_ref_view_state *s)
{
	struct tog_reflist_entry *re;

	while (!TAILQ_EMPTY(&s->refs)) {
		re = TAILQ_FIRST(&s->refs);
		TAILQ_REMOVE(&s->refs, re, entry);
		got_ref_close(re->ref);
		free(re);
	}
}

static const struct got_error *
open_ref_view(struct tog_view *view, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_ref_view_state *s = &view->state.ref;

	s->selected_entry = 0;
	s->repo = repo;

	TAILQ_INIT(&s->refs);
	STAILQ_INIT(&s->colors);

	err = ref_view_load_refs(s);
	if (err)
		goto done;

	if (has_colors() && getenv("TOG_COLORS") != NULL) {
		err = add_color(&s->colors, "^refs/heads/",
		    TOG_COLOR_REFS_HEADS,
		    get_color_value("TOG_COLOR_REFS_HEADS"));
		if (err)
			goto done;

		err = add_color(&s->colors, "^refs/tags/",
		    TOG_COLOR_REFS_TAGS,
		    get_color_value("TOG_COLOR_REFS_TAGS"));
		if (err)
			goto done;

		err = add_color(&s->colors, "^refs/remotes/",
		    TOG_COLOR_REFS_REMOTES,
		    get_color_value("TOG_COLOR_REFS_REMOTES"));
		if (err)
			goto done;

		err = add_color(&s->colors, "^refs/got/backup/",
		    TOG_COLOR_REFS_BACKUP,
		    get_color_value("TOG_COLOR_REFS_BACKUP"));
		if (err)
			goto done;
	}

	view->show = show_ref_view;
	view->input = input_ref_view;
	view->close = close_ref_view;
	view->search_start = search_start_ref_view;
	view->search_next = search_next_ref_view;
done:
	if (err) {
		if (view->close == NULL)
			close_ref_view(view);
		view_close(view);
	}
	return err;
}

static const struct got_error *
close_ref_view(struct tog_view *view)
{
	struct tog_ref_view_state *s = &view->state.ref;

	ref_view_free_refs(s);
	free_colors(&s->colors);

	return NULL;
}

static const struct got_error *
resolve_reflist_entry(struct got_object_id **commit_id,
    struct tog_reflist_entry *re, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *obj_id;
	struct got_tag_object *tag = NULL;
	int obj_type;

	*commit_id = NULL;

	err = got_ref_resolve(&obj_id, repo, re->ref);
	if (err)
		return err;

	err = got_object_get_type(&obj_type, repo, obj_id);
	if (err)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_COMMIT:
		break;
	case GOT_OBJ_TYPE_TAG:
		/*
		 * Git allows nested tags that point to tags; keep peeling
		 * till we reach the bottom, which is always a non-tag ref.
		 */
		do {
			if (tag != NULL)
				got_object_tag_close(tag);
			err = got_object_open_as_tag(&tag, repo, obj_id);
			if (err)
				goto done;
			free(obj_id);
			obj_id = got_object_id_dup(
			    got_object_tag_get_object_id(tag));
			if (obj_id == NULL) {
				err = got_error_from_errno("got_object_id_dup");
				goto done;
			}
			err = got_object_get_type(&obj_type, repo, obj_id);
			if (err)
				goto done;
		} while (obj_type == GOT_OBJ_TYPE_TAG);
		if (obj_type != GOT_OBJ_TYPE_COMMIT)
			err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

done:
	if (tag)
		got_object_tag_close(tag);
	if (err == NULL)
		*commit_id = obj_id;
	else
		free(obj_id);
	return err;
}

static const struct got_error *
log_ref_entry(struct tog_view **new_view, int begin_y, int begin_x,
    struct tog_reflist_entry *re, struct got_repository *repo)
{
	struct tog_view *log_view;
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL;

	*new_view = NULL;

	err = resolve_reflist_entry(&commit_id, re, repo);
	if (err)
		return err;

	log_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_LOG);
	if (log_view == NULL) {
		err = got_error_from_errno("view_open");
		goto done;
	}

	err = open_log_view(log_view, commit_id, repo,
	    got_ref_get_name(re->ref), "", 0, NULL);
done:
	if (err)
		view_close(log_view);
	else
		*new_view = log_view;
	free(commit_id);
	return err;
}

static void
ref_scroll_up(struct tog_ref_view_state *s, int maxscroll)
{
	struct tog_reflist_entry *re;
	int i = 0;

	if (s->first_displayed_entry == TAILQ_FIRST(&s->refs))
		return;

	re = TAILQ_PREV(s->first_displayed_entry, tog_reflist_head, entry);
	while (i++ < maxscroll) {
		if (re == NULL)
			break;
		s->first_displayed_entry = re;
		re = TAILQ_PREV(re, tog_reflist_head, entry);
	}
}

static const struct got_error *
ref_scroll_down(struct tog_view *view, int maxscroll)
{
	struct tog_ref_view_state *s = &view->state.ref;
	struct tog_reflist_entry *next, *last;
	int n = 0;

	if (s->first_displayed_entry)
		next = TAILQ_NEXT(s->first_displayed_entry, entry);
	else
		next = TAILQ_FIRST(&s->refs);

	last = s->last_displayed_entry;
	while (next && n++ < maxscroll) {
		if (last) {
			s->last_displayed_entry = last;
			last = TAILQ_NEXT(last, entry);
		}
		if (last || (view->mode == TOG_VIEW_SPLIT_HRZN)) {
			s->first_displayed_entry = next;
			next = TAILQ_NEXT(next, entry);
		}
	}

	return NULL;
}

static const struct got_error *
search_start_ref_view(struct tog_view *view)
{
	struct tog_ref_view_state *s = &view->state.ref;

	s->matched_entry = NULL;
	return NULL;
}

static int
match_reflist_entry(struct tog_reflist_entry *re, regex_t *regex)
{
	regmatch_t regmatch;

	return regexec(regex, got_ref_get_name(re->ref), 1, &regmatch,
	    0) == 0;
}

static const struct got_error *
search_next_ref_view(struct tog_view *view)
{
	struct tog_ref_view_state *s = &view->state.ref;
	struct tog_reflist_entry *re = NULL;

	if (!view->searching) {
		view->search_next_done = TOG_SEARCH_HAVE_MORE;
		return NULL;
	}

	if (s->matched_entry) {
		if (view->searching == TOG_SEARCH_FORWARD) {
			if (s->selected_entry)
				re = TAILQ_NEXT(s->selected_entry, entry);
			else
				re = TAILQ_PREV(s->selected_entry,
				    tog_reflist_head, entry);
		} else {
			if (s->selected_entry == NULL)
				re = TAILQ_LAST(&s->refs, tog_reflist_head);
			else
				re = TAILQ_PREV(s->selected_entry,
				    tog_reflist_head, entry);
		}
	} else {
		if (s->selected_entry)
			re = s->selected_entry;
		else if (view->searching == TOG_SEARCH_FORWARD)
			re = TAILQ_FIRST(&s->refs);
		else
			re = TAILQ_LAST(&s->refs, tog_reflist_head);
	}

	while (1) {
		if (re == NULL) {
			if (s->matched_entry == NULL) {
				view->search_next_done = TOG_SEARCH_HAVE_MORE;
				return NULL;
			}
			if (view->searching == TOG_SEARCH_FORWARD)
				re = TAILQ_FIRST(&s->refs);
			else
				re = TAILQ_LAST(&s->refs, tog_reflist_head);
		}

		if (match_reflist_entry(re, &view->regex)) {
			view->search_next_done = TOG_SEARCH_HAVE_MORE;
			s->matched_entry = re;
			break;
		}

		if (view->searching == TOG_SEARCH_FORWARD)
			re = TAILQ_NEXT(re, entry);
		else
			re = TAILQ_PREV(re, tog_reflist_head, entry);
	}

	if (s->matched_entry) {
		s->first_displayed_entry = s->matched_entry;
		s->selected = 0;
	}

	return NULL;
}

static const struct got_error *
show_ref_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_ref_view_state *s = &view->state.ref;
	struct tog_reflist_entry *re;
	char *line = NULL;
	wchar_t *wline;
	struct tog_color *tc;
	int width, n, scrollx;
	int limit = view->nlines;

	werase(view->window);

	s->ndisplayed = 0;
	if (view_is_hsplit_top(view))
		--limit;  /* border */

	if (limit == 0)
		return NULL;

	re = s->first_displayed_entry;

	if (asprintf(&line, "references [%d/%d]", re->idx + s->selected + 1,
	    s->nrefs) == -1)
		return got_error_from_errno("asprintf");

	err = format_line(&wline, &width, NULL, line, 0, view->ncols, 0, 0);
	if (err) {
		free(line);
		return err;
	}
	if (view_needs_focus_indication(view))
		wstandout(view->window);
	waddwstr(view->window, wline);
	while (width++ < view->ncols)
		waddch(view->window, ' ');
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	wline = NULL;
	free(line);
	line = NULL;
	if (--limit <= 0)
		return NULL;

	n = 0;
	view->maxx = 0;
	while (re && limit > 0) {
		char *line = NULL;
		char ymd[13];  /* YYYY-MM-DD + "  " + NUL */

		if (s->show_date) {
			struct got_commit_object *ci;
			struct got_tag_object *tag;
			struct got_object_id *id;
			struct tm tm;
			time_t t;

			err = got_ref_resolve(&id, s->repo, re->ref);
			if (err)
				return err;
			err = got_object_open_as_tag(&tag, s->repo, id);
			if (err) {
				if (err->code != GOT_ERR_OBJ_TYPE) {
					free(id);
					return err;
				}
				err = got_object_open_as_commit(&ci, s->repo,
				    id);
				if (err) {
					free(id);
					return err;
				}
				t = got_object_commit_get_committer_time(ci);
				got_object_commit_close(ci);
			} else {
				t = got_object_tag_get_tagger_time(tag);
				got_object_tag_close(tag);
			}
			free(id);
			if (gmtime_r(&t, &tm) == NULL)
				return got_error_from_errno("gmtime_r");
			if (strftime(ymd, sizeof(ymd), "%F  ", &tm) == 0)
				return got_error(GOT_ERR_NO_SPACE);
		}
		if (got_ref_is_symbolic(re->ref)) {
			if (asprintf(&line, "%s%s -> %s", s->show_date ?
			    ymd : "", got_ref_get_name(re->ref),
			    got_ref_get_symref_target(re->ref)) == -1)
				return got_error_from_errno("asprintf");
		} else if (s->show_ids) {
			struct got_object_id *id;
			char *id_str;
			err = got_ref_resolve(&id, s->repo, re->ref);
			if (err)
				return err;
			err = got_object_id_str(&id_str, id);
			if (err) {
				free(id);
				return err;
			}
			if (asprintf(&line, "%s%s: %s", s->show_date ? ymd : "",
			    got_ref_get_name(re->ref), id_str) == -1) {
				err = got_error_from_errno("asprintf");
				free(id);
				free(id_str);
				return err;
			}
			free(id);
			free(id_str);
		} else if (asprintf(&line, "%s%s", s->show_date ? ymd : "",
		    got_ref_get_name(re->ref)) == -1)
			return got_error_from_errno("asprintf");

		/* use full line width to determine view->maxx */
		err = format_line(&wline, &width, NULL, line, 0, INT_MAX, 0, 0);
		if (err) {
			free(line);
			return err;
		}
		view->maxx = MAX(view->maxx, width);
		free(wline);
		wline = NULL;

		err = format_line(&wline, &width, &scrollx, line, view->x,
		    view->ncols, 0, 0);
		if (err) {
			free(line);
			return err;
		}
		if (n == s->selected) {
			if (view->focussed)
				wstandout(view->window);
			s->selected_entry = re;
		}
		tc = match_color(&s->colors, got_ref_get_name(re->ref));
		if (tc)
			wattr_on(view->window,
			    COLOR_PAIR(tc->colorpair), NULL);
		waddwstr(view->window, &wline[scrollx]);
		if (tc)
			wattr_off(view->window,
			    COLOR_PAIR(tc->colorpair), NULL);
		if (width < view->ncols)
			waddch(view->window, '\n');
		if (n == s->selected && view->focussed)
			wstandend(view->window);
		free(line);
		free(wline);
		wline = NULL;
		n++;
		s->ndisplayed++;
		s->last_displayed_entry = re;

		limit--;
		re = TAILQ_NEXT(re, entry);
	}

	view_border(view);
	return err;
}

static const struct got_error *
browse_ref_tree(struct tog_view **new_view, int begin_y, int begin_x,
    struct tog_reflist_entry *re, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL;
	struct tog_view *tree_view;

	*new_view = NULL;

	err = resolve_reflist_entry(&commit_id, re, repo);
	if (err)
		return err;

	tree_view = view_open(0, 0, begin_y, begin_x, TOG_VIEW_TREE);
	if (tree_view == NULL) {
		err = got_error_from_errno("view_open");
		goto done;
	}

	err = open_tree_view(tree_view, commit_id,
	    got_ref_get_name(re->ref), repo);
	if (err)
		goto done;

	*new_view = tree_view;
done:
	free(commit_id);
	return err;
}

static const struct got_error *
ref_goto_line(struct tog_view *view, int nlines)
{
	const struct got_error		*err = NULL;
	struct tog_ref_view_state	*s = &view->state.ref;
	int				 g, idx = s->selected_entry->idx;

	g = view->gline;
	view->gline = 0;

	if (g == 0)
		g = 1;
	else if (g > s->nrefs)
		g = s->nrefs;

	if (g >= s->first_displayed_entry->idx + 1 &&
	    g <= s->last_displayed_entry->idx + 1 &&
	    g - s->first_displayed_entry->idx - 1 < nlines) {
		s->selected = g - s->first_displayed_entry->idx - 1;
		return NULL;
	}

	if (idx + 1 < g) {
		err = ref_scroll_down(view, g - idx - 1);
		if (err)
			return err;
		if (TAILQ_NEXT(s->last_displayed_entry, entry) == NULL &&
		    s->first_displayed_entry->idx + s->selected < g &&
		    s->selected < s->ndisplayed - 1)
			s->selected = g - s->first_displayed_entry->idx - 1;
	} else if (idx + 1 > g)
		ref_scroll_up(s, idx - g + 1);

	if (g < nlines && s->first_displayed_entry->idx == 0)
		s->selected = g - 1;

	return NULL;

}

static const struct got_error *
input_ref_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_ref_view_state *s = &view->state.ref;
	struct tog_reflist_entry *re;
	int n, nscroll = view->nlines - 1;

	if (view->gline)
		return ref_goto_line(view, nscroll);

	switch (ch) {
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'i':
		s->show_ids = !s->show_ids;
		view->count = 0;
		break;
	case 'm':
		s->show_date = !s->show_date;
		view->count = 0;
		break;
	case 'o':
		s->sort_by_date = !s->sort_by_date;
		view->action = s->sort_by_date ? "sort by date" : "sort by name";
		view->count = 0;
		err = got_reflist_sort(&tog_refs, s->sort_by_date ?
		    got_ref_cmp_by_commit_timestamp_descending :
		    tog_ref_cmp_by_name, s->repo);
		if (err)
			break;
		got_reflist_object_id_map_free(tog_refs_idmap);
		err = got_reflist_object_id_map_create(&tog_refs_idmap,
		    &tog_refs, s->repo);
		if (err)
			break;
		ref_view_free_refs(s);
		err = ref_view_load_refs(s);
		break;
	case KEY_ENTER:
	case '\r':
		view->count = 0;
		if (!s->selected_entry)
			break;
		err = view_request_new(new_view, view, TOG_VIEW_LOG);
		break;
	case 'T':
		view->count = 0;
		if (!s->selected_entry)
			break;
		err = view_request_new(new_view, view, TOG_VIEW_TREE);
		break;
	case 'g':
	case '=':
	case KEY_HOME:
		s->selected = 0;
		view->count = 0;
		s->first_displayed_entry = TAILQ_FIRST(&s->refs);
		break;
	case 'G':
	case '*':
	case KEY_END: {
		int eos = view->nlines - 1;

		if (view->mode == TOG_VIEW_SPLIT_HRZN)
			--eos;  /* border */
		s->selected = 0;
		view->count = 0;
		re = TAILQ_LAST(&s->refs, tog_reflist_head);
		for (n = 0; n < eos; n++) {
			if (re == NULL)
				break;
			s->first_displayed_entry = re;
			re = TAILQ_PREV(re, tog_reflist_head, entry);
		}
		if (n > 0)
			s->selected = n - 1;
		break;
	}
	case 'k':
	case KEY_UP:
	case CTRL('p'):
		if (s->selected > 0) {
			s->selected--;
			break;
		}
		ref_scroll_up(s, 1);
		if (s->selected_entry == TAILQ_FIRST(&s->refs))
			view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		if (s->first_displayed_entry == TAILQ_FIRST(&s->refs))
			s->selected -= MIN(nscroll, s->selected);
		ref_scroll_up(s, MAX(0, nscroll));
		if (s->selected_entry == TAILQ_FIRST(&s->refs))
			view->count = 0;
		break;
	case 'j':
	case KEY_DOWN:
	case CTRL('n'):
		if (s->selected < s->ndisplayed - 1) {
			s->selected++;
			break;
		}
		if (TAILQ_NEXT(s->last_displayed_entry, entry) == NULL) {
			/* can't scroll any further */
			view->count = 0;
			break;
		}
		ref_scroll_down(view, 1);
		break;
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		if (TAILQ_NEXT(s->last_displayed_entry, entry) == NULL) {
			/* can't scroll any further; move cursor down */
			if (s->selected < s->ndisplayed - 1)
				s->selected += MIN(nscroll,
				    s->ndisplayed - s->selected - 1);
			if (view->count > 1 && s->selected < s->ndisplayed - 1)
				s->selected += s->ndisplayed - s->selected - 1;
			view->count = 0;
			break;
		}
		ref_scroll_down(view, nscroll);
		break;
	case CTRL('l'):
		view->count = 0;
		tog_free_refs();
		err = tog_load_refs(s->repo, s->sort_by_date);
		if (err)
			break;
		ref_view_free_refs(s);
		err = ref_view_load_refs(s);
		break;
	case KEY_RESIZE:
		if (view->nlines >= 2 && s->selected >= view->nlines - 1)
			s->selected = view->nlines - 2;
		break;
	default:
		view->count = 0;
		break;
	}

	return err;
}

__dead static void
usage_ref(int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;
	endwin();
	fprintf(fp, "usage: %s ref [-r repository-path]\n",
	    getprogname());
	exit(status);
}

static const struct got_error *
cmd_ref(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch;
	struct tog_view *view;
	int *pack_fds = NULL;

	while ((ch = getopt(argc, argv, "r:")) != -1) {
		switch (ch) {
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			break;
		default:
			usage_ref(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage_ref(1);

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	if (repo_path == NULL) {
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno("getcwd");
		error = got_worktree_open(&worktree, cwd, NULL);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree)
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
		else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	init_curses();

	error = apply_unveil(got_repo_get_path(repo), NULL);
	if (error)
		goto done;

	error = tog_load_refs(repo, 0);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_REF);
	if (view == NULL) {
		error = got_error_from_errno("view_open");
		goto done;
	}

	error = open_ref_view(view, repo);
	if (error)
		goto done;

	if (worktree) {
		error = set_tog_base_commit(repo, worktree);
		if (error != NULL)
			goto done;

		/* Release work tree lock. */
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = view_loop(view);

done:
	free(tog_base_commit.id);
	free(repo_path);
	free(cwd);
	if (worktree != NULL)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *close_err;

		close_err = got_repo_close(repo);
		if (close_err && error == NULL)
			error = close_err;
	}
	if (pack_fds) {
		const struct got_error *pack_err;

		pack_err = got_repo_pack_fds_close(pack_fds);
		if (pack_err && error == NULL)
			error = pack_err;
	}
	tog_free_refs();
	return error;
}

static const struct got_error*
win_draw_center(WINDOW *win, size_t y, size_t x, size_t maxx, int focus,
    const char *str)
{
	size_t len;

	if (win == NULL)
		win = stdscr;

	len = strlen(str);
	x = x ? x : maxx > len ? (maxx - len) / 2 : 0;

	if (focus)
		wstandout(win);
	if (mvwprintw(win, y, x, "%s", str) == ERR)
		return got_error_msg(GOT_ERR_RANGE, "mvwprintw");
	if (focus)
		wstandend(win);

	return NULL;
}

static const struct got_error *
add_line_offset(off_t **line_offsets, size_t *nlines, off_t off)
{
	off_t *p;

	p = reallocarray(*line_offsets, *nlines + 1, sizeof(off_t));
	if (p == NULL) {
		free(*line_offsets);
		*line_offsets = NULL;
		return got_error_from_errno("reallocarray");
	}

	*line_offsets = p;
	(*line_offsets)[*nlines] = off;
	++(*nlines);
	return NULL;
}

static const struct got_error *
max_key_str(int *ret, const struct tog_key_map *km, size_t n)
{
	*ret = 0;

	for (;n > 0; --n, ++km) {
		char	*t0, *t, *k;
		size_t	 len = 1;

		if (km->keys == NULL)
			continue;

		t = t0 = strdup(km->keys);
		if (t0 == NULL)
			return got_error_from_errno("strdup");

		len += strlen(t);
		while ((k = strsep(&t, " ")) != NULL)
			len += strlen(k) > 1 ? 2 : 0;
		free(t0);
		*ret = MAX(*ret, len);
	}

	return NULL;
}

/*
 * Write keymap section headers, keys, and key info in km to f.
 * Save line offset to *off. If terminal has UTF8 encoding enabled,
 * wrap control and symbolic keys in guillemets, else use <>.
 */
static const struct got_error *
format_help_line(off_t *off, FILE *f, const struct tog_key_map *km, int width)
{
	int n, len = width;

	if (km->keys) {
		static const char *u8_glyph[] = {
			"\xe2\x80\xb9", /* U+2039  (utf8 <) */
			"\xe2\x80\xba"  /* U+203A  (utf8 >) */
		};
		char	*t0, *t, *k;
		int	 cs, s, first = 1;

		cs = got_locale_is_utf8();

		t = t0 = strdup(km->keys);
		if (t0 == NULL)
			return got_error_from_errno("strdup");

		len = strlen(km->keys);
		while ((k = strsep(&t, " ")) != NULL) {
			s = strlen(k) > 1;  /* control or symbolic key */
			n = fprintf(f, "%s%s%s%s%s", first ? "  " : "",
			    cs && s ? u8_glyph[0] : s ? "<" : "", k,
			    cs && s ? u8_glyph[1] : s ? ">" : "", t ? " " : "");
			if (n < 0) {
				free(t0);
				return got_error_from_errno("fprintf");
			}
			first = 0;
			len += s ? 2 : 0;
			*off += n;
		}
		free(t0);
	}
	n = fprintf(f, "%*s%s\n", width - len, width - len ? " " : "", km->info);
	if (n < 0)
		return got_error_from_errno("fprintf");
	*off += n;

	return NULL;
}

static const struct got_error *
format_help(struct tog_help_view_state *s)
{
	const struct got_error		*err = NULL;
	off_t				 off = 0;
	int				 i, max, n, show = s->all;
	static const struct tog_key_map	 km[] = {
#define KEYMAP_(info, type)	{ NULL, (info), type }
#define KEY_(keys, info)	{ (keys), (info), TOG_KEYMAP_KEYS }
		GENERATE_HELP
#undef KEYMAP_
#undef KEY_
	};

	err = add_line_offset(&s->line_offsets, &s->nlines, 0);
	if (err)
		return err;

	n = nitems(km);
	err = max_key_str(&max, km, n);
	if (err)
		return err;

	for (i = 0; i < n; ++i) {
		if (km[i].keys == NULL) {
			show = s->all;
			if (km[i].type == TOG_KEYMAP_GLOBAL ||
			    km[i].type == s->type || s->all)
				show = 1;
		}
		if (show) {
			err = format_help_line(&off, s->f, &km[i], max);
			if (err)
				return err;
			err = add_line_offset(&s->line_offsets, &s->nlines, off);
			if (err)
				return err;
		}
	}
	fputc('\n', s->f);
	++off;
	err = add_line_offset(&s->line_offsets, &s->nlines, off);
	return err;
}

static const struct got_error *
create_help(struct tog_help_view_state *s)
{
	FILE			*f;
	const struct got_error	*err;

	free(s->line_offsets);
	s->line_offsets = NULL;
	s->nlines = 0;

	f = got_opentemp();
	if (f == NULL)
		return got_error_from_errno("got_opentemp");
	s->f = f;

	err = format_help(s);
	if (err)
		return err;

	if (s->f && fflush(s->f) != 0)
		return got_error_from_errno("fflush");

	return NULL;
}

static const struct got_error *
search_start_help_view(struct tog_view *view)
{
	view->state.help.matched_line = 0;
	return NULL;
}

static void
search_setup_help_view(struct tog_view *view, FILE **f, off_t **line_offsets,
    size_t *nlines, int **first, int **last, int **match, int **selected)
{
	struct tog_help_view_state *s = &view->state.help;

	*f = s->f;
	*nlines = s->nlines;
	*line_offsets = s->line_offsets;
	*match = &s->matched_line;
	*first = &s->first_displayed_line;
	*last = &s->last_displayed_line;
	*selected = &s->selected_line;
}

static const struct got_error *
show_help_view(struct tog_view *view)
{
	struct tog_help_view_state	*s = &view->state.help;
	const struct got_error		*err;
	regmatch_t			*regmatch = &view->regmatch;
	wchar_t				*wline;
	char				*line;
	ssize_t				 linelen;
	size_t				 linesz = 0;
	int				 width, nprinted = 0, rc = 0;
	int				 eos = view->nlines;

	if (view_is_hsplit_top(view))
		--eos;  /* account for border */

	s->lineno = 0;
	rewind(s->f);
	werase(view->window);

	if (view->gline > s->nlines - 1)
		view->gline = s->nlines - 1;

	err = win_draw_center(view->window, 0, 0, view->ncols,
	    view_needs_focus_indication(view),
	    "tog help (press q to return to tog)");
	if (err)
		return err;
	if (eos <= 1)
		return NULL;
	waddstr(view->window, "\n\n");
	eos -= 2;

	s->eof = 0;
	view->maxx = 0;
	line = NULL;
	while (eos > 0 && nprinted < eos) {
		attr_t attr = 0;

		linelen = getline(&line, &linesz, s->f);
		if (linelen == -1) {
			if (!feof(s->f)) {
				free(line);
				return got_ferror(s->f, GOT_ERR_IO);
			}
			s->eof = 1;
			break;
		}
		if (++s->lineno < s->first_displayed_line)
			continue;
		if (view->gline && !gotoline(view, &s->lineno, &nprinted))
			continue;
		if (s->lineno == view->hiline)
			attr = A_STANDOUT;

		err = format_line(&wline, &width, NULL, line, 0, INT_MAX, 0,
		    view->x ? 1 : 0);
		if (err) {
			free(line);
			return err;
		}
		view->maxx = MAX(view->maxx, width);
		free(wline);
		wline = NULL;

		if (attr)
			wattron(view->window, attr);
		if (s->first_displayed_line + nprinted == s->matched_line &&
		    regmatch->rm_so >= 0 && regmatch->rm_so < regmatch->rm_eo) {
			err = add_matched_line(&width, line, view->ncols - 1, 0,
			    view->window, view->x, regmatch);
			if (err) {
				free(line);
				return err;
			}
		} else {
			int skip;

			err = format_line(&wline, &width, &skip, line,
			    view->x, view->ncols, 0, view->x ? 1 : 0);
			if (err) {
				free(line);
				return err;
			}
			waddwstr(view->window, &wline[skip]);
			free(wline);
			wline = NULL;
		}
		if (s->lineno == view->hiline) {
			while (width++ < view->ncols)
				waddch(view->window, ' ');
		} else {
			if (width < view->ncols)
				waddch(view->window, '\n');
		}
		if (attr)
			wattroff(view->window, attr);
		if (++nprinted == 1)
			s->first_displayed_line = s->lineno;
	}
	free(line);
	if (nprinted > 0)
		s->last_displayed_line = s->first_displayed_line + nprinted - 1;
	else
		s->last_displayed_line = s->first_displayed_line;

	view_border(view);

	if (s->eof) {
		rc = waddnstr(view->window,
		    "See the tog(1) manual page for full documentation",
		    view->ncols - 1);
		if (rc == ERR)
			return got_error_msg(GOT_ERR_RANGE, "waddnstr");
	} else {
		wmove(view->window, view->nlines - 1, 0);
		wclrtoeol(view->window);
		wstandout(view->window);
		rc = waddnstr(view->window, "scroll down for more...",
		    view->ncols - 1);
		if (rc == ERR)
			return got_error_msg(GOT_ERR_RANGE, "waddnstr");
		if (getcurx(view->window) < view->ncols - 6) {
			rc = wprintw(view->window, "[%.0f%%]",
			    100.00 * s->last_displayed_line / s->nlines);
			if (rc == ERR)
				return got_error_msg(GOT_ERR_IO, "wprintw");
		}
		wstandend(view->window);
	}

	return NULL;
}

static const struct got_error *
input_help_view(struct tog_view **new_view, struct tog_view *view, int ch)
{
	struct tog_help_view_state	*s = &view->state.help;
	const struct got_error		*err = NULL;
	char				*line = NULL;
	ssize_t				 linelen;
	size_t				 linesz = 0;
	int				 eos, nscroll;

	eos = nscroll = view->nlines;
	if (view_is_hsplit_top(view))
		--eos;  /* border */

	s->lineno = s->first_displayed_line - 1 + s->selected_line;

	switch (ch) {
	case '0':
	case '$':
	case KEY_RIGHT:
	case 'l':
	case KEY_LEFT:
	case 'h':
		horizontal_scroll_input(view, ch);
		break;
	case 'g':
	case KEY_HOME:
		s->first_displayed_line = 1;
		view->count = 0;
		break;
	case 'G':
	case KEY_END:
		view->count = 0;
		if (s->eof)
			break;
		s->first_displayed_line = (s->nlines - eos) + 3;
		s->eof = 1;
		break;
	case 'k':
	case KEY_UP:
		if (s->first_displayed_line > 1)
			--s->first_displayed_line;
		else
			view->count = 0;
		break;
	case CTRL('u'):
	case 'u':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_PPAGE:
	case CTRL('b'):
	case 'b':
		if (s->first_displayed_line == 1) {
			view->count = 0;
			break;
		}
		while (--nscroll > 0 && s->first_displayed_line > 1)
			s->first_displayed_line--;
		break;
	case 'j':
	case KEY_DOWN:
	case CTRL('n'):
		if (!s->eof)
			++s->first_displayed_line;
		else
			view->count = 0;
		break;
	case CTRL('d'):
	case 'd':
		nscroll /= 2;
		/* FALL THROUGH */
	case KEY_NPAGE:
	case CTRL('f'):
	case 'f':
	case ' ':
		if (s->eof) {
			view->count = 0;
			break;
		}
		while (!s->eof && --nscroll > 0) {
			linelen = getline(&line, &linesz, s->f);
			s->first_displayed_line++;
			if (linelen == -1) {
				if (feof(s->f))
					s->eof = 1;
				else
					err = got_ferror(s->f, GOT_ERR_IO);
				break;
			}
		}
		free(line);
		break;
	default:
		view->count = 0;
		break;
	}

	return err;
}

static const struct got_error *
close_help_view(struct tog_view *view)
{
	struct tog_help_view_state *s = &view->state.help;

	free(s->line_offsets);
	s->line_offsets = NULL;
	if (fclose(s->f) == EOF)
		return got_error_from_errno("fclose");

	return NULL;
}

static const struct got_error *
reset_help_view(struct tog_view *view)
{
	struct tog_help_view_state *s = &view->state.help;


	if (s->f && fclose(s->f) == EOF)
		return got_error_from_errno("fclose");

	wclear(view->window);
	view->count = 0;
	view->x = 0;
	s->all = !s->all;
	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->matched_line = 0;

	return create_help(s);
}

static const struct got_error *
open_help_view(struct tog_view *view, struct tog_view *parent)
{
	const struct got_error		*err = NULL;
	struct tog_help_view_state	*s = &view->state.help;

	s->type = (enum tog_keymap_type)parent->type;
	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->selected_line = 1;

	view->show = show_help_view;
	view->input = input_help_view;
	view->reset = reset_help_view;
	view->close = close_help_view;
	view->search_start = search_start_help_view;
	view->search_setup = search_setup_help_view;
	view->search_next = search_next_view_match;

	err = create_help(s);
	return err;
}

static const struct got_error *
view_dispatch_request(struct tog_view **new_view, struct tog_view *view,
    enum tog_view_type request, int y, int x)
{
	const struct got_error *err = NULL;

	*new_view = NULL;

	switch (request) {
	case TOG_VIEW_DIFF:
		if (view->type == TOG_VIEW_LOG) {
			struct tog_log_view_state *s = &view->state.log;

			err = open_diff_view_for_commit(new_view, y, x,
			    s->selected_entry, view, s->repo);
		} else
			return got_error_msg(GOT_ERR_NOT_IMPL,
			    "parent/child view pair not supported");
		break;
	case TOG_VIEW_BLAME:
		if (view->type == TOG_VIEW_TREE) {
			struct tog_tree_view_state *s = &view->state.tree;

			err = blame_tree_entry(new_view, y, x,
			    s->selected_entry, &s->parents, s->commit_id,
			    s->repo);
		} else
			return got_error_msg(GOT_ERR_NOT_IMPL,
			    "parent/child view pair not supported");
		break;
	case TOG_VIEW_LOG:
		tog_base_commit.idx = -1;
		if (view->type == TOG_VIEW_BLAME)
			err = log_annotated_line(new_view, y, x,
			    view->state.blame.repo, view->state.blame.id_to_log);
		else if (view->type == TOG_VIEW_TREE)
			err = log_selected_tree_entry(new_view, y, x,
			    &view->state.tree);
		else if (view->type == TOG_VIEW_REF)
			err = log_ref_entry(new_view, y, x,
			    view->state.ref.selected_entry,
			    view->state.ref.repo);
		else
			return got_error_msg(GOT_ERR_NOT_IMPL,
			    "parent/child view pair not supported");
		break;
	case TOG_VIEW_TREE:
		if (view->type == TOG_VIEW_LOG)
			err = browse_commit_tree(new_view, y, x,
			    view->state.log.selected_entry,
			    view->state.log.in_repo_path,
			    view->state.log.head_ref_name,
			    view->state.log.repo);
		else if (view->type == TOG_VIEW_REF)
			err = browse_ref_tree(new_view, y, x,
			    view->state.ref.selected_entry,
			    view->state.ref.repo);
		else
			return got_error_msg(GOT_ERR_NOT_IMPL,
			    "parent/child view pair not supported");
		break;
	case TOG_VIEW_REF:
		*new_view = view_open(0, 0, y, x, TOG_VIEW_REF);
		if (*new_view == NULL)
			return got_error_from_errno("view_open");
		if (view->type == TOG_VIEW_LOG)
			err = open_ref_view(*new_view, view->state.log.repo);
		else if (view->type == TOG_VIEW_TREE)
			err = open_ref_view(*new_view, view->state.tree.repo);
		else
			err = got_error_msg(GOT_ERR_NOT_IMPL,
			    "parent/child view pair not supported");
		if (err)
			view_close(*new_view);
		break;
	case TOG_VIEW_HELP:
		*new_view = view_open(0, 0, 0, 0, TOG_VIEW_HELP);
		if (*new_view == NULL)
			return got_error_from_errno("view_open");
		err = open_help_view(*new_view, view);
		if (err)
			view_close(*new_view);
		break;
	default:
		return got_error_msg(GOT_ERR_NOT_IMPL, "invalid view");
	}

	return err;
}

/*
 * If view was scrolled down to move the selected line into view when opening a
 * horizontal split, scroll back up when closing the split/toggling fullscreen.
 */
static void
offset_selection_up(struct tog_view *view)
{
	switch (view->type) {
	case TOG_VIEW_BLAME: {
		struct tog_blame_view_state *s = &view->state.blame;
		if (s->first_displayed_line == 1) {
			s->selected_line = MAX(s->selected_line - view->offset,
			    1);
			break;
		}
		if (s->first_displayed_line > view->offset)
			s->first_displayed_line -= view->offset;
		else
			s->first_displayed_line = 1;
		s->selected_line += view->offset;
		break;
	}
	case TOG_VIEW_LOG:
		log_scroll_up(&view->state.log, view->offset);
		view->state.log.selected += view->offset;
		break;
	case TOG_VIEW_REF:
		ref_scroll_up(&view->state.ref, view->offset);
		view->state.ref.selected += view->offset;
		break;
	case TOG_VIEW_TREE:
		tree_scroll_up(&view->state.tree, view->offset);
		view->state.tree.selected += view->offset;
		break;
	default:
		break;
	}

	view->offset = 0;
}

/*
 * If the selected line is in the section of screen covered by the bottom split,
 * scroll down offset lines to move it into view and index its new position.
 */
static const struct got_error *
offset_selection_down(struct tog_view *view)
{
	const struct got_error	*err = NULL;
	const struct got_error	*(*scrolld)(struct tog_view *, int);
	int			*selected = NULL;
	int			 header, offset;

	switch (view->type) {
	case TOG_VIEW_BLAME: {
		struct tog_blame_view_state *s = &view->state.blame;
		header = 3;
		scrolld = NULL;
		if (s->selected_line > view->nlines - header) {
			offset = abs(view->nlines - s->selected_line - header);
			s->first_displayed_line += offset;
			s->selected_line -= offset;
			view->offset = offset;
		}
		break;
	}
	case TOG_VIEW_LOG: {
		struct tog_log_view_state *s = &view->state.log;
		scrolld = &log_scroll_down;
		header = view_is_parent_view(view) ? 3 : 2;
		selected = &s->selected;
		break;
	}
	case TOG_VIEW_REF: {
		struct tog_ref_view_state *s = &view->state.ref;
		scrolld = &ref_scroll_down;
		header = 3;
		selected = &s->selected;
		break;
	}
	case TOG_VIEW_TREE: {
		struct tog_tree_view_state *s = &view->state.tree;
		scrolld = &tree_scroll_down;
		header = 5;
		selected = &s->selected;
		break;
	}
	default:
		selected = NULL;
		scrolld = NULL;
		header = 0;
		break;
	}

	if (selected && *selected > view->nlines - header) {
		offset = abs(view->nlines - *selected - header);
		view->offset = offset;
		if (scrolld && offset) {
			err = scrolld(view, offset);
			*selected -= MIN(*selected, offset);
		}
	}

	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(tog_commands); i++) {
		const struct tog_cmd *cmd = &tog_commands[i];
		fprintf(fp, " %s", cmd->name);
	}
	fputc('\n', fp);
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-hV] command [arg ...]\n",
	    getprogname());
	if (hflag) {
		fprintf(fp, "lazy usage: %s path\n", getprogname());
		list_commands(fp);
	}
	exit(status);
}

static char **
make_argv(int argc, ...)
{
	va_list ap;
	char **argv;
	int i;

	va_start(ap, argc);

	argv = calloc(argc, sizeof(char *));
	if (argv == NULL)
		err(1, "calloc");
	for (i = 0; i < argc; i++) {
		argv[i] = strdup(va_arg(ap, char *));
		if (argv[i] == NULL)
			err(1, "strdup");
	}

	va_end(ap);
	return argv;
}

/*
 * Try to convert 'tog path' into a 'tog log path' command.
 * The user could simply have mistyped the command rather than knowingly
 * provided a path. So check whether argv[0] can in fact be resolved
 * to a path in the HEAD commit and print a special error if not.
 * This hack is for mpi@ <3
 */
static const struct got_error *
tog_log_with_path(int argc, char *argv[])
{
	const struct got_error *error = NULL, *close_err;
	const struct tog_cmd *cmd = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_object_id *commit_id = NULL, *id = NULL;
	struct got_commit_object *commit = NULL;
	char *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	char *commit_id_str = NULL, **cmd_argv = NULL;
	int *pack_fds = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno("getcwd");

	error = got_repo_pack_fds_open(&pack_fds);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, cwd, NULL);
	if (error && error->code != GOT_ERR_NOT_WORKTREE)
		goto done;

	if (worktree)
		repo_path = strdup(got_worktree_get_repo_path(worktree));
	else
		repo_path = strdup(cwd);
	if (repo_path == NULL) {
		error = got_error_from_errno("strdup");
		goto done;
	}

	error = got_repo_open(&repo, repo_path, NULL, pack_fds);
	if (error != NULL)
		goto done;

	error = get_in_repo_path_from_argv0(&in_repo_path, argc, argv,
	    repo, worktree);
	if (error)
		goto done;

	error = tog_load_refs(repo, 0);
	if (error)
		goto done;
	error = got_repo_match_object_id(&commit_id, NULL, worktree ?
	    got_worktree_get_head_ref_name(worktree) : GOT_REF_HEAD,
	    GOT_OBJ_TYPE_COMMIT, &tog_refs, repo);
	if (error)
		goto done;

	if (worktree) {
		got_worktree_close(worktree);
		worktree = NULL;
	}

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&id, repo, commit, in_repo_path);
	if (error) {
		if (error->code != GOT_ERR_NO_TREE_ENTRY)
			goto done;
		fprintf(stderr, "%s: '%s' is no known command or path\n",
		    getprogname(), argv[0]);
		usage(1, 1);
		/* not reached */
	}

	error = got_object_id_str(&commit_id_str, commit_id);
	if (error)
		goto done;

	cmd = &tog_commands[0]; /* log */
	argc = 4;
	cmd_argv = make_argv(argc, cmd->name, "-c", commit_id_str, argv[0]);
	error = cmd->cmd_main(argc, cmd_argv);
done:
	if (repo) {
		close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	if (commit)
		got_object_commit_close(commit);
	if (worktree)
		got_worktree_close(worktree);
	if (pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(pack_fds);
		if (error == NULL)
			error = pack_err;
	}
	free(id);
	free(commit_id_str);
	free(commit_id);
	free(cwd);
	free(repo_path);
	free(in_repo_path);
	if (cmd_argv) {
		int i;
		for (i = 0; i < argc; i++)
			free(cmd_argv[i]);
		free(cmd_argv);
	}
	tog_free_refs();
	return error;
}

int
main(int argc, char *argv[])
{
	const struct got_error *io_err, *error = NULL;
	const struct tog_cmd *cmd = NULL;
	int ch, hflag = 0, Vflag = 0;
	char **cmd_argv = NULL;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0}
	};
	char *diff_algo_str = NULL;
	const char *test_script_path;

	setlocale(LC_CTYPE, "");

	/*
	 * Override default signal handlers before starting ncurses.
	 * This should prevent ncurses from installing its own
	 * broken cleanup() signal handler.
	 */
	signal(SIGWINCH, tog_sigwinch);
	signal(SIGPIPE, tog_sigpipe);
	signal(SIGCONT, tog_sigcont);
	signal(SIGINT, tog_sigint);
	signal(SIGTERM, tog_sigterm);

	/*
	 * Test mode init must happen before pledge() because "tty" will
	 * not allow TTY-related ioctls to occur via regular files.
	 */
	test_script_path = getenv("TOG_TEST_SCRIPT");
	if (test_script_path != NULL) {
		error = init_mock_term(test_script_path);
		if (error) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}
	} else if (!isatty(STDIN_FILENO))
		errx(1, "standard input is not a tty");

#if !defined(PROFILE)
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

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

	if (argc == 0) {
		if (hflag)
			usage(hflag, 0);
		/* Build an argument vector which runs a default command. */
		cmd = &tog_commands[0];
		argc = 1;
		cmd_argv = make_argv(argc, cmd->name);
	} else {
		size_t i;

		/* Did the user specify a command? */
		for (i = 0; i < nitems(tog_commands); i++) {
			if (strncmp(tog_commands[i].name, argv[0],
			    strlen(argv[0])) == 0) {
				cmd = &tog_commands[i];
				break;
			}
		}
	}

	diff_algo_str = getenv("TOG_DIFF_ALGORITHM");
	if (diff_algo_str) {
		if (strcasecmp(diff_algo_str, "patience") == 0)
			tog_diff_algo = GOT_DIFF_ALGORITHM_PATIENCE;
		if (strcasecmp(diff_algo_str, "myers") == 0)
			tog_diff_algo = GOT_DIFF_ALGORITHM_MYERS;
	}

	tog_base_commit.idx = -1;
	tog_base_commit.marker = GOT_WORKTREE_STATE_UNKNOWN;

	if (cmd == NULL) {
		if (argc > 1) {
			fprintf(stderr, "%s: unknown command '%s'\n",
			    getprogname(), argv[0]);
			list_commands(stderr);
			exit(1);
		}
		/* No command specified; try log with a path */
		error = tog_log_with_path(argc, argv);
	} else {
		if (hflag)
			cmd->cmd_usage(0);
		else
			error = cmd->cmd_main(argc, cmd_argv ? cmd_argv : argv);
	}

	if (using_mock_io) {
		io_err = tog_io_close();
		if (error == NULL)
			error = io_err;
	}
	endwin();
	if (cmd_argv) {
		int i;
		for (i = 0; i < argc; i++)
			free(cmd_argv[i]);
		free(cmd_argv);
	}

	if (error && error->code != GOT_ERR_CANCELLED &&
	    error->code != GOT_ERR_EOF &&
	    error->code != GOT_ERR_PRIVSEP_EXIT &&
	    error->code != GOT_ERR_PRIVSEP_PIPE &&
	    !(error->code == GOT_ERR_ERRNO && errno == EINTR)) {
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
		return 1;
	}
	return 0;
}
