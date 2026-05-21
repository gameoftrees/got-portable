sbin_PROGRAMS = cvg

include $(top_builddir)/Makefile.common

cvg_SOURCES = cvg.c \
	$(top_srcdir)/lib/blame.c \
	$(top_srcdir)/lib/bloom.c \
	$(top_srcdir)/lib/buf.c \
	$(top_srcdir)/lib/commit_graph.c \
	$(top_srcdir)/lib/date.c \
	$(top_srcdir)/lib/deflate.c \
	$(top_srcdir)/lib/delta.c \
	$(top_srcdir)/lib/delta_cache.c \
	$(top_srcdir)/lib/deltify.c \
	$(top_srcdir)/lib/dial.c \
	$(top_srcdir)/lib/diff.c \
	$(top_srcdir)/lib/diff3.c \
	$(top_srcdir)/lib/diff_atomize_text.c \
	$(top_srcdir)/lib/diff_main.c \
	$(top_srcdir)/lib/diff_myers.c \
	$(top_srcdir)/lib/diff_output.c \
	$(top_srcdir)/lib/diff_output_edscript.c \
	$(top_srcdir)/lib/diff_output_plain.c \
	$(top_srcdir)/lib/diff_output_unidiff.c \
	$(top_srcdir)/lib/diff_patience.c \
	$(top_srcdir)/lib/diffreg.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/fetch.c \
	$(top_srcdir)/lib/fileindex.c \
	$(top_srcdir)/lib/gotconfig.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/lockfile.c \
	$(top_srcdir)/lib/murmurhash2.c \
	$(top_srcdir)/lib/object.c \
	$(top_srcdir)/lib/object_cache.c \
	$(top_srcdir)/lib/object_create.c \
	$(top_srcdir)/lib/object_idset.c \
	$(top_srcdir)/lib/object_open_privsep.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pack.c \
	$(top_srcdir)/lib/pack_create.c \
	$(top_srcdir)/lib/pack_create_privsep.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/patch.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/ratelimit.c \
	$(top_srcdir)/lib/rcsutil.c \
	$(top_srcdir)/lib/read_gitconfig_privsep.c \
	$(top_srcdir)/lib/read_gotconfig_privsep.c \
	$(top_srcdir)/lib/reference.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/repository.c \
	$(top_srcdir)/lib/repository_gitconfig.c \
	$(top_srcdir)/lib/repository_init.c \
	$(top_srcdir)/lib/send.c \
	$(top_srcdir)/lib/sigs.c \
	$(top_srcdir)/lib/worktree.c \
	$(top_srcdir)/lib/worktree_cvg.c \
	$(top_srcdir)/lib/worktree_open.c

cvg_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = cvg.1

man1_MANS = cvg.1

LDADD = -L$(top_builddir)/compat \
	-lopenbsd-compat -lm
LDADD += $(libbsd_LIBS) \
	 $(zlib_LIBS) \
	 $(libuuid_LIBS) \
	 $(libutil_LIBS) \
	 $(libmd_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libbsd_CFLAGS) $(zlib_CFLAGS) \
	       $(libuuid_CFLAGS) $(libmd_CFLAGS)
