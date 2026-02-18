sbin_PROGRAMS = gotd

SUBDIRS=libexec

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -DGOTD_EMPTY_PATH='"@GOTD_EMPTY_PATHC@"'

gotd_SOURCES = gotd.c \
	$(top_srcdir)/lib/bloom.c \
	$(top_srcdir)/lib/buf.c \
	$(top_srcdir)/lib/commit_graph.c \
	$(top_srcdir)/lib/date.c \
	$(top_srcdir)/lib/deflate.c \
	$(top_srcdir)/lib/delta.c \
	$(top_srcdir)/lib/delta_cache.c \
	$(top_srcdir)/lib/deltify.c \
	$(top_srcdir)/lib/diff.c \
	$(top_srcdir)/lib/diff_atomize_text.c \
	$(top_srcdir)/lib/diff_main.c \
	$(top_srcdir)/lib/diff_myers.c \
	$(top_srcdir)/lib/diff_output.c \
	$(top_srcdir)/lib/diff_output_plain.c \
	$(top_srcdir)/lib/diff_output_unidiff.c \
	$(top_srcdir)/lib/diff_patience.c \
	$(top_srcdir)/lib/diffreg.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitconfig.c \
	$(top_srcdir)/lib/gotd_imsg.c \
	$(top_srcdir)/lib/gotconfig.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/lockfile.c \
	$(top_srcdir)/lib/log.c \
	$(top_srcdir)/lib/murmurhash2.c \
	$(top_srcdir)/lib/object.c \
	$(top_srcdir)/lib/object_cache.c \
	$(top_srcdir)/lib/object_create.c \
	$(top_srcdir)/lib/object_idset.c \
	$(top_srcdir)/lib/object_open_io.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pack.c \
	$(top_srcdir)/lib/pack_create.c \
	$(top_srcdir)/lib/pack_create_io.c \
	$(top_srcdir)/lib/pack_index.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/ratelimit.c \
	$(top_srcdir)/lib/read_gitconfig.c \
	$(top_srcdir)/lib/read_gotconfig.c \
	$(top_srcdir)/lib/reference.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/repository.c \
	$(top_srcdir)/lib/sigs.c \
	auth.c \
	imsg.c \
	listen.c \
	notify.c \
	parse.y \
	privsep_stub.c \
	repo_imsg.c \
	repo_read.c \
	repo_write.c \
	secrets.c \
	session_read.c \
	session_write.c

if HOST_DARWIN
gotd_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

if !HOST_OPENBSD
gotd_SOURCES += chroot-notobsd.c
else
gotd_SOURCES += chroot-openbsd.c
endif
       
gotd_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotd.8 gotd.conf.5 gotd-secrets.conf.5 *.h

man5_MANS = gotd.conf.5 gotd-secrets.conf.5
man8_MANS = gotd.8

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lm
LDADD += $(libuuid_LIBS) \
	 $(zlib_LIBS) \
	 $(libbsd_LIBS) \
	 $(libevent_LIBS) \
	 $(libutil_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libuuid_CFLAGS) \
	       $(zlib_CFLAGS) \
	       $(libbsd_CFLAGS) \
	       $(libevent_CFLAGS)
