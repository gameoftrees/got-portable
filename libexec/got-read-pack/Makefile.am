libexec_PROGRAMS = got-read-pack

include $(top_builddir)/Makefile.common

got_read_pack_SOURCES = got-read-pack.c \
	$(top_srcdir)/lib/delta.c \
	$(top_srcdir)/lib/delta_cache.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_cache.c \
	$(top_srcdir)/lib/object_idset.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pack.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/privsep.c

if HOST_DARWIN
got_read_pack_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

got_read_pack_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(zlib_LIBS) $(libbsd_LIBS) $(libutil_LIBS) $(libmd_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(zlib_CFLAGS) $(libbsd_CFLAGS) $(libmd_CFLAGS)
