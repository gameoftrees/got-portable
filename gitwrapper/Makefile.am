bin_PROGRAMS = gitwrapper

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd
AM_CPPFLAGS += -DGITWRAPPER_GIT_LIBEXEC_DIR='"@GITWRAPPER_LIBEXEC_PATHC@"'

CLEANFILES = parse.h

gitwrapper_SOURCES = gitwrapper.c \
		  $(top_srcdir)/gotd/parse.y \
		  $(top_srcdir)/lib/dial.c \
		  $(top_srcdir)/lib/error.c \
		  $(top_srcdir)/lib/hash.c \
		  $(top_srcdir)/lib/log.c \
		  $(top_srcdir)/lib/object_qid.c \
		  $(top_srcdir)/lib/path.c \
		  $(top_srcdir)/lib/reference_parse.c

if HOST_DARWIN
gitwrapper_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

gitwrapper_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gitwrapper.1

man1_MANS = gitwrapper.1

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(libbsd_LIBS) \
	 $(libuuid_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libbsd_CFLAGS) $(libuuid_CFLAGS) $(libevent_CFLAGS)
