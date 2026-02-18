bin_PROGRAMS = gotctl

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd

gotctl_SOURCES = gotctl.c \
	$(top_srcdir)/gotd/imsg.c \
	$(top_srcdir)/gotd/parse.y \
	$(top_srcdir)/gotd/secrets.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gotd_imsg.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/log.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/reference_parse.c

if HOST_DARWIN
gotctl_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

gotctl_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotctl.8

man8_MANS = gotctl.8

LDADD = -L$(top_builddir)/compat -L$(top_builddir)/gotd -lopenbsd-compat -lm
LDADD += $(libutil_LIBS) \
	 $(zlib_LIBS) \
	 $(libbsd_LIBS) \
	 $(libevent_LIBS)

if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libutil_CFLAGS) \
	       $(libbsd_CFLAGS) \
	       $(zlib_CFLAGS) \
	       $(libevent_CFLAGS)
