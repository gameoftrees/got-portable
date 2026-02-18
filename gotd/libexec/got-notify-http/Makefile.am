libexec_PROGRAMS = got-notify-http

include $(top_builddir)/Makefile.common

EXTRA_DIST = utf8d.h

got_notify_http_SOURCES = got-notify-http.c \
	$(top_srcdir)/lib/bufio.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/log.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pollfd.c

if HOST_DARWIN
got_notify_http_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

got_notify_http_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(zlib_LIBS) $(libbsd_LIBS) $(libutil_LIBS) $(libmd_LIBS) \
	 $(libtls_LIBS) $(libcrypto_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

if HOST_OPENBSD
LDADD += -ltls
endif

AM_CPPFLAGS += $(zlib_CFLAGS) $(libbsd_CFLAGS) $(libmd_CFLAGS) \
	       $(libtls_CFLAGS) $(libcrypto_CFLAGS)
