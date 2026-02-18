libexec_PROGRAMS = got-fetch-http

include $(top_builddir)/Makefile.common

got_fetch_http_SOURCES = got-fetch-http.c \
	$(top_srcdir)/lib/bufio.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pkt.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/object_parse.c

if HOST_DARWIN
got_fetch_http_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

got_fetch_http_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(zlib_LIBS) $(libbsd_LIBS) $(libutil_LIBS) $(libmd_LIBS) $(libtls_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

if HOST_OPENBSD
LDADD += -ltls
endif

AM_CPPFLAGS += $(zlib_CFLAGS) $(libbsd_CFLAGS) $(libmd_CFLAGS) $(libtls_CFLAGS)
