libexec_PROGRAMS = got-notify-email

include $(top_builddir)/Makefile.common

got_notify_email_SOURCES = got-notify-email.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/log.c \
	$(top_srcdir)/lib/pollfd.c

if HOST_DARWIN
got_notify_email_SOURCES += $(top_srcdir)/lib/portable-socket.c
endif

got_notify_email_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(zlib_LIBS) $(libbsd_LIBS) $(libutil_LIBS) $(libmd_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(zlib_CFLAGS) $(libbsd_CFLAGS) $(libmd_CFLAGS)
