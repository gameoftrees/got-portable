sbin_PROGRAMS = gotwebctl

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_srcdir)/gotwebd

gotwebctl_SOURCES = \
		  $(top_srcdir)/lib/error.c \
		  $(top_srcdir)/lib/hash.c \
		  gotwebctl.c

gotwebctl_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotwebctl.8

man8_MANS = gotwebctl.8

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lm 
LDADD += $(libbsd_LIBS) \
	 $(libevent_LIBS) \
	 $(libutil_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libbsd_CFLAGS) \
	       $(libevent_CFLAGS) \
	       $(libuuid_CFLAGS)
