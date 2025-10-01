bin_PROGRAMS = gotsh

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd
AM_CPPFLAGS += -I$(top_srcdir)/gotwebd

gotsh_SOURCES = gotsh.c \
	$(top_srcdir)/gotd/imsg.c \
	$(top_srcdir)/lib/dial.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitproto.c \
	$(top_srcdir)/lib/gotd_imsg.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_qid.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pkt.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/serve.c
       
gotsh_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotsh.1

man1_MANS = gotsh.1

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

# Disable for now (per upstream)...
#
#install-exec-hook:
#	ln -sf $(prefix)/bin/gotsh $(prefix)/bin/git-receive-pack
#	ln -sf $(prefix)/bin/gotsh $(prefix)/bin/git-upload-pack
