sbin_PROGRAMS = gotwebd

include $(top_builddir)/Makefile.common

# /home/n6tadam/projects/got/gotwebd/../template/template -o pages.c pages.tmpl

BUILT_SOURCES = pages.c
CLEANFILES = pages.c parse.c

pages.c: $(top_srcdir)/gotwebd/pages.tmpl
	${MAKE} -C $(top_builddir)/template
	$(top_builddir)/template/template -o pages.c $(top_srcdir)/gotwebd/pages.tmpl

gotwebd_SOURCES = config.c \
		  $(top_srcdir)/lib/blame.c \
		  $(top_srcdir)/lib/bloom.c \
		  $(top_srcdir)/lib/buf.c \
		  $(top_srcdir)/lib/commit_graph.c \
		  $(top_srcdir)/lib/date.c \
		  $(top_srcdir)/lib/deflate.c \
		  $(top_srcdir)/lib/delta.c \
		  $(top_srcdir)/lib/delta_cache.c \
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
		  $(top_srcdir)/lib/fileindex.c \
		  $(top_srcdir)/lib/gotconfig.c \
		  $(top_srcdir)/lib/hash.c \
		  $(top_srcdir)/lib/inflate.c \
		  $(top_srcdir)/lib/lockfile.c \
		  $(top_srcdir)/lib/log.c \
		  $(top_srcdir)/lib/media.c \
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
		  $(top_srcdir)/lib/patch.c \
		  $(top_srcdir)/lib/path.c \
		  $(top_srcdir)/lib/pollfd.c \
		  $(top_srcdir)/lib/privsep.c \
		  $(top_srcdir)/lib/rcsutil.c \
		  $(top_srcdir)/lib/read_gitconfig_privsep.c \
		  $(top_srcdir)/lib/read_gotconfig_privsep.c \
		  $(top_srcdir)/lib/reference.c \
		  $(top_srcdir)/lib/reference_parse.c \
		  $(top_srcdir)/lib/repository.c \
		  $(top_srcdir)/lib/sigs.c \
		  $(top_srcdir)/lib/utf8.c \
		  $(top_srcdir)/lib/worktree.c \
		  $(top_srcdir)/lib/worktree_open.c \
		  $(top_srcdir)/template/tmpl.c \
		  auth.c \
		  fcgi.c \
		  got_operations.c \
		  gotweb.c \
		  gotwebd.c \
		  login.c \
		  pages.c \
		  parse.y \
		  sockets.c

gotwebd_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = $(top_srcdir)/gotwebd/*.h \
	     $(top_srcdir)/gotwebd/*.tmpl \
	     $(top_srcdir)/template/tmpl.h \
	     gotwebd.8 gotwebd.conf.5 files

man5_MANS = gotwebd.conf.5
man8_MANS = gotwebd.8

LDADD = -L$(top_builddir)/compat -L$(top_builddir)/template \
	-lopenbsd-compat -lm 
LDADD += $(libbsd_LIBS) \
	 $(libcrypto_LIBS) \
	 $(libevent_LIBS) \
	 $(zlib_LIBS) \
	 $(libuuid_LIBS) \
	 $(libutil_LIBS) \
	 $(libmd_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libbsd_CFLAGS) \
	       $(libcrypto_CFLAGS) \
	       $(libevent_CFLAGS) \
	       $(zlib_CFLAGS) \
	       $(libuuid_CFLAGS) \
	       $(libmd_CFLAGS)

#realinstall:
#	if [ ! -d ${DESTDIR}${PUB_REPOS_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PUB_REPOS_DIR}; \
#	fi
#	${INSTALL} -c -o root -g daemon -m 0755 ${PROG} ${BINDIR}/${PROG}
#	if [ ! -d ${DESTDIR}${HTTPD_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${HTTPD_DIR}; \
#	fi
#	if [ ! -d ${DESTDIR}${PROG_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PROG_DIR}; \
#	fi
#	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
#	    ${.CURDIR}/files/htdocs/${PROG}/* ${DESTDIR}${PROG_DIR}
#
#.include <bsd.prog.mk>
