.PATH:${.CURDIR}/../lib

SUBDIR = libexec

.include "../got-version.mk"

.if ${GOT_RELEASE} == "Yes"
BINDIR ?=	${PREFIX}/sbin
.endif

PROG=		gotd
SRCS=		gotd.c auth.c repo_read.c repo_write.c log.c privsep_stub.c \
		listen.c imsg.c parse.y secrets.c pack_create.c ratelimit.c \
		deltify.c gotd_imsg.c \
		bloom.c buf.c date.c deflate.c delta.c delta_cache.c error.c \
		gitconfig.c gotconfig.c inflate.c lockfile.c murmurhash2.c \
		object.c object_cache.c object_create.c object_idset.c \
		object_open_io.c object_parse.c opentemp.c pack.c path.c \
		read_gitconfig.c read_gotconfig.c reference.c repository.c  \
		hash.c sigs.c pack_create_io.c pollfd.c reference_parse.c \
		repo_imsg.c pack_index.c session_read.c session_write.c \
		object_qid.c notify.c commit_graph.c diffreg.c diff.c \
		diff_main.c diff_atomize_text.c diff_myers.c diff_output.c \
		diff_output_plain.c diff_output_unidiff.c \
		diff_output_edscript.c diff_patience.c repository_gitconfig.c

CLEANFILES = parse.h

MAN =		${PROG}.conf.5 ${PROG}-secrets.conf.5 ${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}
YFLAGS =

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p -levent_p
.else
LDADD = -lutil -lz -lm -levent
.endif
DPADD = ${LIBZ} ${LIBUTIL} ${LIBM} ${LIBEVENT}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
