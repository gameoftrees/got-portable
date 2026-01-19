.PATH:${.CURDIR}/../lib ${.CURDIR}

.include "../got-version.mk"

PROG=	gotsys
SRCS=	gotsys.c gotsys_conf.c bloom.c buf.c date.c deflate.c delta.c \
	delta_cache.c error.c gitconfig.c gotconfig.c hash.c inflate.c \
	lockfile.c log.c murmurhash2.c object.c object_cache.c \
	object_create.c object_idset.c object_open_io.c object_parse.c \
	object_qid.c opentemp.c pack.c parse.y path.c pollfd.c \
	privsep_stub.c read_gitconfig.c read_gotconfig.c reference.c \
	reference_parse.c repository.c sigs.c media.c

MAN =		${PROG}.1 ${PROG}.conf.5

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib \
	-I${.CURDIR}/../gotsysd -I${.CURDIR}/../gotwebd -I${.CURDIR}

.if defined(PROFILE)
LDADD = -lutil_p -lm_p -lz_p -lc_p
.else
LDADD = -lutil -lm -lz
.endif
DPADD = ${LIBZ} ${LIBUTIL} ${LiBM} ${LIBZ}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
