.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotd

.include "../got-version.mk"

PROG=		gotsh
SRCS=		gotsh.c error.c pkt.c hash.c serve.c path.c gitproto.c \
		imsg.c pollfd.c dial.c reference_parse.c object_qid.c \
		gotd_imsg.c

MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotd \
	-I${.CURDIR}/../gotwebd

.if defined(PROFILE)
LDADD = -lutil_p -lc_p -levent_p
.else
LDADD = -lutil -levent
.endif
DPADD = ${LIBEVENT} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
