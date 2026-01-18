.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotwebd

.include "../got-version.mk"

PROG=		gotwebctl
SRCS=		gotwebctl.c error.c hash.c

MAN =		${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotwebd

.if defined(PROFILE)
LDADD = -lutil_p -levent_p
.else
LDADD = -lutil -levent
.endif
DPADD = ${LIBUTIL} ${LIBEVENT}

PREFIX ?= /usr/local
BINDIR = ${PREFIX}/sbin

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
