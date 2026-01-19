.PATH: ${.CURDIR}/../lib

SUBDIR = libexec

.include "../got-version.mk"

.if ${GOT_RELEASE} == "Yes"
BINDIR ?=	${PREFIX}/sbin
.endif

PROG=		gotsysd
SRCS=		gotsysd.c log.c error.c pollfd.c hash.c imsg.c parse.y path.c \
		listen.c auth.c helpers.c sysconf.c media.c gotsys_conf.c \
		gotsys_imsg.c reference_parse.c

CLEANFILES = parse.h

MAN =		${PROG}.conf.5 ${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotsys \
	-I${.CURDIR}/../gotwebd -I${.CURDIR}
YFLAGS =

.if defined(PROFILE)
LDADD = -lutil_p -lc_p -levent_p
.else
LDADD = -lutil -levent
.endif
DPADD = ${LIBUTIL} ${LIBEVENT}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
