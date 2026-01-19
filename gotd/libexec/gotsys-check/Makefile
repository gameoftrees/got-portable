.PATH:${.CURDIR}/../../../lib ${.CURDIR}/../../../gotsys \
	${.CURDIR}/../../../include

.include "../../..//got-version.mk"

PROG=	gotsys-check
SRCS=	gotsys-check.c error.c gotd_imsg.c gotsys_conf.c hash.c parse.y \
	path.c pollfd.c reference_parse.c media.c

NOMAN =	Yes

CLEANFILES = parse.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../gotsysd -I${.CURDIR}/../../../gotsys \
	-I${.CURDIR}/../../../gotwebd -I${.CURDIR}/../../../gotd

.if defined(PROFILE)
LDADD = -lutil_p -levent_p -lc_p
.else
LDADD = -lutil -levent
.endif
DPADD = ${LIBUTIL} ${LIBEVENT}

.include <bsd.prog.mk>
