.PATH: ${.CURDIR}/../../../gotsys ${.CURDIR}/../.. ${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		gotsys-read-conf
SRCS=		gotsys-read-conf.c error.c path.c hash.c parse.y pollfd.c \
		log.c reference_parse.c imsg.c gotsys_conf.c media.c \
		gotsys_imsg.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../gotsys -I${.CURDIR}/../../../gotwebd \
	-I${.CURDIR}/../../ -I${.CURDIR}
YFLAGS =

CLEANFILES = parse.c

.if defined(PROFILE)
LDADD = -lutil_p -levent_p
.else
LDADD = -lutil -levent
.endif

DPADD = ${LIBUTIL} ${LIBEVENT}


.include <bsd.prog.mk>
