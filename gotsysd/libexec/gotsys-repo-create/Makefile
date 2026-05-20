.PATH: ${.CURDIR}/../../../gotsys ${.CURDIR}/../.. ${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		gotsys-repo-create
SRCS=		gotsys-repo-create.c error.c hash.c pollfd.c path.c \
		imsg.c gotsys_conf.c media.c gotsys_imsg.c repository_init.c \
		reference_parse.c lockfile.c repository_gitconfig.c \
		read_gitconfig.c gitconfig.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../gotsys -I${.CURDIR}/../../../gotwebd \
	-I${.CURDIR}/../../ -I${.CURDIR}
YFLAGS =

.if defined(PROFILE)
LDADD = -lutil_p -levent_p
.else
LDADD = -lutil -levent
.endif

DPADD = ${LIBUTIL} ${LIBEVENT}


.include <bsd.prog.mk>
