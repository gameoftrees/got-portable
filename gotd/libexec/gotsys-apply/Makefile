.PATH:${.CURDIR}/../../../lib ${.CURDIR}/../../../gotsys \
	${.CURDIR}/../../../include

.include "../../..//got-version.mk"

PROG=	gotsys-apply
SRCS=	gotsys-apply.c bloom.c buf.c date.c deflate.c delta.c delta_cache.c \
	error.c gitconfig.c gotconfig.c gotd_imsg.c gotsys_conf.c hash.c \
	inflate.c lockfile.c log.c murmurhash2.c object.c object_cache.c \
	object_create.c object_idset.c object_open_io.c object_parse.c \
	object_qid.c opentemp.c pack.c path.c pollfd.c privsep_stub.c \
	read_gitconfig.c read_gotconfig.c reference.c reference_parse.c \
	repository.c sigs.c media.c

NOMAN =	Yes

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../gotsysd -I${.CURDIR}/../../../gotsys \
	-I${.CURDIR}/../../../gotwebd -I${.CURDIR}/../../../gotd

.if defined(PROFILE)
LDADD = -lutil_p -levent_p -lm_p -lz_p -lc_p
.else
LDADD = -lutil -levent -lm -lz
.endif
DPADD = ${LIBZ} ${LIBUTIL} ${LIBEVENT} ${LiBM} ${LIBZ}

.include <bsd.prog.mk>
