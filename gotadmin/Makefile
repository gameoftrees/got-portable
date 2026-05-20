.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		gotadmin
SRCS=		gotadmin.c \
		deflate.c delta.c delta_cache.c deltify.c error.c gotconfig.c \
		inflate.c lockfile.c object.c object_cache.c object_create.c \
		object_idset.c object_parse.c opentemp.c pack.c pack_create.c \
		path.c privsep.c reference.c repository.c repository_admin.c \
		worktree_open.c hash.c bloom.c murmurhash2.c ratelimit.c \
		sigs.c buf.c date.c object_open_privsep.c \
		read_gitconfig_privsep.c read_gotconfig_privsep.c \
		pack_create_privsep.c pollfd.c reference_parse.c object_qid.c \
		dump.c load.c repository_init.c repository_gitconfig.c
MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p
.else
LDADD = -lutil -lz -lm
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
