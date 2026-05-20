.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		tog
SRCS=		tog.c blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c hash.c worktree.c \
		worktree_open.c utf8.c inflate.c buf.c rcsutil.c diff3.c \
		lockfile.c deflate.c object_create.c delta_cache.c \
		gotconfig.c diff_main.c diff_atomize_text.c \
		diff_myers.c diff_output.c diff_output_plain.c \
		diff_output_unidiff.c diff_output_edscript.c \
		diff_patience.c bloom.c murmurhash2.c sigs.c date.c \
		object_open_privsep.c read_gitconfig_privsep.c \
		read_gotconfig_privsep.c pollfd.c reference_parse.c \
		object_qid.c keyword.c repository_gitconfig.c
MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lpanel_p -lncursesw_p -lutil_p -lz_p -lpthread_p -lm_p -lc_p
.else
LDADD = -lpanel -lncursesw -lutil -lz -lpthread -lm
.endif
DPADD = ${LIBZ} ${LIBUTIL} ${LIBM}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

.if defined(TOG_REGRESS)
CPPFLAGS += -DTOG_REGRESS
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
