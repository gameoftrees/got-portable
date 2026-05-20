.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		got
SRCS=		got.c blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c keyword.c object.c \
		object_cache.c object_idset.c object_parse.c opentemp.c \
		path.c pack.c privsep.c reference.c repository.c hash.c \
		worktree.c worktree_open.c inflate.c buf.c rcsutil.c \
		diff3.c lockfile.c deflate.c object_create.c delta_cache.c \
		fetch.c gotconfig.c diff_main.c diff_atomize_text.c \
		diff_myers.c diff_output.c diff_output_plain.c \
		diff_output_unidiff.c diff_output_edscript.c \
		diff_patience.c send.c deltify.c pack_create.c dial.c \
		bloom.c murmurhash2.c ratelimit.c patch.c sigs.c date.c \
		object_open_privsep.c read_gitconfig_privsep.c \
		read_gotconfig_privsep.c pack_create_privsep.c pollfd.c \
		reference_parse.c object_qid.c repository_init.c \
		repository_gitconfig.c

MAN =		${PROG}.1 got-worktree.5 git-repository.5 got.conf.5

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p
.else
LDADD = -lutil -lz -lm
.endif
DPADD = ${LIBZ} ${LIBUTIL} ${LIBM}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
