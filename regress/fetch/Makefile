.PATH:${.CURDIR}/../../lib

PROG = fetch_test
SRCS = error.c privsep.c reference.c hash.c object.c object_parse.c path.c \
	opentemp.c repository.c lockfile.c object_cache.c pack.c inflate.c \
	deflate.c delta.c delta_cache.c object_idset.c object_create.c \
	fetch.c gotconfig.c dial.c fetch_test.c bloom.c murmurhash2.c sigs.c \
	buf.c date.c object_open_privsep.c read_gitconfig_privsep.c \
	read_gotconfig_privsep.c pollfd.c reference_parse.c object_qid.c \
	repository_gitconfig.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz -lm

NOMAN = yes

run-regress-fetch_test:
	${.OBJDIR}/fetch_test -q

.include <bsd.regress.mk>
