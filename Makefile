SUBDIR = libexec got tog gotadmin gotsys

.PHONY: release dist

.if make(regress) || make(obj) || make(clean) || make(release)
SUBDIR += regress
.endif

.if make(clean) || make(obj) || make(release)
SUBDIR += gotwebd gotd gotsh gotctl template gitwrapper
SUBDIR += gotsysd gotsys gotsysctl
.endif

.if make(tags) || make(cleandir)
SUBDIR += lib
.endif

.include "got-version.mk"

.if "${GOT_RELEASE}" != "Yes" || make(clean) || make(obj)
SUBDIR += cvg
.endif

release: clean
	sed -i -e "s/_RELEASE=No/_RELEASE=Yes/" got-version.mk
	${MAKE} dist
	sed -i -e "s/_RELEASE=Yes/_RELEASE=No/" got-version.mk

dist: clean
	mkdir /tmp/got-${GOT_VERSION}
	pax -rw * /tmp/got-${GOT_VERSION}
	find /tmp/got-${GOT_VERSION} -name obj -type d -delete
	rm /tmp/got-${GOT_VERSION}/got-dist.txt
	tar -C /tmp -zcf got-${GOT_VERSION}.tar.gz got-${GOT_VERSION}
	rm -rf /tmp/got-${GOT_VERSION}
	tar -ztf got-${GOT_VERSION}.tar.gz | sed -e 's/^got-${GOT_VERSION}//' \
		| sort > got-dist.txt.new
	diff -u got-dist.txt got-dist.txt.new
	rm got-dist.txt.new

tmpl:
	${MAKE} -C template

tmpl-regress:
	${MAKE} -C regress/template

webd: tmpl
	${MAKE} -C gotwebctl
	${MAKE} -C gotwebd

webd-install:
	${MAKE} -C gotwebctl install
	${MAKE} -C gotwebd install

server:
	${MAKE} -C gotctl
	${MAKE} -C gotd
	${MAKE} -C gotsh
	${MAKE} -C gitwrapper

server-install:
	${MAKE} -C gotctl install
	${MAKE} -C gotd install
	${MAKE} -C gotsh install
	${MAKE} -C gitwrapper install

server-regress:
	${MAKE} -C regress/gotd

webd-regress:
	${MAKE} -C regress/gotwebd

sysd:
	${MAKE} -C gotsysctl
	${MAKE} -C gotsysd

sysd-install:
	${MAKE} -C gotsysctl install
	${MAKE} -C gotsysd install

.include <bsd.subdir.mk>
