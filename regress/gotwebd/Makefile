.PATH:${.CURDIR}/../../lib

REGRESS_TARGETS=test_gotwebd test_gotwebd_paginate

PROG = gotwebd_test
SRCS = gotwebd_test.c error.c hash.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

NOMAN = yes

.PHONY: ensure_root prepare_test_env prepare_test_repo start_gotwebd \
	gotwebd_test_conf gotwebd_test_conf_paginate

GOTWEBD_TEST_TMPDIR=/tmp
GOTWEBD_TEST_ROOT?!!=mktemp -d "${GOTWEBD_TEST_TMPDIR}/gotwebd-test-XXXXXXXXXX"
GOTWEBD_TEST_CHROOT=${GOTWEBD_TEST_ROOT}/var/www
GOTWEBD_TEST_CONF=${GOTWEBD_TEST_ROOT}/gotwebd.conf
GOTWEBD_TEST_SOCK=${GOTWEBD_TEST_CHROOT}/gotweb.sock
GOTWEBD_TEST_FCGI=${.OBJDIR}/${PROG}
GOTWEBD_TEST_PAGINATE_NITEMS?=15  # must be a multiple of 3 (items per page)
GOTWEBD_CHECK_MEMLEAK=export MALLOC_OPTIONS=1; ktrace -d -tu -i -f ${GOTWEBD_TEST_ROOT}/ktrace.out

GOTWEBD_TEST_USER?=${DOAS_USER}
.if empty(GOTWEBD_TEST_USER)
GOTWEBD_TEST_USER=${SUDO_USER}
.endif
.if empty(GOTWEBD_TEST_USER)
GOTWEBD_TEST_USER=${USER}
.endif

GOTWEBD_TEST_USER_HOME!=getent passwd ${GOTWEBD_TEST_USER} | cut -d: -f6

PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/sbin

GOTWEBD_START_CMD?=${BINDIR}/gotwebd -vvf ${GOTWEBD_TEST_CONF}
GOTWEBD_STOP_CMD?=pkill -TERM -fx '${GOTWEBD_START_CMD}'
GOTWEBD_TRAP=trap "${GOTWEBD_STOP_CMD}" HUP INT QUIT PIPE TERM

GOTWEBD_TEST_ENV=GOTWEBD_TEST_SOCK=${GOTWEBD_TEST_SOCK} \
	GOTWEBD_TEST_CHROOT=${GOTWEBD_TEST_CHROOT} \
	GOTWEBD_TEST_ROOT=${GOTWEBD_TEST_ROOT} \
	GOTWEBD_TEST_CONF=${GOTWEBD_TEST_CONF} \
	GOTWEBD_TEST_USER=${GOTWEBD_TEST_USER} \
	GOTWEBD_TEST_FCGI=${GOTWEBD_TEST_FCGI} \
	GOTWEBD_TEST_PAGINATE_NITEMS=${GOTWEBD_TEST_PAGINATE_NITEMS} \
	PATH=$(GOTWEBD_TEST_USER_HOME)/bin:${PATH} \
	HOME=$(GOTWEBD_TEST_USER_HOME) \
	GOTWEBD_TEST_DATA_DIR=${.CURDIR}

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotwebd test suite must be started by root >&2; \
		false; \
	fi ; \
	if [[ "${GOTWEBD_TEST_USER}" = "root" ]]; then \
		echo GOTWEBD_TEST_USER must be a non-root user >&2; \
		false; \
	fi

prepare_test_env: ensure_root
	@mkdir -p "${GOTWEBD_TEST_CHROOT}"
	@chown ${GOTWEBD_TEST_USER} "${GOTWEBD_TEST_ROOT}" \
	    "${GOTWEBD_TEST_CHROOT}"

prepare_test_repo: prepare_test_env
	@su -m ${GOTWEBD_TEST_USER} -c 'env ${GOTWEBD_TEST_ENV} \
	    sh ${.CURDIR}/prepare_test_repo.sh "${GOTWEBD_TEST_CHROOT}"'

gotwebd_test_conf:
	@echo 'user "${GOTWEBD_TEST_USER}"' > ${GOTWEBD_TEST_CONF}
	@echo 'chroot "${GOTWEBD_TEST_CHROOT}"' >> ${GOTWEBD_TEST_CONF}
	@echo 'listen on socket "${GOTWEBD_TEST_SOCK}"' >> ${GOTWEBD_TEST_CONF}
	@echo 'server "localhost" {' >> ${GOTWEBD_TEST_CONF}
	@echo '    show_repo_owner off' >> ${GOTWEBD_TEST_CONF}
	@echo '}' >> ${GOTWEBD_TEST_CONF}
	@echo 'disable authentication' >> ${GOTWEBD_TEST_CONF}
	@echo 'gotweb_url_root "/gotwebd_test_harness"' >> $(GOTWEBD_TEST_CONF)

gotwebd_test_conf_paginate: gotwebd_test_conf
	@printf '5i\n    max_commits_display 3\n.\nwq\n' | \
	    ed -s ${GOTWEBD_TEST_CONF}

start_gotwebd: prepare_test_repo gotwebd_test
	@${GOTWEBD_TRAP}; ${GOTWEBD_CHECK_MEMLEAK} ${GOTWEBD_START_CMD}
	@${GOTWEBD_TRAP}; sleep .5

test_gotwebd: gotwebd_test_conf start_gotwebd
	@-$(GOTWEBD_TRAP); su -m ${GOTWEBD_TEST_USER} -c \
		'env $(GOTWEBD_TEST_ENV) sh ${.CURDIR}/test_gotwebd.sh'
	@${GOTWEBD_STOP_CMD} 2>/dev/null
	@kdump -u malloc -f ${GOTWEBD_TEST_ROOT}/ktrace.out \
		> ${GOTWEBD_TEST_ROOT}/leak-report && \
	if grep -q "/gotwebd 0x" ${GOTWEBD_TEST_ROOT}/leak-report; then \
		cat ${GOTWEBD_TEST_ROOT}/leak-report; \
		exit 1; \
	fi

test_gotwebd_paginate: gotwebd_test_conf_paginate start_gotwebd
	@-${GOTWEBD_TRAP}; su -m ${GOTWEBD_TEST_USER} -c \
	    'env ${GOTWEBD_TEST_ENV} sh ${.CURDIR}/test_gotwebd_paginate.sh'
	@${GOTWEBD_STOP_CMD} 2>/dev/null
	@kdump -u malloc -f ${GOTWEBD_TEST_ROOT}/ktrace.out \
	    > ${GOTWEBD_TEST_ROOT}/leak-report && \
	if grep -q "/gotwebd 0x" ${GOTWEBD_TEST_ROOT}/leak-report; then \
		cat ${GOTWEBD_TEST_ROOT}/leak-report; \
		exit 1; \
	fi

.include <bsd.regress.mk>
