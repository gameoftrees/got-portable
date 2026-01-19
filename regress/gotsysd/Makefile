.include "../../got-version.mk"

REGRESS_TARGETS=test_gotsysd test_gotwebd test_gotwebd_www \
	test_gotwebd_repos_www

REGRESS_SETUP_ONCE=setup_test_vm
REGRESS_CLEANUP=stop_test_vm

NOOBJ=Yes
CLEANFILES= SHA256.sig bsd.rd bsd.rd.fs bsd.rd.decomp ${AUTOINSTALL_CONF} \
	${GOTSYSD_BSD_RD} ${GOTSYSD_SSH_KEY} ${GOTSYSD_SSH_PUBKEY} \
	${GOTSYSD_TEST_VM_BASE_IMAGE} ${GOTSYSD_VM_PASSWD_FILE} ${GOTD_CONF} \
	${GOTSYSD_CONF} ${GOTSYS_CONF} ${GOT_CONF} ${INSTALL_SITE} \
	${HTTPD_CONF}

.PHONY: ensure_root vm start_test_vm build_got

GOTSYSD_TEST_ROOT=/tmp
GOTSYSD_TEST_DIR!!=mktemp -d "$(GOTSYSD_TEST_ROOT)/gotsysd-test-XXXXXXXXXX"
GOTSYSD_TEST_VM_BASE_IMAGE=gotsysd_test_vm_base.qcow2
GOTSYSD_BSD_RD=gotsysd_bsd.rd
GOTSYSD_VND?=vnd0
GOTSYSD_MIRROR?=ftp.bit.nl
GOTSYSD_MIRROR_URL?=https://${GOTSYSD_MIRROR}/pub/OpenBSD
GOTSYSD_OPENBSD_VERSION?=snapshots
GOTSYSD_VM_NAME=gotsysd-test
GOTSYSD_VM_PASSWORD?=gameoftrees
GOTSYSD_VM_PASSWD_FILE=gotsysd_vm_passwd
GOTD_CONF=gotd.conf
GOTD_UID=501	# /usr/ports/infrastructure/db/user.list
GOTD_USER=_gotd
GOTSYSD_CONF=gotsysd.conf
GOTSYSD_UNIX_SOCKET=/var/run/gotsysd.sock
GOTSYSD_UID=600	# /usr/ports/infrastructure/db/user.list
GOTSYS_CONF=gotsys.conf
GOT_CONF=got.conf
GOTSYS_REPO=gotsys.git
GOTWEBD_UID=593	# /usr/ports/infrastructure/db/user.list
GOTSYSD_TEST_SMTP_PORT=2525
GOTSYSD_TEST_HTTP_PORT=8000
GOTSYSD_TEST_HMAC_SECRET!=openssl rand -base64 32
HTTPD_CONF=httpd.conf

GOTSYSD_TEST_USER?=${DOAS_USER}
.if empty(GOTSYSD_TEST_USER)
GOTSYSD_TEST_USER=${SUDO_USER}
.endif
.if empty(GOTSYSD_TEST_USER)
GOTSYSD_TEST_USER=${USER}
.endif
GOTSYSD_TEST_USER_HOME!=getent passwd $(GOTSYSD_TEST_USER) | cut -d: -f6

GOTSYSD_DEV_USER=flan_hacker
GOTSYSD_DEV_PASSWORD=hack1234

GOTSYSD_TEST_ENV=GOTSYSD_TEST_ROOT=${GOTSYSD_TEST_ROOT} \
	GOTSYSD_TEST_DIR=$(GOTSYSD_TEST_DIR) \
	GOTSYSD_TEST_USER=$(GOTSYSD_TEST_USER) \
	GOTSYSD_VM_PASSWORD=$(GOTSYSD_VM_PASSWORD) \
	GOTSYSD_DEV_USER=$(GOTSYSD_DEV_USER) \
	GOTSYSD_DEV_PASSWORD=$(GOTSYSD_DEV_PASSWORD) \
	GOTSYSD_SSH_KEY=${GOTSYSD_SSH_KEY} \
	GOTSYSD_SSH_PUBKEY=${GOTSYSD_SSH_PUBKEY} \
	GOTSYS_REPO=${GOTSYS_REPO} \
	HOME=$(GOTSYSD_TEST_USER_HOME) \
	PATH=$(GOTSYSD_TEST_USER_HOME)/bin:$(PATH) \
	GOTD_USER=${GOTD_USER} \
	GOTSYSD_TEST_SMTP_PORT=${GOTSYSD_TEST_SMTP_PORT} \
	GOTSYSD_TEST_HTTP_PORT=${GOTSYSD_TEST_HTTP_PORT} \
	GOTSYSD_TEST_HMAC_SECRET=${GOTSYSD_TEST_HMAC_SECRET}


UNPRIV=su -m ${GOTSYSD_TEST_USER} -c
AUTOINSTALL_CONF=auto_install.conf
INSTALL_SITE=install.site
GOTSYSD_SSH_KEY=gotsysd_sshkey
GOTSYSD_SSH_PUBKEY=gotsysd_sshkey.pub
GOTSYSD_SSH_OPTIONS= -i ${GOTSYSD_SSH_KEY} -o StrictHostKeyChecking=accept-new
GOTSYSD_SSH_CMD= ssh ${GOTSYSD_SSH_OPTIONS}
GOTSYSD_SCP_CMD= scp ${GOTSYSD_SSH_OPTIONS} -B -C -q

.if "${GOT_RELEASE}" == "Yes"
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/sbin
.else
PREFIX ?= ${GOTSYSD_TEST_USER_HOME}
BINDIR ?= ${PREFIX}/bin
.endif

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotsysd test suite must be started by root >&2; \
		false; \
	fi ; \
	if [[ "$(GOTSYSD_TEST_USER)" = "root" ]]; then \
		echo GOTSYSD_TEST_USER must be a non-root user >&2; \
		false; \
	fi

ensure_ipforwarding:
	@if [[ `sysctl -n net.inet.ip.forwarding` -ne 1 ]]; then \
		echo IPv4 forwarding should be enabled first: sysctl net.inet.ip.forwarding=1 >&2; \
		false; \
	fi ; \

bsd.rd:
	${UNPRIV} "ftp -o SHA256.sig \
		${GOTSYSD_MIRROR_URL}/${GOTSYSD_OPENBSD_VERSION}/`uname -m`/SHA256.sig"
	${UNPRIV} "ftp -o bsd.rd \
		${GOTSYSD_MIRROR_URL}/${GOTSYSD_OPENBSD_VERSION}/`uname -m`/bsd.rd" \
	${UNPRIV} "set -e; \
		KEY=$$(head -1 < SHA256.sig | cut -d' ' -f5 | \
		egrep '^openbsd-[[:digit:]]{2,3}-base.pub$$' || true); \
		signify -C -p /etc/signify/$${KEY} -x SHA256.sig bsd.rd"

${GOTSYSD_SSH_PUBKEY}:
	${UNPRIV} "ssh-keygen -q -f ${GOTSYSD_SSH_KEY} -P '' \
		-C 'temporary-gotsysd-regress-ssh-key'"

${GOTSYSD_VM_PASSWD_FILE}:
	${UNPRIV} "touch ${GOTSYSD_VM_PASSWD_FILE}"
	${UNPRIV} "chmod 700 ${GOTSYSD_VM_PASSWD_FILE}"
	@${UNPRIV} "echo ${GOTSYSD_VM_PASSWORD} | encrypt > $@"

${AUTOINSTALL_CONF}: ${GOTSYSD_VM_PASSWD_FILE} ${GOTSYSD_SSH_PUBKEY}
	${UNPRIV} "echo System hostname = $(GOTSYSD_VM_NAME) > $@"
	${UNPRIV} "echo -n 'Password for root = ' >> $@"
	${UNPRIV} "cat ${GOTSYSD_VM_PASSWD_FILE} >> $@"
	${UNPRIV} "echo -n 'Public ssh key for root account = ' >> $@"
	${UNPRIV} "cat ${GOTSYSD_SSH_PUBKEY} >> $@"
	${UNPRIV} "echo Allow root ssh login? = prohibit-password >> $@"
	${UNPRIV} "echo Setup a user = ${GOTSYSD_TEST_USER} >> $@"
	${UNPRIV} "echo -n 'Password for user ${GOTSYSD_TEST_USER}? = ' >> $@"
	${UNPRIV} "cat ${GOTSYSD_VM_PASSWD_FILE} >> $@"
	${UNPRIV} "echo -n 'Public ssh key for user = ' >> $@"
	${UNPRIV} "cat ${GOTSYSD_SSH_PUBKEY} >> $@"
	${UNPRIV} "echo Location of sets = http >> $@"
	${UNPRIV} "echo Server directory = pub/OpenBSD/${GOTSYSD_OPENBSD_VERSION}/`uname -m` >> $@"
	${UNPRIV} "echo HTTP Server = ${GOTSYSD_MIRROR} >> $@"

${INSTALL_SITE}:
	${UNPRIV} "echo 'echo library_aslr=NO >> /etc/rc.conf.local' >> $@" 
	${UNPRIV} "echo sed -i \'/\\\/usr\\\/libexec\\\/reorder_kernel/d\' /etc/rc >> $@" 
	
${GOTSYSD_BSD_RD}: bsd.rd ${AUTOINSTALL_CONF} ${INSTALL_SITE}
	${UNPRIV} "gzcat bsd.rd > bsd.rd.decomp"
	rdsetroot -x bsd.rd.decomp bsd.rd.fs
	vnconfig ${GOTSYSD_VND} bsd.rd.fs
	mount /dev/${GOTSYSD_VND}a /mnt
	cp ${AUTOINSTALL_CONF} /mnt/auto_install.conf
	install -o root -m 755 ${INSTALL_SITE} /mnt/install.site
	sed -i 's/if \[\[ -x \/mnt\/$$MODE.site \]\]; then/if cp \/install.site \/mnt\/install.site; then/' /mnt/install.sub
	umount /mnt
	vnconfig -u ${GOTSYSD_VND}
	rdsetroot bsd.rd.decomp bsd.rd.fs
	mv bsd.rd.decomp $@

${GOTSYSD_TEST_VM_BASE_IMAGE}:
	vmctl create -s 4G $@

# Install the base VM image. This target should be run interactively.
vm: ensure_root ensure_ipforwarding ${GOTSYSD_TEST_VM_BASE_IMAGE} ${GOTSYSD_BSD_RD}
	vmctl start -d ${GOTSYSD_TEST_VM_BASE_IMAGE} \
		-b $(GOTSYSD_BSD_RD) -c -L ${GOTSYSD_VM_NAME}

start_test_vm: ensure_root ensure_ipforwarding
	@set -e; \
	vmctl create -b ${.CURDIR}/${GOTSYSD_TEST_VM_BASE_IMAGE} \
		${GOTSYSD_TEST_DIR}/vm.qcow2; \
		vmctl start -d ${GOTSYSD_TEST_DIR}/vm.qcow2 -B disk -L \
		${GOTSYSD_VM_NAME}; \
	while sleep 1; do \
		if vmctl status ${GOTSYSD_VM_NAME} | \
		    grep -q ${GOTSYSD_VM_NAME}; then \
			break; \
		fi; \
	done; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	echo "Waiting for VM to finish booting..."; \
	while sleep 1; do \
		if nc -z $${VMIP} ssh; then \
			break; \
		else \
			sleep 5; \
		fi; \
	done; \

${GOTD_CONF}:
	@${UNPRIV} "echo repository gotsys { > $@"
	@${UNPRIV} "echo path \'/git/gotsys.git\' >> $@"
	@${UNPRIV} "echo permit rw ${GOTSYSD_TEST_USER} >> $@"
	@${UNPRIV} "echo } >> $@"

${GOTSYSD_CONF}:
	@${UNPRIV} "echo permit root > $@"
	@${UNPRIV} "echo permit _gotd >> $@"
	@${UNPRIV} "echo listen on \\\"${GOTSYSD_UNIX_SOCKET}\\\" >> $@"
	@${UNPRIV} "echo 'gotweb {' >> $@"
	@${UNPRIV} "printf '\tprefork 1\n'  >> $@"
	@${UNPRIV} "printf '\tenable authentication insecure\n' >> $@"
	@${UNPRIV} "printf '\tlogin hint user \"${GOTSYSD_TEST_USER}\"\n' >> $@"
	@${UNPRIV} "echo '}' >> $@"
	@${UNPRIV} "echo 'web server \"VMIP\"' >> $@"

${GOTSYS_CONF}: ${GOTSYSD_SSH_PUBKEY}
	@${UNPRIV} "echo user ${GOTSYSD_TEST_USER} { >> $@"
	@${UNPRIV} "echo -n \ \ \ \ password \\\" >> $@"
	@${UNPRIV} "echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n' >> $@"
	@${UNPRIV} "echo \\\" >> $@"
	@${UNPRIV} "echo } >> $@"
	@${UNPRIV} "echo repository gotsys { >> $@"
	@${UNPRIV} "echo \ \ \ \ permit rw ${GOTSYSD_TEST_USER} >> $@"
	@${UNPRIV} "echo } >> $@"

${GOT_CONF}:
	@${UNPRIV} "echo author \\'${GOTSYSD_TEST_USER} \\<${GOTSYSD_TEST_USER}@localhost\\>\\' > $@"


$(HTTPD_CONF):
	@${UNPRIV} 'echo server "VMIP" { > $@'
	@${UNPRIV} 'echo \ \ listen on VMIP port http >> $@'
	@${UNPRIV} 'echo \ \ root \"/htdocs/gotwebd\" >> $@'
	@${UNPRIV} 'echo \ \ fastcgi socket \"/run/gotweb.sock\" >> $@'
	@${UNPRIV} 'echo } >> $@'

build_got:
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	${UNPRIV} "ssh-keygen -R $${VMIP}"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} ${GOTSYSD_TEST_USER}@$${VMIP} \
		mkdir -p src/got bin"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} -r \
		${.CURDIR}/../../{Makefile*,cvg,got*,git*,lib*,include,tog,template} \
		${GOTSYSD_TEST_USER}@$${VMIP}:src/got/"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} build-got.sh \
		${GOTSYSD_TEST_USER}@$${VMIP}:bin/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} ${GOTSYSD_TEST_USER}@$${VMIP} \
		./bin/build-got.sh"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		make -C /home/${GOTSYSD_TEST_USER}/src/got -- GOT_RELEASE=Yes \
		DEBUG=\\'-Oo -g\\' sysd-install server-install webd-install install"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} -- root@$${VMIP} \
		ln -f -s gitwrapper /usr/local/bin/git-upload-pack"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} -- root@$${VMIP} \
		ln -f -s gitwrapper /usr/local/bin/git-receive-pack"

setup_test_vm: start_test_vm build_got ${GOTD_CONF} ${GOTSYSD_CONF} ${GOTSYS_CONF} ${GOT_CONF} ${HTTPD_CONF}
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	${UNPRIV} "ssh-keygen -R $${VMIP}"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} sysctl kern.nosuidcoredump=3"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir -p -m 700 \
		/var/crash/gotd /var/crash/gotsysd /var/crash/gotwebd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} sed -i 's/daemon.info/daemon.*/' /etc/syslog.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} rcctl restart syslogd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir -m 750 /git "; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got init /git/${GOTSYS_REPO}"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOT_CONF} root@$${VMIP}:/git/${GOTSYS_REPO}/got.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir /tmp/gotsys "; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTSYS_CONF} root@$${VMIP}:/tmp/gotsys/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got import -m init -r /git/${GOTSYS_REPO} \
		/tmp/gotsys >/dev/null"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		groupadd -g ${GOTD_UID} _gotd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		useradd -d /nonexistent -s /sbin/nologin \
		-u ${GOTD_UID} -g ${GOTD_UID} _gotd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		chown -R _gotd:_gotd /git "; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTD_CONF} root@$${VMIP}:/etc/gotd.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		/usr/local/sbin/gotd -vvv"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		groupadd -g ${GOTSYSD_UID} _gotsysd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		useradd -d /nonexistent -s /sbin/nologin \
		-u ${GOTSYSD_UID} -g ${GOTSYSD_UID} _gotsysd"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTSYSD_CONF} root@$${VMIP}:/etc/gotsysd.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		/usr/local/sbin/gotsysd -vvv"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		groupadd -g ${GOTWEBD_UID} _gotwebd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		useradd -d /nonexistent -s /sbin/nologin \
		-u ${GOTWEBD_UID} -g ${GOTWEBD_UID} -G _gotd _gotwebd"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} ${HTTPD_CONF} root@$${VMIP}:/etc/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		sed -i s/VMIP/$${VMIP}/ /etc/httpd.conf /etc/gotsysd.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} rcctl -f start httpd"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		/usr/local/sbin/gotwebd -v"; \
	
stop_test_vm: ensure_root
	@vmctl stop ${GOTSYSD_VM_NAME}

test_gotsysd: 
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	GWIP="100.64.$$VMID.2"; \
	${UNPRIV} "env ${GOTSYSD_TEST_ENV} VMIP=$${VMIP} GWIP=$${GWIP} \
		sh ./test_gotsysd.sh"

test_gotwebd:
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	GWIP="100.64.$$VMID.2"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		'rm -rf /git/${GOTSYS_REPO} /git/{foo,hidden}.git /tmp/gotsys'"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got init /git/${GOTSYS_REPO}"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got init /git/hidden.git"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOT_CONF} root@$${VMIP}:/git/${GOTSYS_REPO}/got.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir /tmp/gotsys "; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTSYS_CONF} root@$${VMIP}:/tmp/gotsys/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got import -m init -r /git/${GOTSYS_REPO} \
		/tmp/gotsys >/dev/null"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		chown -R _gotd:_gotd /git"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		gotsys apply -w > /dev/null"; \
	${UNPRIV} "env ${GOTSYSD_TEST_ENV} VMIP=$${VMIP} GWIP=$${GWIP} \
		sh ./test_gotwebd.sh"

test_gotwebd_www:
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	GWIP="100.64.$$VMID.2"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		'rm -rf /git/*.git /tmp/gotsys'"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got init /git/${GOTSYS_REPO}"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOT_CONF} root@$${VMIP}:/git/${GOTSYS_REPO}/got.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir /tmp/gotsys "; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTSYS_CONF} root@$${VMIP}:/tmp/gotsys/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got import -m init -r /git/${GOTSYS_REPO} \
		/tmp/gotsys >/dev/null"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		chown -R _gotd:_gotd /git"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} gotctl reload"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		gotsys apply -w > /dev/null"; \
	${UNPRIV} "env ${GOTSYSD_TEST_ENV} VMIP=$${VMIP} GWIP=$${GWIP} \
		sh ./test_gotwebd_www.sh"

test_gotwebd_repos_www:
	@set -e; \
	VMID=`vmctl status ${GOTSYSD_VM_NAME} | tail -n1 | \
		awk '{print $$1}'`; \
	VMIP="100.64.$$VMID.3"; \
	GWIP="100.64.$$VMID.2"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		'rm -rf /git/*.git /tmp/gotsys'"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got init /git/${GOTSYS_REPO}"; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOT_CONF} root@$${VMIP}:/git/${GOTSYS_REPO}/got.conf"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} mkdir /tmp/gotsys "; \
	${UNPRIV} "${GOTSYSD_SCP_CMD} \
		${GOTSYS_CONF} root@$${VMIP}:/tmp/gotsys/"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		got import -m init -r /git/${GOTSYS_REPO} \
		/tmp/gotsys >/dev/null"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		chown -R _gotd:_gotd /git"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} gotctl reload"; \
	${UNPRIV} "${GOTSYSD_SSH_CMD} root@$${VMIP} \
		gotsys apply -w > /dev/null"; \
	${UNPRIV} "env ${GOTSYSD_TEST_ENV} VMIP=$${VMIP} GWIP=$${GWIP} \
		sh ./test_gotwebd_repos_www.sh"

.include <bsd.regress.mk>
