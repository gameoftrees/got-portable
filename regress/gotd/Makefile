.include "../../got-version.mk"

REGRESS_TARGETS=test_repo_read test_repo_read_group \
	test_repo_read_denied_user test_repo_read_denied_group \
	test_repo_read_bad_user test_repo_read_bad_group \
	test_repo_write test_repo_write_empty test_request_bad test_send_bad \
	test_repo_write_protected test_repo_write_readonly \
	test_email_notification test_http_notification \
	test_git_interop test_email_and_http_notification \
	test_http_notification_hmac test_connection_limit \
	test_large_files
NOOBJ=Yes
CLEANFILES=gotd.conf gotd-secrets.conf

.PHONY: ensure_root ensure_secrets prepare_test_repo check_test_repo start_gotd

GOTD_TEST_ROOT=/tmp
GOTD_DEVUSER?=gotdev
GOTD_DEVUSER_HOME!=getent passwd $(GOTD_DEVUSER) | cut -d: -f6
GOTD_TEST_REPO!!=mktemp -d "$(GOTD_TEST_ROOT)/gotd-test-repo-XXXXXXXXXX"
GOTD_TEST_REPO_NAME=test-repo
GOTD_TEST_REPO_URL=ssh://${GOTD_DEVUSER}@127.0.0.1/$(GOTD_TEST_REPO_NAME)
GOTD_TEST_SMTP_PORT=2525
GOTD_TEST_HTTP_PORT=8000
GOTD_TEST_HMAC_SECRET!=openssl rand -base64 32
GOT_TEST_ALGO=sha1

GOTD_TEST_USER?=${DOAS_USER}
.if empty(GOTD_TEST_USER)
GOTD_TEST_USER=${SUDO_USER}
.endif
.if empty(GOTD_TEST_USER)
GOTD_TEST_USER=${USER}
.endif
GOTD_TEST_USER_HOME!=getent passwd $(GOTD_TEST_USER) | cut -d: -f6

# gotd.conf parameters
GOTD_USER?=got
GOTD_SOCK=${GOTD_DEVUSER_HOME}/gotd.sock

.if "${GOT_RELEASE}" == "Yes"
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/sbin
.else
PREFIX ?= ${GOTD_TEST_USER_HOME}
BINDIR ?= ${PREFIX}/bin
.endif

GOTD_START_CMD?=env ${GOTD_ENV} $(BINDIR)/gotd -vv -f $(PWD)/gotd.conf
GOTD_STOP_CMD?=$(BINDIR)/gotctl -f $(GOTD_SOCK) stop
GOTD_TRAP=trap "$(GOTD_STOP_CMD)" HUP INT QUIT PIPE TERM

GOTD_ENV=GOT_NOTIFY_TIMEOUT=10

GOTD_TEST_ENV=GOTD_TEST_ROOT=$(GOTD_TEST_ROOT) \
	GOTD_TEST_REPO_URL=$(GOTD_TEST_REPO_URL) \
	GOTD_TEST_REPO_NAME=$(GOTD_TEST_REPO_NAME) \
	GOTD_TEST_REPO=$(GOTD_TEST_REPO) \
	GOTD_SOCK=$(GOTD_SOCK) \
	GOTD_DEVUSER=$(GOTD_DEVUSER) \
	GOTD_USER=$(GOTD_USER) \
	GOTD_CONF=$(PWD)/gotd.conf \
	GOTD_TEST_SMTP_PORT=$(GOTD_TEST_SMTP_PORT) \
	GOTD_TEST_HTTP_PORT=$(GOTD_TEST_HTTP_PORT) \
	GOTD_TEST_HMAC_SECRET=$(GOTD_TEST_HMAC_SECRET) \
	GOT_TEST_ALGO=${GOT_TEST_ALGO} \
	HOME=$(GOTD_TEST_USER_HOME) \
	PATH=$(GOTD_TEST_USER_HOME)/bin:$(PATH)

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotd test suite must be started by root >&2; \
		false; \
	fi ; \
	if [[ "$(GOTD_TEST_USER)" = "root" ]]; then \
		echo GOTD_TEST_USER must be a non-root user >&2; \
		false; \
	fi

ensure_secrets:
	@echo 'auth flan user flan password password' > $(PWD)/gotd-secrets.conf
	@echo 'hmac flan ${GOTD_TEST_HMAC_SECRET}' >> $(PWD)/gotd-secrets.conf
	@chown root:0 $(PWD)/gotd-secrets.conf
	@chmod 600 $(PWD)/gotd-secrets.conf

start_gotd_ro: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_implicit_ro: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_ro_group: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro :$(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# try a permit rule followed by a deny rule; last matched rule wins
start_gotd_ro_denied_user: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    deny $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# try a permit rule followed by a deny rule; last matched rule wins
start_gotd_ro_denied_group: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    deny :$(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# $GOTD_DEVUSER should not equal $GOTD_USER
start_gotd_ro_bad_user: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_USER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# $GOTD_DEVUSER should not be in group wheel
start_gotd_ro_bad_group: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro :wheel' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_rw: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_rw_protected: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    protect branch foo' >> $(PWD)/gotd.conf
	@echo '    protect tag namespace "refs/tags/"' >> $(PWD)/gotd.conf
	@echo '    protect { branch refs/heads/main }' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_email_notification: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    notify {' >> $(PWD)/gotd.conf
	@echo -n '      email to ${GOTD_DEVUSER}' >> $(PWD)/gotd.conf
	@echo ' relay 127.0.0.1 port ${GOTD_TEST_SMTP_PORT}' >> $(PWD)/gotd.conf
	@echo "    }" >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_http_notification: ensure_root ensure_secrets
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    notify {' >> $(PWD)/gotd.conf
	@echo '         url "http://localhost:${GOTD_TEST_HTTP_PORT}/" auth flan insecure' >> $(PWD)/gotd.conf
	@echo "    }" >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD) -s $(PWD)/gotd-secrets.conf
	@$(GOTD_TRAP); sleep .5

start_gotd_email_and_http_notification: ensure_root ensure_secrets
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    notify {' >> $(PWD)/gotd.conf
	@echo '         url "http://localhost:${GOTD_TEST_HTTP_PORT}/" auth flan insecure' >> $(PWD)/gotd.conf
	@echo -n '      email to ${GOTD_DEVUSER}' >> $(PWD)/gotd.conf
	@echo ' relay 127.0.0.1 port ${GOTD_TEST_SMTP_PORT}' >> $(PWD)/gotd.conf
	@echo "    }" >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD) -s $(PWD)/gotd-secrets.conf
	@$(GOTD_TRAP); sleep .5

start_gotd_http_notification_hmac: ensure_root ensure_secrets
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    notify {' >> $(PWD)/gotd.conf
	@echo '         url "http://localhost:${GOTD_TEST_HTTP_PORT}/" auth flan insecure hmac flan' >> $(PWD)/gotd.conf
	@echo "    }" >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD) -s $(PWD)/gotd-secrets.conf
	@$(GOTD_TRAP); sleep .5

start_gotd_connection_limit: ensure_root
	@echo 'listen on "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo 'connection limit user ${GOTD_DEVUSER} 2' >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

prepare_test_repo: ensure_root
	@chown ${GOTD_USER} "${GOTD_TEST_REPO}"
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./prepare_test_repo.sh'

prepare_test_repo_empty: ensure_root
	@chown ${GOTD_USER} "${GOTD_TEST_REPO}"
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./prepare_test_repo.sh 1'

prepare_large_files: ensure_root prepare_test_repo
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) \
		sh ./prepare_large_files.sh'

test_repo_read: prepare_test_repo start_gotd_ro
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_group: prepare_test_repo start_gotd_ro_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_denied_user: prepare_test_repo start_gotd_ro_denied_user
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_denied_group: prepare_test_repo start_gotd_ro_denied_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_bad_user: prepare_test_repo start_gotd_ro_bad_user
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_bad_group: prepare_test_repo start_gotd_ro_bad_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write: prepare_test_repo start_gotd_rw
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write_empty: prepare_test_repo_empty start_gotd_rw
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write_empty.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write_protected: prepare_test_repo start_gotd_rw_protected
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write_protected.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'
	
test_repo_write_readonly: prepare_test_repo_empty start_gotd_implicit_ro
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write_readonly.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_request_bad: prepare_test_repo_empty start_gotd_ro
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./request_bad.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_send_bad: prepare_test_repo_empty start_gotd_rw
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./send_bad.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_email_notification: prepare_test_repo start_gotd_email_notification
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./email_notification.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_http_notification: prepare_test_repo start_gotd_http_notification
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./http_notification.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_http_notification_hmac: prepare_test_repo start_gotd_http_notification_hmac
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./http_notification_hmac.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_email_and_http_notification: prepare_test_repo start_gotd_email_and_http_notification
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./http_notification.sh test_file_changed'
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./email_notification.sh test_file_changed'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_git_interop: prepare_test_repo start_gotd_rw
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./test_git_interop.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_connection_limit: prepare_test_repo start_gotd_connection_limit
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./connection_limit.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

test_large_files: prepare_large_files start_gotd_ro
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./large_files.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

.include <bsd.regress.mk>
