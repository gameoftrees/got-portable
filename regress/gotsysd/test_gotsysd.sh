#!/bin/sh
#
# Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

. ../cmdline/common.sh
. ./common.sh

test_user_add() {
	local testroot=`test_init user_add 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
user deleteme {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "create user ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the GOTSYSD_DEV_USER account does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "user ${GOTSYSD_DEV_USER} already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "userinfo: can't find user \`${GOTSYSD_DEV_USER}'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the GOTSYSD_DEV_USER login group does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo ${GOTSYSD_DEV_USER} \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "group ${GOTSYSD_DEV_USER} already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "groupinfo: can't find group \`${GOTSYSD_DEV_USER}'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The GOTSYSD_DEV_USER account should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER}
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# GOTSYSD_DEV_USER should be present in /etc/passwd.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/passwd \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
${GOTSYSD_DEV_USER}:*:5000:5000:gotsys user account:/home/${GOTSYSD_DEV_USER}:/usr/local/bin/gotsh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user's login group should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	${GOTSYSD_DEV_USER}
passwd	*
gid	5000
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user should have a home directory and ~/.ssh.
	# TODO: stat ~ and ~/.ssh, then verify ownership and permissions.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} ls /home/${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /home/${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
.ssh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user should have an ssh key installed.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		${GOTSYSD_DEV_USER}@${VMIP} true \
			> $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "ssh ${GOTSYSD_DEV_USER}@${VMIP}succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
usage: gotsh -c 'git-receive-pack|git-upload-pack repository-path'
       gotsh -c 'weblogin [hostname]'
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# The "deleteme" user should be present in /etc/passwd.
	# A later test will remove it from gotsys.conf.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ^deleteme /etc/passwd \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
deleteme:*:5001:5001:gotsys user account:/home/deleteme:/usr/local/bin/gotsh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The deleteme user should have an ssh key installed as well.
	ssh -q -i ${GOTSYSD_SSH_KEY} deleteme@${VMIP} true \
			> $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "ssh deleteme@${VMIP}succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
usage: gotsh -c 'git-receive-pack|git-upload-pack repository-path'
       gotsh -c 'weblogin [hostname]'
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_user_mod() {
	local testroot=`test_init user_mod 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD}1234 | encrypt | tr -d '\n'`
	# strip the optional ssh key comment for better test coverage
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY} | cut -d' ' -f 1,2`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
user deleteme {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "change password of ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.before
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.after
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	cmp -s $testroot/master.passwd.before $testroot/master.passwd.after
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "${GOTSYSD_DEV_USER}'s line in master.passwd is unchanged"
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_user_del() {
	local testroot=`test_init user_del 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD}1234 | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "remove the deleteme user from gotsys.conf" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.before
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep deleteme /etc/master.passwd \
		> $testroot/master.passwd.after
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find deleteme in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	cmp -s $testroot/master.passwd.before $testroot/master.passwd.after
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "${GOTSYSD_DEV_USER}'s line in master.passwd is unchanged"
		test_done "$testroot" "1"
		return 1
	fi

	# The deleteme account should still exist because we oo not
	# allow UIDs to be recycled.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} userinfo deleteme \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo deleteme failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	deleteme
passwd	*
uid	5001
groups	deleteme
change	NEVER
class	
gecos	gotsys user account
dir	/home/deleteme
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The deleteme account's password should be locked.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ^deleteme /etc/master.passwd | cut -d: -f2 \
		> $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
*************
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# There should be no authorized keys for this user anymore.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} cat /home/deleteme/.ssh/authorized_keys \
		> $testroot/stdout 2> $testroot/stderr

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
cat: /home/deleteme/.ssh/authorized_keys: No such file or directory
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_group_add() {
	local testroot=`test_init group_add 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group developers
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
	group developers
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "create user ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the developers group does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "user already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "groupinfo: can't find group \`developers'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The developers group should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	${GOTSYSD_DEV_USER} 
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user account should now be a developers group member.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER} developers
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the slackers group now exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo slackers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo slackers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	slackers
passwd	*
gid	5003
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_group_del() {
	local testroot=`test_init group_del 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "remove the developers group" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the developers group exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	${GOTSYSD_DEV_USER} 
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The developers group should still exist because we do not
	# recycle GIDs. But the group should have no members.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user account should no longer be a developers group member.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER}
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the slackers group still exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo slackers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo slackers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	slackers
passwd	*
gid	5003
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_repo_create() {
	local testroot=`test_init repo_create 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit -m "create repository foo" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The new repository should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} ls /git \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /git failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
foo.git
gotsys.git
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The repositories should have 750 permissions and be owned by _gotd.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} ls -l /git | \
		grep -v ^total | awk '{print $1" "$3" "$4}' > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /git failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
drwxr-x--- _gotd _gotd
drwxr-x--- _gotd _gotd
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should be able to import data into the newly created repository.
	got init $testroot/foo.git
	mkdir $testroot/foo
	echo alpha > $testroot/foo/alpha
	got import -m init -r $testroot/foo.git $testroot/foo >/dev/null

	cat > $testroot/foo.git/got.conf <<EOF
remote "origin" {
	server ${GOTSYSD_DEV_USER}@${VMIP}
	protocol ssh
	repository "foo.git"
	branch "main"
}
EOF
	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/foo.git
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_user_anonymous() {
	local testroot=`test_init user_anonymous 1`

	# An attempt to grant write permissions to anonymous is an error.
	cat > ${testroot}/bad-gotsys.conf <<EOF
repository "gotsys" {
	permit rw anonymous
}
EOF
	gotsys check -f ${testroot}/bad-gotsys.conf \
		> $testroot/stdout  2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotsys check succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo -n "gotsys: ${testroot}/bad-gotsys.conf: line 2: " \
		> $testroot/stderr.expected
	echo "the \"anonymous\" user must not have write permission" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
	permit ro anonymous
}
EOF
	(cd ${testroot}/wt && got commit -m "add anonymous user" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The new repository should be readable anonymously.
	got clone -q anonymous@${VMIP}:foo.git $testroot/foo-anonclone.git
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_user_anonymous_remove() {
	local testroot=`test_init user_anonymous_remove 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit -m "remove anonymous user" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Repository foo should no longer be readable anonymously.
	env SSH_ASKPASS="/usr/bin/true" SSH_ASKPASS_REQUIRE=force \
		got clone anonymous@${VMIP}:foo.git \
		$testroot/foo-anonclone.git > /dev/null 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got clone succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	printf "Permission denied, please try again.\r\n" \
		> $testroot/stderr.expected
	printf "Permission denied, please try again.\r\n" \
		>> $testroot/stderr.expected
	printf "anonymous@${VMIP}: Permission denied (publickey,password,keyboard-interactive).\r\n" \
		>> $testroot/stderr.expected
	echo "got-fetch-pack: unexpected end of file" \
		>> $testroot/stderr.expected
	echo "got: unexpected end of file" >> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_bad_gotsysconf() {
	local testroot=`test_init bad_gotsysconf 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# An attempt to send an invalid gotsys.conf file
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

looser ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
looser ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
	permit ro anonymous
}
EOF
	gotsys check -f ${testroot}/wt/gotsys.conf \
		> $testroot/stdout  2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotsys check succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "gotsys: ${testroot}/wt/gotsys.conf: line 3: syntax error" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd ${testroot}/wt && got commit -m "commit a bad gotsys.conf" \
		>/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO} \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > ${testroot}/stderr.expected <<EOF
git-receive-pack: gotsys.conf: line 3: syntax error
got-send-pack: gotsys.conf: line 3: syntax error
got: could not send pack file
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_bad_ref_in_gotsysconf() {
	local testroot=`test_init bad_ref_in_gotsysconf 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`

	# An attempt to send an invalid gotsys.conf file
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
	permit ro anonymous
	protect branch 'mai"n'
}
EOF
	gotsys check -f ${testroot}/wt/gotsys.conf \
		> $testroot/stdout  2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotsys check succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "gotsys: ${testroot}/wt/gotsys.conf: line 18: invalid reference name: refs/heads/mai\"n" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd ${testroot}/wt && got commit -m "commit a bad gotsys.conf" \
		>/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO} \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > ${testroot}/stderr.expected <<EOF
git-receive-pack: gotsys.conf: line 18: invalid reference name: refs/heads/mai"n
got-send-pack: gotsys.conf: line 18: invalid reference name: refs/heads/mai"n
got: could not send pack file
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_set_head() {
	local testroot=`test_init set_head 1`

	# An attempt to set the HEAD of gotsys.git is an error.
	cat > ${testroot}/bad-gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}

repository "gotsys" {
	permit rw ${GOTSYSD_TEST_USER}
	head "refs/heads/foo"
}
EOF
	gotsys check -f ${testroot}/bad-gotsys.conf \
		> $testroot/stdout  2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotsys check succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
gotsys: ${testroot}/bad-gotsys.conf: line 8: HEAD of the "gotsys" repository cannot be overridden
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
	permit ro anonymous
	head foo
}
EOF
	(cd ${testroot}/wt && got commit -m "set foo as head" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create branch "foo" in foo.git.
	got clone -q -i ${GOTSYSD_SSH_KEY} -b main \
		${GOTSYSD_DEV_USER}@${VMIP}:foo.git $testroot/foo.git
	got branch -r $testroot/foo.git -c main foo
	got send -q -i ${GOTSYSD_SSH_KEY} -r $testroot/foo.git -b foo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		return 1
	fi

	# The foo repository should now advertise refs/heads/foo as HEAD.
	got clone -q -l anonymous@${VMIP}:foo.git | egrep '^HEAD:' \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_protect_refs() {
	local testroot=`test_init protect_refs 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
	permit ro anonymous
	head foo
	protect branch foo
	protect {
		tag namespace "refs/tags"
	}
}
EOF
	(cd ${testroot}/wt && \
		got commit -m "protect branch and tags" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a new commit on branch "foo" and send it.
	got clone -q -i ${GOTSYSD_SSH_KEY} -b foo \
		${GOTSYSD_DEV_USER}@${VMIP}:foo.git $testroot/foo.git
	got checkout -q $testroot/foo.git $testroot/wt-foo > /dev/null
	echo "tweak alpha" > $testroot/wt-foo/alpha
	(cd $testroot/wt-foo && got commit -m 'change alpha' > /dev/null)
	got send -q -i ${GOTSYSD_SSH_KEY} -r $testroot/foo.git -b foo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		return 1
	fi

	# Attempt to rewrite the history of branch "foo".
	(cd $testroot/wt-foo && got update -q -c :head:-1 > /dev/null)
	(cd $testroot/wt-foo && got histedit -d > /dev/null)
	got send -q -i ${GOTSYSD_SSH_KEY} -r $testroot/foo.git -b foo -f \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		return 1
	fi

	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "gotsh: refs/heads/foo: reference is protected" \
		> $testroot/stderr.expected
	grep '^gotsh:' $testroot/stderr > $testroot/stderr.filtered
	cmp -s $testroot/stderr.expected $testroot/stderr.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_deny_access() {
	local testroot=`test_init deny_access 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	deny ${GOTSYSD_DEV_USER}
	permit ro anonymous
	head foo
	protect branch foo
	protect {
		tag namespace "refs/tags"
	}
}
EOF
	(cd ${testroot}/wt && \
		got commit -m "deny access to foo repository" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Try to clone repository foo. Should fail.
	got clone -q -i ${GOTSYSD_SSH_KEY} -b foo \
		${GOTSYSD_DEV_USER}@${VMIP}:foo.git $testroot/foo.git \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got clone succeeded unexpectedly" >&2
		return 1
	fi

	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "gotsh: foo: Permission denied" > $testroot/stderr.expected
	grep '^gotsh:' $testroot/stderr > $testroot/stderr.filtered
	cmp -s $testroot/stderr.expected $testroot/stderr.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_override_access_rules() {
	local testroot=`test_init override_access_rules 1`

	# Override gotsys.conf access rules which deny access to foo.git.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'cp /etc/gotsysd.conf /etc/gotsysd.conf.orig'
	echo "repository permit ro ${GOTSYSD_DEV_USER}" | \
		ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
		'cat >> /etc/gotsysd.conf'

	# Restart gotsysd (XXX need a better way to do this...)
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'pkill -xf /usr/local/sbin/gotsysd'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} '/usr/local/sbin/gotsysd -vvv'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'gotsys apply -w' > /dev/null

	# Cloning repository foo should now succeed.
	got clone -q -i ${GOTSYSD_SSH_KEY} -b foo \
		${GOTSYSD_DEV_USER}@${VMIP}:foo.git $testroot/foo.git \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# gotsys.git access should now be read-only.
	got clone -q -i ${GOTSYSD_SSH_KEY} \
		${GOTSYSD_DEV_USER}@${VMIP}:gotsys.git $testroot/gotsys2.git \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	got checkout -q $testroot/gotsys2.git $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository "foo" {
	deny ${GOTSYSD_DEV_USER}
	permit ro anonymous
	head foo
	protect branch foo
	protect {
		tag namespace "refs/tags"
	}
}
repository "bar" {
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && \
		got commit -m "add bar.git repository" >/dev/null)
	local commit_id=`git_show_head $testroot/gotsys2.git`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/gotsys2.git \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "gotsh: gotsys.git: Permission denied" > $testroot/stderr.expected
	grep '^gotsh:' $testroot/stderr > $testroot/stderr.filtered
	cmp -s $testroot/stderr.expected $testroot/stderr.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	# Undo gotsys.conf override
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'mv -f /etc/gotsysd.conf.orig /etc/gotsysd.conf'

	# Restart gotsysd (XXX need a better way to do this...)
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'pkill -xf /usr/local/sbin/gotsysd'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} '/usr/local/sbin/gotsysd -vvv'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'gotsys apply -w' > /dev/null

	test_done "$testroot" "$ret"
}

test_override_all_user_access() {
	local testroot=`test_init override_all_user_access 1`

	# Override gotsys.conf access rules which deny access to foo.git.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'cp /etc/gotsysd.conf /etc/gotsysd.conf.orig'
	echo 'repository deny "*"' | \
		ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
		'cat >> /etc/gotsysd.conf'

	# Restart gotsysd (XXX need a better way to do this...)
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'pkill -xf /usr/local/sbin/gotsysd'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} '/usr/local/sbin/gotsysd -vvv'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'gotsys apply -w' > /dev/null

	# Cloning any repository as any user should now fail.
	for user in ${GOTSYSD_TEST_USER} ${GOTSYSD_DEV_USER} anonymous; do
		got clone -q -i ${GOTSYSD_SSH_KEY} -b foo \
			${user}@${VMIP}:foo.git $testroot/foo-${user}.git \
			> $testroot/stdout 2> $testroot/stderr
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "got clone succeeded unexpectedly" >&2
			test_done "$testroot" 1
			return 1
		fi

		echo "got-fetch-pack: foo: Permission denied" \
			> $testroot/stderr.expected
		grep '^got-fetch-pack:' $testroot/stderr \
			> $testroot/stderr.filtered
		cmp -s $testroot/stderr.expected $testroot/stderr.filtered
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected \
				$testroot/stderr.filtered
			test_done "$testroot" "$ret"
			return 1
		fi

		got clone -q -i ${GOTSYSD_SSH_KEY} \
			${user}@${VMIP}:gotsys.git \
			$testroot/gotsys-${user}.git \
			> $testroot/stdout 2> $testroot/stderr
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "got clone succeeded unexpectedly" >&2
			test_done "$testroot" 1
			return 1
		fi

		echo "got-fetch-pack: gotsys.git: Permission denied" \
			> $testroot/stderr.expected
		grep '^got-fetch-pack:' $testroot/stderr \
			> $testroot/stderr.filtered
		cmp -s $testroot/stderr.expected $testroot/stderr.filtered
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected \
				$testroot/stderr.filtered
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	# Undo gotsys.conf override
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'mv -f /etc/gotsysd.conf.orig /etc/gotsysd.conf'

	# Restart gotsysd (XXX need a better way to do this...)
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'pkill -xf /usr/local/sbin/gotsysd'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} '/usr/local/sbin/gotsysd -vvv'
	sleep 1
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} 'gotsys apply -w' > /dev/null

	test_done "$testroot" "$ret"
}

# flan:password encoded in base64
AUTH="ZmxhbjpwYXNzd29yZA=="

test_http_notification() {
	local testroot=`test_init http_notification 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}

	notify url "http://${GWIP}:${GOTSYSD_TEST_HTTP_PORT}/" user flan password "password" insecure
}
EOF
	(cd ${testroot}/wt && got commit -m "send http notifications" \
		>/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}

user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}

repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}

	notify url "http://${GWIP}:${GOTSYSD_TEST_HTTP_PORT}/" user flan password "password" insecure
}
EOF

	(cd ${testroot}/wt && got commit -m "whitespace changes" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local author_time=`git_show_author_time $testroot/${GOTSYS_REPO}`

	timeout 5 ./http-server -a $AUTH -l "$GWIP" \
	    -p "$GOTSYSD_TEST_HTTP_PORT" > $testroot/stdout &

	sleep 1 # server starts up

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	wait %1 # wait for the http "server"

	echo -n > "$testroot/stdout.expected"
	ed -s "$testroot/stdout.expected" <<-EOF
	a
	{"notifications":[{
		"type":"commit",
		"short":false,
		"repo":"gotsys.git",
		"authenticated_user":"${GOTSYSD_TEST_USER}",
		"id":"$commit_id",
		"author":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"committer":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"date":$author_time,
		"short_message":"whitespace changes",
		"message":"whitespace changes\n",
		"diffstat":{
			"files":[{
				"action":"modified",
				"file":"gotsys.conf",
				"added":2,
				"removed":0
			}],
			"total":{
				"added":1,
				"removed":2
			}
		}
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_http_notification_hmac() {
	local testroot=`test_init http_notification_hmac 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}

user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}

repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}

	notify url "http://${GWIP}:${GOTSYSD_TEST_HTTP_PORT}/" user flan password "password" insecure hmac "${GOTSYSD_TEST_HMAC_SECRET}"
}
EOF

	(cd ${testroot}/wt && got commit -m "add hmac" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
	notify url "http://${GWIP}:${GOTSYSD_TEST_HTTP_PORT}/" user flan password "password" insecure hmac "${GOTSYSD_TEST_HMAC_SECRET}"
}
EOF

	(cd ${testroot}/wt && got commit -m "whitespace changes" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local author_time=`git_show_author_time $testroot/${GOTSYS_REPO}`

	timeout 5 ./http-server -a $AUTH -l "$GWIP" \
	    -p "$GOTSYSD_TEST_HTTP_PORT" -s "$GOTSYSD_TEST_HMAC_SECRET" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	wait %1 # wait for the http "server"

	echo -n > "$testroot/stdout.expected"
	ed -s "$testroot/stdout.expected" <<-EOF
	a
	{"notifications":[{
		"type":"commit",
		"short":false,
		"repo":"gotsys.git",
		"authenticated_user":"${GOTSYSD_TEST_USER}",
		"id":"$commit_id",
		"author":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"committer":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"date":$author_time,
		"short_message":"whitespace changes",
		"message":"whitespace changes\n",
		"diffstat":{
			"files":[{
				"action":"modified",
				"file":"gotsys.conf",
				"added":0,
				"removed":3
			}],
			"total":{
				"added":1,
				"removed":0
			}
		}
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_email_notification() {
	local testroot=`test_init email_notification 1`

	# Need to smtpd in the test VM since we will be using port 25
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
		'/etc/rc.d/smtpd stop' > /dev/null

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
	notify email to "${GOTSYSD_TEST_USER}@example.com"
}
EOF
	(cd ${testroot}/wt && got commit -m "send email notifications" \
		>/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}

user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}

repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}

	notify email to "${GOTSYSD_TEST_USER}@example.com"
}
EOF
	(cd ${testroot}/wt && got commit -m "whitespace changes" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local author_time=`git_show_author_time $testroot/${GOTSYS_REPO}`

	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
		'printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l 25' > $testroot/stdout &

	sleep 1 # server starts up

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	wait %1 # wait for ssh / nc -l

	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTSYSD_TEST_USER}@example.com>\r\n" \
		>> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTSYSD_TEST_USER}@example.com\r\n" \
		>> $testroot/stdout.expected
	printf "Subject: $GOTSYS_REPO: " >> $testroot/stdout.expected
	printf "${GOTSYSD_TEST_USER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 20\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " whitespace changes\n \n" >> $testroot/stdout.expected
	printf " M  gotsys.conf  |  3+  0-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 3 insertions(+), 0 deletions(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	# Restart smtpd 
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
		'/etc/rc.d/smtpd start' > /dev/null

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_user_add
run_test test_user_mod
run_test test_user_del
run_test test_group_add
run_test test_group_del
run_test test_repo_create
run_test test_user_anonymous
run_test test_user_anonymous_remove
run_test test_bad_gotsysconf
run_test test_bad_ref_in_gotsysconf
run_test test_set_head
run_test test_protect_refs
run_test test_deny_access
run_test test_override_access_rules
run_test test_override_all_user_access
run_test test_http_notification
run_test test_http_notification_hmac
run_test test_email_notification
