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


test_repos_at_root_path_and_website() {
	local testroot=`test_init repos_at_root_path_and_website 1`

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
repository gotsys {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository www {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
web server "${VMIP}" {
	repository gotsys {
		hide repository on
	}

	repositories url path "/"

	website "/website" {
		repository "www"
		disable authentication
	}

	repository www {
		permit ${GOTSYSD_TEST_USER}
	}
}
EOF
	(cd ${testroot}/wt && got commit  -m "add www.git" >/dev/null)
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

	got init $testroot/www.git > /dev/null
	mkdir -p $testroot/www

	cat > $testroot/www/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>testing gotwebd</title>
</head>
<body>
<h1>testing gotwebd</h1>
<p>Testing the web site feature of gotwebd.</p>
</body>
</html>
EOF
	got import -m init -r $testroot/www.git $testroot/www > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got import failed unexpectedly" >&2
		return 1
	fi

	cat > $testroot/www.git/got.conf <<EOF
remote "origin" {
	server "${GOTSYSD_DEV_USER}@$VMIP"
	protocol ssh
	repository "www"
}
EOF
	got send -q -i ${GOTSYSD_SSH_KEY} -b main -r $testroot/www.git
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		return 1
	fi

	# Attempt website access.
	w3m "http://${VMIP}/website" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
testing gotwebd

Testing the web site feature of gotwebd.

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to access a non-existent location.
	w3m "http://${VMIP}/nonexistent" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
not found

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt unauthenticated access to repositories.
	w3m "http://${VMIP}/" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Log in by running: ssh ${GOTSYSD_TEST_USER}@${VMIP} "weblogin ${VMIP}"

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Obtain a login token over ssh.
	ssh -q -i ${GOTSYSD_SSH_KEY} ${GOTSYSD_TEST_USER}@${VMIP} \
		'gotsh -c weblogin' > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ssh login failed failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Request the index page again using the login token and
	# storing the cookie sent by gotwebd.
	url=$(cut -d: -f 2,3 < $testroot/stdout | sed -e 's/ https:/http:/')
	w3m -cookie-jar "$testroot/cookies" "$url" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Project
www.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------

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

test_parseargs "$@"
run_test test_repos_at_root_path_and_website
