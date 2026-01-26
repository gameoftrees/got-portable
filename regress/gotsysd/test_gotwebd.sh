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

test_login() {
	local testroot=`test_init login 1`

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
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository gotdev.git {
	permit rw ${GOTSYSD_DEV_USER}
}
repository hidden.git {
	permit rw ${GOTSYSD_TEST_USER}
}
web server "${VMIP}" {
	repository gotsys.git {
		permit ${GOTSYSD_TEST_USER}
	}
	repository gotdev.git {
		permit ${GOTSYSD_DEV_USER}
		deny ${GOTSYSD_TEST_USER}
	}
	repository hidden.git {
		permit ${GOTSYSD_TEST_USER}
		deny ${GOTSYSD_DEV_USER}
		hide repository on
	}
}
EOF
	(cd ${testroot}/wt && gotsys check -q)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "bad gotsys.conf written by test" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd ${testroot}/wt && got commit -m "configure web server" >/dev/null)
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

	# Attempt unauthorized access.
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
gotsys.git
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

	# Request a tree page using the stored cookie.
	w3m -cookie-jar "$testroot/cookies" \
		"http://${VMIP}/?action=tree&path=gotsys.git" -dump \
		> $testroot/stdout

	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local commit_time=`git_show_author_time $testroot/${GOTSYS_REPO} $commit_id`
	local d=$(env LC_ALL=C date -u -r "$commit_time" \
		+"%a %b %e %H:%M:%S %Y UTC" | sed -e 's/  / /')
	local tree_id=$(got cat -r $testroot/${GOTSYS_REPO} $commit_id | \
		grep 'tree ' | cut -d ' ' -f2)

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / gotsys.git / tree /

Tree

Tree:
    $tree_id
Date:
    $d
Message:
    configure web server

-------------------------------------------------------------------------------

gotsys.conf commits | blame

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to access the same page again without the cookie.
	w3m "http://${VMIP}/?action=tree&path=gotsys.git" -dump \
		> $testroot/stdout

	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local tree_id=$(got cat -r $testroot/${GOTSYS_REPO} $commit_id | \
		grep 'tree ' | cut -d ' ' -f2)

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / gotsys.git / tree /
Log in by running: ssh ${GOTSYSD_TEST_USER}@${VMIP} "weblogin ${VMIP}"

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to access a non-existent repository without the cookie.
	# Observable behaviour should match the case where the name of a
	# hidden and existing repository was guessed correctly.
	w3m "http://${VMIP}/?action=tree&path=nonexistent.git" -dump \
		> $testroot/stdout

	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`
	local tree_id=$(got cat -r $testroot/${GOTSYS_REPO} $commit_id | \
		grep 'tree ' | cut -d ' ' -f2)

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / nonexistent.git / tree /
Log in by running: ssh ${GOTSYSD_TEST_USER}@${VMIP} "weblogin ${VMIP}"

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_access_rules_index_page() {
	local testroot=`test_init access_rules_index_page 1`

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
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository public.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository gotdev.git {
	permit rw ${GOTSYSD_DEV_USER}
}
repository gottest.git {
	permit rw ${GOTSYSD_TEST_USER}
}
repository hidden.git {
	permit rw ${GOTSYSD_TEST_USER}
}
web server "${VMIP}" {
	repository gotsys.git {
		permit ${GOTSYSD_TEST_USER}
	}
	repository public.git {
		disable authentication
	}
	repository gotdev.git {
		permit ${GOTSYSD_DEV_USER}
		deny ${GOTSYSD_TEST_USER}
	}
	repository gottest.git {
		permit ${GOTSYSD_TEST_USER}
	}
	repository hidden.git {
		permit ${GOTSYSD_TEST_USER}
		deny ${GOTSYSD_DEV_USER}
		hide repository on
	}
}
EOF
	(cd ${testroot}/wt && gotsys check -q)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "bad gotsys.conf written by test" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd ${testroot}/wt && got commit \
		-m "add public and gottest repositories" >/dev/null)
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

	# Request the index page without being logged in.
	# Repositories we do not have access to should not be listed.
	w3m "http://${VMIP}/" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Project
public.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------

EOF

	# Obtain a login token over ssh.
	ssh -q -i ${GOTSYSD_SSH_KEY} ${GOTSYSD_TEST_USER}@${VMIP} \
		'gotsh -c weblogin' > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ssh login failed failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Request the index page. Repositories we do not have access
	# to should not be listed.
	url=$(cut -d: -f 2,3 < $testroot/stdout | sed -e 's/ https:/http:/')
	w3m -cookie-jar "$testroot/cookies" "$url" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Project
gotsys.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------
gottest.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------
public.git
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

	# Obtain a different login token over ssh.
	ssh -q -i ${GOTSYSD_SSH_KEY} ${GOTSYSD_DEV_USER}@${VMIP} \
		'weblogin' > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ssh login failed failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Request the index page. Repositories we do not have access
	# to should not be listed.
	url=$(cut -d: -f 2,3 < $testroot/stdout | sed -e 's/ https:/http:/')
	w3m -cookie-jar "$testroot/cookies" "$url" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Project
gotdev.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------
public.git
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
	test_done "$testroot" "0"
}

test_access_rules_tree_page() {
	local testroot=`test_init access_rules_tree_page 1`

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
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository public.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
repository gotdev.git {
	permit rw ${GOTSYSD_DEV_USER}
}
repository gottest.git {
	permit rw ${GOTSYSD_TEST_USER}
}
repository hidden.git {
	permit rw ${GOTSYSD_TEST_USER}
}
web server "${VMIP}" {
	repository gotsys.git {
		permit ${GOTSYSD_TEST_USER}
	}
	repository public {
		disable authentication
	}
	repository gotdev.git {
		permit ${GOTSYSD_DEV_USER}
		deny ${GOTSYSD_TEST_USER}
	}
	repository gottest.git {
		permit ${GOTSYSD_TEST_USER}
	}
	repository hidden {
		permit ${GOTSYSD_TEST_USER}
		deny ${GOTSYSD_DEV_USER}
		hide repository on
	}
}
EOF
	(cd ${testroot}/wt && gotsys check -q)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "bad gotsys.conf written by test" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd ${testroot}/wt && got commit -m "no-op update" >/dev/null)
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

	# Attempt to access a public repository's tree
	w3m "http://${VMIP}/?action=tree&path=public.git" -dump \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / public.git / tree /
reference refs/heads/main not found

EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to access a private repository's tree
	w3m "http://${VMIP}/?action=tree&path=gottest.git" -dump \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / gottest.git / tree /
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

	url=$(cut -d: -f 2,3 < $testroot/stdout | sed -e 's/ https:/http:/')
	w3m -cookie-jar "$testroot/cookies" "$url" -dump > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
[got]
Repos
Project
gotsys.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------
gottest.git
summary | briefs | commits | tags | tree | rss
-------------------------------------------------------------------------------
public.git
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

	# Attempt to access the private repository's tree again with cookie
	w3m -cookie-jar $testroot/cookies \
		"http://${VMIP}/?action=tree&path=gottest.git" -dump \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
[got]
Repos / gottest.git / tree /
reference refs/heads/main not found

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
run_test test_login
run_test test_access_rules_index_page
run_test test_access_rules_tree_page
