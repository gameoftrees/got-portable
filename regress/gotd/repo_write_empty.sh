#!/bin/sh
#
# Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

test_send_empty() {
	local testroot=`test_init send_empty`
	local commit_id=`git_show_head $testroot/repo`

	(cd ${GOTD_TEST_REPO} && find . > $testroot/repo-list.before)

	# The gotd-controlled test repository starts out empty.
	got ref -l -r ${GOTD_TEST_REPO} > $testroot/ref-list.before
	echo "HEAD: refs/heads/main" > $testroot/ref-list.expected
	cmp -s $testroot/ref-list.expected $testroot/ref-list.before
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/ref-list.expected $testroot/ref-list.before
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout -q $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# send contents of $testroot/repo to ${GOTD_TEST_REPO}
	cat >> $testroot/wt/.got/got.conf <<EOF
remote "gotd" {
	server ${GOTD_DEVUSER}@127.0.0.1
	repository "test-repo"
	protocol ssh
}
EOF
	(cd $testroot/wt && got send -q -a gotd)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Server should have created a new reference.
	got ref -l -r ${GOTD_TEST_REPO} > $testroot/ref-list.after
	cat > $testroot/ref-list.expected <<EOF
HEAD: refs/heads/main
refs/heads/master: $commit_id
EOF
	cmp -s $testroot/ref-list.expected $testroot/ref-list.after
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/ref-list.expected $testroot/ref-list.after
		test_done "$testroot" "$ret"
		return 1
	fi

	# Verify that the result can be cloned again.
	# XXX need -b master at present because gotd does not rewrite HEAD
	got clone -q -b master ${GOTD_TEST_REPO_URL} $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got tree -R -r $testroot/repo-clone2 > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
beta
epsilon/
epsilon/zeta
gamma/
gamma/delta
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# sending to a repository should result in a new pack file
	(cd ${GOTD_TEST_REPO} && find . > $testroot/repo-list.after)
	diff -u $testroot/repo-list.before $testroot/repo-list.after \
		> $testroot/repo-list.diff
	grep '^+[^+]' < $testroot/repo-list.diff > $testroot/repo-list.newlines
	nplus=`awk '/^\+[^+]/{c++} END{print c}' $testroot/repo-list.diff`
	if [ "$nplus" != "4" ]; then
		echo "$nplus new files created:" >&2
		cat $testroot/repo-list.diff
		test_done "$testroot" 1
		return 1
	fi

	if [ "$GOT_TEST_ALGO" = "sha256" ]; then
		digest_len=64
	else
		digest_len=40
	fi

	egrep -q "\+\./objects/pack/pack-[a-f0-9]{$digest_len}\.pack" \
		$testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack file not found in ${GOTD_TEST_REPO}"
		cat $testroot/repo-list.newlines
		test_done "$testroot" "$ret"
		return 1
	fi
	egrep -q "\+\./objects/pack/pack-[a-f0-9]{$digest_len}\.idx" \
		$testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack index not found in ${GOTD_TEST_REPO}"
		test_done "$testroot" "$ret"
		return 1
	fi
	fgrep -q '+./refs/heads' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new refs/heads directory not found"
		test_done "$testroot" "$ret"
		return 1
	fi
	if [ ! -d ${GOTD_TEST_REPO}/refs/heads ]; then
		echo "new refs/heads is not a directory"
		test_done "$testroot" 1
		return 1
	fi
	fgrep -q '+./refs/heads/master' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new refs/heads/master not found"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_send_empty
