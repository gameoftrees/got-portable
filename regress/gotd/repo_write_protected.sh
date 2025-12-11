#!/bin/sh
#
# Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

test_create_protected_branch() {
	local testroot=`test_init create_protected_branch 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch foo) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo modified alpha > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha') >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	local commit_id=`git_show_branch_head $testroot/repo-clone foo`

	# Creating a new branch should succeed.
	got send -q -r $testroot/repo-clone -b foo 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Verify that the send operation worked fine.
	got clone -l ${GOTD_TEST_REPO_URL} | grep foo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "refs/heads/foo: $commit_id" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" $ret
}

test_modify_protected_tag_namespace() {
	local testroot=`test_init modify_protected_tag_namespace`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got tag -r $testroot/repo-clone -m "1.0" 1.0 >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tag failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Creating a new tag should succeed.
	got send -q -r $testroot/repo-clone -t 1.0 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got ref -r $testroot/repo-clone -d refs/tags/1.0 > /dev/null
	got tag -r $testroot/repo-clone -m "another 1.0" 1.0 >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tag failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Overwriting an existing tag should fail.
	got send -q -f -r $testroot/repo-clone -t 1.0 2> $testroot/stderr
	ret=$?
	if [ $ret == 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! egrep -q '(gotsh|got-send-pack): refs/tags/: reference namespace is protected' \
		$testroot/stderr; then
		echo -n "error message unexpected or missing: " >&2
		cat $testroot/stderr >&2
		test_done "$testroot" 1
		return 1
	fi

	# Deleting an existing tag should fail.
	# 'got send' cannot even do this so we use 'git push'.
	(cd $testroot/repo-clone && git push -q -d origin refs/tags/1.0 \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "git push -d succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! egrep -q '(fatal: remote error|gotsh): refs/tags/: reference namespace is protected' \
		$testroot/stderr; then
		echo -n "error message unexpected or missing: " >&2
		cat $testroot/stderr >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_delete_protected_branch() {
	local testroot=`test_init delete_protected_branch`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if got send -q -r $testroot/repo-clone -d main 2> $testroot/stderr; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! egrep -q '(gotsh|got-send-pack): refs/heads/main: reference is protected' \
		$testroot/stderr; then
		echo -n "error message unexpected or missing: " >&2
		cat $testroot/stderr >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_modify_protected_branch() {
	local testroot=`test_init modify_protected_branch`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout $testroot/repo-clone $testroot/wt >/dev/null

	for i in 1 2; do
		echo "more alpha" >> $testroot/wt/alpha
		(cd $testroot/wt && got commit -m "more" >/dev/null)
	done
	local commit_id=`git_show_head $testroot/repo-clone`
	local parent_commit_id=`git_show_parent_commit $testroot/repo-clone \
		"$commit_id"`

	# Modifying the branch by adding new commits on top should succeed.
	got send -q -r $testroot/repo-clone 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Verify that the send operation worked fine.
	got clone -l ${GOTD_TEST_REPO_URL} | grep main > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "HEAD: refs/heads/main" > $testroot/stdout.expected
	echo "refs/heads/main: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" $ret
		return 1
	fi

	# Attempt to remove the tip commit
	(cd $testroot/wt && got update -c "$parent_commit_id" >/dev/null)
	(cd $testroot/wt && got histedit -d >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got histedit failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# The client should reject sending without -f.
	got send -q -r $testroot/repo-clone 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
 
	echo -n 'got: refs/heads/main: branch on server has' \
	    > $testroot/stderr.expected
	echo -n ' a different ancestry; either fetch changes' \
	    >> $testroot/stderr.expected
	echo -n ' from server and then rebase or merge local' \
	    >> $testroot/stderr.expected
	echo -n ' branch before sending, or ignore ancestry' \
	    >> $testroot/stderr.expected
	echo -n ' with send -f (can lead to data loss on' \
	    >> $testroot/stderr.expected
	echo ' server)' >> $testroot/stderr.expected

	if ! cmp -s $testroot/stderr.expected $testroot/stderr; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" 1
		return 1
	fi

	# Try again with -f.
	got send -q -r $testroot/repo-clone -f 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! egrep -q '(gotsh|got-send-pack): refs/heads/main: reference is protected' \
		$testroot/stderr; then
		echo -n "error message unexpected or missing: " >&2
		cat $testroot/stderr >&2
		test_done "$testroot" 1
		return 1
	fi

	# Verify that the send -f operation did not have any effect.
	got clone -l ${GOTD_TEST_REPO_URL} | grep main > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "HEAD: refs/heads/main" > $testroot/stdout.expected
	echo "refs/heads/main: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	# Put the tip commit back.
	got ref -r $testroot/repo-clone -c $commit_id refs/heads/main

	# Try adding a new commit to 'main' while sending an empty pack file.
	# First, create a new branch 'bar' and send it.
	got branch -r $testroot/repo-clone -c $commit_id bar > /dev/null
	(cd $testroot/wt && got up -q -b bar > /dev/null)
	echo "change beta" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'change beta' > /dev/null)
	got send -q -r $testroot/repo-clone  -b bar
	# Now merge branch 'bar' into 'main' and send the 'main' branch.
	# Because the server already has the relevant commit, we will send
	# an empty pack file during our second send operation.
	# This would cause a bogus 'reference is protected' error.
	(cd $testroot/wt && got up -q -b main > /dev/null)
	(cd $testroot/wt && got merge bar > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	got send -q -r $testroot/repo-clone -b main
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Verify that the send operation worked fine.
	got clone -l ${GOTD_TEST_REPO_URL} | grep '^refs/heads/' \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local commit_id_foo=`git_show_branch_head $testroot/repo-clone foo`
	echo "refs/heads/bar: $commit_id" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id_foo" >> $testroot/stdout.expected
	echo "refs/heads/main: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" $ret
}

test_parseargs "$@"
run_test test_create_protected_branch
run_test test_modify_protected_tag_namespace
run_test test_delete_protected_branch
run_test test_modify_protected_branch
