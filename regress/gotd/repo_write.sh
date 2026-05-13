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

test_send_basic() {
	local testroot=`test_init send_basic 1`

	ls -R ${GOTD_TEST_REPO}/objects/pack > $testroot/repo-list.before

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create a second clone to test an incremental fetch with later
	got clone -q -m ${GOTD_TEST_REPO_URL} $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	# same for Git
	git clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone3 \
		>$testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	mkdir $testroot/wt/psi
	echo "new" > $testroot/wt/psi/new
	(cd $testroot/wt && got add psi/new > /dev/null)
	echo "more alpha" >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	(cd $testroot/wt && got branch newbranch >/dev/null)
	echo "even more alpha" >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'more changes' > /dev/null)
	got tag -r $testroot/repo-clone -m "tagging 1.0" 1.0 >/dev/null

	got send -b main -b newbranch -q -r $testroot/repo-clone -t 1.0
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the send operation worked fine.
	got fetch -q -r $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch failed unexpectedly" >&2
		test_done "$testroot" "1"
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
psi/
psi/new
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Verify that git pull works, too
	(cd $testroot/repo-clone3 && git pull -q > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git pull failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that git push reports no changes to send and no error.
	(cd $testroot/repo-clone3 && git push -q > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git push failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# sending to a repository should result in a new pack file
	ls -R ${GOTD_TEST_REPO}/objects/pack > $testroot/repo-list.after
	diff -u $testroot/repo-list.before $testroot/repo-list.after \
		> $testroot/repo-list.diff
	grep '^+[^+]' < $testroot/repo-list.diff > $testroot/repo-list.newlines
	nplus=`wc -l < $testroot/repo-list.newlines | tr -d ' '`
	if [ "$nplus" != "2" ]; then
		echo "$nplus new files created:"
		cat $testroot/repo-list.diff
		test_done "$testroot" "$ret"
		return 1
	fi
	egrep -q '\+pack-[a-f0-9]{40}.pack' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack file not found in ${GOTD_TEST_REPO}"
		cat $testroot/repo-list.newlines
		test_done "$testroot" "$ret"
		return 1
	fi
	egrep -q '\+pack-[a-f0-9]{40}.idx' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack index not found in ${GOTD_TEST_REPO}"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_fetch_more_history() {
	local testroot=`test_init fetch_more_history 1`

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Create some more commit history on the main branch.
	# History needs to be deep enough to trick 'git pull' into sending
	# a lot of 'have' lines, which triggered a bug in gotd.
	for i in `seq 50`; do
		echo "more alpha" >> $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'more changes' > /dev/null)
	done
	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create a second clone to test an incremental fetch with later
	got clone -q -m ${GOTD_TEST_REPO_URL} $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	# same for Git, which used to fail:
	# fetch-pack: protocol error: bad band #69
	# fatal: protocol error: bad pack header
	# gotsh: unexpected 'have' packet
	git clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone3 \
		>$testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Create more commit history on the main branch
	echo "more alpha" >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	echo "more beta" >> $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'more changes' > /dev/null)
	(cd $testroot/wt && got rm epsilon/zeta > /dev/null)
	(cd $testroot/wt && got commit -m 'rm epsilon/zeta' > /dev/null)
	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the new changes can be fetched
	got fetch -q -r $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got tree -R -r $testroot/repo-clone2 > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
beta
gamma/
gamma/delta
psi/
psi/new
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Verify that git pull works, too
	(cd $testroot/repo-clone3 && git pull -q > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git pull failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_send_new_empty_branch() {
	local testroot=`test_init send_new_empty_branch 1`

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local commit_id=`git_show_head $testroot/repo-clone`

	got branch -r $testroot/repo-clone -c main newbranch2 >/dev/null
	got send -b newbranch2 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the send operation worked fine.
	got clone -l ${GOTD_TEST_REPO_URL} | grep newbranch2 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone -l failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "refs/heads/newbranch2: $commit_id" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_delete_branch() {
	local testroot=`test_init delete_branch 1`

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

	local foo_id=`git_show_branch_head "$testroot/repo-clone" foo`
	local main_id=`git_show_branch_head "$testroot/repo-clone" main`
	local nb_id=`git_show_branch_head "$testroot/repo-clone" newbranch`
	local nb2_id=`git_show_branch_head "$testroot/repo-clone" newbranch2`
	local tag_id=`got ref -r "$testroot/repo-clone" -l refs/tags/1.0 | \
		awk '{print $2}'`

	if ! got send -q -r $testroot/repo-clone -b foo; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -l >$testroot/refs
	cat <<EOF >$testroot/refs.expected
HEAD: refs/heads/main
HEAD: $main_id
refs/heads/foo: $foo_id
refs/heads/main: $main_id
refs/heads/newbranch: $nb_id
refs/heads/newbranch2: $nb2_id
refs/tags/1.0: $tag_id
EOF
	if ! cmp -s $testroot/refs.expected $testroot/refs; then
		diff -u $testroot/refs.expected $testroot/refs
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/repo-clone && git push -d origin foo) >/dev/null 2>&1
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git push -d failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -l >$testroot/refs
	cat <<EOF >$testroot/refs.expected
HEAD: refs/heads/main
HEAD: $main_id
refs/heads/main: $main_id
refs/heads/newbranch: $nb_id
refs/heads/newbranch2: $nb2_id
refs/tags/1.0: $tag_id
EOF
	if ! cmp -s $testroot/refs.expected $testroot/refs; then
		diff -u $testroot/refs.expected $testroot/refs
		test_done "$testroot" 1
		return 1
	fi

	# try to delete multiple branches in one go
	got send -r $testroot/repo-clone -d newbranch -d newbranch2 \
		>$testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send with multiple -d failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
Connecting to "origin" ${GOTD_TEST_REPO_URL}
Server has deleted refs/heads/newbranch2
Server has deleted refs/heads/newbranch
EOF
	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -l >$testroot/refs
	cat <<EOF >$testroot/refs.expected
HEAD: refs/heads/main
HEAD: $main_id
refs/heads/main: $main_id
refs/tags/1.0: $tag_id
EOF
	if ! cmp -s $testroot/refs.expected $testroot/refs; then
		diff -u $testroot/refs.expected $testroot/refs
		test_done "$testroot" 1
		return 1
	fi

	# now try again but while also updating another branch
	# other than deleting `foo'.

	(cd $testroot/wt && got up -b main && \
		echo 'more alpha' > alpha && \
		got commit -m 'edit alpha on main' && \
		got send -q -b foo) >/dev/null
	main_id=`git_show_branch_head "$testroot/repo-clone" main`

	got send -r $testroot/repo-clone -d foo -b main | \
		grep '^Server has' >$testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send -d foo -b main failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
Server has accepted refs/heads/main
Server has deleted refs/heads/foo
EOF
	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -l >$testroot/refs
	cat <<EOF >$testroot/refs.expected
HEAD: refs/heads/main
HEAD: $main_id
refs/heads/main: $main_id
refs/tags/1.0: $tag_id
EOF
	if ! cmp -s $testroot/refs.expected $testroot/refs; then
		diff -u $testroot/refs.expected $testroot/refs
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_rewind_branch() {
	local testroot=`test_init rewind_branch 1`

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

	if ! got send -q -r $testroot/repo-clone -b foo; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	local foo_id=`git_show_branch_head "$testroot/repo-clone" foo`
	local main_id=`git_show_branch_head "$testroot/repo-clone" main`
	local tag_id=`got ref -r "$testroot/repo-clone" -l refs/tags/1.0 | \
		awk '{print $2}'`

	(cd $testroot/wt && got update -c $main_id) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got histedit -d) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got histedit failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! got send -q -r $testroot/repo-clone -f -b foo; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -l >$testroot/refs
	cat <<EOF >$testroot/refs.expected
HEAD: refs/heads/main
HEAD: $main_id
refs/heads/foo: $main_id
refs/heads/main: $main_id
refs/tags/1.0: $tag_id
EOF
	if ! cmp -s $testroot/refs.expected $testroot/refs; then
		diff -u $testroot/refs.expected $testroot/refs
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_fetch_unrelated_history() {
	local testroot=`test_init fetch_unrelated_history 1`

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local commit_id0=`git_show_head $testroot/repo-clone`
	
	mkdir $testroot/new-repo
	git_init $testroot/new-repo
	git -C $testroot/new-repo symbolic-ref HEAD refs/heads/main

	echo 'new history with just one file' > $testroot/new-repo/alpha
	git -C $testroot/new-repo add alpha
	git_commit $testroot/new-repo -m "adding the test tree"
	for i in 1 2 3; do
		echo 'line $i' >> $testroot/new-repo/alpha
		git -C $testroot/new-repo add alpha
		git_commit $testroot/new-repo -m "more changes" 
	done
	got tag -r $testroot/new-repo -m "tagging 1.0" 1.0 >/dev/null
	local commit_id2=`git_show_head $testroot/new-repo`
	local tag_id=`got ref -r "$testroot/new-repo" -l refs/tags/1.0 | \
		awk '{print $2}'`

	cp $testroot/repo-clone/got.conf $testroot/new-repo/.git/got.conf

	got send -q -b main -t 1.0 -r $testroot/new-repo -f
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the send operation worked fine.
	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got tree -R -r $testroot/repo-clone2 > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# This test checks for server-side behaviour where progress output
	# gets generated before any ACK or NAK arrive.
	# To trigger the problem we should not be sending any refs the
	# server already knows about. So delete the following:
	got ref -d -r $testroot/repo-clone refs/tags/1.0 > /dev/null
	got fetch -X -r $testroot/repo-clone origin > /dev/null

	# Rewrite main branch hisotry to avoid sending a HAVE with a
	# commit ID which the server can find locally.
	got ref -r $testroot/repo-clone -d refs/heads/main > /dev/null
	mkdir $testroot/import-tree
	echo 'parallel universe alpha' > $testroot/import-tree/alpha

	got import -r $testroot/repo-clone -b main -m init \
		$testroot/import-tree > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got import failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	local commit_id=`git_show_head $testroot/repo-clone`

	cp -r $testroot/repo-clone $testroot/repo-clone3
	cp $testroot/repo-clone/config $testroot/repo-clone3/config

	# verify that unrelated history can be fetched into the initial clone.
	# This used to fail with:
	# got-fetch-pack: readpkt: 48:    [0x02]1 commits colored, \
	#    0 objects found, deltify 0%[0x0d]
	# got-fetch-pack: unexpected message from server
	got fetch -q -r $testroot/repo-clone > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/main
refs/heads/main: $commit_id
refs/remotes/origin/HEAD: refs/remotes/origin/main
refs/remotes/origin/main: $commit_id2
refs/tags/1.0: $tag_id
EOF
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Now try the same fetch operation against gotd with Git.
	# This used to fail with:
	# fatal: git fetch-pack: expected ACK/NAK, got '?1 commits colored, \
	#     0 objects found, deltify 0%?'
	git -C $testroot/repo-clone3 fetch > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone3 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/main
refs/heads/main: $commit_id
refs/remotes/origin/HEAD: refs/remotes/origin/main
refs/remotes/origin/main: $commit_id2
refs/tags/1.0: $tag_id
EOF
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_send_basic
run_test test_fetch_more_history
run_test test_send_new_empty_branch
run_test test_delete_branch
run_test test_rewind_branch
run_test test_fetch_unrelated_history
