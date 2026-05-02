#!/bin/sh
#
# Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

. ./common.sh

test_send_basic() {
	local testroot=`test_init send_basic`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	got tag -r $testroot/repo -m '1.0' 1.0 >/dev/null
	tag_id=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	echo "modified alpha" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	(cd $testroot/repo && ln -s epsilon/zeta symlink)
	git -C $testroot/repo add symlink
	echo "new file alpha" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got send -q -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo-clone -c $commit_id2 -i -R \
		> $testroot/stdout
	got tree -r $testroot/repo -c $commit_id2 -i -R \
		> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo-clone" \
		> $testroot/stdout.expected
	echo "Already up-to-date" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_rebase_required() {
	local testroot=`test_init send_rebase_required`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got checkout $testroot/repo-clone $testroot/wt-clone >/dev/null
	echo "modified alpha, too" > $testroot/wt-clone/alpha
	(cd $testroot/wt-clone && got commit -m 'change alpha' >/dev/null)

	got send -q -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
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

	echo -n "got: refs/heads/master: " > $testroot/stderr.expected
	echo -n "branch on server has a different ancestry; " \
		>> $testroot/stderr.expected
	echo -n "either fetch changes from server and then " \
		>> $testroot/stderr.expected
	echo -n "rebase or merge local branch before sending, or " \
		>> $testroot/stderr.expected
	echo "ignore ancestry with send -f (can lead to data loss on server)" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_rebase_required_overwrite() {
	local testroot=`test_init send_rebase_required_overwrite`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "foobar" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got checkout $testroot/repo-clone $testroot/wt-clone >/dev/null
	echo "modified alpha, too" > $testroot/wt-clone/alpha
	(cd $testroot/wt-clone && got commit -m 'change alpha' >/dev/null)
	local commit_id3=`git_show_head $testroot/repo-clone`

	# non-default remote requires an explicit argument
	got send -q -r $testroot/repo -f > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo "got: origin: remote repository not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -r $testroot/repo -f foobar > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/foobar/master: $commit_id2" \
		>> $testroot/stdout.expected

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

	wt_uuid=`(cd $testroot/wt-clone && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_merge_commit() {
	local testroot=`test_init send_merge_commit`
	local testurl=ssh://127.0.0.1/$testroot

	if ! got clone -q "$testurl/repo" "$testroot/repo-clone"; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! got clone -b master -m -q "$testurl/repo" "$testroot/repo-dest"; \
	then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo 'upstream change' > $testroot/repo/alpha
	git_commit $testroot/repo -m 'upstream change'
	local commit_id_upstream=`git_show_head $testroot/repo`

	got checkout $testroot/repo-clone $testroot/wt-clone > /dev/null
	echo 'downstream change' > $testroot/wt-clone/beta
	(cd $testroot/wt-clone && got commit -m 'downstream change' > /dev/null)
	local commit_id_downstream=`git_show_head $testroot/repo-clone`

	got fetch -q -r $testroot/repo-clone
	(cd $testroot/wt-clone && got update > /dev/null)
	(cd $testroot/wt-clone && got merge origin/master > /dev/null)
	local commit_id_merge=`git_show_head $testroot/repo-clone`
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat >> $testroot/repo-clone/got.conf <<EOF
remote "dest" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo-dest"
}
EOF
	got send -b master -q -r $testroot/repo-clone dest
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	for commit_id in \
		$commit_id_upstream $commit_id_downstream $commit_id_merge; do
		got cat -r $testroot/repo-dest $commit_id > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got cat $commit_id failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" 0
}

test_send_delete() {
	local testroot=`test_init send_delete`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	# branch1 exists in both repositories
	got branch -r $testroot/repo branch1

	got clone -a -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	# branch2 exists only in the remote repository
	got branch -r $testroot/repo-clone branch2

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch2: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

	# Sending changes for a branch and deleting it at the same
	# time is not allowed.
	got send -q -r $testroot/repo -d branch1 -b branch1 \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo -n "got: changes on refs/heads/branch1 will be sent to server" \
		> $testroot/stderr.expected
	echo ": reference cannot be deleted" >> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -r $testroot/repo -d refs/heads/branch1 origin \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -r $testroot/repo -d refs/heads/branch2 origin \
		> $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo-clone" \
		> $testroot/stdout.expected
	echo "Server has deleted refs/heads/branch2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# branchX exists in neither repository
	got send -q -r $testroot/repo -d refs/heads/branchX origin \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo -n "got-send-pack: refs/heads/branchX does not exist in remote " \
		> $testroot/stderr.expected
	echo "repository: no such reference found" >> $testroot/stderr.expected
	echo "got: no such reference found" >> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# References outside of refs/heads/ cannot be deleted with 'got send'.
	got send -q -r $testroot/repo -d refs/tags/1.0 origin \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo -n "got-send-pack: refs/heads/refs/tags/1.0 does not exist " \
		> $testroot/stderr.expected
	echo "in remote repository: no such reference found" \
		>> $testroot/stderr.expected
	echo "got: no such reference found" >> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/branch1: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_clone_and_send() {
	local testroot=`test_init send_clone_and_send`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	git -C $testroot/repo config receive.denyCurrentBranch ignore

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo-clone $testroot/wt >/dev/null
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)
	local commit_id2=`git_show_head $testroot/repo-clone`

	(cd $testroot/wt && got send -q > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected

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

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_tags() {
	local testroot=`test_init send_tags`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	got tag -r $testroot/repo -m '1.0' 1.0 >/dev/null
	tag_id=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got tag -r $testroot/repo -m '2.0' 2.0 >/dev/null
	tag_id2=`got ref -r $testroot/repo -l | grep "^refs/tags/2.0" \
		| tr -d ' ' | cut -d: -f2`

	got send -q -r $testroot/repo -T > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/2.0: $tag_id2" >> $testroot/stdout.expected

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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/2.0: $tag_id2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -l -r $testroot/repo-clone | grep ^tag | sort > $testroot/stdout
	echo "tag 1.0 $tag_id" > $testroot/stdout.expected
	echo "tag 2.0 $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Send the same tags again. This should be a no-op.
	got send -q -r $testroot/repo -T > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	# Overwriting an existing tag 'got send -f'.
	got ref -r $testroot/repo -d refs/tags/1.0 >/dev/null
	got tag -r $testroot/repo -m '1.0' 1.0 >/dev/null
	tag_id3=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	got send -q -r $testroot/repo -t 1.0 > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "got: refs/tags/1.0: tag already exists on server" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# attempting the same with -T should fail, too
	got send -q -r $testroot/repo -T > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "got: refs/tags/1.0: tag already exists on server" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -l -r $testroot/repo-clone | grep ^tag | sort > $testroot/stdout
	echo "tag 1.0 $tag_id" > $testroot/stdout.expected
	echo "tag 2.0 $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# overwrite the 1.0 tag only
	got send -q -r $testroot/repo -t 1.0 -f > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -l -r $testroot/repo-clone | grep ^tag | sort > $testroot/stdout
	echo "tag 1.0 $tag_id3" > $testroot/stdout.expected
	echo "tag 2.0 $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo $testroot/wt > /dev/null
	echo 'new line in file alpha' >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'changing file alpha' > /dev/null)

	# Send the new commit in isolation.
	got send -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# Now tag it and send the tag.
	# Verify that just the new tag object gets sent.
	got tag -r $testroot/repo -m '3.0' 3.0 >/dev/null
	tag_id4=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	got send -r $testroot/repo -t 3.0 > $testroot/stdout.raw \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	tr -d '\r' < $testroot/stdout.raw > $testroot/stdout
	if ! grep -q "packing 2 references; 1 object; deltify: 100%" \
		$testroot/stdout; then
		echo "got send did apparently pack too many objects:" >&2
		cat $testroot/stdout.raw >&2
		test_done "$testroot" "1"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_tag_of_deleted_branch() {
	local testroot=`test_init send_tag_of_deleted_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF
	got branch -r $testroot/repo foo

	# modify beta on branch foo
	got checkout -b foo $testroot/repo $testroot/wt > /dev/null
	echo boo >> $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'changed beta on branch foo' \
		> /dev/null)
	echo buu >> $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'changed beta again on branch foo' \
		> /dev/null)
	echo baa >> $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'changed beta again on branch foo' \
		> /dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo foo`

	# tag HEAD commit of branch foo
	got tag -r $testroot/repo -c foo -m '1.0' 1.0 > /dev/null
	tag_id=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	# delete the branch; commit is now only reachable via tags/1.0
	got branch -r $testroot/repo -d foo > /dev/null

	# unrelated change on master branch, then try sending this branch
	# and the tag
	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id3=`git_show_head $testroot/repo`

	got send -q -r $testroot/repo -T > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id3" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id3" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -l -r $testroot/repo-clone | grep ^tag | sort > $testroot/stdout
	echo "tag 1.0 $tag_id" > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_new_branch() {
	local testroot=`test_init send_new_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	git -C $testroot/repo config receive.denyCurrentBranch ignore

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo-clone foo >/dev/null
	got checkout -b foo $testroot/repo-clone $testroot/wt >/dev/null
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo-clone foo`

	(cd $testroot/wt && got send -q > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

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

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_all_branches() {
	local testroot=`test_init send_all_branches`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	git -C $testroot/repo config receive.denyCurrentBranch ignore

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo-clone $testroot/wt >/dev/null
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)
	local commit_id2=`git_show_head $testroot/repo-clone`

	got branch -r $testroot/repo-clone foo >/dev/null
	(cd $testroot/wt && got update -b foo >/dev/null)
	echo "modified beta on new branch foo" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "modified beta" >/dev/null)
	local commit_id3=`git_show_branch_head $testroot/repo-clone foo`

	got branch -r $testroot/repo-clone bar >/dev/null
	(cd $testroot/wt && got update -b bar >/dev/null)
	echo "modified beta again on new branch bar" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "modified beta" >/dev/null)
	local commit_id4=`git_show_branch_head $testroot/repo-clone bar`

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id4" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected

	got send -a -q -r $testroot/repo-clone -b master > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo "got: -a and -b options are mutually exclusive" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -a -q -r $testroot/repo-clone > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id4" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected

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

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id4" \
		>> $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id4" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/bar: $commit_id4" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_to_empty_repo() {
	local testroot=`test_init send_to_empty_repo`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	gotadmin init $testroot/repo2

	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo2"
}
EOF
	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got send -q -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	# XXX Workaround: We cannot give the target for HEAD to 'gotadmin init'
	got ref -r $testroot/repo2 -s refs/heads/master HEAD

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo2 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo2" \
		> $testroot/stdout.expected
	echo "Already up-to-date" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo2"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_and_fetch_config() {
	local testroot=`test_init send_fetch_conf`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -r $testroot/repo -m '1.0' 1.0 >/dev/null
	tag_id=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	cp -R $testroot/repo-clone $testroot/repo-clone2
	got tag -r $testroot/repo-clone2 -m '2.0' 2.0 >/dev/null
	tag_id2=`got ref -r $testroot/repo-clone2 -l | grep "^refs/tags/2.0" \
		| tr -d ' ' | cut -d: -f2`

	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	send {
		repository "$testroot/repo-clone"
	}
	fetch {
		repository "$testroot/repo-clone2"
	}
}
EOF
	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# fetch tag 2.0 from repo-clone2
	got fetch -q -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/2.0: $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# send tag 1.0 to repo-clone
	got send -q -r $testroot/repo -t 1.0 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_config() {
	local testroot=`test_init send_config`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	branch foo
	repository "$testroot/repo-clone"
}
EOF
	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo foo

	got send -q -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_send_gitconfig() {
	local testroot=`test_init send_config`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	git init -q --bare $testroot/upstream-repo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git init failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

cat >> $testroot/repo/.git/config <<EOF
[remote "hasnourl"]
	unrelated = setting
[remote "foo"]
	url = $testurl/upstream-repo
[remote "another"]
	url = $testurl/some-other-repo
EOF

	# unset in a subshell to avoid affecting our environment
	(unset GOT_IGNORE_GITCONFIG && got send -q -r $testroot/repo foo)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/upstream-repo > $testroot/stdout

	cat > $testroot/stdout.expected <<-EOF
		HEAD: refs/heads/master
		refs/heads/master: $commit_id
		EOF

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_send_rejected() {
	local testroot=`test_init send_rejected`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	if ! got clone -q "$testurl/repo" "$testroot/repo-clone"; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	mkdir "$testroot/repo-clone/hooks"
	cat <<'EOF' >$testroot/repo-clone/hooks/update
case "$1" in
*master*)
	echo "rejecting push on master branch"
	exit 1
	;;
esac
exit 0
EOF
	chmod +x "$testroot/repo-clone/hooks/update"

	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo-clone"
}
EOF

	echo "modified alpha" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "modified alpha"

	got send -q -r "$testroot/repo" >$testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" $ret
		return 1
	fi

	touch "$testroot/stdout.expected"
	if ! cmp -s "$testroot/stdout.expected" "$testroot/stdout"; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" 1
		return 1
	fi

	cat <<EOF >$testroot/stderr.expected
rejecting push on master branch
error: hook declined to update refs/heads/master
EOF

	if ! cmp -s "$testroot/stderr.expected" "$testroot/stderr"; then
		diff -u "$testroot/stderr.expected" "$testroot/stderr"
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_send_basic_http() {
	local testroot=`test_init send_basic_http`
	local testurl=http://127.0.0.1:$GOT_TEST_HTTP_PORT
	local commit_id=`git_show_head $testroot/repo`

	timeout 20 ./http-server -p $GOT_TEST_HTTP_PORT $testroot \
	    > $testroot/http-server.log &
	trap "kill %1" HUP INT QUIT PIPE TERM

	while ! grep -q 'ready' $testroot/http-server.log; do
		sleep 1 # server starts up
	done

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cat > $testroot/repo/.git/got.conf <<EOF
remote "origin" {
	protocol http
	server 127.0.0.1
	port $GOT_TEST_HTTP_PORT
	repository "/repo-clone"
}
EOF
	got tag -r $testroot/repo -m '1.0' 1.0 >/dev/null
	tag_id=`got ref -r $testroot/repo -l | grep "^refs/tags/1.0" \
		| tr -d ' ' | cut -d: -f2`

	echo "modified alpha" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	(cd $testroot/repo && ln -s epsilon/zeta symlink)
	git -C $testroot/repo add symlink
	echo "new file alpha" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got send -q -r $testroot/repo > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send command succeeded unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	kill %1
	wait %1 # wait for http-server

	echo "got: http: feature not implemented" > $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"

}

test_send_with_unknown_ref_on_server() {
	local testroot=`test_init send_with_unknown_ref_on_server`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# Add a commit on a new branch in the source repo.
	# To trigger a known bug in 'got send', this branch reference must
	# alphabetically sort last.
	git -C $testroot/repo checkout -q -b zzz 
	echo "modified alpha" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	(cd $testroot/repo && ln -s epsilon/zeta symlink)
	git -C $testroot/repo add symlink
	echo "new file alpha" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	# This would error "got: reference refs/remotes/origin/zzz not found"
	got send -r $testroot/repo-clone > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo" \
		> $testroot/stdout.expected
	echo "Already up-to-date" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/zzz" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/zzz: $commit_id2" >> $testroot/stdout.expected

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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_send_basic			no-sha256
run_test test_send_rebase_required		no-sha256
run_test test_send_rebase_required_overwrite	no-sha256
run_test test_send_merge_commit			no-sha256
run_test test_send_delete			no-sha256
run_test test_send_clone_and_send		no-sha256
run_test test_send_tags				no-sha256
run_test test_send_tag_of_deleted_branch	no-sha256
run_test test_send_new_branch			no-sha256
run_test test_send_all_branches			no-sha256
run_test test_send_to_empty_repo		no-sha256
run_test test_send_and_fetch_config		no-sha256
run_test test_send_config			no-sha256
run_test test_send_gitconfig			no-sha256
run_test test_send_rejected			no-sha256
run_test test_send_basic_http			no-sha256
run_test test_send_with_unknown_ref_on_server	no-sha256
