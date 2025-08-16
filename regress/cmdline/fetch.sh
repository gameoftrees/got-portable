#!/bin/sh
#
# Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

test_fetch_basic() {
	local testroot=`test_init fetch_basic`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

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

	got log -l0 -p -r $testroot/repo > $testroot/log-repo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	got log -l0 -p -r $testroot/repo > $testroot/log-repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/log-repo $testroot/log-repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "log -p output of cloned repository differs" >&2
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_list() {
	local testroot=`test_init fetch_list`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo-clone && got fetch -q -l \
		> $testroot/stdout 2>$testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_branch() {
	local testroot=`test_init fetch_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q foo
	echo "modified alpha on foo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id3=`git_show_head $testroot/repo`

	# foo is now the default HEAD branch in $testroot/repo and should be
	# fetched as the clone's remote HEAD symref target no longer matches
	got fetch -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# fetch branch foo via command-line switch
	got fetch -q -r $testroot/repo-clone -b foo > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# got.conf tells us to fetch the 'master' branch by default
	got fetch -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta on foo" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified beta"
	local commit_id4=`git_show_head $testroot/repo`

	# set the default HEAD branch back to master
	git -C $testroot/repo checkout -q master

	got checkout -b foo $testroot/repo-clone $testroot/wt > /dev/null

	# fetch new commits on branch 'foo', implicitly obtaining the
	# branch name from a work tree
	(cd $testroot/wt && got fetch -q > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id4" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# remove default branch information from got.conf
	ed -s $testroot/repo-clone/got.conf <<-EOF
	g/branch {/d
	w
	EOF

	# make another change on 'foo' and fetch it without got.conf
	git -C $testroot/repo checkout -q foo
	echo "modified beta on foo agan" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified beta"
	local commit_id5=`git_show_head $testroot/repo`
	git -C $testroot/repo checkout -q master

	# fetch new commits on branch 'foo', implicitly obtaining the
	# branch name from a work tree
	(cd $testroot/wt && got fetch -q > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id3" \
		>> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id5" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_all() {
	local testroot=`test_init fetch_all`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

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

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got fetch -q -a -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	git -C $testroot/repo checkout -q foo
	echo "modified beta on foo" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified beta"
	local commit_id2=`git_show_head $testroot/repo`

	# set the default HEAD branch back to master
	git -C $testroot/repo checkout -q master

	# remove default branch from got.conf, fetch all branches
	ed -s $testroot/repo-clone/got.conf <<-EOF
	/fetch {/d
	/branch {/c
	fetch_all_branches yes
	.
	/}/d
	w
	EOF

	got fetch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	
	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_empty_packfile() {
	local testroot=`test_init fetch_empty_packfile`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -a -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_delete_branch() {
	local testroot=`test_init fetch_delete_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`


	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -a -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -d foo >/dev/null

	got fetch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -d -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	# refs/heads/foo is now deleted
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	# refs/remotes/origin/foo is now deleted
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_fetch_delete_branch_mirror() {
	local testroot=`test_init fetch_delete_branch_mirror`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -a -m -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -d foo >/dev/null

	got fetch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -d -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	# refs/heads/foo is now deleted
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_fetch_update_tag() {
	local testroot=`test_init fetch_update_tag`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`


	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -a -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got ref -r $testroot/repo -d "refs/tags/1.0"  >/dev/null
	got tag -r $testroot/repo -c $commit_id2 -m tag "1.0" >/dev/null
	local tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -a -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -r $testroot/repo-clone 2> $testroot/stderr | \
		tail -n 1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Rejecting update of existing tag refs/tags/1.0: $tag_id2" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -t -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_reference() {
	local testroot=`test_init fetch_reference`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q foo
	echo "modified alpha on foo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id3=`git_show_head $testroot/repo`
	git -C $testroot/repo checkout -q master

	got fetch -q -r $testroot/repo-clone -R refs/remotes/origin/main \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got fetch command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
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

	echo "got: refs/remotes/origin/main: reference cannot be fetched" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -R refs/hoo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo/boo/zoo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_fetch_replace_symref() {
	local testroot=`test_init fetch_replace_symref`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -m -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got ref -r $testroot/repo-clone -s refs/heads/master refs/hoo/boo/zoo

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/hoo/boo/zoo: refs/heads/master" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -r $testroot/repo-clone -R refs/hoo \
		2> $testroot/stderr | grep ^Replacing > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Replacing reference refs/hoo/boo/zoo: refs/heads/master" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/hoo/boo/zoo: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_fetch_update_headref() {
	local testroot=`test_init fetch_update_headref`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

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

	got ref -r $testroot/repo -c refs/heads/master refs/heads/foo
	got ref -r $testroot/repo -s refs/heads/foo HEAD
	got ref -l -r $testroot/repo > $testroot/stdout

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
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

	got fetch -q -r $testroot/repo-clone -a

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_headref_deleted_locally() {
	local testroot=`test_init fetch_headref_deleted_locally`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

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

	got ref -r $testroot/repo-clone -d refs/remotes/origin/HEAD > /dev/null

	got fetch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	# refs/remotes/origin/HEAD has been restored:
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_gotconfig_remote_repo() {
	local testroot=`test_init fetch_gotconfig_remote_repo`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

cat > $testroot/repo-clone/got.conf <<EOF
remote "foobar" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo"
}

remote "barbaz" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/does-not-exist"
}
EOF
	echo "got: nonexistent: remote repository not found" \
		> $testroot/stderr.expected
	(cd $testroot/repo-clone && got fetch -q nonexistent \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got fetch command succeeded unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/repo-clone && got fetch -q -l foobar \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo $testroot/wt > /dev/null

cat > $testroot/wt/.got/got.conf <<EOF
remote "barbaz" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo"
}
EOF
	(cd $testroot/wt && got fetch -q -l barbaz > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

cat > $testroot/repo-clone/got.conf <<EOF
remote "origin" {
	protocol ssh
	server 127.0.0.1
	repository "$testroot/repo"
	branch { "foo" }
	reference { "hoo/boo/zoo" }
}
EOF
	(cd $testroot/repo-clone && got fetch -q > $testroot/stdout)

	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/1.0" | tr -d ' ' | cut -d: -f2`
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo/boo/zoo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_gitconfig_remote_repo() {
	local testroot=`test_init fetch_gotconfig_remote_repo`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	make_single_file_repo $testroot/alternate-repo foo
	local alt_commit_id=`git_show_head $testroot/alternate-repo`

cat >> $testroot/repo/.git/config <<EOF
[remote "hasnourl"]
	unrelated = setting
[remote "alt"]
	url = $testurl/alternate-repo
[remote "another"]
	url = $testurl/some-other-repo
EOF

	# unset in a subshell to avoid affecting our environment
	(unset GOT_IGNORE_GITCONFIG && cd $testroot/repo && got fetch -q alt)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout

	cat > $testroot/stdout.expected <<-EOF
		HEAD: refs/heads/master
		refs/heads/master: $commit_id
		refs/remotes/alt/HEAD: refs/remotes/alt/master
		refs/remotes/alt/master: $alt_commit_id
		EOF

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_delete_remote_refs() {
	local testroot=`test_init fetch_delete_remote_refs`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
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

	got fetch -q -r $testroot/repo-clone -X > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got fetch command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: -X option requires a remote name" > $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -X origin > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "Deleted refs/remotes/origin/HEAD: " > $testroot/stdout.expected
	echo "refs/remotes/origin/master" >> $testroot/stdout.expected
	echo "Deleted refs/remotes/origin/master: $commit_id" \
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_honor_wt_conf_bflag() {
	local testroot=`test_init fetch_honor_wt_conf_bflag`
	local testurl=ssh://127.0.0.1/$testroot

	# server will have 'boo', 'hoo', and 'master'
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id boo
	git -C $testroot/repo checkout -q boo
	echo "modified beta on boo" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified beta"
	local commit_id2=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id2 hoo
	git -C $testroot/repo checkout -q hoo
	echo "modified delta on hoo" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "modified delta"
	local commit_id3=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# only clone will have foo and bar
	got branch -r $testroot/repo-clone -c $commit_id foo
	got branch -r $testroot/repo-clone -c $commit_id bar

	got fetch -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
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

	git -C $testroot/repo checkout -q boo
	# clone has remote/origin/HEAD symref with "master" as its target
	# but the repo has changed HEAD to "boo", so we should fetch "boo"
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/boo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	got fetch -q -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# from repo: fetch -b hoo
	got fetch -q -r $testroot/repo-clone -b hoo > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/hoo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/boo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo: $commit_id3" \
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

	# from repo: fetch -b foo which doesn't exist on the server but
	# do not fallback to repo HEAD "boo" because we used the -b flag
	got fetch -r $testroot/repo-clone -b foo > $testroot/stdout \
	    2> $testroot/stderr

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo" \
	    > $testroot/stdout.expected
	echo "got-fetch-pack: branch \"foo\" not found on server" \
	    > $testroot/stderr.expected
	echo "got: could not find any branches to fetch" \
	    >> $testroot/stderr.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# from repo: fetch got.conf branch which doesn't exist, so fallback
	# to repo HEAD "boo"
	# change default branch in got.conf from "master" to "foo"
	ed -s $testroot/repo-clone/got.conf <<-EOF
	,s/master/foo/
	w
	EOF

	got fetch -q -r $testroot/repo-clone > $testroot/stdout
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/hoo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/boo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo: $commit_id3" \
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

	# from wt: fetch got.conf "foo", which doesn't exist on the server,
	# and implicit wt branch "boo", not repo HEAD "master"
	echo "modified delta on boo" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "modified delta"
	local commit_id4=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master

	got checkout -b boo $testroot/repo-clone $testroot/wt > /dev/null
	(cd $testroot/wt && got fetch -q > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/hoo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id4" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo: $commit_id3" \
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

	# from wt: fetch got.conf "master", wt "boo", and the repo's new HEAD
	# "hoo" as it no longer matches our remote HEAD symref target "master"
	ed -s $testroot/repo-clone/got.conf <<-EOF
	,s/foo/master/
	w
	EOF
	echo "modified delta on master" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "modified delta on master"
	local commit_id5=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q boo
	echo "modified alpha on boo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on boo"
	local commit_id6=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q hoo
	echo "modified beta on hoo" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified beta on hoo"
	local commit_id7=`git_show_head $testroot/repo`

	(cd $testroot/wt && got fetch -q > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/hoo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/hoo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id6" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo: $commit_id7" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id5" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# from wt: fetch -b hoo not got.conf "master" or wt "boo" or
	# repo HEAD "boo"
	git -C $testroot/repo checkout -q boo
	echo "modified alpha again on boo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha again on boo"
	local commit_id8=`git_show_head $testroot/repo`

	(cd $testroot/wt && got fetch -q -b hoo > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/got/worktree/base-$wt_uuid: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/boo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/hoo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/boo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/boo: $commit_id6" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo: $commit_id7" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id5" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# from wt: fetch -b bar that doesn't exist on the server but
	# do not fetch got.conf "master" or wt "boo" or repo HEAD "boo"
	(cd $testroot/wt && got fetch -b bar > $testroot/stdout \
	    2> $testroot/stderr)

	echo "Connecting to \"origin\" ssh://127.0.0.1$testroot/repo" \
	    > $testroot/stdout.expected
	echo "got-fetch-pack: branch \"bar\" not found on server" \
	    > $testroot/stderr.expected
	echo "got: could not find any branches to fetch" \
	    >> $testroot/stderr.expected

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_fetch_from_out_of_date_remote() {
	local testroot=`test_init fetch_from_out_of_date_remote`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone2 \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone2 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/master
refs/heads/master: $commit_id2
refs/remotes/origin/HEAD: refs/remotes/origin/master
refs/remotes/origin/master: $commit_id2
EOF
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat >> $testroot/repo-clone2/got.conf <<EOF
remote "other" {
	server "127.0.0.1"
	protocol ssh
	repository "$testroot/repo-clone"
	branch { "master" }
}
EOF
	got fetch -q -r $testroot/repo-clone2 other \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone2 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/master
refs/heads/master: $commit_id2
refs/remotes/origin/HEAD: refs/remotes/origin/master
refs/remotes/origin/master: $commit_id2
refs/remotes/other/HEAD: refs/remotes/other/master
refs/remotes/other/master: $commit_id
EOF
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_fetch_basic_http() {
	local testroot=`test_init fetch_basic_http`
	local testurl=http://127.0.0.1:$GOT_TEST_HTTP_PORT
	local commit_id=`git_show_head $testroot/repo`

	timeout 20 ./http-server -p $GOT_TEST_HTTP_PORT $testroot \
	    > $testroot/http-server.log &

	sleep 1 # server starts up
	for i in 1 2 3 4; do
		if grep -q ': ready' $testroot/http-server.log; then
			break
		fi
		if [ $i -eq 4 ]; then
			echo "http-server startup timeout" >&2
			test_done "$testroot" "1"
			# timeout(1) will kill the server eventually
			return 1
		fi
		sleep 1 # server is still starting up
	done

	http_pid=`head -n 1 $testroot/http-server.log | cut -d ':' -f1`
	trap "kill -9 $http_pid; wait $http_pid" HUP INT QUIT PIPE TERM

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	kill $http_pid
	wait $http_pid

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got log -l0 -p -r $testroot/repo > $testroot/log-repo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	got log -l0 -p -r $testroot/repo > $testroot/log-repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/log-repo $testroot/log-repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "log -p output of cloned repository differs" >&2
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

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_fetch_basic			no-sha256
run_test test_fetch_list			no-sha256
run_test test_fetch_branch			no-sha256
run_test test_fetch_all				no-sha256
run_test test_fetch_empty_packfile		no-sha256
run_test test_fetch_delete_branch		no-sha256
run_test test_fetch_delete_branch_mirror	no-sha256
run_test test_fetch_update_tag			no-sha256
run_test test_fetch_reference			no-sha256
run_test test_fetch_replace_symref		no-sha256
run_test test_fetch_update_headref		no-sha256
run_test test_fetch_headref_deleted_locally	no-sha256
run_test test_fetch_gotconfig_remote_repo	no-sha256
run_test test_fetch_gitconfig_remote_repo	no-sha256
run_test test_fetch_delete_remote_refs		no-sha256
run_test test_fetch_honor_wt_conf_bflag		no-sha256
run_test test_fetch_from_out_of_date_remote	no-sha256
run_test test_fetch_basic_http			no-sha256
