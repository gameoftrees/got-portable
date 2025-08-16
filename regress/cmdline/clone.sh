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

test_clone_basic() {
	local testroot=`test_init clone_basic`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
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
	got log -l0 -p -r $testroot/repo-clone | \
		sed 's@master, origin/master@master@g' \
		> $testroot/log-repo-clone

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
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "master" }
	}
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/master:refs/remotes/origin/master
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_quoting() {
	local testroot=`test_init clone_basic`

	got log -l0 -p -r "$testroot/repo" > $testroot/log-repo

	(cd "$testroot" && cp -R repo "rock'n roll.git")

	got clone -q "ssh://127.0.0.1/$testroot/rock'n roll.git" \
		"$testroot/rock-clone"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got log -l0 -p -r "$testroot/rock-clone" | \
		sed 's@master, origin/master@master@g' \
		>$testroot/log-repo-clone

	cmp -s "$testroot/log-repo" "$testroot/log-repo-clone"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "log -p output of cloned repository differs" >&2
		diff -u "$testroot/log-repo" "$testroot/log-repo-clone"
		test_done "$testroot" "$ret"
	fi
	test_done "$testroot" "$ret"
}

test_clone_list() {
	local testroot=`test_init clone_list`
	local testurl=ssh://127.0.0.1$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null

	got clone -l $testurl/repo > $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connecting to $testurl/repo" > $testroot/stdout.expected
	got ref -l -r $testroot/repo >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_clone_branch() {
	local testroot=`test_init clone_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -b foo $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	# refs/heads/master is missing because it wasn't passed via -b
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "foo" }
	}
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/foo:refs/remotes/origin/foo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_all() {
	local testroot=`test_init clone_all`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -a $testurl/repo $testroot/repo-clone
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

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch_all_branches yes
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/*:refs/remotes/origin/*
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_mirror() {
	local testroot=`test_init clone_mirror`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -m $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	# refs/heads/foo is missing because we're not fetching all branches
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

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "master" }
	}
	mirror_references yes
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/master:refs/heads/master
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_mirror_all() {
	local testroot=`test_init clone_mirror_all`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -m -a $testurl/repo $testroot/repo-clone
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

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	mirror_references yes
	fetch_all_branches yes
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/*:refs/heads/*
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_reference() {
	local testroot=`test_init clone_reference`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -R hoo $testurl/repo $testroot/repo-clone
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
	echo "refs/remotes/origin/hoo/boo/zoo: $commit_id" \
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

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "master" }
	}
	reference { "hoo" }
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/master:refs/remotes/origin/master
	fetch = refs/hoo:refs/remotes/origin/hoo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_branch_and_reference() {
	local testroot=`test_init clone_reference`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -R hoo/boo/zoo -b foo $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo/boo/zoo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "foo" }
	}
	reference { "hoo/boo/zoo" }
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/foo:refs/remotes/origin/foo
	fetch = refs/hoo/boo/zoo:refs/remotes/origin/hoo/boo/zoo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_reference_mirror() {
	local testroot=`test_init clone_reference_mirror`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q -R hoo -m $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/hoo/boo/zoo: $commit_id" >> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "master" }
	}
	reference { "hoo" }
	mirror_references yes
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/master:refs/heads/master
	fetch = refs/hoo:refs/hoo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_multiple_branches() {
	local testroot=`test_init clone_multiple_branches`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got branch -r $testroot/repo -c $commit_id bar

	got clone -q -b foo -b bar $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/bar" > $testroot/stdout.expected
	echo "refs/heads/bar: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/bar: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "bar" "foo" }
	}
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/bar:refs/remotes/origin/bar
	fetch = refs/heads/foo:refs/remotes/origin/foo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_dangling_headref() {
	local testroot=`test_init clone_dangling_headref`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -d master > /dev/null
	got branch -r $testroot/repo -c $commit_id foo

	got ref -l -r $testroot/repo > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	# refs/heads/master is missing because it was deleted above

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got clone -q -b foo $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol ssh
	repository "$testroot/repo"
	fetch {
		branch { "foo" }
	}
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = ssh://127.0.0.1$testroot/repo
	fetch = refs/heads/foo:refs/remotes/origin/foo
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_clone_basic_http() {
	local testroot=`test_init clone_basic_http`
	local testurl=http://127.0.0.1:${GOT_TEST_HTTP_PORT}
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

	# Test our custom HTTP server with git clone. Should succeed.
	git clone -q $testurl/repo $testroot/repo-clone-with-git
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# Test got clone with our custom HTTP server.
	got clone -q $testurl/repo $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	kill $http_pid
	wait $http_pid

	got log -l0 -p -r $testroot/repo > $testroot/log-repo
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	got log -l0 -p -r $testroot/repo-clone | \
		sed 's@master, origin/master@master@g' \
		> $testroot/log-repo-clone

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
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/got.conf.expected <<EOF
remote "origin" {
	server 127.0.0.1
	protocol http
	port $GOT_TEST_HTTP_PORT
	repository "/repo"
	fetch {
		branch { "master" }
	}
}
EOF
	cmp -s $testroot/repo-clone/got.conf $testroot/got.conf.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/got.conf.expected \
			$testroot/repo-clone/got.conf
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/config.expected <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true

[remote "origin"]
	url = $testurl/repo
	fetch = refs/heads/master:refs/remotes/origin/master
	fetch = refs/tags/*:refs/tags/*
EOF
	cmp -s $testroot/repo-clone/config $testroot/config.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/config.expected \
			$testroot/repo-clone/config
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_clone_basic			no-sha256
run_test test_clone_quoting			no-sha256
run_test test_clone_list			no-sha256
run_test test_clone_branch			no-sha256
run_test test_clone_all				no-sha256
run_test test_clone_mirror			no-sha256
run_test test_clone_mirror_all			no-sha256
run_test test_clone_reference			no-sha256
run_test test_clone_branch_and_reference	no-sha256
run_test test_clone_reference_mirror		no-sha256
run_test test_clone_multiple_branches		no-sha256
run_test test_clone_dangling_headref		no-sha256
run_test test_clone_basic_http			no-sha256
