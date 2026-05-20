#!/bin/sh
#
# Copyright (c) 2024 Kyle Ackerman <kack@kyleackerman.net>
# Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

export MEM_CHECK=1

. ./common.sh

test_memleak_add_basic() {
	local testroot=`test_init memleak_add_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo

	echo 'A  foo' > $testroot/stdout.expected
	(cd $testroot/wt && $(check_memleak $testroot) \
		got add foo > $testroot/stdout)

	test_memleak_done "$testroot" "$ret"
}

test_memleak_send_basic() {
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

	$(check_memleak $testroot) got send -q -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	test_memleak_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_memleak_add_basic
run_test test_memleak_send_basic
