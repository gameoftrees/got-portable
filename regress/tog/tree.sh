#!/bin/sh
#
# Copyright (c) 2023 Mark Jamsek <mark@jamsek.dev>
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

test_tree_basic()
{
	test_init tree_basic 48 8

	local head_id=`git_show_head $testroot/repo`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 48 "commit $head_id")
[1/4] /

  alpha
  beta
  epsilon/
  gamma/

EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tree_vsplit_blame()
{
	test_init tree_vsplit_blame 120 8

	local head_id=`git_show_head $testroot/repo`
	local head_id_truncated=`trim_obj_id 32 $head_id`
	local head_id_short=`trim_obj_id 8 $head_id`

	cat <<EOF >$TOG_TEST_SCRIPT
KEY_ENTER
WAIT_FOR_UI	wait for blame to finish
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $head_id_truncated|commit $head_id
[1/4] /                                |[1/1] /alpha
                                       |$head_id_short alpha
  alpha                                |
  beta                                 |
  epsilon/                             |
  gamma/                               |
                                       |
EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tree_hsplit_blame()
{
	test_init tree_hsplit_blame 48 24

	local head_id=`git_show_head $testroot/repo`
	local head_id_truncated=`trim_obj_id 32 $head_id`
	local head_id_short=`trim_obj_id 8 $head_id`

	cat <<EOF >$TOG_TEST_SCRIPT
j
KEY_ENTER
S		toggle horizontal split
4-		4x decrease blame split
WAIT_FOR_UI	wait for blame to finish
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 48 "commit $head_id")
[2/4] /

  alpha
  beta
  epsilon/
  gamma/



------------------------------------------------
$(trim 48 "commit $head_id")
[1/1] /beta
$head_id_short beta










EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tree_symlink()
{
	test_init tree_symlink 48 8

	(cd $testroot/repo && ln -s alpha symlink)
	(cd $testroot/repo && git add symlink)
	git_commit $testroot/repo -m "symlink to alpha"
	local head_id=`git_show_head $testroot/repo`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 48 "commit $head_id")
[1/5] /

  alpha
  beta
  epsilon/
  gamma/
  symlink@ -> alpha
EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tree_commit_keywords()
{
	test_init tree_commit_keywords 48 11
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id=$(git_show_head "$repo")

	set -- "$id"

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# move into the work tree (test is run in a subshell)
	cd "$wt"

	for i in $(seq 8); do
		if [ $(( i % 2 )) -eq 0 ]; then
			echo "file${i}" > "file${i}"
			got add "file${i}" > /dev/null
		else
			echo "alpha $i" > alpha
		fi

		got ci -m "commit $i" > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		id=$(git_show_head "$repo")
		set -- "$@" "$id"
	done


	cat <<-EOF >$TOG_TEST_SCRIPT
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 48 "commit $(pop_idx 8 $@)")
	[1/7] /

	  alpha
	  beta
	  epsilon/
	  file2
	  file4
	  file6
	  gamma/

	EOF

	tog tree -c:base:-
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	$(trim 48 "commit $(pop_idx 6 $@)")
	[1/6] /

	  alpha
	  beta
	  epsilon/
	  file2
	  file4
	  gamma/


	EOF

	tog tree -cmaster:-3
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	$(trim 48 "commit $(pop_idx 9 $@)")
	[1/8] /

	  alpha
	  beta
	  epsilon/
	  file2
	  file4
	  file6
	  file8
	  gamma/
	EOF

	got up -c:head:-99 > /dev/null
	tog tree -c:base:+99
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	$(trim 48 "commit $(pop_idx 4 $@)")
	[1/5] /

	  alpha
	  beta
	  epsilon/
	  file2
	  gamma/



	EOF

	tog tree -c:head:-5
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	$(trim 48 "commit $(pop_idx 1 $@)")
	[1/4] /

	  alpha
	  beta
	  epsilon/
	  gamma/




	EOF

	tog tree -r "$repo" -cmaster:-99
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_tree_insufficient_height()
{
	test_init tree_insufficient_height 120 3

	local id=$(git_show_head $testroot/repo)

	# Cover the path that guards a NULL dereference when scrolling
	# down in a tree view too small to display any tree entries.
	cat <<-EOF >$TOG_TEST_SCRIPT
	j		attempt to scroll down
	f
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $id
	[1/4] /

	EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tree_empty()
{
	test_init tree_empty 48 8

	(
	cd $testroot/repo

	blob="$(echo -n '' | git hash-object -w --stdin)"
	tree="$(echo -n '' | git hash-object -w -t tree --stdin --literally)"

	commit="$(echo cursed | git commit-tree "$tree")"
	git update-ref refs/heads/main "$commit"
	git symbolic-ref HEAD refs/heads/main
	)

	local head_id=`git_show_head $testroot/repo`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 48 "commit $head_id")
[1/0] /






EOF

	cd $testroot/repo && tog tree
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_tree_basic
run_test test_tree_vsplit_blame
run_test test_tree_hsplit_blame
run_test test_tree_symlink
run_test test_tree_commit_keywords
run_test test_tree_insufficient_height
run_test test_tree_empty
