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

test_log_hsplit_diff()
{
	test_init log_hsplit_diff

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`

	cat <<EOF >$TOG_TEST_SCRIPT
KEY_ENTER	open diff view of selected commit
S		toggle horizontal split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "commit $head_id [1/1] master")
$ymd flan_hacker  [master] adding the test tree




--------------------------------------------------------------------------------
$(trim 80 "[1/40] diff /dev/null $head_id")
commit $head_id (master)
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date

 adding the test tree

A  alpha         |  1+  0-
A  beta          |  1+  0-
A  epsilon/zeta  |  1+  0-
A  gamma/delta   |  1+  0-

4 files changed, 4 insertions(+), 0 deletions(-)

commit - /dev/null
commit + $head_id
blob - /dev/null
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_vsplit_diff()
{
	# make screen wide enough for vsplit
	test_init log_vsplit_diff 142

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`
	local blobid_alpha=`get_blob_id $testroot/repo "" alpha`
	local blobid_beta=`get_blob_id $testroot/repo "" beta`

	cat <<EOF >$TOG_TEST_SCRIPT
KEY_ENTER	open diff view of selected commit in vertical split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 61 "commit $head_id [1/1] master ")|$(trim 80 "[1/40] diff /dev/null $head_id")
$ymd flan_hacker  [master] adding the test tree        |commit $head_id (master)
                                                             |from: Flan Hacker <flan_hacker@openbsd.org>
                                                             |date: $date
                                                             |
                                                             | adding the test tree
                                                             |
                                                             |A  alpha         |  1+  0-
                                                             |A  beta          |  1+  0-
                                                             |A  epsilon/zeta  |  1+  0-
                                                             |A  gamma/delta   |  1+  0-
                                                             |
                                                             |4 files changed, 4 insertions(+), 0 deletions(-)
                                                             |
                                                             |commit - /dev/null
                                                             |commit + $head_id
                                                             |blob - /dev/null
                                                             |$(trim 80 "blob + $blobid_alpha (mode 644)")
                                                             |--- /dev/null
                                                             |+++ alpha
                                                             |@@ -0,0 +1 @@
                                                             |+alpha
                                                             |blob - /dev/null
                                                             |$(trim 80 "blob + $blobid_beta (mode 644)")
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_show_author()
{
	# make view wide enough to show id
	test_init log_show_author 120 4

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`
	local head_id_len8=`trim_obj_id 8 $head_id`

	echo "mod alpha" > $testroot/repo/alpha
	cd $testroot/repo && git add .
	cd $testroot/repo && \
	    git commit --author "Johnny Cash <john@cash.net>" -m author > \
	    /dev/null

	local commit1=`git_show_head $testroot/repo`
	local id1_len8=`trim_obj_id 8 $commit1`

	cat <<EOF >$TOG_TEST_SCRIPT
@		toggle show author
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $commit1 [1/2] master
$ymd $id1_len8 john         [master] author
$ymd $head_id_len8 flan_hacker  adding the test tree
:show commit author
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_scroll_right()
{
	test_init log_scroll_right 80 3

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`
	local msg="scroll this log message to the right four characters"
	local scrolled_msg="ter] scroll this log message to the right four character"

	echo "mod alpha" > $testroot/repo/alpha
	cd $testroot/repo && git add . && git commit -m "$msg" > /dev/null

	local commit1=`git_show_head $testroot/repo`

	cat <<EOF >$TOG_TEST_SCRIPT
l		scroll right
l		scroll right
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "commit $commit1 [1/2] master")
$ymd flan_hacker  $scrolled_msg
$ymd flan_hacker  ng the test tree
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_hsplit_ref()
{
	test_init log_hsplit_ref 80 10

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`

	cat <<EOF >$TOG_TEST_SCRIPT
R		open ref view
S		toggle horizontal split
-		reduce size of ref view split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "commit $head_id [1/1] master")
$ymd flan_hacker  [master] adding the test tree

--------------------------------------------------------------------------------
references [1/2]
HEAD -> refs/heads/master
refs/heads/master



EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_hsplit_tree()
{
	test_init log_hsplit_tree 80 10

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%F"`

	cat <<EOF >$TOG_TEST_SCRIPT
T		open tree view
S		toggle horizontal split
j		move selection cursor down one entry to "beta"
-		reduce size of tree view split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "commit $head_id [1/1] master")
$ymd flan_hacker  [master] adding the test tree

--------------------------------------------------------------------------------
commit $head_id
[2/4] /

  alpha
  beta
  epsilon/
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# test T keymap on a work tree entry
	got checkout "$testroot/repo" "$testroot/wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cd "$testroot/wt"
	echo "'alpha" >> alpha

	local id10=$(trim_obj_id 10 $head_id)

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to fetch wt state
	T		open tree view
	S		toggle horizontal split
	SCREENDUMP
	EOF

	cat <<EOF >$testroot/view.expected
diff $testroot/wt (work tree changes) [0/1] maste
$ymd flan_hacker  work tree changes based on [$id10]
--------------------------------------------------------------------------------
commit $head_id
[1/4] /

  alpha
  beta
  epsilon/
  gamma/
EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_logmsg_widechar()
{
	# make view wide enough to fit logmsg line length
	# but short enough so long diff lines are truncated
	test_init log_logmsg_widechar 182 30
	widechar_commit $testroot/repo

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local commit1=`git_show_parent_commit $testroot/repo`
	local blobid=`get_blob_id $testroot/repo "" $(widechar_filename)`

	cat <<EOF >$TOG_TEST_SCRIPT
KEY_ENTER	open selected commit in diff view
F		toggle fullscreen
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
[1/25] diff $commit1 $head_id
commit $head_id (master)
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date

 $(widechar_logmsg1)
$(echo)
 $(widechar_logmsg2)

A  $(widechar_filename)  |  5+  0-

1 file changed, 5 insertions(+), 0 deletions(-)

commit - $commit1
commit + $head_id
blob - /dev/null
blob + $blobid (mode 644)
--- /dev/null
+++ $(widechar_filename)
@@ -0,0 +1,5 @@
+ウィリアム・ユワート・グラッドストン（英語: William Ewart Gladstone PC FRS FSS、1809年12月29日 - 1898年5月19日）は、イギリスの政治家。
+
+ヴィクトリア朝中期から後期にかけて、自由党を指導して、4度にわたり首相を務めた。
+
+生涯を通じて敬虔なイングランド国教会の信徒であり、キリスト教の精神を政治に反映させることを目指した。多くの自由主義改革を行い、帝国主義にも批判的であった。好敵手である保守党党首ベン




(END)
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_commit_keywords()
{
	test_init log_commit_keywords 120 10
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id=$(git_show_head "$repo")
	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r $author_time +"%F")

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
	echo -n > alpha

	for i in $(seq 8); do
		echo "alpha $i" >> alpha

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
	WAIT_FOR_UI	wait for log thread to finish
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 5 $@) [1/5]
	$ymd $(trim_obj_id 8 $(pop_idx 5 $@)) flan_hacker  commit 4
	$ymd $(trim_obj_id 8 $(pop_idx 4 $@)) flan_hacker  commit 3
	$ymd $(trim_obj_id 8 $(pop_idx 3 $@)) flan_hacker  commit 2
	$ymd $(trim_obj_id 8 $(pop_idx 2 $@)) flan_hacker  commit 1
	$ymd $(trim_obj_id 8 $(pop_idx 1 $@)) flan_hacker  adding the test tree




	EOF

	tog log -c:base:-4
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 7 $@) [1/7]
	$ymd $(trim_obj_id 8 $(pop_idx 7 $@)) flan_hacker  commit 6
	$ymd $(trim_obj_id 8 $(pop_idx 6 $@)) flan_hacker  commit 5
	$ymd $(trim_obj_id 8 $(pop_idx 5 $@)) flan_hacker  commit 4
	$ymd $(trim_obj_id 8 $(pop_idx 4 $@)) flan_hacker  commit 3
	$ymd $(trim_obj_id 8 $(pop_idx 3 $@)) flan_hacker  commit 2
	$ymd $(trim_obj_id 8 $(pop_idx 2 $@)) flan_hacker  commit 1
	$ymd $(trim_obj_id 8 $(pop_idx 1 $@)) flan_hacker  adding the test tree


	EOF

	tog log -r "$repo" -c:head:-2
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 5 $@) [1/5]
	$ymd $(trim_obj_id 8 $(pop_idx 5 $@)) flan_hacker  commit 4
	$ymd $(trim_obj_id 8 $(pop_idx 4 $@)) flan_hacker  commit 3
	$ymd $(trim_obj_id 8 $(pop_idx 3 $@)) flan_hacker ~commit 2
	$ymd $(trim_obj_id 8 $(pop_idx 2 $@)) flan_hacker  commit 1
	$ymd $(trim_obj_id 8 $(pop_idx 1 $@)) flan_hacker  adding the test tree




	EOF

	got up -c:base:-6 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	tog log -c:base:+2
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 1 $@) [1/1]
	$ymd $(trim_obj_id 8 $(pop_idx 1 $@)) flan_hacker  adding the test tree








	EOF

	tog log -c:base:-99
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_show_base_commit()
{
	# make view wide enough to show full headline
	test_init log_show_base_commit 80 4
	local repo="$testroot/repo"
	local id=$(git_show_head "$repo")

	echo "alpha" >> "$repo/alpha"
	git_commit "$repo" -m "base commit"

	got checkout "$repo" "$testroot/wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# move into the work tree (test is run in a subshell)
	cd "$testroot/wt"

	local head_id=$(git_show_head "$repo")
	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r "$author_time" +"%F")

	# check up-to-date base commit marker prefixes base commit log message
	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to finish
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $head_id [1/2] master")
	$ymd flan_hacker *[master] base commit
	$ymd flan_hacker  adding the test tree

	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# check marker is not drawn when not in a work tree
	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $head_id [1/2] master")
	$ymd flan_hacker  [master] base commit
	$ymd flan_hacker  adding the test tree

	EOF

	tog log -r "$repo"
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# check out-of-date marker is shown with a mixed-commit tree
	echo "mixed" > alpha
	got commit -m "new base mixed-commit" > /dev/null
	head_id=$(git_show_head "$repo")

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to finish
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $head_id [1/3] master")
	$ymd flan_hacker ~[master] new base mixed-commit
	$ymd flan_hacker  base commit
	$ymd flan_hacker  adding the test tree
	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# check marker is not incorrectly drawn when opening a nested log view
	cat <<-EOF >$TOG_TEST_SCRIPT
	T		# open tree view of base commit
	j		# select beta tree entry
	L		# load log view of commits involving beta
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $id /beta [1/1]")
	$ymd flan_hacker  adding the test tree


	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_limit_view()
{
	test_init log_limit_view 80 4
	local repo="$testroot/repo"
	local wt="$testroot/wt"

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cd "$wt"

	echo "alpha0" > alpha
	got commit -m alpha0 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "beta0" > beta
	got commit -m beta0 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha1" > alpha
	got commit -m alpha1 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "beta1" > beta
	got commit -m beta1 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r $author_time +"%F")
	local id=$(git_show_head "$repo")

	# check base commit marker is not drawn
	cat <<-EOF >$TOG_TEST_SCRIPT
	&beta
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $id [1/2] master")
	$ymd flan_hacker  [master] beta1
	$ymd flan_hacker  beta0

	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
	fi
	test_done "$testroot" "$ret"
}

test_log_search()
{
	test_init log_search 80 8
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

	cd "$wt"

	for i in $(seq 16); do
		echo "alpha $i" > alpha

		got ci -m "alpha commit $i" > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		id=$(git_show_head "$repo")
		set -- "$@" "$id"
	done

	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r $author_time +"%F")

	cat <<-EOF >$TOG_TEST_SCRIPT
	/alpha commit 8
	n
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	$(trim 80 "commit $(pop_idx 9 $@) [9/17] no more matches")
	$ymd flan_hacker  alpha commit 14
	$ymd flan_hacker  alpha commit 13
	$ymd flan_hacker  alpha commit 12
	$ymd flan_hacker  alpha commit 11
	$ymd flan_hacker  alpha commit 10
	$ymd flan_hacker  alpha commit 9
	$ymd flan_hacker  alpha commit 8
	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
	fi
	test_done "$testroot" "$ret"
}

test_log_mark_keymap()
{
	test_init log_mark_keymap 141 14

	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id_root=$(git_show_head $repo)
	local prefix_root=$(trim_obj_id 8 $id_root)
	local author_time=$(git_show_author_time $repo)
	local ymd_root=$(date -u -r $author_time +"%F")
	local alpha_root=$(get_blob_id $testroot/repo "" alpha)

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cd "$wt"

	echo "new alpha" > alpha
	got commit -m "new alpha" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" $ret
		return 1
	fi

	author_time=$(git_show_author_time $repo)
	local ymd_head=$(date -u -r $author_time +"%F")
	local id_head=$(git_show_head $repo)
	local prefix_head=$(trim_obj_id 8 $id_head)
	local alpha_head=$(get_blob_id $testroot/repo "" alpha)

	# test marker is correctly applied to arbitrary commit
	cat <<-EOF >$TOG_TEST_SCRIPT
	j
	m		mark commit
	WAIT_FOR_UI
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $id_root [2/2]
	$ymd_head $prefix_head flan_hacker ~[master] new alpha
	$ymd_root $prefix_root flan_hacker >adding the test tree











	EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" $ret
		return 1
	fi

	# test commit is correctly unmarked
	cat <<-EOF >$TOG_TEST_SCRIPT
	j
	m		mark commit
	m		unmark commit
	WAIT_FOR_UI
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $id_root [2/2]
	$ymd_head $prefix_head flan_hacker ~[master] new alpha
	$ymd_root $prefix_root flan_hacker  adding the test tree











	EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" $ret
		return 1
	fi

	# test marker correctly overwrites base commit marker
	cat <<-EOF >$TOG_TEST_SCRIPT
	m		mark commit
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $id_head [1/2] master
	$ymd_head $prefix_head flan_hacker >[master] new alpha
	$ymd_root $prefix_root flan_hacker  adding the test tree











	EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" $ret
		return 1
	fi

	# test diff of marked and selected commit is correctly rendered
	cat <<-EOF >$TOG_TEST_SCRIPT
	m		mark commit
	j
	KEY_ENTER	show diff of marked and root commit
	F		toggle fullscreen
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	[1/14] diff $id_head $id_root
	M  alpha  |  1+  1-

	1 file changed, 1 insertion(+), 1 deletion(-)

	commit - $id_head
	commit + $id_root
	blob - $alpha_head
	blob + $alpha_root
	--- alpha
	+++ alpha
	@@ -1 +1 @@
	-new alpha
	+alpha
	EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" $ret
		return 1
	fi

	test_done "$testroot" $ret
}

test_log_worktree_entries()
{
	test_init log_worktree_entries 96 4
	local repo="$testroot/repo"

	got checkout "$repo" "$testroot/wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# test dirty work tree (no staged changes)
	cd "$testroot/wt"
	echo "'alpha" >> alpha

	local id=$(git_show_head "$repo")
	local id10=$(trim_obj_id 10 $id)
	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r "$author_time" +"%F")

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to fetch wt state
	WAIT_FOR_UI	trigger redraw to reveal work tree entries
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	diff $testroot/wt (work tree changes) [0/1] master
	$ymd flan_hacker  work tree changes based on [$id10]
	$ymd flan_hacker *[master] adding the test tree

	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# test dirty work tree with staged changes too
	echo "'beta" >> beta
	got stage beta > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to fetch wt state
	j		select staged entry
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	diff -s $testroot/wt (staged work tree changes) [0/1] master
	$ymd flan_hacker  work tree changes based on [$id10]
	$ymd flan_hacker  staged work tree changes based on [$id10]
	$ymd flan_hacker *[master] adding the test tree
	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# test with only staged changes
	got revert alpha > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for log thread to fetch wt state
	WAIT_FOR_UI	trigger redraw to reveal work tree entries
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	diff -s $testroot/wt (staged work tree changes) [0/1] master
	$ymd flan_hacker  staged work tree changes based on [$id10]
	$ymd flan_hacker *[master] adding the test tree

	EOF

	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# test with no author set
	echo "'alpha" >> alpha

	cat <<-EOF >$testroot/view.expected
	diff $testroot/wt (work tree changes) [0/1] master
	$ymd              work tree changes based on [$id10]
	$ymd              staged work tree changes based on [$id10]
	$ymd flan_hacker *[master] adding the test tree
	EOF

	unset GOT_AUTHOR
	tog log
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" 0
}

test_log_tiny_child_tree_view()
{
	test_init log_tiny_child_tree_view 120 3

	local id=$(git_show_head $testroot/repo)

	# This test covers the offset_selection_down() path ensuring
	# indexes are properly clamped to prevent negative values.
	cat <<-EOF >$TOG_TEST_SCRIPT
	T		open tree view in vsplit
	F		toggle fullscreen to hit offset_selection_down()
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	commit $id
	[1/4] /

	EOF

	cd $testroot/repo && tog log
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
run_test test_log_hsplit_diff
run_test test_log_vsplit_diff
run_test test_log_show_author
run_test test_log_scroll_right
run_test test_log_hsplit_ref
run_test test_log_hsplit_tree
run_test test_log_logmsg_widechar
run_test test_log_commit_keywords
run_test test_log_show_base_commit
run_test test_log_limit_view
run_test test_log_search
run_test test_log_mark_keymap
run_test test_log_worktree_entries
run_test test_log_tiny_child_tree_view
