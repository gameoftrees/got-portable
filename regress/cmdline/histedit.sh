#!/bin/sh
#
# Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

test_histedit_no_op() {
	local testroot=`test_init histedit_no_op`

	local orig_commit=`git_show_head $testroot/repo`
	local orig_author_time=`git_show_author_time $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`
	local old_author_time1=`git_show_author_time $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`
	local old_author_time2=`git_show_author_time $testroot/repo`

	got diff -r $testroot/repo $orig_commit $old_commit2 \
		> $testroot/diff.expected

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "pick $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`
	local new_author_time2=`git_show_author_time $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "$short_old_commit1 -> $short_new_commit1: committing changes" \
		>> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 -> $short_new_commit2: " \
		>> $testroot/stdout.expected
	echo "committing to zeta on master" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $orig_commit $new_commit2 \
		> $testroot/diff
	ed -s $testroot/diff.expected <<-EOF
	,s/$old_commit2/$new_commit2/
	w
	EOF
	cmp -s $testroot/diff.expected $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/diff.expected $testroot/diff
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)

	echo 'Already up-to-date' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should have a backup of old commits
	(cd $testroot/repo && got histedit -l > $testroot/stdout)
	d_orig1=`date -u -r $old_author_time1 +"%F"`
	d_orig2=`date -u -r $old_author_time2 +"%a %b %e %X %Y UTC"`
	d_new2=`date -u -r $new_author_time2 +"%F"`
	d_orig=`date -u -r $orig_author_time +"%F"`
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
commit $old_commit2 (formerly master)
from: $GOT_AUTHOR
date: $d_orig2
 
 committing to zeta on master
 
has become commit $new_commit2 (master)
 $d_new2 $GOT_AUTHOR_11  committing to zeta on master
EOF

	local is_forked=true d_fork fork_commit fork_commit_msg

	if [ "$old_commit1" = "$new_commit1" ]; then
		if [ "$old_commit2" = "$new_commit2" ]; then
			is_forked=false
		else
			d_fork=$d_orig1
			fork_commit=$new_commit1
			fork_commit_msg="committing changes"
		fi
	else
		d_fork=$d_orig
		fork_commit=$orig_commit
		fork_commit_msg="adding the test tree"
	fi

	$is_forked && cat >> $testroot/stdout.expected <<EOF
history forked at $fork_commit
 $d_fork $GOT_AUTHOR_11  $fork_commit_msg
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got histedit -X master \
		> $testroot/stdout 2> $testroot/stderr)
	echo -n "Deleted refs/got/backup/histedit/master/$new_commit2: " \
		> $testroot/stdout.expected
	echo "$old_commit2" >> $testroot/stdout.expected
	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got histedit -l > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_swap() {
	local testroot=`test_init histedit_swap`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got diff -r $testroot/repo $orig_commit $old_commit2 \
		> $testroot/diff.expected

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "pick $old_commit2" > $testroot/histedit-script
	echo "pick $old_commit1" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local new_commit2=`git_show_parent_commit $testroot/repo`
	local new_commit1=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  epsilon/zeta" > $testroot/stdout.expected
	echo -n "$short_old_commit2 -> $short_new_commit2: " \
		>> $testroot/stdout.expected
	echo "committing to zeta on master" >> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "$short_old_commit1 -> $short_new_commit1: committing changes" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	echo "commit $new_commit2" >> $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $orig_commit $new_commit1 \
		> $testroot/diff
	ed -s $testroot/diff.expected <<-EOF
	,s/$old_commit2/$new_commit1/
	w
	EOF
	cmp -s $testroot/diff.expected $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/diff.expected $testroot/diff
	fi
	test_done "$testroot" "$ret"
}

test_histedit_drop() {
	local testroot=`test_init histedit_drop`
	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got diff -r $testroot/repo $old_commit1 $old_commit2 \
		> $testroot/diff.expected

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "drop $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local new_commit2=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "$short_old_commit1 ->  drop commit: committing changes" \
		> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 -> $short_new_commit2: " \
		>> $testroot/stdout.expected
	echo "committing to zeta on master" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	for f in alpha beta; do
		echo "$f" > $testroot/content.expected
		cat $testroot/wt/$f > $testroot/content
		cmp -s $testroot/content.expected $testroot/content
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/content.expected $testroot/content
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	if [ -e $testroot/wt/new ]; then
		echo "file new exists on disk but should not" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $orig_commit $new_commit2 \
		> $testroot/diff
	ed -s $testroot/diff.expected <<-EOF
	,s/$old_commit1/$orig_commit/
	,s/$old_commit2/$new_commit2/
	w
	EOF
	cmp -s $testroot/diff.expected $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/diff.expected $testroot/diff
	fi
	test_done "$testroot" "$ret"
}

test_histedit_fold() {
	local testroot=`test_init histedit_fold`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	echo "modified delta on master" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on master"
	local old_commit3=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo "fold $old_commit1" > $testroot/histedit-script
	echo "drop $old_commit2" >> $testroot/histedit-script
	echo "pick $old_commit3" >> $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout)

	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_old_commit3=`trim_obj_id 12 $old_commit3`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: committing changes" \
		>> $testroot/stdout.expected
	echo -n "$short_old_commit2 ->  " >> $testroot/stdout.expected
	echo "drop commit: committing to zeta on master" \
		>> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_old_commit3 -> $short_new_commit2: " \
		>> $testroot/stdout.expected
	echo "committing folded changes" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_edit() {
	local testroot=`test_init histedit_edit`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edit $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited modified alpha on master" > $testroot/wt/alpha

	# test interaction of 'got stage' and histedit -c
	(cd $testroot/wt && got stage alpha > /dev/null)
	(cd $testroot/wt && got histedit -c > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: work tree contains files with staged changes; " \
		> $testroot/stderr.expected
	echo "these changes must be committed or unstaged first" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage alpha > /dev/null)

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -c > $testroot/stdout)

	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "$short_old_commit1 -> $short_new_commit1: committing changes" \
		> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 -> $short_new_commit2: " \
		>> $testroot/stdout.expected
	echo "committing to zeta on master" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_fold_last_commit() {
	local testroot=`test_init histedit_fold_last_commit`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "pick $old_commit1" > $testroot/histedit-script
	echo "fold $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: last commit in histedit script cannot be folded" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_histedit_missing_commit_pick() {
	local testroot=`test_init histedit_missing_commit`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "pick $old_commit1" > $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: commit $old_commit2 missing from histedit script" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_histedit_missing_commit_mesg() {
	local testroot=`test_init histedit_missing_commit`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo "mesg $old_commit1" > $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout \
			2>$testroot/stderr)

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: commit $old_commit2 missing from histedit script" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_histedit_abort() {
	local testroot=`test_init histedit_abort`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# unrelated unversioned file in work tree
	touch $testroot/wt/unversioned-file

	echo "edit $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited modified alpha on master" > $testroot/wt/alpha

	(cd $testroot/wt && got histedit -a > $testroot/stdout)

	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	echo "Switching work tree to refs/heads/master" \
		> $testroot/stdout.expected
	echo "R  alpha" >> $testroot/stdout.expected
	echo "R  beta" >> $testroot/stdout.expected
	echo "R  epsilon/new" >> $testroot/stdout.expected
	echo "Histedit of refs/heads/master aborted" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	for f in alpha beta; do
		echo "$f" > $testroot/content.expected
		cat $testroot/wt/$f > $testroot/content
		cmp -s $testroot/content.expected $testroot/content
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/content.expected $testroot/content
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	if [ -e $testroot/wt/epsilon/new ]; then
		echo "removed file new still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "?  unversioned-file" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_path_prefix_drop() {
	local testroot=`test_init histedit_path_prefix_drop`
	local orig_commit=`git_show_head $testroot/repo`

	echo "modified zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing zeta"
	local old_commit1=`git_show_head $testroot/repo`

	got checkout -c $orig_commit -p gamma $testroot/repo \
		$testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "drop $old_commit1" > $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: cannot edit branch history which contains changes " \
		> $testroot/stderr.expected
	echo "outside of this work tree's path prefix" \
		>> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	rm -rf $testroot/wt
	got checkout -c $orig_commit -p epsilon $testroot/repo \
		$testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "$short_old_commit1 ->  drop commit: changing zeta" \
		> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/zeta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi


	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $orig_commit (master)" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_path_prefix_edit() {
	local testroot=`test_init histedit_path_prefix_edit`
	local orig_commit=`git_show_head $testroot/repo`

	echo "modified zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing zeta"
	local old_commit1=`git_show_head $testroot/repo`

	got diff -r $testroot/repo $orig_commit $old_commit1 \
		> $testroot/diff.expected

	got checkout -c $orig_commit -p gamma $testroot/repo \
		$testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edit $old_commit1" > $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: cannot edit branch history which contains changes " \
		> $testroot/stderr.expected
	echo "outside of this work tree's path prefix" \
		>> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	rm -rf $testroot/wt
	got checkout -c $orig_commit -p epsilon $testroot/repo \
		$testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	local short_old_commit1=`trim_obj_id 12 $old_commit1`

	echo "G  zeta" > $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified zeta" > $testroot/content.expected
	cat $testroot/wt/zeta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
M  zeta
Work tree is editing the history of refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	
	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/modified zeta/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -c > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo -n "$short_old_commit1 -> $short_new_commit1: " \
		> $testroot/stdout.expected
	echo "modified zeta" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $orig_commit $new_commit1 \
		> $testroot/diff
	ed -s $testroot/diff.expected <<-EOF
	,s/$old_commit1/$new_commit1/
	w
	EOF
	cmp -s $testroot/diff.expected $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/diff.expected $testroot/diff
	fi
	test_done "$testroot" "$ret"
}

test_histedit_outside_refs_heads() {
	local testroot=`test_init histedit_outside_refs_heads`
	local commit1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit -m 'change alpha' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local commit2=`git_show_head $testroot/repo`

	got ref -r $testroot/repo -c master refs/remotes/origin/master
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got update -b origin/master -c $commit1 >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edit $commit2" > $testroot/histedit-script
	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		2> $testroot/stderr)

	echo -n "got: will not edit commit history of a branch outside the " \
		> $testroot/stderr.expected
	echo '"refs/heads/" reference namespace' \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_histedit_fold_last_commit_swap() {
	local testroot=`test_init histedit_fold_last_commit_swap`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	# fold commit2 into commit1 (requires swapping commits)
	echo "fold $old_commit2" > $testroot/histedit-script
	echo "mesg $old_commit1" >> $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout \
		2> $testroot/stderr)

	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local new_commit=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit=`trim_obj_id 12 $new_commit`

	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 ->  fold commit: committing to zeta " \
		>> $testroot/stdout.expected
	echo "on master" >> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo -n "$short_old_commit1 -> $short_new_commit: " \
		>> $testroot/stdout.expected
	echo "committing folded changes" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_split_commit() {
	local testroot=`test_init histedit_split_commit`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes 1"
	local old_commit1=`git_show_head $testroot/repo`
	local short_old_commit1=`trim_obj_id 12 $old_commit1`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing changes 2"
	local old_commit2=`git_show_head $testroot/repo`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# split commit1 into commitA and commitB and commitC
	echo "e $old_commit1" > $testroot/histedit-script
	echo "p $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit failed unexpectedly:" >&2
		cat $testroot/stderr >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got ci -m "commitA" alpha >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got ci -m "commitB" beta >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got ci -m "commitC" epsilon/new >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got histedit -c \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit failed unexpectedly:" >&2
		cat $testroot/stderr >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	local new_commit2=`git_show_head $testroot/repo`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "$short_old_commit1 -> no-op change: committing changes 1" \
		> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo "$short_old_commit2 -> $short_new_commit2: committing changes 2" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_histedit_duplicate_commit_in_script() {
	local testroot=`test_init histedit_duplicate_commit_in_script`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes 1"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing changes 2"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# This histedit script lists commit1 more than once
	echo "p $old_commit1" > $testroot/histedit-script
	echo "p $old_commit1" >> $testroot/histedit-script
	echo "p $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "histedit succeeded unexpectedly:" >&2
		cat $testroot/stdout >&2
		test_done "$testroot" 1
		return 1
	fi

	echo -n "got: commit $old_commit1 is listed more than once " \
		> $testroot/stderr.expected
	echo "in histedit script" >> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"

}

# if a previous commit introduces a new file, and it is folded into a commit
# that deletes the same file, the file still exists after the histedit
test_histedit_fold_add_delete() {
	local testroot=`test_init histedit_fold_add_delete`

	local orig_commit=`git_show_head $testroot/repo`

	echo "added new file epsilon/psi" > $testroot/repo/epsilon/psi
	git -C $testroot/repo add epsilon/psi
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified epsilon/psi" > $testroot/repo/epsilon/psi
	git_commit $testroot/repo -m "editing psi"
	local old_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo rm -q epsilon/psi
	git_commit $testroot/repo -m "removing psi"
	local old_commit3=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo "fold $old_commit1" > $testroot/histedit-script
	echo "fold $old_commit2" >> $testroot/histedit-script
	echo "pick $old_commit3" >> $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_old_commit3=`trim_obj_id 12 $old_commit3`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "A  epsilon/psi" >> $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: committing changes" \
		>> $testroot/stdout.expected
	echo "G  epsilon/psi" >> $testroot/stdout.expected
	echo "$short_old_commit2 ->  fold commit: editing psi" \
		>> $testroot/stdout.expected
	echo "D  epsilon/psi" >> $testroot/stdout.expected
	echo "$short_old_commit3 -> no-op change: folded changes" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/psi ]; then
		echo "removed file psi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo epsilon > $testroot/stdout
	echo "zeta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

# if a previous commit edits a file, and it is folded into a commit
# that deletes the same file, the file will be deleted by histedit
test_histedit_fold_edit_delete() {
	local testroot=`test_init histedit_fold_edit_delete`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modify alpha" > $testroot/repo/alpha
	git -C $testroot/repo add alpha
	git_commit $testroot/repo -m "modified alpha"
	local old_commit1=`git_show_head $testroot/repo`

	git_rm $testroot/repo alpha
	git_commit $testroot/repo -m "deleted alpha"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo "fold $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "G  alpha" >> $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: modified alpha" \
		>> $testroot/stdout.expected
	echo "D  alpha" >> $testroot/stdout.expected
	echo "$short_old_commit2 -> $short_new_commit1: folded changes" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/alpha ]; then
		echo "removed file alpha still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l2 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_histedit_fold_delete_add() {
	local testroot=`test_init histedit_fold_delete_add`

	local orig_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo rm -q alpha
	git_commit $testroot/repo -m "removing alpha"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified alpha" >$testroot/repo/alpha
	git -C $testroot/repo add alpha
	git_commit $testroot/repo -m "add back modified alpha"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo "fold $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -F $testroot/histedit-script > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`
	
	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "D  alpha" > $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: removing alpha" \
		>> $testroot/stdout.expected
	echo "A  alpha" >> $testroot/stdout.expected
	echo "$short_old_commit2 -> $short_new_commit1: folded changes" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -e $testroot/wt/alpha ]; then
		echo "file alpha is missing on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "0"
}

test_histedit_fold_only() {
	local testroot=`test_init histedit_fold_only`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	echo "modified delta on master" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on master"
	local old_commit3=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing folded changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" got histedit -f > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_old_commit3=`trim_obj_id 12 $old_commit3`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: committing changes" \
		>> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 ->  " >> $testroot/stdout.expected
	echo "fold commit: committing to zeta on master" \
		>> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_old_commit3 -> $short_new_commit1: " \
		>> $testroot/stdout.expected
	echo "committing folded changes" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_fold_only_empty_logmsg() {
	local testroot=`test_init histedit_fold_only_empty_logmsg`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	echo "modified delta on master" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on master"
	local old_commit3=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,d
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" got histedit -f > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local very_short_old_commit1=`trim_obj_id 11 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`
	local short_old_commit3=`trim_obj_id 12 $old_commit3`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "$short_old_commit1 ->  fold commit: committing changes" \
		>> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_old_commit2 ->  " >> $testroot/stdout.expected
	echo "fold commit: committing to zeta on master" \
		>> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_old_commit3 -> $short_new_commit1: " \
		>> $testroot/stdout.expected
	echo "# log message of folded commit $very_short_old_commit1" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (master)" > $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_edit_only() {
	local testroot=`test_init histedit_edit_only`

	local orig_commit=`git_show_head $testroot/repo`

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got histedit -e > $testroot/stdout)

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited modified alpha on master" > $testroot/wt/alpha

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing edited changes 1/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" got histedit -c > $testroot/stdout)

	local new_commit1=$(cd $testroot/wt && got info | \
		grep '^work tree base commit: ' | cut -d: -f2 | tr -d ' ')
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo -n "$short_old_commit1 -> $short_new_commit1: " \
		> $testroot/stdout.expected
	echo "committing edited changes 1" >> $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit2" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited zeta on master" > $testroot/wt/epsilon/zeta

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing edited changes 2/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" got histedit -c > $testroot/stdout)

	local new_commit2=`git_show_head $testroot/repo`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo -n "$short_old_commit2 -> $short_new_commit2: " \
		> $testroot/stdout.expected
	echo "committing edited changes 2" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edited modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on master" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (master)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $orig_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_prepend_line() {
	local testroot=`test_init histedit_prepend_line`
	local orig_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null

	ed -s "$testroot/wt/alpha" <<EOF
1i
first line
.
wq
EOF

	cp $testroot/wt/alpha $testroot/content.expected

	(cd $testroot/wt/ && got commit -m 'modified alpha on master' \
		alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local top_commit=`git_show_head $testroot/repo`
	echo "pick $top_commit" > "$testroot/histedit-script"

	(cd $testroot/wt/ && got update -c $orig_commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got histedit -F "$testroot/histedit-script" \
		> /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got histedit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cp $testroot/wt/alpha $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" $ret
}

test_histedit_resets_committer() {
	local testroot=`test_init histedit_resets_committer`
	local orig_commit=`git_show_head $testroot/repo`
	local committer="Flan Luck <flan_luck@openbsd.org>"

	got checkout $testroot/repo $testroot/wt > /dev/null

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt/ && got commit -m 'modified alpha on master' \
		alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local top_commit=`git_show_head $testroot/repo`
	echo "pick $top_commit" > "$testroot/histedit-script"

	(cd $testroot/wt/ && got update -c $orig_commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && env GOT_AUTHOR="$committer" \
		got histedit -F "$testroot/histedit-script" > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got histedit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	local edited_commit=`git_show_head $testroot/repo`

	# Original commit only had one author
	(cd $testroot/repo && got log -l1 -c $top_commit | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $GOT_AUTHOR" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Edited commit should have new committer name added
	(cd $testroot/repo && got log -l1 -c $edited_commit | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $GOT_AUTHOR" > $testroot/stdout.expected
	echo "via: $committer" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_umask() {
	local testroot=`test_init histedit_umask`
	local orig_commit=`git_show_head "$testroot/repo"`

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null

	echo "modified alpha" > $testroot/wt/alpha
	(cd "$testroot/wt" && got commit -m 'edit #1') >/dev/null
	local commit1=`git_show_head "$testroot/repo"`

	echo "modified again" > $testroot/wt/alpha
	(cd "$testroot/wt" && got commit -m 'edit #2') >/dev/null
	local commit2=`git_show_head "$testroot/repo"`

	echo "modified again!" > $testroot/wt/alpha
	echo "modify beta too!" > $testroot/wt/beta
	(cd "$testroot/wt" && got commit -m 'edit #3') >/dev/null
	local commit3=`git_show_head "$testroot/repo"`

	(cd "$testroot/wt" && got update -c "$orig_commit") >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update to $orig_commit failed!" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/folding changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	echo fold $commit1 >$testroot/histedit-script
	echo fold $commit2 >>$testroot/histedit-script
	echo pick $commit3 >>$testroot/histedit-script

	# using a subshell to avoid clobbering global umask
	(umask 077 && cd "$testroot/wt" && \
		env EDITOR="$testroot/editor.sh" VISUAL="$testroot/editor.sh" \
		got histedit -F "$testroot/histedit-script") >/dev/null
	ret=$?

	if [ $ret -ne 0 ]; then
		echo "histedit operation failed" >&2
		test_done "$testroot" $ret
		return 1
	fi

	for f in alpha beta; do
		ls -l "$testroot/wt/$f" | grep -q ^-rw-------
		if [ $? -ne 0 ]; then
			echo "$f is not 0600 after histedi" >&2
			ls -l "$testroot/wt/$f" >&2
			test_done "$testroot" 1
			return 1
		fi
	done

	test_done "$testroot" 0
}

test_histedit_mesg_filemode_change() {
	local testroot=`test_init histedit_mode_change`

	local orig_commit=`git_show_head $testroot/repo`
	local orig_author_time=`git_show_author_time $testroot/repo`

	chmod +x $testroot/repo/alpha
	git_commit $testroot/repo -m "set x bit on alpha"
	local old_commit1=`git_show_head $testroot/repo`
	local old_author_time1=`git_show_author_time $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -x $testroot/wt/alpha ]; then
		echo "file alpha has unexpected executable bit" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/ x bit / executable bit /
	w
	EOF
EOF

	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env VISUAL="$testroot/editor.sh" \
		got histedit -m > $testroot/stdout)

	local new_commit1=`git_show_head $testroot/repo`
	local new_author_time1=`git_show_author_time $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "G  alpha" > $testroot/stdout.expected
	echo "$short_old_commit1 -> $short_new_commit1: set executable bit on alpha" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	cmp -s $testroot/content.expected $testroot/wt/alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/wt/alpha
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -x $testroot/wt/alpha ]; then
		echo "file alpha lost its executable bit" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l1 | grep ' set executable bit on alpha' \
		> $testroot/stdout)

	echo ' set executable bit on alpha' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_histedit_drop_only() {
	local testroot=`test_init histedit_drop_only`

	local orig_commit=`git_show_head $testroot/repo`
	local drop="->  drop commit:"
	local dropmsg="commit changes to drop"

	echo "modified alpha on master" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on master" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new

	git_commit $testroot/repo -m "$dropmsg 1"
	local drop_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta

	git_commit $testroot/repo -m "$dropmsg 2"
	local drop_commit2=`git_show_head $testroot/repo`

	echo "modified delta on master" > $testroot/repo/gamma/delta

	git_commit $testroot/repo -m "$dropmsg 3"
	local drop_commit3=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got histedit -d > $testroot/stdout)
	local new_commit1=`git_show_head $testroot/repo`

	local short_commit1=`trim_obj_id 12 $drop_commit1`
	local short_commit2=`trim_obj_id 12 $drop_commit2`
	local short_commit3=`trim_obj_id 12 $drop_commit3`

	echo "$short_commit1 $drop $dropmsg 1" > $testroot/stdout.expected
	echo "$short_commit2 $drop $dropmsg 2" >> $testroot/stdout.expected
	echo "$short_commit3 $drop $dropmsg 3" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "delta" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -e $testroot/wt/beta ]; then
		echo "removed file beta should be restored" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/new ]; then
		echo "new file should no longer exist" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log | grep ^commit > $testroot/stdout)
	echo "commit $orig_commit (master)" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_histedit_conflict_revert() {
	local testroot=`test_init histedit_conflict_revert`
	local orig_commit=`git_show_head $testroot/repo`

	echo "first change of alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`
	local short_old_commit1=`trim_obj_id 12 $old_commit1`

	echo "second change of alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing changes"
	local old_commit2=`git_show_head $testroot/repo`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "third change of alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing changes"
	local old_commit3=`git_show_head $testroot/repo`
	local short_old_commit3=`trim_obj_id 12 $old_commit3`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "edit $old_commit1" > $testroot/histedit-script
	echo "edit $old_commit2" >> $testroot/histedit-script
	echo "pick $old_commit3" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout)

	echo "G  alpha" > $testroot/stdout.expected
	echo "Stopping histedit for amending commit $old_commit1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "tweaked first change of alpha" > $testroot/wt/alpha

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/committing changes/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -c > $testroot/stdout 2> $testroot/stderr)

	local new_commit1=$(cd $testroot/wt && got info | \
		grep 'work tree base commit:' | cut -d ' ' -f5)
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "$short_old_commit1 -> $short_new_commit1: committing changes" \
		> $testroot/stdout.expected
	echo "C  alpha" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo "$short_old_commit2 -> merge conflict: committing changes" \
		>> $testroot/stdout.expected

	echo "got: conflicts must be resolved before histedit can continue" \
		> $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert alpha > /dev/null)
	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -c > $testroot/stdout 2> $testroot/stderr)

	echo "$short_old_commit2 -> no-op change: committing changes" \
		> $testroot/stdout.expected
	echo "C  alpha" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo "$short_old_commit3 -> merge conflict: committing changes" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert alpha > /dev/null)
	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -c > $testroot/stdout 2> $testroot/stderr)

	echo "$short_old_commit3 -> no-op change: committing changes" \
		> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_histedit_no_eof_newline() {
	local testroot=$(test_init histedit_no_eof_newline)
	local id_root=$(git_show_head "$testroot/repo")

	got checkout "$testroot/repo" "$testroot/wt" > /dev/null

	echo -n "fubar" >> $testroot/wt/alpha

	(cd "$testroot/wt" && got commit -m 'no eof newline' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cp $testroot/wt/alpha $testroot/content.expected

	(cd $testroot/wt && got update -c :base:- > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update to $id_root failed" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/ eof / terminating /
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
	    VISUAL="$testroot/editor.sh" got histedit -m > /dev/null)

	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit -m failed" >&2
		test_done "$testroot" $ret
		return 1
	fi

	cp $testroot/wt/alpha $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/wt/beta <<-EOF
	beta
	2
	3
	4

	6
	7
	8
	EOF

	(cd "$testroot/wt" && got commit -m 'padding beta' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local id=$(git_show_head "$testroot/repo")

	cat > $testroot/wt/beta <<-EOF
	betazoid
	3
	4

	7
	8
	a
	b
	c
	d
	e
	f
	0
	1
	2
	3
	4
	5
	6
	7
	8
	9
	EOF

	echo -n "fubar" >> $testroot/wt/beta

	(cd "$testroot/wt" && got commit -m 'beta no eof newline' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cp $testroot/wt/beta $testroot/content.expected

	(cd $testroot/wt && got update -c :base:- > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update to $id failed" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
	    VISUAL="$testroot/editor.sh" got histedit -m > /dev/null)

	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit -m failed" >&2
		test_done "$testroot" $ret
		return 1
	fi

	cp $testroot/wt/beta $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" 0
}

test_histedit_preserve_bad_link() {
	local testroot=`test_init histedit_preserve_bad_link`
	local orig_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "file outside worktree" > $testroot/external_file
	ln -sf $testroot/external_file $testroot/wt/bad_link

	(cd $testroot/wt && got add bad_link && \
		got commit -S -m 'add bad link') >/dev/null 2>&1
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local old_commit1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update -c $orig_commit \
		>/dev/null 2>&1)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/.*/add really bad link/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env EDITOR="$testroot/editor.sh" \
		VISUAL="$testroot/editor.sh" \
		got histedit -m > $testroot/stdout \
			2>$testroot/stderr)

	ret=$?
	if [ $ret -ne 0 ]; then
		echo "histedit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local old_commit2=`git_show_head $testroot/repo`

	local short_old_commit1=`trim_obj_id 12 $old_commit1`
	local short_old_commit2=`trim_obj_id 12 $old_commit2`

	echo "A  bad_link" > $testroot/stdout.expected
	echo "$short_old_commit1 -> $short_old_commit2: add really bad link" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/external_file $testroot/wt/bad_link
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "contents of linked file and external file do not match" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	bad_link_path=$(readlink $testroot/wt/bad_link)
	if [ "$bad_link_path" != "$testroot/external_file" ]; then
		echo "link was not preserved" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_histedit_added_file() {
	local testroot=`test_init histedit_added_file`
	local orig_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo new > $testroot/wt/new
	(cd $testroot/wt && got add new > /dev/null)

	(cd $testroot/wt && got commit -m 'add new file' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local commit2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got up -q -c $orig_commit > /dev/null)

	# Place an unversioned file into the work tree where the new
	# file was added. This triggered a bug where histedit would
	# assume the file was already present in earlier commits and then
	# treat the commit which actually adds this file as a no-op change.
	# This test then failed with:
	# -2f81c7988242 -> c53428a3640e: add new file
	# +2f81c7988242 -> no-op change: add new file
	echo new > $testroot/wt/new

	(cd $testroot/wt && got histedit -f > $testroot/stdout)
	local new_commit=`git_show_head $testroot/repo`

	local short_commit2=`trim_obj_id 12 $commit2`
	local short_new_commit=`trim_obj_id 12 $new_commit`

	echo "A  new" > $testroot/stdout.expected
	echo "$short_commit2 -> $short_new_commit: add new file" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

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
run_test test_histedit_no_op
run_test test_histedit_swap
run_test test_histedit_drop
run_test test_histedit_fold
run_test test_histedit_edit
run_test test_histedit_fold_last_commit
run_test test_histedit_missing_commit_pick
run_test test_histedit_missing_commit_mesg
run_test test_histedit_abort
run_test test_histedit_path_prefix_drop
run_test test_histedit_path_prefix_edit
run_test test_histedit_outside_refs_heads
run_test test_histedit_fold_last_commit_swap
run_test test_histedit_split_commit
run_test test_histedit_duplicate_commit_in_script
run_test test_histedit_fold_add_delete
run_test test_histedit_fold_edit_delete
run_test test_histedit_fold_delete_add
run_test test_histedit_fold_only
run_test test_histedit_fold_only_empty_logmsg
run_test test_histedit_edit_only
run_test test_histedit_prepend_line
run_test test_histedit_resets_committer
run_test test_histedit_umask
run_test test_histedit_mesg_filemode_change
run_test test_histedit_drop_only
run_test test_histedit_conflict_revert
run_test test_histedit_no_eof_newline
run_test test_histedit_preserve_bad_link
run_test test_histedit_added_file
