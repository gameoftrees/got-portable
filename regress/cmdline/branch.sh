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

test_branch_create() {
	local testroot=`test_init branch_create`
	local commit_id0=`git_show_head $testroot/repo`

	# Create a branch based on repository's HEAD reference
	got branch -r $testroot/repo newbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that Git recognizes the branch Got has created
	git -C $testroot/repo checkout -q newbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	got checkout -b newbranch $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta on branch" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on the work tree's branch
	(cd $testroot/wt && got branch -n refs/heads/anotherbranch)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q anotherbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on another specific branch
	(cd $testroot/wt && got branch -n -c master yetanotherbranch)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q yetanotherbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on a specific commit
	local commit_id=`git_show_head $testroot/repo`
	got branch -r $testroot/repo -c $commit_id commitbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q commitbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch and let the work tree be updated to it
	(cd $testroot/wt && got branch -c $commit_id0 updatebranch \
		> $testroot/stdout)

	echo -n "Switching work tree from refs/heads/newbranch to " \
		> $testroot/stdout.expected
	echo "refs/heads/updatebranch" >> $testroot/stdout.expected
	echo "U  gamma/delta" >> $testroot/stdout.expected
	echo "Updated to refs/heads/updatebranch: $commit_id0" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_branch_list() {
	local testroot=`test_init branch_list`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "* master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "~ master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "* master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -b branch1 > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "* branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_branch_delete() {
	local testroot=`test_init branch_delete`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got branch -d branch2 -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -d bogus_branch_name -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got branch succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: reference refs/heads/bogus_branch_name not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -c master refs/remotes/origin/master
	got ref -r $testroot/repo -c branch1 refs/remotes/origin/branch1
	got ref -r $testroot/repo -c branch3 refs/remotes/origin/branch3

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/branch1: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/branch3: $commit_id" \
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

	got branch -d origin/branch1 -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -d refs/remotes/origin/branch3 -r $testroot/repo \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_branch_delete_current_branch() {
	local testroot=`test_init branch_delete_current_branch`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -d master > $testroot/stdout \
		2> $testroot/stderr)

	echo "got: will not delete this work tree's current branch" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_branch_delete_packed() {
	local testroot=`test_init branch_delete_packed`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	git -C $testroot/repo pack-refs --all

	got branch -d refs/heads/branch2 -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -d bogus_branch_name -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got update succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: reference refs/heads/bogus_branch_name not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_branch_show() {
	local testroot=`test_init branch_show`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch > $testroot/stdout)
	echo "master" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -b branch1 > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch > $testroot/stdout)
	echo "branch1" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_branch_packed_ref_collision() {
	local testroot=`test_init branch_packed_ref_collision`
	local commit_id=`git_show_head $testroot/repo`

	got br -r $testroot/repo zoo > $testroot/stdout
	got co -b zoo $testroot/repo $testroot/wt > /dev/null
	echo "modified alpha" > $testroot/wt/alpha

	# sleep in order to ensure that a significant fraction of time
	# passes between commits; required for got branch -t option below
	sleep 1

	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo zoo`

	# Fabricate a packed reference which points to an older commit
	# and collides with the existing on-disk reference
	echo '# pack-refs with: peeled fully-peeled sorted' > \
		$testroot/repo/.git/packed-refs
	echo "$commit_id refs/heads/zoo" >> $testroot/repo/.git/packed-refs

	# Bug: This command used to show both packed and on-disk
	# variants of ref/heads/zoo:
	(cd $testroot/wt && got br -lt > $testroot/stdout)

	echo "~ zoo: $commit_id2" > $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_commit_keywords() {
	local testroot=$(test_init branch_commit_keywords)

	set -- "$(git_show_head $testroot/repo)"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	for i in $(seq 4); do
		echo "beta change $i" > "$testroot/wt/beta"

		(cd "$testroot/wt" && got ci -m "commit number $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi
		set -- "$@" "$(git_show_head $testroot/repo)"
	done

	(cd "$testroot/wt" && got up > /dev/null)

	echo "  kwbranch: $(pop_idx 3 $@)" > $testroot/stdout.expected
	echo "  master: $(pop_idx 5 $@)" >> $testroot/stdout.expected

	(cd "$testroot/wt" && got br -nc :head:-2 kwbranch > /dev/null)
	got br -r "$testroot/repo" -l > "$testroot/stdout"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "  kwbranch2: $(pop_idx 4 $@)" > $testroot/stdout.expected

	got br -r "$testroot/repo" -c master:- kwbranch2 > /dev/null
	got br -r "$testroot/repo" -l | grep kwbranch2 > "$testroot/stdout"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_branch_list_worktree_state() {
	local testroot=$(test_init branch_list_worktree_state)
	local wt="$testroot/wt"

	set -- "$(git_show_head "$testroot/repo")"

	got checkout "$testroot/repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$wt" && got br -n newbranch > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "branch failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# check up-to-date marker is shown with fresh checkout
	(cd "$wt" && got br -l > "$testroot/stdout")
	echo "* master: $(pop_idx 1 $@)" > $testroot/stdout.expected
	echo "  newbranch: $(pop_idx 1 $@)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check out-of-date marker is shown with mixed-commit state
	echo "mixed-commit" > "$wt/alpha"
	(cd "$wt" && got commit -m "mixed-commit" > "$testroot/stdout")
	set -- "$@" "$(git_show_head "$testroot/repo")"

	(cd "$wt" && got br -l > "$testroot/stdout")
	echo "~ master: $(pop_idx 2 $@)" > $testroot/stdout.expected
	echo "  newbranch: $(pop_idx 1 $@)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check up-to-date marker is shown after 'got update'
	(cd "$wt" && got up > /dev/null)
	(cd "$wt" && got br -l > "$testroot/stdout")
	echo "* master: $(pop_idx 2 $@)" > $testroot/stdout.expected
	echo "  newbranch: $(pop_idx 1 $@)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check out-of-date marker is shown with out-of-date base commit
	(cd "$wt" && got up -c:head:- > /dev/null)
	(cd "$wt" && got br -l > "$testroot/stdout")
	echo "~ master: $(pop_idx 2 $@)" > $testroot/stdout.expected
	echo "  newbranch: $(pop_idx 1 $@)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_del_child_create_parent() {
	local testroot=$(test_init branch_del_child_create_parent)
	local wt="$testroot/wt"

	set -- "$(git_show_head "$testroot/repo")"

	got checkout "$testroot/repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$wt" && got br -n a/b > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "branch a/b failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd "$wt" && got br -d a/b > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "branch deletion a/b failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd "$wt" && got br -n a > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "branch a failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_branch_create
run_test test_branch_list
run_test test_branch_delete
run_test test_branch_delete_current_branch
run_test test_branch_delete_packed
run_test test_branch_show
run_test test_branch_packed_ref_collision
run_test test_branch_commit_keywords
run_test test_branch_list_worktree_state
run_test test_branch_del_child_create_parent
