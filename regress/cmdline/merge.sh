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

test_merge_basic() {
	local testroot=`test_init merge_basic`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit1=`git_show_branch_head $testroot/repo newbranch`
	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing beta on newbranch"
	local branch_commit2=`git_show_branch_head $testroot/repo newbranch`
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "adding new file on newbranch"
	local branch_commit3=`git_show_branch_head $testroot/repo newbranch`
	(cd $testroot/repo && ln -s alpha symlink)
	git -C $testroot/repo add symlink
	git_commit $testroot/repo -m "adding symlink on newbranch"
	local branch_commit4=`git_show_branch_head $testroot/repo newbranch`
	(cd $testroot/repo && ln -sf .got/bar dotgotbar.link)
	git -C $testroot/repo add dotgotbar.link
	git_commit $testroot/repo -m "adding a bad symlink on newbranch"
	local branch_commit5=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a divergent commit
	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: work tree must be updated before it can be used " \
		> $testroot/stderr.expected
	echo "to merge a branch" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# must not use a mixed-commit work tree with 'got merge'
	(cd $testroot/wt && got update -c $commit0 alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: work tree contains files from multiple base commits; " \
		> $testroot/stderr.expected
	echo "the entire work tree must be updated first" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# must not have staged files with 'got merge'
	echo "modified file alpha"  > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: alpha: file is staged" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got unstage alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# must not have local changes with 'got merge'
	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: work tree contains local changes; " \
		> $testroot/stderr.expected
	echo "these changes must be committed or reverted first" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_head $testroot/repo`

	echo "G  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  dotgotbar.link" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo "A  symlink" >> $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	echo "modified alpha on branch" > $testroot/content.expected
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

	echo "new file on branch" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/symlink > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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
	echo "commit $merge_commit (master)" > $testroot/stdout.expected
	echo "commit $master_commit" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)

	echo 'U  dotgotbar.link' > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# update has changed the bad symlink into a regular file
	if [ -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	# We should have created a merge commit with two parents.
	(cd $testroot/wt && got log -l1 | grep ^parent > $testroot/stdout)
	echo "parent 1: $master_commit" > $testroot/stdout.expected
	echo "parent 2: $branch_commit5" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo -c $merge_commit -R > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tree failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# bad symlink dotgotbar.link appears as a symlink in the merge commit:
	cat > $testroot/stdout.expected <<EOF
alpha
dotgotbar.link@ -> .got/bar
epsilon/
epsilon/new
epsilon/zeta
gamma/
gamma/delta
symlink@ -> alpha
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_forward() {
	local testroot=`test_init merge_forward`
	local commit0=`git_show_head $testroot/repo`

	# Create a commit before branching, which will be used to help test
	# preconditions for "got merge".
	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "common commit"
	local commit1=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified beta on branch" > $testroot/repo/beta
	git_commit $testroot/repo -m "committing to beta on newbranch"
	local commit2=`git_show_head $testroot/repo`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# must not use a mixed-commit work tree with 'got merge'
	(cd $testroot/wt && got update -c $commit0 alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	echo -n "got: work tree contains files from multiple base commits; " \
		> $testroot/stderr.expected
	echo "the entire work tree must be updated first" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# 'got merge -n' refuses to fast-forward
	(cd $testroot/wt && got merge -n newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: there are no changes to merge since " \
		> $testroot/stderr.expected
	echo -n "refs/heads/newbranch is already based on " \
		>> $testroot/stderr.expected
	echo -n "refs/heads/master; merge cannot be interrupted " \
		>> $testroot/stderr.expected
	echo "for amending; -n: option cannot be used" \
		>> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Forwarding refs/heads/master to refs/heads/newbranch" \
		> $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo "Updated to commit $commit2" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log | grep ^commit > $testroot/stdout)
	echo -n "commit $commit2 " > $testroot/stdout.expected
	echo "(master, newbranch)" >> $testroot/stdout.expected
	echo "commit $commit1" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_merge_forward_commit() {
	local testroot=`test_init merge_forward_commit`
	local commit0=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local commit1=`git_show_head $testroot/repo`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -M newbranch > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_branch_head $testroot/repo master`

	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should have created a merge commit with two parents.
	(cd $testroot/wt && got log -l1 | grep ^parent > $testroot/stdout)
	echo "parent 1: $commit0" > $testroot/stdout.expected
	echo "parent 2: $commit1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_merge_forward_interrupt() {
	# Test -M and -n options together.
	local testroot=`test_init merge_forward_commit`
	local commit0=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local commit1=`git_show_head $testroot/repo`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -M -n newbranch > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "G  alpha" > $testroot/stdout.expected
	echo "Merge of refs/heads/newbranch interrupted on request" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Continue the merge.
	(cd $testroot/wt && got merge -c > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_branch_head $testroot/repo master`

	echo "M  alpha" > $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should have created a merge commit with two parents.
	(cd $testroot/wt && got log -l1 | grep ^parent > $testroot/stdout)
	echo "parent 1: $commit0" > $testroot/stdout.expected
	echo "parent 2: $commit1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_backward() {
	local testroot=`test_init merge_backward`
	local commit0=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "Already up-to-date" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_merge_continue() {
	local testroot=`test_init merge_continue`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit1=`git_show_branch_head $testroot/repo newbranch`
	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing beta on newbranch"
	local branch_commit2=`git_show_branch_head $testroot/repo newbranch`
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "adding new file on newbranch"
	local branch_commit3=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "C  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before merging can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
D  beta
A  epsilon/new
M  gamma/delta
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '<<<<<<<' > $testroot/content.expected
	echo "modified alpha on master" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $commit0" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha on branch" >> $testroot/content.expected
	echo ">>>>>>> merged change: commit $branch_commit3" \
		>> $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict
	echo "modified alpha by both branches" > $testroot/wt/alpha

	(cd $testroot/wt && got merge -c > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_head $testroot/repo`

	echo "M  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "M  gamma/delta" >> $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	echo "modified alpha by both branches" > $testroot/content.expected
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

	echo "new file on branch" > $testroot/content.expected
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
	echo "commit $merge_commit (master)" > $testroot/stdout.expected
	echo "commit $master_commit" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	# We should have created a merge commit with two parents.
	(cd $testroot/wt && got log -l1 | grep ^parent > $testroot/stdout)
	echo "parent 1: $master_commit" > $testroot/stdout.expected
	echo "parent 2: $branch_commit3" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_continue_new_commit() {
	# "got merge -c" should refuse to run if the current branch tip has
	# changed since the merge was started, to avoid clobbering the changes.
	local testroot=`test_init merge_continue_new_commit`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -n newbranch >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha again on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master again"

	(cd $testroot/wt && got merge -c > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: merging cannot proceed because the work tree is no " \
		> $testroot/stderr.expected
	echo "longer up-to-date; merge must be aborted and retried" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_merge_abort() {
	local testroot=`test_init merge_abort`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit1=`git_show_branch_head $testroot/repo newbranch`
	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing beta on newbranch"
	local branch_commit2=`git_show_branch_head $testroot/repo newbranch`
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "adding new file on newbranch"
	local branch_commit3=`git_show_branch_head $testroot/repo newbranch`
	(cd $testroot/repo && ln -s alpha symlink)
	git -C $testroot/repo add symlink
	git_commit $testroot/repo -m "adding symlink on newbranch"
	local branch_commit4=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# unrelated unversioned file in work tree
	touch $testroot/wt/unversioned-file

	# create a conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "C  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo "A  symlink" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before merging can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# unrelated added file added during conflict resolution
	touch $testroot/wt/added-file
	(cd $testroot/wt && got add added-file > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
A  added-file
C  alpha
D  beta
A  epsilon/new
M  gamma/delta
A  symlink
?  unversioned-file
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -a > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  added-file" > $testroot/stdout.expected
	echo "R  alpha" >> $testroot/stdout.expected
	echo "R  beta" >> $testroot/stdout.expected
	echo "R  epsilon/new" >> $testroot/stdout.expected
	echo "R  gamma/delta" >> $testroot/stdout.expected
	echo "R  symlink" >> $testroot/stdout.expected
	echo "G  added-file" >> $testroot/stdout.expected
	echo "Merge of refs/heads/newbranch aborted" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/new ]; then
		echo "reverted file epsilon/new still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/symlink ]; then
		echo "reverted symlink still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "?  added-file" > $testroot/stdout.expected
	echo "?  unversioned-file" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $master_commit (master)" > $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)

	echo 'Already up-to-date' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_in_progress() {
	local testroot=`test_init merge_in_progress`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "C  alpha" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before merging can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	for cmd in update commit histedit "rebase newbranch" \
		"integrate newbranch" "merge newbranch" "stage alpha"; do
		(cd $testroot/wt && got $cmd > $testroot/stdout \
			2> $testroot/stderr)
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "got $cmd succeeded unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi

		echo -n > $testroot/stdout.expected
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi

		echo -n "got: a merge operation is in progress in this " \
			> $testroot/stderr.expected
		echo "work tree and must be continued or aborted first" \
			>> $testroot/stderr.expected
		cmp -s $testroot/stderr.expected $testroot/stderr
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "$ret"
}

test_merge_path_prefix() {
	local testroot=`test_init merge_path_prefix`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	got checkout -p epsilon -b master $testroot/repo $testroot/wt \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: cannot merge branch which contains changes outside " \
		> $testroot/stderr.expected
	echo "of this work tree's path prefix" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_merge_missing_file() {
	local testroot=`test_init merge_missing_file`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to alpha and delta"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a conflicting commit which renames alpha
	git -C $testroot/repo checkout -q master
	git -C $testroot/repo mv alpha epsilon/alpha-moved
	git_commit $testroot/repo -m "moving alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "!  alpha" > $testroot/stdout.expected
	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "Files which had incoming changes but could not be found " \
		>> $testroot/stdout.expected
	echo "in the work tree: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: changes destined for some files " \
		> $testroot/stderr.expected
	echo -n "were not yet merged and should be merged manually if " \
		>> $testroot/stderr.expected
	echo "required before the merge operation is continued" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
M  gamma/delta
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_merge_no_op() {
	local testroot=`test_init merge_no_op`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got merge succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "C  alpha" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before merging can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict by reverting all changes; now it is no-op merge
	(cd $testroot/wt && got revert alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -c > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n '' > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_head $testroot/repo`
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should have created a merge commit with two parents.
	got log -r $testroot/repo -l1 -c $merge_commit | grep ^parent \
		> $testroot/stdout
	echo "parent 1: $master_commit" > $testroot/stdout.expected
	echo "parent 2: $branch_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_imported_branch() {
	local testroot=`test_init merge_import`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	# import a new sub-tree to the 'files' branch such that
	# none of the files added here collide with existing ones
	mkdir -p $testroot/tree/there
	mkdir -p $testroot/tree/be/lots
	mkdir -p $testroot/tree/files
	echo "there should" > $testroot/tree/there/should
	echo "be lots of" > $testroot/tree/be/lots/of
	echo "files here" > $testroot/tree/files/here
	got import -r $testroot/repo -b files -m 'import files' \
		$testroot/tree > /dev/null

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge files > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit0=`git_show_head $testroot/repo`
	cat > $testroot/stdout.expected <<EOF
A  be/lots/of
A  files/here
A  there/should
Merged refs/heads/files into refs/heads/master: $merge_commit0
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# try to merge again while no new changes are available
	(cd $testroot/wt && got merge files > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "Already up-to-date" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# update the 'files' branch
	git -C $testroot/repo reset -q --hard master
	git -C $testroot/repo checkout -q files
	echo "indeed" > $testroot/repo/indeed
	git -C $testroot/repo add indeed
	git_commit $testroot/repo -m "adding another file indeed"
	echo "be lots and lots of" > $testroot/repo/be/lots/of
	git_commit $testroot/repo -m "lots of changes"

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# we should now be able to merge more changes from files branch
	(cd $testroot/wt && got merge files > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit1=`git_show_branch_head $testroot/repo master`
	cat > $testroot/stdout.expected <<EOF
G  be/lots/of
A  indeed
Merged refs/heads/files into refs/heads/master: $merge_commit1
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_interrupt() {
	local testroot=`test_init merge_interrupt`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local branch_commit0=`git_show_branch_head $testroot/repo newbranch`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a non-conflicting commit
	git -C $testroot/repo checkout -q master
	echo "modified beta on master" > $testroot/repo/beta
	git_commit $testroot/repo -m "committing to beta on master"
	local master_commit=`git_show_head $testroot/repo`

	# need an up-to-date work tree for 'got merge'
	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got merge -n newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "G  alpha" > $testroot/stdout.expected
	echo "Merge of refs/heads/newbranch interrupted on request" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
M  alpha
Work tree is merging refs/heads/newbranch into refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on branch" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# adjust merge result
	echo "adjusted merge result" > $testroot/wt/alpha

	# continue the merge
	(cd $testroot/wt && got merge -c > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got merge failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local merge_commit=`git_show_head $testroot/repo`

	echo "M  alpha" > $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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
	echo "commit $merge_commit (master)" > $testroot/stdout.expected
	echo "commit $master_commit" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	# We should have created a merge commit with two parents.
	(cd $testroot/wt && got log -l1 | grep ^parent > $testroot/stdout)
	echo "parent 1: $master_commit" > $testroot/stdout.expected
	echo "parent 2: $branch_commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_umask() {
	local testroot=`test_init merge_umask`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "committing alpha on newbranch"
	echo "modified delta on branch" >$testroot/repo/gamma/delta
	git_commit "$testroot/repo" -m "committing delta on newbranch"

	# diverge from newbranch
	git -C "$testroot/repo" checkout -q master
	echo "modified beta on master" >$testroot/repo/beta
	git_commit "$testroot/repo" -m "committing zeto no master"

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null

	# using a subshell to avoid clobbering global umask
	(umask 077 && cd "$testroot/wt" && got merge newbranch) >/dev/null

	for f in alpha gamma/delta; do
		ls -l "$testroot/wt/$f" | grep -q ^-rw-------
		if [ $? -ne 0 ]; then
			echo "$f is not 0600 after merge" >&2
			ls -l "$testroot/wt/$f" >&2
			test_done "$testroot" 1
		fi
	done

	test_done "$testroot" 0
}

test_merge_gitconfig_author() {
	local testroot=`test_init merge_gitconfig_author`

	git -C $testroot/repo config user.name 'Flan Luck'
	git -C $testroot/repo config user.email 'flan_luck@openbsd.org'

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "committing alpha on newbranch"
	echo "modified delta on branch" >$testroot/repo/gamma/delta
	git_commit "$testroot/repo" -m "committing delta on newbranch"

	# diverge from newbranch
	git -C "$testroot/repo" checkout -q master
	echo "modified beta on master" >$testroot/repo/beta
	git_commit "$testroot/repo" -m "committing zeto no master"

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null

	# unset in a subshell to avoid affecting our environment
	(unset GOT_IGNORE_GITCONFIG && cd $testroot/wt && \
		 got merge newbranch > /dev/null)

	(cd $testroot/repo && got log -l1 | grep ^from: > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "from: Flan Luck <flan_luck@openbsd.org>" \
		> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_fetched_branch() {
	local testroot=`test_init merge_fetched_branch`
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
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
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

	got checkout $testroot/repo-clone $testroot/wt > /dev/null

	echo "modified beta" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "modified beta" > /dev/null)
	local commit_id3=`git_show_head $testroot/repo-clone`

	(cd $testroot/wt && got update > /dev/null)
	(cd $testroot/wt && got merge origin/master > $testroot/stdout)
	local merge_commit_id=`git_show_head $testroot/repo-clone`

	cat > $testroot/stdout.expected <<EOF
G  alpha
Merged refs/remotes/origin/master into refs/heads/master: $merge_commit_id
EOF

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_merge_fetched_branch_remote() {
	local testroot=`test_init merge_fetched_branch_remote`
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
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
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

	got checkout $testroot/repo-clone $testroot/wt > /dev/null

	echo "modified beta" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "modified beta" > /dev/null)
	local commit_id3=`git_show_head $testroot/repo-clone`

	(cd $testroot/wt && got update -b origin/master > /dev/null)
	(cd $testroot/wt && got merge master > \
		$testroot/stdout 2> $testroot/stderr)
	local merge_commit_id=`git_show_head $testroot/repo-clone`

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: work tree's current branch refs/remotes/origin/master " \
		> $testroot/stderr.expected
	echo -n 'is outside the "refs/heads/" reference namespace; ' \
		>> $testroot/stderr.expected
	echo -n "update -b required: will not commit to a branch " \
		>> $testroot/stderr.expected
	echo 'outside the "refs/heads/" reference namespace' \
		>> $testroot/stderr.expected

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_merge_basic
run_test test_merge_forward
run_test test_merge_forward_commit
run_test test_merge_forward_interrupt
run_test test_merge_backward
run_test test_merge_continue
run_test test_merge_continue_new_commit
run_test test_merge_abort
run_test test_merge_in_progress
run_test test_merge_path_prefix
run_test test_merge_missing_file
run_test test_merge_no_op
run_test test_merge_imported_branch
run_test test_merge_interrupt
run_test test_merge_umask
run_test test_merge_gitconfig_author
run_test test_merge_fetched_branch
run_test test_merge_fetched_branch_remote
