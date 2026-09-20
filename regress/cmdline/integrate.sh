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

test_integrate_basic() {
	local testroot=`test_init integrate_basic`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rebase failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update -b master > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got integrate newbranch > $testroot/stdout)

	echo "U  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "U  gamma/delta" >> $testroot/stdout.expected
	echo "Integrated refs/heads/newbranch into refs/heads/master" \
		>> $testroot/stdout.expected
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
	echo "commit $new_commit2 (master, newbranch)" \
		> $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $master_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)
	echo "Already up-to-date" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_integrate_requires_rebase_first() {
	local testroot=`test_init integrate_requires_rebase_first`
	local init_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	got checkout -b master $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got integrate newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got integrate succeeded unexpectedly"
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

	echo "got: specified branch must be rebased first" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got log -c master | \
		grep ^commit > $testroot/stdout)
	echo "commit $master_commit (master)" > $testroot/stdout.expected
	echo "commit $init_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got log -c newbranch | \
		grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (newbranch)" \
		> $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $init_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got branch -l > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rebase failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "  master: $master_commit" > $testroot/stdout.expected
	echo "  newbranch: $new_commit2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_integrate_path_prefix() {
	local testroot=`test_init integrate_path_prefix`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rebase failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	rm -r $testroot/wt
	got checkout -b master -p epsilon $testroot/repo $testroot/wt \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got integrate newbranch > $testroot/stdout)

	echo "A  new" > $testroot/stdout.expected
	echo "Integrated refs/heads/newbranch into refs/heads/master" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_integrate_backwards_in_time() {
	local testroot=`test_init integrate_backwards_in_time`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rebase failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	# attempt to integrate master into newbranch (wrong way around)
	(cd $testroot/wt && got update -b newbranch > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly"
		test_done "$testroot" "$ret"
	 return 1
	fi

	(cd $testroot/wt && got integrate master \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got integrate succeeded unexpectedly"
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

	echo "got: specified branch must be rebased first" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_integrate_replace_symlink_with_file() {
	local testroot=`test_init integrate_replace_symlink_with_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -s alpha alpha.link)
	(cd $testroot/wt && got add alpha alpha.link >/dev/null)
	(cd $testroot/wt && got commit -m "add regular file and symlink" \
		>/dev/null)

	(cd $testroot/wt && got br replace_symlink_with_file >/dev/null)
	(cd $testroot/wt && rm alpha.link >/dev/null)
	(cd $testroot/wt && cp alpha alpha.link)
	(cd $testroot/wt && got stage alpha.link >/dev/null)
	(cd $testroot/wt && got commit -m "replace symlink" >/dev/null)

	(cd $testroot/wt && got up -b master >/dev/null)
	(cd $testroot/wt && got integrate replace_symlink_with_file \
		> $testroot/stdout)

	echo "U  alpha.link" > $testroot/stdout.expected
	echo -n "Integrated refs/heads/replace_symlink_with_file " \
		>> $testroot/stdout.expected
	echo "into refs/heads/master" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is still a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	cat $testroot/wt/alpha.link > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_integrate_replace_file_with_symlink() {
	local testroot=`test_init integrate_replace_file_with_symlink`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got br replace_file_with_symlink >/dev/null)
	(cd $testroot/wt && rm alpha)
	(cd $testroot/wt && ln -s beta alpha)
	(cd $testroot/wt && got commit -m "replace regular file with symlink" \
		>/dev/null)

	(cd $testroot/wt && got up -b master >/dev/null)
	(cd $testroot/wt && got integrate replace_file_with_symlink \
		> $testroot/stdout)

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Integrated refs/heads/replace_file_with_symlink " \
		>> $testroot/stdout.expected
	echo "into refs/heads/master" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/alpha ]; then
		echo "alpha is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha > $testroot/stdout
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_integrate_into_nonbranch() {
	local testroot=`test_init test_integrate_into_nonbranch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local commit=`git_show_head $testroot/repo`
	(cd $testroot/repo && got ref -c $commit refs/remotes/origin/master)

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"

	(cd $testroot/wt && got up -b origin/master > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got branch failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got integrate master \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got integrate succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: will not integrate into a reference outside the " \
		> $testroot/stderr.expected
	echo "\"refs/heads/\" reference namespace" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_integrate_with_obstructed_file() {
	local testroot=`test_init integrate_with_obstructed_file`
	local commit0=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	echo "new file on branch" > $testroot/repo/gamma/new
	git -C $testroot/repo add gamma/new > /dev/null
	git_commit $testroot/repo -m "committing changes on newbranch"
	local commit1=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir $testroot/wt/gamma/new
	echo newfile > $testroot/wt/gamma/new/newfile
	
	(cd $testroot/wt && got integrate newbranch > $testroot/stdout)

	echo "U  gamma/delta" >> $testroot/stdout.expected
	echo "~  gamma/new" >> $testroot/stdout.expected
	echo "Integrated refs/heads/newbranch into refs/heads/master" \
		>> $testroot/stdout.expected
	echo "File paths obstructed by a non-regular file: 1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $commit1 (master, newbranch)" \
		> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "?  gamma/new/newfile" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	rm -r $testroot/wt/gamma/new

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "A  gamma/new" > $testroot/stdout.expected
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
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_integrate_basic
run_test test_integrate_requires_rebase_first
run_test test_integrate_path_prefix
run_test test_integrate_backwards_in_time
run_test test_integrate_replace_symlink_with_file
run_test test_integrate_replace_file_with_symlink
run_test test_integrate_into_nonbranch
run_test test_integrate_with_obstructed_file
