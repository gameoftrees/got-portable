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

test_checkout_basic() {
	local testroot=`test_init checkout_basic`
	local commit_id=`git_show_head $testroot/repo`

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_dir_exists() {
	local testroot=`test_init checkout_dir_exists`
	local commit_id=`git_show_head $testroot/repo`

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	mkdir $testroot/wt

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_dir_not_empty() {
	local testroot=`test_init checkout_dir_not_empty`
	local commit_id=`git_show_head $testroot/repo`

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	mkdir $testroot/wt
	touch $testroot/wt/foo

	got checkout $testroot/repo $testroot/wt > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "checkout succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: $testroot/wt: directory exists and is not empty" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_checkout_into_repo() {
	local testroot=`test_init checkout_into_repo`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/repo/wt \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "checkout succeeded unexpectedly" >&2
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

	echo -n "got: work tree and repository paths may not overlap: " \
		> $testroot/stderr.expected
	echo "$testroot/repo/wt: bad path" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_checkout_overlap_repo() {
	local testroot=`test_init checkout_into_repo`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "checkout succeeded unexpectedly" >&2
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

	echo -n "got: work tree and repository paths may not overlap: " \
		> $testroot/stderr.expected
	echo "$testroot: bad path" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_checkout_sets_xbit() {
	local testroot=`test_init checkout_sets_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding executable file"
	local commit_id=`git_show_head $testroot/repo`

	echo "A  $testroot/wt/xfile" > $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

test_checkout_commit_from_wrong_branch() {
	local testroot=`test_init checkout_commit_from_wrong_branch`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on new branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on new branch"

	local head_rev=`git_show_head $testroot/repo`
	got checkout -b master -c $head_rev $testroot/repo $testroot/wt \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: target commit is not contained in branch 'master'; " \
		> $testroot/stderr.expected
	echo -n "the branch to use must be specified with -b; if necessary " \
		>> $testroot/stderr.expected
	echo -n "a new branch can be created for this commit with "\
		>> $testroot/stderr.expected
	echo "'got branch -c $head_rev BRANCH_NAME'" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_checkout_tag() {
	local testroot=`test_init checkout_tag`
	local commit_id=`git_show_head $testroot/repo`
	local tag="1.0.0"

	git -C $testroot/repo tag -a -m "test" $tag

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout -c $tag $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_ignores_submodules() {
	local testroot=`test_init checkout_ignores_submodules`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'
	local commit_id=`git_show_head $testroot/repo`

	echo "A  $testroot/wt/.gitmodules" > $testroot/stdout.expected
	echo "A  $testroot/wt/alpha" >> $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_read_only() {
	local testroot=`test_init checkout_read_only`
	local commit_id=`git_show_head $testroot/repo`

	# Make the repository read-only
	chmod -R a-w $testroot/repo

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: warning: could not create a reference " \
		> $testroot/stderr.expected
	echo -n "to the work tree's base commit; the commit could " \
		>> $testroot/stderr.expected
	echo -n "be garbage-collected by Git or 'gotadmin cleanup'; " \
		>> $testroot/stderr.expected
	echo -n "making the repository " >> $testroot/stderr.expected
	echo "writable and running 'got update' will prevent this" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	chmod -R u+w $testroot/repo # make repo cleanup work
	test_done "$testroot" "$ret"
}

test_checkout_into_nonempty_dir() {
	local testroot=`test_init checkout_into_nonempty_dir`
	local commit_id=`git_show_head $testroot/repo`

	mkdir -p $testroot/wt
	make_test_tree $testroot/wt

	got checkout $testroot/repo $testroot/wt > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "checkout succeeded unexpectedly" >&2
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

	echo "got: $testroot/wt: directory exists and is not empty" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "E  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "E  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout -E $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "E  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "E  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout -E $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# retry, but with alpha modified

	rm -rf "$testroot/wt/.got"
	echo modified alpha >$testroot/wt/alpha

	echo "E  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "E  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "E  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout -E $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_checkout_symlink() {
	local testroot=`test_init checkout_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s passwd.link passwd2.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -s .got/foo dotgotfoo.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/alpha.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/dotgotfoo.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/beta.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/nonexistent.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/passwd.link" >> $testroot/stdout.expected
	echo "A  $testroot/wt/passwd2.link" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon.link > $testroot/stdout
	echo "epsilon" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/passwd2.link ]; then
		echo "passwd2.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/passwd2.link > $testroot/stdout
	echo "passwd.link" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/nonexistent.link > $testroot/stdout
	echo "nonexistent" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotfoo.link ]; then
		echo -n "dotgotfoo.link symlink points into .got dir: " >&2
		readlink $testroot/wt/dotgotfoo.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n ".got/foo" > $testroot/content.expected
	cp $testroot/wt/dotgotfoo.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_symlink_relative_wtpath() {
	local testroot=`test_init checkout_symlink_with_wtpath`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -s .got/foo dotgotfoo.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"

	(cd $testroot && got checkout $testroot/repo wt > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon.link > $testroot/stdout
	echo "epsilon" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/nonexistent.link > $testroot/stdout
	echo "nonexistent" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotfoo.link ]; then
		echo -n "dotgotfoo.link symlink points into .got dir: " >&2
		readlink $testroot/wt/dotgotfoo.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n ".got/foo" > $testroot/content.expected
	cp $testroot/wt/dotgotfoo.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_repo_with_unknown_extension() {
	local testroot=`test_init checkout_repo_with_unknown_extension`

	git -C $testroot/repo config --add extensions.badExtension foobar
	git -C $testroot/repo config --add extensions.otherBadExtension 0

	echo "got: badExtension: unsupported repository format extension" \
		> $testroot/stderr.expected
	got checkout $testroot/repo $testroot/wt \
		> $testroot/stdout 2> $testroot/stderr

	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got checkout command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_checkout_quiet() {
	local testroot=`test_init checkout_quiet`

	echo -n "Checked out refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	printf "\nNow shut up and hack\n" >> $testroot/stdout.expected

	got checkout -q $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_umask() {
	local testroot=`test_init checkout_umask`

	# using a subshell to avoid clobbering global umask
	(umask 044 && got checkout "$testroot/repo" "$testroot/wt") \
		>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	for f in alpha beta epsilon/zeta gamma/delta; do
		ls -l "$testroot/wt/$f" | grep -q ^-rw-------
		if [ $? -ne 0 ]; then
			echo "$f is not 0600 after checkout" >&2
			ls -l "$testroot/wt/$f" >&2
			test_done "$testroot" 1
			return 1
		fi
	done

	for d in epsilon gamma; do
		ls -ld "$testroot/wt/$d" | grep -q ^drwx--x--x
		if [ $? -ne 0 ]; then
			echo "$d is not 711 after checkout" >&2
			ls -ld "$testroot/wt/$d" >&2
			test_done "$testroot" 1
			return 1
		fi
	done

	test_done "$testroot" 0
}

test_checkout_ulimit_n() {
	local testroot=`test_init checkout_ulimit_n`

	echo -n "Checked out refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	printf "\nNow shut up and hack\n" >> $testroot/stdout.expected

	# Drastically reduce the number of files we are allowed to use.
	# This tests our down-scaling of caches which store open file handles.
	# Checkout should still work; if it does not, then either there is
	# a bug or the fixed limit used by this test case is no longer valid
	# and must be raised. Use a subshell to avoid changing global ulimit.
	(ulimit -n 33; got checkout -q $testroot/repo $testroot/wt \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_commit_keywords() {
	local testroot=$(test_init checkout_commit_keywords)

	set -- "$(git_show_head $testroot/repo)"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	for i in $(seq 4); do
		echo "zeta change $i" > "$testroot/wt/epsilon/zeta"

		(cd "$testroot/wt" && got ci -m "commit number $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi
		set -- "$@" "$(git_show_head $testroot/repo)"
	done

	echo "A  $testroot/wt2/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt2/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt2/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt2/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $(pop_idx 4 $@)" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got co -c :head:- $testroot/repo $testroot/wt2 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  $testroot/wt3/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt3/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt3/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt3/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $(pop_idx 4 $@)" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got co -bmaster -c:base:- $testroot/repo $testroot/wt3 > \
	    $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_checkout_tree_with_dot_got() {
	local testroot=`test_init checkout_tree_with_dot_got`

	mkdir -p $testroot/repo/.got
	echo 'foo' > $testroot/repo/.got/foo
	git -C $testroot/repo add .got/foo
	git_commit $testroot/repo -m "adding .got/foo"

	local commit_id=`git_show_head $testroot/repo`

	echo "?  $testroot/wt/.got/foo" > $testroot/stdout.expected
	echo "A  $testroot/wt/alpha" >> $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/master: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_checkout_bad_tree_entry() {
	local testroot=`test_init checkout_bad_tree_entry 1`

	gotadmin load -q -r $testroot/repo < ./testdata/bad-tree-entry.bundle
	local commit_id=d52a061702e571487aaa7419511966945f2a23da
	git -C $testroot/repo update-ref refs/heads/main "$commit_id"
	git -C $testroot/repo symbolic-ref HEAD refs/heads/main

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "?  $testroot/wt/../pwned" > $testroot/stdout.expected
	echo "Checked out refs/heads/main: $commit_id" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/../pwned ]; then
		echo "unexpected file $testroot/wt/../pwned exists" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && ls -a > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
.
..
.got
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret" "1"
}

test_parseargs "$@"
run_test test_checkout_basic
run_test test_checkout_dir_exists
run_test test_checkout_dir_not_empty
run_test test_checkout_into_repo
run_test test_checkout_overlap_repo
run_test test_checkout_sets_xbit
run_test test_checkout_commit_from_wrong_branch
run_test test_checkout_tag
run_test test_checkout_ignores_submodules
run_test test_checkout_read_only
run_test test_checkout_into_nonempty_dir
run_test test_checkout_symlink
run_test test_checkout_symlink_relative_wtpath
run_test test_checkout_repo_with_unknown_extension	no-sha256 # XXX git fsck fails?
run_test test_checkout_quiet
run_test test_checkout_umask
run_test test_checkout_ulimit_n
run_test test_checkout_commit_keywords
run_test test_checkout_tree_with_dot_got
run_test test_checkout_bad_tree_entry
