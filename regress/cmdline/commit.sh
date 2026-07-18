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

test_commit_basic() {
	local testroot=`test_init commit_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got commit -m 'test commit_basic' > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "M  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_new_subdir() {
	local testroot=`test_init commit_new_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/d
	echo "new file" > $testroot/wt/d/new
	echo "another new file" > $testroot/wt/d/new2
	(cd $testroot/wt && got add d/new >/dev/null)
	(cd $testroot/wt && got add d/new2 >/dev/null)

	(cd $testroot/wt && \
		got commit -m 'test commit_new_subdir' > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  d/new" > $testroot/stdout.expected
	echo "A  d/new2" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_subdir() {
	local testroot=`test_init commit_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && \
		got commit -m 'test commit_subdir' epsilon > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_subdirs() {
	local testroot=`test_init commit_subdir`

	# trailing slash for -p on purpose, we used to have a bug
	# that was triggered by the presence of trailing slashes.
	got checkout -p epsilon/ $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/foo/bar
	mkdir -p $testroot/wt/foo/baz

	echo omega > $testroot/wt/foo/bar/omega
	echo kappa > $testroot/wt/foo/bar/kappa

	(cd $testroot/wt && got add -R foo >$testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  foo/bar/kappa" > $testroot/stdout.expected
	echo "A  foo/bar/omega" >>$testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && \
		got commit -m 'test commit_subdirs' > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  foo/bar/kappa" > $testroot/stdout.expected
	echo "A  foo/bar/omega" >>$testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_single_file() {
	local testroot=`test_init commit_single_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got commit -m 'changed zeta' epsilon/zeta \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_out_of_date() {
	local testroot=`test_init commit_out_of_date`
	local first_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit -m 'test commit_out_of_date' \
		> $testroot/stdout 2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	echo "got: work tree must be updated before these" \
		"changes can be committed" > $testroot/stderr.expected

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

	echo "alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "reset alpha contents"
	(cd $testroot/wt && got update -c $first_commit > /dev/null)

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit -m 'changed alpha ' > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local head_rev=`git_show_head $testroot/repo`
	echo "M  alpha" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_added_subdirs() {
	local testroot=`test_init commit_added_subdirs`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/d
	echo "new file" > $testroot/wt/d/new
	echo "new file 2" > $testroot/wt/d/new2
	mkdir -p $testroot/wt/d/f
	echo "new file 3" > $testroot/wt/d/f/new3
	mkdir -p $testroot/wt/d/f/g
	echo "new file 4" > $testroot/wt/d/f/g/new4

	(cd $testroot/wt && got add $testroot/wt/*/new* \
		$testroot/wt/*/*/new* $testroot/wt/*/*/*/new* > /dev/null)

	(cd $testroot/wt && got commit -m 'test commit_added_subdirs' \
		> $testroot/stdout 2> $testroot/stderr)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  d/f/g/new4" > $testroot/stdout.expected
	echo "A  d/f/new3" >> $testroot/stdout.expected
	echo "A  d/new" >> $testroot/stdout.expected
	echo "A  d/new2" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_deleted_subdirs() {
	local testroot=`test_init commit_deleted_subdirs`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && \
		got rm -R $testroot/wt/epsilon $testroot/wt/gamma >/dev/null)

	(cd $testroot/wt && got commit -m 'test commit_deleted_subdirs' \
		> $testroot/stdout 2> $testroot/stderr)

	local head_rev=`git_show_head $testroot/repo`
	echo "D  epsilon/zeta" > $testroot/stdout.expected
	echo "D  gamma/delta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo > $testroot/stdout

	echo "alpha" > $testroot/stdout.expected
	echo "beta" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_rejects_conflicted_file() {
	local testroot=`test_init commit_rejects_conflicted_file`

	local initial_rev=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update -c $initial_rev > /dev/null)

	echo "modified alpha, too" > $testroot/wt/alpha

	echo "C  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m 'commit it' > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got commit succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "C  alpha" > $testroot/stdout.expected
	echo "got: cannot commit file in conflicted status" \
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

	(cd $testroot/wt && got commit -C -m 'commit it' > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# make sure the conflicted commit produces a diff
	local conflict_commit=`git_show_head $testroot/repo`
	local blob_minus=`got tree -r $testroot/repo -c $commit_id1 -i | \
	    grep 'alpha$' | cut -d' ' -f1`
	local blob_plus=`got tree -r $testroot/repo -c $conflict_commit -i | \
	    grep 'alpha$' | cut -d' ' -f1`

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -c master > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cat > $testroot/stdout.expected <<EOF
diff $commit_id1 refs/heads/master
commit - $commit_id1
commit + $conflict_commit
blob - $blob_minus
blob + $blob_plus
--- alpha
+++ alpha
@@ -1 +1,7 @@
+<<<<<<< merged change: commit $commit_id1
 modified alpha
+||||||| 3-way merge base: commit $initial_rev
+alpha
+=======
+modified alpha, too
+>>>>>>>
EOF

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
	fi
	test_done "$testroot" "$ret"
}

test_commit_single_file_multiple() {
	local testroot=`test_init commit_single_file_multiple`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	for i in 1 2 3 4; do
		echo "modified alpha" >> $testroot/wt/alpha

		(cd $testroot/wt && \
			got commit -m "changed alpha" > $testroot/stdout)

		local head_rev=`git_show_head $testroot/repo`
		echo "M  alpha" > $testroot/stdout.expected
		echo "Created commit $head_rev" >> $testroot/stdout.expected

		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

test_commit_added_and_modified_in_same_dir() {
	local testroot=`test_init commit_added_and_modified_in_same_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified zeta" > $testroot/wt/epsilon/zeta
	echo "new file" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new >/dev/null)

	(cd $testroot/wt && got commit \
		-m 'added and modified in same dir' > $testroot/stdout \
		2> $testroot/stderr)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_path_prefix() {
	local testroot=`test_init commit_path_prefix`
	local commit1=`git_show_head $testroot/repo`

	got checkout -p gamma $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta" > $testroot/wt/delta

	(cd $testroot/wt && got commit -m 'changed gamma/delta' > $testroot/stdout)

	local commit2=`git_show_head $testroot/repo`
	echo "M  delta" > $testroot/stdout.expected
	echo "Created commit $commit2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $commit1 $commit2" > $testroot/stdout.expected
	echo "commit - $commit1" >> $testroot/stdout.expected
	echo "commit + $commit2" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit1 -i gamma | grep 'delta$' \
		| cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit2 -i gamma | grep 'delta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo '--- gamma/delta' >> $testroot/stdout.expected
	echo '+++ gamma/delta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-delta' >> $testroot/stdout.expected
	echo '+modified delta' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit1 $commit2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm delta > /dev/null)
	echo new > $testroot/wt/new
	(cd $testroot/wt && got add new > /dev/null)

	(cd $testroot/wt && got commit -m 'remove gamma/delta; add gamma/new' \
		> $testroot/stdout)

	local commit3=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "D  delta" >> $testroot/stdout.expected
	echo "Created commit $commit3" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $commit2 $commit3" > $testroot/stdout.expected
	echo "commit - $commit2" >> $testroot/stdout.expected
	echo "commit + $commit3" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit2 -i gamma | grep 'delta$' \
		| cut -d' ' -f 1 | sed -e 's/$/ (mode 644)/' \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- gamma/delta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-modified delta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit3 -i gamma | grep 'new$' | \
		cut -d' ' -f 1 | sed -e 's/$/ (mode 644)/' \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ gamma/new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit2 $commit3 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
	return "$ret"
}

test_commit_dir_path() {
	local testroot=`test_init commit_dir_path`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got commit -m 'changed zeta' epsilon \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "M  alpha" > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_selected_paths() {
	local testroot=`test_init commit_selected_paths`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified delta" > $testroot/wt/gamma/delta
	echo "modified zeta" > $testroot/wt/epsilon/zeta
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got commit -m 'many paths' nonexistent alpha \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "commit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: nonexistent: no changes to commit" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m 'many paths' \
		beta new gamma > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "M  gamma/delta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_outside_refs_heads() {
	local testroot=`test_init commit_outside_refs_heads`

	got ref -r $testroot/repo -c master refs/remotes/origin/master

	got checkout -b refs/remotes/origin/master \
	    $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit -m 'change alpha' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "commit succeeded unexpectedly" >&2
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

	echo -n "got: will not commit to a branch outside the " \
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

test_commit_no_email() {
	local testroot=`test_init commit_no_email`
	local errmsg=""

	errmsg="commit author's email address is required for"
	errmsg="$errmsg compatibility with Git"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && env GOT_AUTHOR=":flan_hacker:" \
		got commit -m 'test no email' > $testroot/stdout \
		2> $testroot/stderr)

	printf "got: :flan_hacker:: %s\n" "$errmsg" > $testroot/stderr.expected
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
		test_done "$testroot" $ret
		return 1
	fi

	# try again with a newline inside the email
	(cd $testroot/wt \
		&& FS=' ' env GOT_AUTHOR="$(printf "Flan <hack\ner>")" \
		got commit -m 'test invalid email' > $testroot/stdout \
		2> $testroot/stderr)

	printf "got: Flan <hack\ner>: %s\n" "$errmsg" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" $ret
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" $ret
		return 1
	fi

	# try again with a < inside the email
	(cd $testroot/wt && env GOT_AUTHOR="$(printf "Flan <ha<ker>")" \
		got commit -m 'test invalid email' > $testroot/stdout \
		2> $testroot/stderr)

	printf "got: Flan <ha<ker>: %s\n" "$errmsg" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" $ret
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" $ret
}

test_commit_tree_entry_sorting() {
	local testroot=`test_init commit_tree_entry_sorting`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# Git's index gets corrupted when tree entries are written in the
	# order defined by got_path_cmp() rather than Git's own ordering.
	# Create a new tree where a directory "got" and a file "got-version"
	# would sort in the wrong order according to Git's opinion.
	mkdir $testroot/wt/got
	touch $testroot/wt/got/foo
	echo foo > $testroot/wt/got-version
	echo zzz > $testroot/wt/zzz
	(cd $testroot/wt && got add got-version got/foo zzz > /dev/null)

	(cd $testroot/wt && got commit -m 'test' > /dev/null)

	# Let git-fsck verify the newly written tree to make sure Git is happy
	git -C $testroot/repo fsck --strict  \
		> $testroot/fsck.stdout 2> $testroot/fsck.stderr
	ret=$?
	test_done "$testroot" "$ret"
}

test_commit_cmdline_author() {
	local testroot=`test_init commit_cmdline_author`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha

	local author="Foo <foo@example.com>"
	(cd $testroot/wt && got commit -A "$author" -m 'edit alpha') \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	(cd $testroot/repo && got log -l1 | egrep '^(from|via):') \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	echo "from: $author" > $testroot/stdout.expected
	echo "via: $GOT_AUTHOR" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" $ret
}

test_commit_gotconfig_author() {
	local testroot=`test_init commit_gotconfig_author`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	echo 'author "Flan Luck <flan_luck@openbsd.org>"' \
		> $testroot/repo/.git/got.conf

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test gotconfig author' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

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

test_commit_gotconfig_worktree_author() {
	local testroot=`test_init commit_gotconfig_worktree_author`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	echo 'author "Flan Luck <flan_luck@openbsd.org>"' \
		> $testroot/repo/.git/got.conf
	echo 'author "Flan Squee <flan_squee@openbsd.org>"' \
		> $testroot/wt/.got/got.conf

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test gotconfig author' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got log -l1 | grep ^from: > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "from: Flan Squee <flan_squee@openbsd.org>" \
		> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_gitconfig_author() {
	local testroot=`test_init commit_gitconfig_author`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo config user.name 'Flan Luck'
	git -C $testroot/repo config user.email 'flan_luck@openbsd.org'

	echo "modified alpha" > $testroot/wt/alpha

	# unset in a subshell to avoid affecting our environment
	(unset GOT_IGNORE_GITCONFIG && cd $testroot/wt && \
		 got commit -m 'test gitconfig author' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

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
		test_done "$testroot" "$ret"
		return 1
	fi

	# retry with spaces in the git config
	ed -s "$testroot/repo/.git/config" <<EOF
/^\[user/ a
    # it's me!
.
,s/	/    /g
wq
EOF
	echo "modified again" > $testroot/wt/alpha

	# unset in a subshell to avoid affecting our environment
	(unset GOT_IGNORE_GITCONFIG && cd "$testroot/wt" && \
		got commit -m 'test gitconfig author again' \
		>/dev/null 2>$testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# shouldn't have triggered any parsing error
	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$testroot/repo" && got log -l1 | grep ^from: > $testroot/stdout)
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

test_commit_xbit_change() {
	local testroot=`test_init commit_xbit_change`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	chmod +x $testroot/wt/alpha

	echo 'm  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -mx > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo 'm  alpha' > $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
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

	chmod -x $testroot/wt/alpha

	echo 'm  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -mx > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo 'm  alpha' > $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	chmod +x $testroot/wt/alpha

	echo 'm  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

commit_check_mode() {
	local mode="$1"
	local expected_mode="$2"

	chmod 644 $testroot/wt/alpha
	echo a >> $testroot/wt/alpha
	chmod $mode $testroot/wt/alpha

	(cd $testroot/wt && got commit -mm > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo 'M  alpha' > $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local tree_id=$(got cat -r $testroot/repo $commit_id | \
		grep ^tree | cut -d' ' -f2)
	local alpha_id=$(got cat -r $testroot/repo $tree_id | \
		grep 'alpha$' | cut -d' ' -f1)
	echo "$alpha_id $expected_mode alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo $tree_id | grep 'alpha$' > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	return $ret
}

test_commit_normalizes_filemodes() {
	local testroot=`test_init commit_normalizes_filemodes`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	modes="600 400 460 640 440 660 444 666"
	for m in $modes; do
		commit_check_mode "$m" "0100644"
		ret=$?
		if [ $ret -ne 0 ]; then
			break
		fi
	done
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	modes="700 500 570 750 550 770 555 777"
	for m in $modes; do
		commit_check_mode "$m" "0100755"
		ret=$?
		if [ $ret -ne 0 ]; then
			break
		fi
	done
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_commit_with_unrelated_submodule() {
	local testroot=`test_init commit_with_unrelated_submodule`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha

	echo "" > $testroot/stdout.expected

	(cd $testroot/wt && got commit -m 'modify alpha' > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_rev=`git_show_head $testroot/repo`
	echo "M  alpha" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

check_symlinks() {
	local wtpath="$1"
	if ! [ -h $wtpath/alpha.link ]; then
		echo "alpha.link is not a symlink"
		return 1
	fi

	readlink $wtpath/alpha.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	if ! [ -h $wtpath/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		return 1
	fi

	readlink $wtpath/epsilon.link > $testroot/stdout
	echo "epsilon" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	if [ -h $wtpath/passwd.link ]; then
		echo -n "passwd.link is a symlink and points outside of work tree: " >&2
		readlink $wtpath/passwd.link >&2
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $wtpath/passwd.link $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "cp command failed unexpectedly" >&2
		return 1
	fi

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		return 1
	fi

	readlink $wtpath/epsilon/beta.link > $testroot/stdout
	echo "../beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	readlink $wtpath/nonexistent.link > $testroot/stdout
	echo "nonexistent" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	return 0
}

test_commit_symlink() {
	local testroot=`test_init commit_symlink`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -s alpha alpha.link)
	(cd $testroot/wt && ln -s epsilon epsilon.link)
	(cd $testroot/wt && ln -s /etc/passwd passwd.link)
	(cd $testroot/wt && ln -s ../beta epsilon/beta.link)
	(cd $testroot/wt && ln -s nonexistent nonexistent.link)
	(cd $testroot/wt && got add alpha.link epsilon.link passwd.link \
		epsilon/beta.link nonexistent.link > /dev/null)

	(cd $testroot/wt && got commit -m 'test commit_symlink' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got commit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: $testroot/wt/passwd.link: " > $testroot/stderr.expected
	echo "symbolic link points outside of paths under version control" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -S -m 'test commit_symlink' \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  alpha.link" > $testroot/stdout.expected
	echo "A  epsilon.link" >> $testroot/stdout.expected
	echo "A  nonexistent.link" >> $testroot/stdout.expected
	echo "A  passwd.link" >> $testroot/stdout.expected
	echo "A  epsilon/beta.link" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# verify created in-repository tree
	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	check_symlinks $testroot/wt2
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/passwd.link ]; then
		echo 'passwd.link is not a symlink' >&2
		test_done "$testroot" 1
		return 1
	fi

	# 'got update' should reinstall passwd.link as a regular file
	(cd $testroot/wt && got update > /dev/null)
	check_symlinks $testroot/wt
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -sf beta alpha.link)
	(cd $testroot/wt && rm epsilon.link && ln -s gamma epsilon.link)
	rm $testroot/wt/epsilon/beta.link
	echo "this is a regular file" > $testroot/wt/epsilon/beta.link
	(cd $testroot/wt && ln -sf .got/bar dotgotbar.link)
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	(cd $testroot/wt && got rm nonexistent.link > /dev/null)
	(cd $testroot/wt && ln -sf gamma/delta zeta.link)
	(cd $testroot/wt && ln -sf alpha new.link)
	(cd $testroot/wt && got add new.link > /dev/null)

	(cd $testroot/wt && got commit -m 'test commit_symlink' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got commit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: $testroot/wt/dotgotbar.link: " > $testroot/stderr.expected
	echo "symbolic link points outside of paths under version control" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -S -m 'test commit_symlink' \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  dotgotbar.link" > $testroot/stdout.expected
	echo "A  new.link" >> $testroot/stdout.expected
	echo "M  alpha.link" >> $testroot/stdout.expected
	echo "M  epsilon/beta.link" >> $testroot/stdout.expected
	echo "M  epsilon.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo -c $head_rev -R > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
alpha.link@ -> beta
beta
dotgotbar.link@ -> .got/bar
epsilon/
epsilon/beta.link
epsilon/zeta
epsilon.link@ -> gamma
gamma/
gamma/delta
new.link@ -> alpha
passwd.link@ -> /etc/passwd
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_fix_bad_symlink() {
	local testroot=`test_init commit_fix_bad_symlink`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -s /etc/passwd passwd.link)
	(cd $testroot/wt && got add passwd.link > /dev/null)

	(cd $testroot/wt && got commit -S -m 'commit bad symlink' \
		> $testroot/stdout)

	if ! [ -h $testroot/wt/passwd.link ]; then
		echo 'passwd.link is not a symlink' >&2
		test_done "$testroot" 1
		return 1
	fi
	(cd $testroot/wt && got update >/dev/null)
	if [ -h $testroot/wt/passwd.link ]; then
		echo "passwd.link is a symlink but should be a regular file" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create another work tree which will contain the "bad" symlink
	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# change "bad" symlink back into a "good" symlink
	(cd $testroot/wt && rm passwd.link && ln -s alpha passwd.link)

	(cd $testroot/wt && got commit -m 'fix bad symlink' \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  passwd.link" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/passwd.link ]; then
		echo 'passwd.link is not a symlink' >&2
		test_done "$testroot" 1
		return 1
	fi

	readlink $testroot/wt/passwd.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	# Update the other work tree; the bad symlink should be fixed
	(cd $testroot/wt2 && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt2/passwd.link ]; then
		echo 'passwd.link is not a symlink' >&2
		test_done "$testroot" 1
		return 1
	fi

	readlink $testroot/wt2/passwd.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	test_done "$testroot" "0"
}

test_commit_prepared_logmsg() {
	local testroot=`test_init commit_prepared_logmsg`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	echo 'test commit_prepared_logmsg' > $testroot/logmsg

	# a no-op editor script
	> $testroot/editor.sh
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env VISUAL="$testroot/editor.sh" \
		got commit -F "$testroot/logmsg" > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "M  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local author_time=`git_show_author_time $testroot/repo`
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	echo "-----------------------------------------------" > $testroot/stdout.expected
	echo "commit $head_rev (master)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test commit_prepared_logmsg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt && got log -l 1 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha again" > $testroot/wt/alpha

	echo 'test commit_prepared_logmsg non-interactive' \
		> $testroot/logmsg

	(cd $testroot/wt && got commit -N -F "$testroot/logmsg" \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  alpha" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local author_time=`git_show_author_time $testroot/repo`
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "commit $head_rev (master)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test commit_prepared_logmsg non-interactive" \
		>> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt && got log -l 1 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_large_file() {
	local testroot=`test_init commit_large_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	dd status=none if=/dev/zero of=$testroot/wt/new bs=1M count=64
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got commit -m 'test commit_large_file' \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	new_id=`get_blob_id $testroot/repo "" new`
	got cat -r $testroot/repo $new_id > $testroot/new
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/new $testroot/wt/new
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/new $testroot/wt/new
	fi
	test_done "$testroot" "$ret"


}

test_commit_gitignore() {
	local testroot=`test_init commit_gitignores`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/tree1/foo
	mkdir -p $testroot/wt/tree2/foo
	echo "tree1/**" > $testroot/wt/.gitignore
	echo "tree2/**" >> $testroot/wt/.gitignore
	echo -n > $testroot/wt/tree1/bar
	echo -n > $testroot/wt/tree1/foo/baz
	echo -n > $testroot/wt/tree2/bar
	echo -n > $testroot/wt/tree2/foo/baz
	echo -n > $testroot/wt/epsilon/zeta1
	echo -n > $testroot/wt/epsilon/zeta2

	(cd $testroot/wt && got add -I -R tree1 > /dev/null)
	(cd $testroot/wt && got add -I tree2/foo/baz > /dev/null)
	(cd $testroot/wt && got commit -m "gitignore add" > /dev/null)
	(cd $testroot/wt && got log -P -l 1 | egrep '^ .' > $testroot/stdout)

	echo ' gitignore add' > $testroot/stdout.expected
	echo ' A  tree1/bar' >> $testroot/stdout.expected
	echo ' A  tree1/foo/baz' >> $testroot/stdout.expected
	echo ' A  tree2/foo/baz' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo touch > $testroot/wt/tree1/bar
	echo touch > $testroot/wt/tree1/foo/baz
	echo touch > $testroot/wt/epsilon/zeta1

	(cd $testroot/wt && got commit -m "gitignore change" > /dev/null)
	(cd $testroot/wt && got log -P -l 1 | egrep '^ .' > $testroot/stdout)

	echo ' gitignore change' > $testroot/stdout.expected
	echo ' M  tree1/bar' >> $testroot/stdout.expected
	echo ' M  tree1/foo/baz' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_commit_bad_author() {
	local testroot=`test_init commit_bad_author`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit \
		-A "${GIT_AUTHOR_NAME}<${GIT_AUTHOR_EMAIL}>" -m 'edit alpha') \
		> /dev/null 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		test_done "$testroot" 1
		return 1
	fi

	echo -n "got: ${GIT_AUTHOR_NAME}<${GIT_AUTHOR_EMAIL}>: " \
	     > $testroot/stderr.expected
	echo -n 'space between author name and email required: ' \
	     >> $testroot/stderr.expected
	echo 'commit author formatting would make Git unhappy' \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" $ret
		return 1
	fi

	test_done "$testroot" 0
}

test_commit_logmsg_ref() {
	local testroot=`test_init commit_logmsg_ref`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q -b newbranch

	local bo_logmsg_prefix="log message of backed-out commit"
	local cy_logmsg_prefix="log message of cherrypicked commit"
	local branch_rev_logmsg="changes on newbranch to cherrypick"
	local branch_rev2_logmsg="modified zeta on newbranch to cherrypick"

	echo "modified delta on branch" > $testroot/repo/gamma/delta
	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new

	git_commit $testroot/repo -m "$branch_rev_logmsg"
	local branch_rev=`git_show_head $testroot/repo`

	echo "modified zeta on branch" > $testroot/repo/epsilon/zeta

	git_commit $testroot/repo -m "$branch_rev2_logmsg"
	local branch_rev2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $branch_rev > /dev/null)
	(cd $testroot/wt && got cherrypick $branch_rev2 > /dev/null)

	cat > $testroot/editor.sh <<EOF
#!/bin/sh
ed -s "\$1" <<-EOF
	,s/# l/l/
	w
	EOF
EOF
	chmod +x $testroot/editor.sh

	(cd $testroot/wt && env VISUAL="$testroot/editor.sh" \
	    got commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "'got commit' failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# check that multiple cherrypicked log messages populate the editor
	local first=`printf '%s\n%s' $branch_rev $branch_rev2 | sort | head -1`
	local second=`printf '%s\n%s' $branch_rev $branch_rev2 | sort | tail -1`

	if [ $branch_rev = $first ]; then
		local first_msg=$branch_rev_logmsg
		local second_msg=$branch_rev2_logmsg
	else
		local first_msg=$branch_rev2_logmsg
		local second_msg=$branch_rev_logmsg
	fi

	echo " $cy_logmsg_prefix $first:" > $testroot/stdout.expected
	echo " $first_msg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " $cy_logmsg_prefix $second:" >> $testroot/stdout.expected
	echo " $second_msg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt && got log -l2 | \
	    grep -A2 'log message' | sed '/^--/d' > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check that only the relevant log message populates the editor
	# when the changes from one of two backout commits are reverted
	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt2 && got backout $branch_rev > /dev/null)
	(cd $testroot/wt2 && got backout $branch_rev2 > /dev/null)
	(cd $testroot/wt2 && got revert epsilon/zeta > /dev/null)

	(cd $testroot/wt2 && env VISUAL="$testroot/editor.sh" \
	    got commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "'got commit' failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo " $bo_logmsg_prefix $branch_rev:" > $testroot/stdout.expected
	echo " $branch_rev_logmsg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt2 && got log -l1 | \
	    grep -A2 'log message' > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check that a cherrypicked log message is still
	# used when its changes are only partially reverted
	branch_rev_logmsg="changes to cherrypick and partially revert"

	echo "newline in alpha" >> $testroot/repo/alpha
	echo "modified epsilon/zeta on branch" > $testroot/repo/epsilon/zeta

	git_commit $testroot/repo -m "$branch_rev_logmsg"
	branch_rev=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $branch_rev > /dev/null)
	(cd $testroot/wt && got revert alpha > /dev/null)

	(cd $testroot/wt && env VISUAL="$testroot/editor.sh" \
	    got commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "'got commit' failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo " $cy_logmsg_prefix $branch_rev:" > $testroot/stdout.expected
	echo " $branch_rev_logmsg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt && got log -l1 | \
	    grep -A2 'log message' > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# check we don't use and consequently delete the logmsg ref of a
	# cherrypicked commit when omitting its changed path from the commit
	branch_rev_logmsg="changes to cherrypick but omit from the commit"

	echo "changed delta" >> $testroot/repo/gamma/delta

	git_commit $testroot/repo -m "$branch_rev_logmsg"
	local author_time=`git_show_author_time $testroot/repo`
	local d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	branch_rev=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got cherrypick $branch_rev > /dev/null)

	echo "changed alpha" >> $testroot/wt/alpha

	(cd $testroot/wt && got commit -m \
	    "don't commit cy change to gamma/delta" alpha > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "'got commit' failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# confirm logmsg ref was not deleted with got cherrypick -l
	echo "-----------------------------------------------" \
	    > $testroot/stdout.expected
	echo "cherrypick $branch_rev (newbranch)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " $branch_rev_logmsg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " M  gamma/delta" >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got cherrypick -l > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# confirm a previously unused logmsg ref is picked up
	# when an affected path is actually committed
	(cd $testroot/wt && env VISUAL="$testroot/editor.sh" \
	    got commit > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "'got commit' failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo " $cy_logmsg_prefix $branch_rev:" > $testroot/stdout.expected
	echo " $branch_rev_logmsg" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected

	(cd $testroot/wt && got log -l1 | \
	    grep -A2 'log message' > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# make sure we are not littering work trees
	# by leaving temp got-logmsg-* files behind
	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "$testroot/wt is not clean"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt2 && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "$testroot/repo is not clean"
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_commit_from_different_worktrees() {
	local testroot=$(test_init commit_from_different_worktrees)

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt2/new
	(cd $testroot/wt2 && got add new >/dev/null)
	(cd $testroot/wt2 && got commit -m 'add new file from wt2' > \
	    $testroot/stdout)
	local wt2_head_id=$(git_show_head $testroot/repo)

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'mod alpha in wt' > $testroot/stdout)
	local wt1_parent_id=$(git_show_parent_commit $testroot/repo)

	if [ $wt2_head_id != $wt1_parent_id ]; then
		echo "commit lost from different work tree" >&2
		test_done "$testroot" "1"
	fi

	test_done "$testroot" "0"
}

test_parseargs "$@"
run_test test_commit_basic
run_test test_commit_new_subdir
run_test test_commit_subdir
run_test test_commit_subdirs
run_test test_commit_single_file
run_test test_commit_out_of_date
run_test test_commit_added_subdirs
run_test test_commit_deleted_subdirs
run_test test_commit_rejects_conflicted_file
run_test test_commit_single_file_multiple
run_test test_commit_added_and_modified_in_same_dir
run_test test_commit_path_prefix
run_test test_commit_dir_path
run_test test_commit_selected_paths
run_test test_commit_outside_refs_heads
run_test test_commit_no_email
run_test test_commit_tree_entry_sorting
run_test test_commit_cmdline_author
run_test test_commit_gotconfig_author
run_test test_commit_gotconfig_worktree_author
run_test test_commit_gitconfig_author
run_test test_commit_xbit_change
run_test test_commit_normalizes_filemodes
run_test test_commit_with_unrelated_submodule
run_test test_commit_symlink
run_test test_commit_fix_bad_symlink
run_test test_commit_prepared_logmsg
run_test test_commit_large_file
run_test test_commit_gitignore
run_test test_commit_bad_author
run_test test_commit_logmsg_ref
run_test test_commit_from_different_worktrees
