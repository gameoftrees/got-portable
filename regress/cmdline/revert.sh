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

test_revert_basic() {
	local testroot=`test_init revert_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	echo 'R  epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got revert epsilon/zeta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"

}

test_revert_rm() {
	local testroot=`test_init revert_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta >/dev/null)

	echo 'R  beta' > $testroot/stdout.expected

	(cd $testroot/wt && got revert beta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
		test_done "$testroot" "$ret"
}

test_revert_add() {
	local testroot=`test_init revert_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	echo 'R  new' > $testroot/stdout.expected

	(cd $testroot/wt && got revert new > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '?  new' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_multiple() {
	local testroot=`test_init revert_multiple`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	echo 'R  alpha' > $testroot/stdout.expected
	echo 'R  epsilon/zeta' >> $testroot/stdout.expected

	(cd $testroot/wt && got revert alpha epsilon/zeta > $testroot/stdout)

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
	fi
	test_done "$testroot" "$ret"
}

test_revert_file_in_new_subdir() {
	local testroot=`test_init revert_file_in_new_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi


	mkdir -p $testroot/wt/newdir
	echo new > $testroot/wt/newdir/new
	(cd $testroot/wt && got add newdir/new > /dev/null)

	(cd $testroot/wt && got revert newdir/new > $testroot/stdout)

	echo "R  newdir/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "?  newdir/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_revert_no_arguments() {
	local testroot=`test_init revert_no_arguments`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "revert command succeeded unexpectedly" >&2
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

	echo "usage: got revert [-pR] [-F response-script] path ..." \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_revert_directory() {
	local testroot=`test_init revert_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert . > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got revert command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: reverting directories requires -R option" \
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
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	echo 'R  epsilon/zeta' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_revert_directory_unknown() {
	local testroot=`test_init revert_directory_unknown`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "new untracked file" > $testroot/wt/epsilon/new_file
	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	echo 'R  alpha' > $testroot/stdout.expected
	echo 'R  epsilon/zeta' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new untracked file" > $testroot/content.expected
	cat $testroot/wt/epsilon/new_file > $testroot/content

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
	fi

	test_done "$testroot" "$ret"
}

test_revert_missing_directory() {
	local testroot=`test_init revert_missing_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm -r $testroot/wt/epsilon

	(cd $testroot/wt && got revert -R epsilon > $testroot/stdout)

	echo 'R  epsilon/zeta' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi

	test_done "$testroot" "$ret"
}

test_revert_patch() {
	local testroot=`test_init revert_patch`

	seq 16 > $testroot/repo/numbers
	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/wt/numbers <<-\EOF
	,s/^2$/a/
	,s/^7$/b/
	,s/^16$/c/
	w
	EOF

	(cd $testroot/wt && got diff > $testroot/numbers.diff)

	# don't revert any hunks
	printf "n\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/numbers.diff $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/numbers.diff $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# revert first hunk
	printf "y\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] y
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
EOF
	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# put first hunk back
	ed -s $testroot/wt/numbers <<-\EOF
	,s/^2$/a/
	w
	EOF

	# revert middle hunk
	printf "n\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# revert last hunk
	printf "n\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 2)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 2 of 2)
revert this change? [y/n/q] y
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_patch_added() {
	local testroot=`test_init revert_patch_added`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)

	printf "n\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "revert this addition? [y/n] n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "A  epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "revert this addition? [y/n] y" >> $testroot/stdout.expected
	echo "R  epsilon/new" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "?  epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_patch_removed() {
	local testroot=`test_init revert_patch_removed`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	printf "n\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		beta > $testroot/stdout)
	echo "D  beta" > $testroot/stdout.expected
	echo "revert this deletion? [y/n] n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "D  beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		beta > $testroot/stdout)

	echo "D  beta" > $testroot/stdout.expected
	echo "revert this deletion? [y/n] y" >> $testroot/stdout.expected
	echo "R  beta" >> $testroot/stdout.expected
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

test_revert_patch_one_change() {
	local testroot=`test_init revert_patch_one_change`

	seq 16 > $testroot/repo/numbers
	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure file size is changed. Avoids race condition causing test
	# failures where 'got revert' does not see changes to revert if
	# timestamps and size in stat info remain unchanged.
	ed -s $testroot/wt/numbers <<-\EOF
	,s/^2$/aa/
	w
	EOF

	# revert change with -p
	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+aa
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 1)
revert this change? [y/n/q] y
EOF
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

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

	(cd $testroot/wt && got diff > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_added_subtree() {
	local testroot=`test_init revert_added_subtree`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/epsilon/foo/bar/baz
	mkdir -p $testroot/wt/epsilon/foo/bar/bax
	echo "new file" > $testroot/wt/epsilon/foo/a.o
	echo "new file" > $testroot/wt/epsilon/foo/a.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/b.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/b.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/f.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/f.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/c.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/c.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/e.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/e.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/x.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/x.d
	(cd $testroot/wt && got add -R epsilon >/dev/null)

	echo "R  epsilon/foo/a.o" > $testroot/stdout.expected
	echo "R  epsilon/foo/bar/b.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/b.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/e.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/e.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/x.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/x.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/c.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/c.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/f.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/f.o" >> $testroot/stdout.expected

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "?  epsilon/foo/a.o" > $testroot/stdout.expected
	echo "?  epsilon/foo/bar/b.d" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/b.o" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/bax/e.d" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/bax/e.o" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/bax/x.d" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/bax/x.o" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/baz/c.d" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/baz/c.o" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/baz/f.d" >> $testroot/stdout.expected
	echo "?  epsilon/foo/bar/baz/f.o" >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_deleted_subtree() {
	local testroot=`test_init revert_deleted_subtree`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/epsilon/foo/bar/baz
	mkdir -p $testroot/wt/epsilon/foo/bar/bax
	echo "new file" > $testroot/wt/epsilon/foo/a.o
	echo "new file" > $testroot/wt/epsilon/foo/a.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/b.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/b.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/f.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/f.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/c.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/baz/c.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/e.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/e.d
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/x.o
	echo "new file" > $testroot/wt/epsilon/foo/bar/bax/x.d
	(cd $testroot/wt && got add -R epsilon >/dev/null)
	(cd $testroot/wt && got commit -m "add subtree" >/dev/null)

	# now delete and revert the entire subtree
	(cd $testroot/wt && got rm -R epsilon/foo >/dev/null)

	echo "R  epsilon/foo/a.o" > $testroot/stdout.expected
	echo "R  epsilon/foo/bar/b.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/b.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/e.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/e.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/x.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/bax/x.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/c.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/c.o" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/f.d" >> $testroot/stdout.expected
	echo "R  epsilon/foo/bar/baz/f.o" >> $testroot/stdout.expected

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_revert_symlink() {
	local testroot=`test_init revert_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null

	# symlink to file A now points to file B
	(cd $testroot/wt && ln -sf gamma/delta alpha.link)
	# symlink to a directory A now points to file B
	(cd $testroot/wt && rm epsilon.link && ln -s beta epsilon.link)
	# "bad" symlink now contains a different target path
	echo "foo" > $testroot/wt/passwd.link
	# relative symlink to directory A now points to relative directory B
	(cd $testroot/wt && rm epsilon/beta.link && ln -s ../gamma \
		epsilon/beta.link)
	# an unversioned symlink
	(cd $testroot/wt && ln -sf .got/foo dotgotfoo.link)
	# symlink to file A now points to non-existent file B
	(cd $testroot/wt && ln -sf nonexistent2 nonexistent.link)
	# removed symlink
	(cd $testroot/wt && got rm zeta.link > /dev/null)
	# added symlink
	(cd $testroot/wt && ln -sf beta new.link)
	(cd $testroot/wt && got add new.link > /dev/null)

	(cd $testroot/wt && got revert alpha.link epsilon.link \
		passwd.link epsilon/beta.link dotgotfoo.link \
		nonexistent.link zeta.link new.link > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
R  alpha.link
R  epsilon/beta.link
R  epsilon.link
R  new.link
R  nonexistent.link
R  passwd.link
R  zeta.link
EOF
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
		echo "passwd.link should not be a symlink" >&2
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

	if [ ! -h $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is not a symlink " >&2
		test_done "$testroot" "1"
		return 1
	fi
	readlink $testroot/wt/dotgotfoo.link > $testroot/stdout
	echo ".got/foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/zeta.link ]; then
		echo -n "zeta.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/zeta.link > $testroot/stdout
	echo "epsilon/zeta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/new.link ]; then
		echo -n "new.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "?  dotgotfoo.link" > $testroot/stdout.expected
	echo "?  new.link" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_revert_patch_symlink() {
	local testroot=`test_init revert_patch_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta2.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null

	# symlink to file A now points to file B
	(cd $testroot/wt && ln -sf gamma/delta alpha.link)
	# symlink to a directory A now points to file B
	(cd $testroot/wt && rm epsilon.link && ln -s beta epsilon.link)
	# "bad" symlink now contains a different target path
	echo "foo" > $testroot/wt/passwd.link
	# relative symlink to directory A now points to relative directory B
	(cd $testroot/wt && rm epsilon/beta.link && ln -s ../gamma \
		epsilon/beta.link)
	# an unversioned symlink
	(cd $testroot/wt && ln -sf .got/foo dotgotfoo.link)
	# symlink to file A now points to non-existent file B
	(cd $testroot/wt && ln -sf nonexistent2 nonexistent.link)
	# removed symlink
	(cd $testroot/wt && got rm zeta.link > /dev/null)
	(cd $testroot/wt && got rm zeta2.link > /dev/null)
	# added symlink
	(cd $testroot/wt && ln -sf beta new.link)
	(cd $testroot/wt && got add new.link > /dev/null)
	(cd $testroot/wt && ln -sf beta zeta3.link)
	(cd $testroot/wt && got add zeta3.link > /dev/null)

	printf "y\nn\ny\nn\ny\ny\nn\ny\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p -R . \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1 +1 @@
-alpha
\ No newline at end of file
+gamma/delta
\ No newline at end of file
-----------------------------------------------
M  alpha.link (change 1 of 1)
revert this change? [y/n/q] y
R  alpha.link
-----------------------------------------------
@@ -1 +1 @@
-../beta
\ No newline at end of file
+../gamma
\ No newline at end of file
-----------------------------------------------
M  epsilon/beta.link (change 1 of 1)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -1 +1 @@
-epsilon
\ No newline at end of file
+beta
\ No newline at end of file
-----------------------------------------------
M  epsilon.link (change 1 of 1)
revert this change? [y/n/q] y
R  epsilon.link
A  new.link
revert this addition? [y/n] n
-----------------------------------------------
@@ -1 +1 @@
-nonexistent
\ No newline at end of file
+nonexistent2
\ No newline at end of file
-----------------------------------------------
M  nonexistent.link (change 1 of 1)
revert this change? [y/n/q] y
R  nonexistent.link
-----------------------------------------------
@@ -1 +1 @@
-/etc/passwd
\ No newline at end of file
+foo
-----------------------------------------------
M  passwd.link (change 1 of 1)
revert this change? [y/n/q] y
R  passwd.link
D  zeta.link
revert this deletion? [y/n] n
D  zeta2.link
revert this deletion? [y/n] y
R  zeta2.link
A  zeta3.link
revert this addition? [y/n] y
R  zeta3.link
EOF
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
		echo "passwd.link should not be a symlink" >&2
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
	echo "../gamma" > $testroot/stdout.expected
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

	if [ ! -h $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is not a symlink " >&2
		test_done "$testroot" "1"
		return 1
	fi
	readlink $testroot/wt/dotgotfoo.link > $testroot/stdout
	echo ".got/foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi


	if [ -e $testroot/wt/zeta.link ]; then
		echo -n "zeta.link should not exist on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ ! -h $testroot/wt/zeta2.link ]; then
		echo -n "zeta2.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/zeta2.link > $testroot/stdout
	echo "epsilon/zeta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/zeta3.link ]; then
		echo -n "zeta3.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/zeta3.link > $testroot/stdout
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/new.link ]; then
		echo -n "new.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "?  dotgotfoo.link" > $testroot/stdout.expected
	echo "M  epsilon/beta.link" >> $testroot/stdout.expected
	echo "A  new.link" >> $testroot/stdout.expected
	echo "D  zeta.link" >> $testroot/stdout.expected
	echo "?  zeta3.link" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_revert_umask() {
	local testroot=`test_init revert_umask`

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null
	echo "edit alpha" > $testroot/wt/alpha

	# using a subshell to avoid clobbering global umask
	(umask 077 && cd "$testroot/wt" && got revert alpha) \
		>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	if ! ls -l "$testroot/wt/alpha" | grep -q ^-rw-------; then
		echo "alpha is not 0600 after revert" >&2
		ls -l "$testroot/wt/alpha" >&2
		test_done "$testroot" 1
		return 1
	fi
	test_done "$testroot" 0
}

test_revert_patch_binary() {
	local testroot=$(test_init revert_patch_binary)

	dd if=/dev/urandom of=$testroot/repo/binary bs=1024 count=16 \
	    > /dev/null 2>&1
	git -C $testroot/repo add binary
	git_commit $testroot/repo -m "add binary file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/wt/binary <<-EOF
	2m8
	7m16
	15m24
	23m32
	w
	EOF

	cp $testroot/wt/binary $testroot/binary.expected

	# cancel reverting changes with 'n' response
	printf "n\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p binary \
	    > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<-EOF
	-----------------------------------------------
	Binary files binary and binary differ
	-----------------------------------------------
	M  binary (change 1 of 1)
	revert this change? [y/n/q] n
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "M  binary" > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/binary.expected $testroot/wt/binary
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "binary file changes discarded by canceled revert" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# cancel reverting changes with 'q' response
	printf "q\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p binary \
	    > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<-EOF
	-----------------------------------------------
	Binary files binary and binary differ
	-----------------------------------------------
	M  binary (change 1 of 1)
	revert this change? [y/n/q] q
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "M  binary" > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/binary.expected $testroot/wt/binary
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "binary file changes discarded by canceled revert" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# confirm reverting changes with 'y'
	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p binary \
	    > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<-EOF
	-----------------------------------------------
	Binary files binary and binary differ
	-----------------------------------------------
	M  binary (change 1 of 1)
	revert this change? [y/n/q] y
	R  binary
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	seq 16 > $testroot/wt/numbers
	(cd $testroot/wt && got add numbers > /dev/null)
	(cd $testroot/wt && got commit -m "add numbers" numbers > /dev/null)

	ed -s $testroot/wt/numbers <<-EOF
	,s/^2$/x/
	,s/^8$/y/
	,s/^16$/z/
	w
	EOF

	# restore changed binary
	cp -f $testroot/binary.expected $testroot/wt/binary

	# revert last numbers hunk but cancel reverting binary file changes
	printf "n\nn\nn\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p -R .\
	    > $testroot/stdout)

	cat > $testroot/stdout.expected <<-EOF
	-----------------------------------------------
	Binary files binary and binary differ
	-----------------------------------------------
	M  binary (change 1 of 1)
	revert this change? [y/n/q] n
	-----------------------------------------------
	@@ -1,5 +1,5 @@
	 1
	-2
	+x
	 3
	 4
	 5
	-----------------------------------------------
	M  numbers (change 1 of 3)
	revert this change? [y/n/q] n
	-----------------------------------------------
	@@ -5,7 +5,7 @@
	 5
	 6
	 7
	-8
	+y
	 9
	 10
	 11
	-----------------------------------------------
	M  numbers (change 2 of 3)
	revert this change? [y/n/q] n
	-----------------------------------------------
	@@ -13,4 +13,4 @@
	 13
	 14
	 15
	-16
	+z
	-----------------------------------------------
	M  numbers (change 3 of 3)
	revert this change? [y/n/q] y
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "M  binary" > $testroot/stdout.expected
	echo "M  numbers" >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/binary.expected $testroot/wt/binary
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "binary file changes discarded by canceled revert" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# revert first numbers hunk and binary file changes
	printf "y\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p -R . \
	    > $testroot/stdout)

	cat > $testroot/stdout.expected <<-EOF
	-----------------------------------------------
	Binary files binary and binary differ
	-----------------------------------------------
	M  binary (change 1 of 1)
	revert this change? [y/n/q] y
	R  binary
	-----------------------------------------------
	@@ -1,5 +1,5 @@
	 1
	-2
	+x
	 3
	 4
	 5
	-----------------------------------------------
	M  numbers (change 1 of 2)
	revert this change? [y/n/q] y
	-----------------------------------------------
	@@ -5,7 +5,7 @@
	 5
	 6
	 7
	-8
	+y
	 9
	 10
	 11
	-----------------------------------------------
	M  numbers (change 2 of 2)
	revert this change? [y/n/q] n
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "M  numbers" > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" 0
}

test_revert_staged_file() {
	local testroot=`test_init revert_staged_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "line 0" > $testroot/wt/epsilon/zeta
	for i in `seq 1 10`; do
		echo "line $i" >> $testroot/wt/epsilon/zeta
	done

	(cd $testroot/wt && got commit -m 'make zeta a multi-line file' \
		> /dev/null)
	local commit_id=`git_show_head $testroot/repo`

	ed -s $testroot/wt/epsilon/zeta <<-\EOF
	,s/line 0/line 0a/
	,s/line 4/line 4a/
	,s/line 6/line 6a/
	w
	EOF

	# stage line 0 and line 6
	printf "y\n" > $testroot/patchscript
	for i in `seq 1 5`; do
		printf "n\n" >> $testroot/patchscript
	done
	printf "y\n" >> $testroot/patchscript
	for i in `seq 7 10`; do
		printf "n\n" >> $testroot/patchscript
	done

	(cd $testroot/wt && got stage > /dev/null)

	echo ' M epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blobid_zeta=$(get_blob_id $testroot/repo epsilon zeta)
	stageid_zeta=$(cd $testroot/wt && got stage -l epsilon/zeta | cut -d' ' -f 1)

	(cd $testroot/wt && got revert epsilon/zeta > $testroot/stdout)

	echo -n '' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M epsilon/zeta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-eof >$testroot/stdout.expected
	diff -s $testroot/wt
	path + $testroot/wt (staged changes)
	commit - $commit_id
	blob - $blobid_zeta
	blob + $stageid_zeta
	--- epsilon/zeta
	+++ epsilon/zeta
	@@ -1,10 +1,10 @@
	-line 0
	+line 0a
	 line 1
	 line 2
	 line 3
	-line 4
	+line 4a
	 line 5
	-line 6
	+line 6a
	 line 7
	 line 8
	 line 9
	eof

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_revert_partially_staged_file() {
	local testroot=`test_init revert_partially_staged_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "line 0" > $testroot/wt/epsilon/zeta
	for i in `seq 1 10`; do
		echo "line $i" >> $testroot/wt/epsilon/zeta
	done

	(cd $testroot/wt && got commit -m 'make zeta a multi-line file' \
		> /dev/null)
	local commit_id=`git_show_head $testroot/repo`

	ed -s $testroot/wt/epsilon/zeta <<-\EOF
	,s/line 0/line 0a/
	,s/line 4/line 4a/
	,s/line 6/line 6a/
	w
	EOF

	# stage line 0 and line 6
	printf "y\n" > $testroot/patchscript
	for i in `seq 1 5`; do
		printf "n\n" >> $testroot/patchscript
	done
	printf "y\n" >> $testroot/patchscript
	for i in `seq 7 10`; do
		printf "n\n" >> $testroot/patchscript
	done

	(cd $testroot/wt && got stage -F $testroot/patchscript -p > /dev/null)

	echo 'MM epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blobid_zeta=$(get_blob_id $testroot/repo epsilon zeta)
	stageid_zeta=$(cd $testroot/wt && got stage -l epsilon/zeta | \
		cut -d' ' -f 1)

	(cd $testroot/wt && got revert epsilon/zeta > $testroot/stdout)

	echo 'R  epsilon/zeta' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M epsilon/zeta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-eof >$testroot/stdout.expected
	diff -s $testroot/wt
	path + $testroot/wt (staged changes)
	commit - $commit_id
	blob - $blobid_zeta
	blob + $stageid_zeta
	--- epsilon/zeta
	+++ epsilon/zeta
	@@ -1,4 +1,4 @@
	-line 0
	+line 0a
	 line 1
	 line 2
	 line 3
	eof

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_revert_backout_with_path_prefix() {
	local testroot=`test_init revert_backout_with_path_prefix`

	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified zeta" > $testroot/wt2/epsilon/zeta
	(cd $testroot/wt2 && got commit -m 'modify zeta' > /dev/null)
	local commit_id=`git_show_head $testroot/repo`

	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got backout "$commit_id" >/dev/null)

	echo "unversioned file" > $testroot/wt/epsilon

	echo 'R  zeta' > $testroot/stdout.expected

	# This used to fail with:
	# "got: fopen: $testroot/wt/epsilon/.cvsignore: Not a directory"
	(cd $testroot/wt && got revert -R . > $testroot/stdout)

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
	fi
	test_done "$testroot" "$ret"

}

test_parseargs "$@"
run_test test_revert_basic
run_test test_revert_rm
run_test test_revert_add
run_test test_revert_multiple
run_test test_revert_file_in_new_subdir
run_test test_revert_no_arguments
run_test test_revert_directory
run_test test_revert_directory_unknown
run_test test_revert_missing_directory
run_test test_revert_patch
run_test test_revert_patch_added
run_test test_revert_patch_removed
run_test test_revert_patch_one_change
run_test test_revert_added_subtree
run_test test_revert_deleted_subtree
run_test test_revert_symlink
run_test test_revert_patch_symlink
run_test test_revert_umask
run_test test_revert_patch_binary
run_test test_revert_staged_file
run_test test_revert_partially_staged_file
run_test test_revert_backout_with_path_prefix
