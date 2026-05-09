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

test_add_basic() {
	local testroot=`test_init add_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo

	echo 'A  foo' > $testroot/stdout.expected
	(cd $testroot/wt && got add foo > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_double_add() {
	local testroot=`test_init double_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	(cd $testroot/wt && got add foo > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
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

	echo "new file" > $testroot/wt/epsilon/zeta2
	(cd $testroot/wt && got add epsilon/zeta* > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo 'A  epsilon/zeta2' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_add_multiple() {
	local testroot=`test_init multiple_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo
	echo "new file" > $testroot/wt/bar
	echo "new file" > $testroot/wt/baz
	(cd $testroot/wt && got add foo bar baz > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "A  bar" > $testroot/stdout.expected
	echo "A  baz" >> $testroot/stdout.expected
	echo "A  foo" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "changed file" > $testroot/wt/alpha
	echo "new file" > $testroot/wt/bax
	(cd $testroot/wt && got add -R * > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "A  bax" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_add_file_in_new_subdir() {
	local testroot=`test_init add_file_in_new_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/new
	echo "new file" > $testroot/wt/new/foo

	echo 'A  new/foo' > $testroot/stdout.expected
	(cd $testroot/wt && got add new/foo > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_add_deleted() {
	local testroot=`test_init add_deleted`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got add beta > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got add command succeeded unexpectedly" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: beta: file has unexpected status" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_add_force_delete_commit() {
	local testroot=`test_init add_force_delete_commit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo new > $testroot/wt/new

	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got add new > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add command failed unexpectedly" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && mv new new2 > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "rename the file failed unexpectedly" >&2
		ls beta2
		test_done "$testroot" "1"
		return 1
	fi


	(cd $testroot/wt && got add new2 > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got add  command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# File 'new' was once in A status (locally added) but is now
	# in "!" (missing) status since it was never committed.
	# Removing it effectively reverts the local addition.
	(cd $testroot/wt && got remove -f new > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got remove -f command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo 'A  new2' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m "add force remove commit" \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit command failed unexpectedly" >&2
	fi
	test_done "$testroot" "$ret"
}

test_add_directory() {
	local testroot=`test_init add_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got add . > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	echo "got: adding directories requires -R option" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got add -I . > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	echo "got: adding directories requires -R option" \
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

	mkdir -p $testroot/wt/tree1
	mkdir -p $testroot/wt/tree2
	echo "tree1/**" > $testroot/wt/.gitignore
	echo "tree2/**" >> $testroot/wt/.gitignore
	echo -n > $testroot/wt/tree1/foo
	echo -n > $testroot/wt/tree2/foo
	echo -n > $testroot/wt/epsilon/zeta1
	echo -n > $testroot/wt/epsilon/zeta2

	(cd $testroot/wt && got add -R . > $testroot/stdout)

	echo 'A  .gitignore' > $testroot/stdout.expected
	echo 'A  epsilon/zeta1' >> $testroot/stdout.expected
	echo 'A  epsilon/zeta2' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got add -RI tree1 > $testroot/stdout)

	echo 'A  tree1/foo' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got add tree2/foo > $testroot/stdout)

	echo -n '' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got add -I tree2/foo > $testroot/stdout)

	echo 'A  tree2/foo' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_add_clashes_with_submodule() {
	local testroot=`test_init add_clashes_with_submodule`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	got checkout $testroot/repo $testroot/wt > /dev/null

	# Attempt to add a file clashes with a submodule
	echo "This is a file called repo2" > $testroot/wt/repo2
	(cd $testroot/wt && got add repo2 > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "A  repo2" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Update for good measure; see the error below.
	(cd $testroot/wt && got update > /dev/null)

	# This currently fails with "work tree must be updated"...
	(cd $testroot/wt && got commit -m 'add file repo2' \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "commit succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "got: work tree must be updated " > $testroot/stderr.expected
	echo "before these changes can be committed" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_add_symlink() {
	local testroot=`test_init add_symlink`

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

	echo "A  alpha.link" > $testroot/stdout.expected
	(cd $testroot/wt && got add alpha.link > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  epsilon.link" > $testroot/stdout.expected
	(cd $testroot/wt && got add epsilon.link > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  passwd.link" > $testroot/stdout.expected
	(cd $testroot/wt && got add passwd.link > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  epsilon/beta.link" > $testroot/stdout.expected
	(cd $testroot/wt && got add epsilon/beta.link > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  nonexistent.link" > $testroot/stdout.expected
	(cd $testroot/wt && got add nonexistent.link > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_add_file_in_dotgit() {
	local testroot=`test_init add_file_in_dotgit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/.git
	echo "new file" > $testroot/wt/.git/foo

	(cd $testroot/wt && got add .git/foo \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got add succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
got: path '.git/foo' cannot be added to the file-index: bad path
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_add_file_in_dotgot() {
	local testroot=`test_init add_file_in_dotgot`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/.got/foo

	(cd $testroot/wt && got add .got/foo \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got add succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
got: path '.got/foo' cannot be added to the file-index: bad path
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_add_basic
run_test test_double_add
run_test test_add_multiple
run_test test_add_file_in_new_subdir
run_test test_add_deleted
run_test test_add_force_delete_commit
run_test test_add_directory
run_test test_add_clashes_with_submodule
run_test test_add_symlink
run_test test_add_file_in_dotgit
run_test test_add_file_in_dotgot
