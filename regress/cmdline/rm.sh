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

test_rm_basic() {
	local testroot=`test_init rm_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	(cd $testroot/wt && got rm alpha beta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	for f in alpha beta; do
		if [ -e $testroot/wt/$f ]; then
			echo "removed file $f still exists on disk" >&2
			test_done "$testroot" "1"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

test_rm_with_local_mods() {
	local testroot=`test_init rm_with_local_mods`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/wt/beta
	echo 'got: beta: file contains modifications' \
		> $testroot/stderr.expected
	(cd $testroot/wt && got rm beta 2>$testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got rm -f beta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_double_rm() {
	local testroot=`test_init double_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	for fflag in "" "-f"; do
		echo -n > $testroot/stderr.expected
		(cd $testroot/wt && got rm $fflag beta > $testroot/stdout \
			2> $testroot/stderr)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got rm command failed unexpectedly" >&2
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
	done
	test_done "$testroot" "0"
}

test_rm_and_add_elsewhere() {
	local testroot=`test_init rm_and_add_elsewhere`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && mv alpha epsilon/)

	(cd $testroot/wt && got status > $testroot/stdout)

	echo '!  alpha' > $testroot/stdout.expected
	echo '?  epsilon/alpha' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm alpha > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got rm command succeeded unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: alpha: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm -f alpha > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rm command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  alpha' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	# While here, test behaviour of rm on files in unversioned status.
	(cd $testroot/wt && got rm epsilon/alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got rm command succeeded unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: epsilon/alpha: file has unexpected status" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# And test the same case with -f.
	(cd $testroot/wt && got rm -f epsilon/alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got rm command succeeded unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: epsilon/alpha: file has unexpected status" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'A  epsilon/alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got add epsilon/alpha > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'A  epsilon/alpha' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rm_directory() {
	local testroot=`test_init rm_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm . > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	echo "got: removing directories requires -R option" \
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

	(cd $testroot/wt && got rm -R . > $testroot/stdout)

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	echo 'D  gamma/delta' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ls -l | sed '/^total/d' > $testroot/stdout)

	echo -n '' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ls -l | sed '/^total/d' > $testroot/stdout)

	echo -n '' > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_rm_directory_keep_files() {
	local testroot=`test_init rm_directory_keep_files`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm . > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	echo "got: removing directories requires -R option" \
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

	(cd $testroot/wt && got rm -k -R . > $testroot/stdout)

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	echo 'D  gamma/delta' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got st . > $testroot/stdout)

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	echo 'D  gamma/delta' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m "keep" > /dev/null)
	(cd $testroot/wt && got st . > $testroot/stdout)

	echo '?  alpha' > $testroot/stdout.expected
	echo '?  beta' >> $testroot/stdout.expected
	echo '?  epsilon/zeta' >> $testroot/stdout.expected
	echo '?  gamma/delta' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_rm_subtree() {
	local testroot=`test_init rm_subtree`

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

	if [ -d $testroot/wt/epsilon/foo ]; then
		echo "removed dir epsilon/foo still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "D  epsilon/foo/a.o" > $testroot/stdout.expected
	echo "D  epsilon/foo/bar/b.d" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/b.o" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/bax/e.d" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/bax/e.o" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/bax/x.d" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/bax/x.o" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/baz/c.d" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/baz/c.o" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/baz/f.d" >> $testroot/stdout.expected
	echo "D  epsilon/foo/bar/baz/f.o" >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rm_symlink() {
	local testroot=`test_init rm_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  alpha.link' > $testroot/stdout.expected
	echo 'D  epsilon/beta.link' >> $testroot/stdout.expected
	echo 'D  epsilon.link' >> $testroot/stdout.expected
	echo 'D  nonexistent.link' >> $testroot/stdout.expected
	echo 'D  passwd.link' >> $testroot/stdout.expected
	(cd $testroot/wt && got rm alpha.link epsilon.link passwd.link \
		epsilon/beta.link nonexistent.link > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rm_status_code() {
	local testroot=`test_init rm_status_code`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/wt/beta

	echo "got: invalid status code 'x'" > $testroot/stderr.expected
	(cd $testroot/wt && got rm -s Mx beta 2>$testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/epsilon/zeta # put file into 'missing' status

	echo 'D  epsilon/zeta' > $testroot/stdout.expected
	(cd $testroot/wt && got rm -R -s '!' . >$testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	if [ ! -e $testroot/wt/beta ]; then
		echo "file beta was unexpectedly removed from disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# put file into 'missing' status again
	(cd $testroot/wt && got revert epsilon/zeta > /dev/null)
	rm $testroot/wt/epsilon/zeta

	echo 'D  beta' > $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	(cd $testroot/wt && got rm -R -s 'M!' . >$testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got revert -R . > /dev/null)

	# Test deletion of unversioned files via "-s ?".
	touch $testroot/wt/unversioned
	touch $testroot/wt/epsilon/unversioned

	echo '?  epsilon/unversioned' > $testroot/stdout.expected
	echo '?  unversioned' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	# Unversioned files should never be removed without -s ?.
	for flag in "" "-k" "-f" "-R"; do
		(cd $testroot/wt && got rm $flag unversioned \
			>$testroot/stdout 2>$testroot/stderr)

		echo -n > $testroot/stdout.expected
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "1"
			return 1
		fi

		if [ -n "$flag" -a "$flag" = "-k" ]; then
			echo -n > $testroot/stderr.expected
		else
			echo "got: unversioned: file has unexpected status" \
				> $testroot/stderr.expected
		fi

		cmp -s $testroot/stderr.expected $testroot/stderr
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "1"
			return 1
		fi

		echo '?  epsilon/unversioned' > $testroot/stdout.expected
		echo '?  unversioned' >> $testroot/stdout.expected
		(cd $testroot/wt && got status > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "1"
			return 1
		fi
	done

	# -k takes priority over -s ?, such that files are kept on disk.
	(cd $testroot/wt && got rm -k -s ? unversioned \
		>$testroot/stdout 2>$testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	# Remove all unversioned files from the work tree with -R -s ?
	(cd $testroot/wt && got rm -R -s ? . \
		>$testroot/stdout 2>$testroot/stderr)

	echo "D  epsilon/unversioned" > $testroot/stdout.expected
	echo "D  unversioned" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e "$testroot/wt/unversioned" ]; then
		echo "file $testroot/wt/unversioned still exists on disk" &>2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e "$testroot/wt/epsilon/unversioned" ]; then
		echo "file $testroot/wt/epsilon/unversioned still exists on disk" &>2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_rm_nonexistent_directory() {
	local testroot=`test_init rm_nonexistent_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm -r $testroot/wt/epsilon

	(cd $testroot/wt && got rm epsilon > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got rm command succeeded unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: epsilon/zeta: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm -f epsilon > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rm command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  epsilon/zeta' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

	test_done "$testroot" "$ret"
}

test_rm_empty_pwd() {
	local testroot=`test_init rm_empty_pwd`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt/epsilon && got rm * > /dev/null)

	if [ ! -e $testroot/wt/epsilon ]; then
		echo "epsilon directory doesn't exist" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_parseargs "$@"
run_test test_rm_basic
run_test test_rm_with_local_mods
run_test test_double_rm
run_test test_rm_and_add_elsewhere
run_test test_rm_directory
run_test test_rm_directory_keep_files
run_test test_rm_subtree
run_test test_rm_symlink
run_test test_rm_status_code
run_test test_rm_nonexistent_directory
run_test test_rm_empty_pwd
