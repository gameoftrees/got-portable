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

test_status_basic() {
	local testroot=`test_init status_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/beta
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	mkdir -m 0000 $testroot/wt/bar

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo '!  epsilon/zeta' >> $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	echo 'A  new' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	chmod 700 $testroot/wt/bar
	rmdir $testroot/wt/bar
	test_done "$testroot" "$ret"
}

test_status_subdir_no_mods() {
	local testroot=`test_init status_subdir_no_mods 1`

	mkdir $testroot/repo/Basic/
	mkdir $testroot/repo/Basic/Targets/
	touch $testroot/repo/Basic/Targets/AArch64.cpp
	touch $testroot/repo/Basic/Targets.cpp
	touch $testroot/repo/Basic/Targets.h
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add subdir with files"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	touch $testroot/stdout.expected

	# This used to erroneously print:
	#
	# !  Basic/Targets.cpp
	# ?  Basic/Targets.cpp
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_subdir_no_mods2() {
	local testroot=`test_init status_subdir_no_mods2 1`

	mkdir $testroot/repo/AST
	touch $testroot/repo/AST/APValue.cpp
	mkdir $testroot/repo/ASTMatchers
	touch $testroot/repo/ASTMatchers/ASTMatchFinder.cpp
	mkdir $testroot/repo/Frontend
	touch $testroot/repo/Frontend/ASTConsumers.cpp
	mkdir $testroot/repo/Frontend/Rewrite
	touch $testroot/repo/Frontend/Rewrite/CMakeLists.txt
	mkdir $testroot/repo/FrontendTool
	touch $testroot/repo/FrontendTool/CMakeLists.txt
	touch $testroot/repo/FrontendTool/ExecuteCompilerInvocation.cpp
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add subdir with files"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	touch $testroot/stdout.expected

	# This used to erroneously print:
	#
	# !  AST/APValue.cpp
	# ?  AST/APValue.cpp
	# !  Frontend/ASTConsumers.cpp
	# !  Frontend/Rewrite/CMakeLists.txt
	# ?  Frontend/ASTConsumers.cpp
	# ?  Frontend/Rewrite/CMakeLists.txt
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_obstructed() {
	local testroot=`test_init status_obstructed`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/epsilon/zeta
	mkdir $testroot/wt/epsilon/zeta

	echo '~  epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status epsilon/zeta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_shows_local_mods_after_update() {
	local testroot=`test_init status_shows_local_mods_after_update 1`

	echo "1" > $testroot/repo/numbers
	echo "2" >> $testroot/repo/numbers
	echo "3" >> $testroot/repo/numbers
	echo "4" >> $testroot/repo/numbers
	echo "5" >> $testroot/repo/numbers
	echo "6" >> $testroot/repo/numbers
	echo "7" >> $testroot/repo/numbers
	echo "8" >> $testroot/repo/numbers
	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/repo/numbers <<-\EOF
	,s/2/22/
	w
	EOF
	git_commit $testroot/repo -m "modified line 2"

	# modify line 7; both changes should merge cleanly
	ed -s $testroot/wt/numbers <<-\EOF
	,s/7/77/
	w
	EOF

	echo "G  numbers" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  numbers' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_unversioned_subdirs() {
	local testroot=`test_init status_unversioned_subdirs 1`

	mkdir $testroot/repo/cdfs/
	touch $testroot/repo/cdfs/Makefile
	mkdir $testroot/repo/common/
	touch $testroot/repo/common/Makefile
	mkdir $testroot/repo/iso/
	touch $testroot/repo/iso/Makefile
	mkdir $testroot/repo/ramdisk/
	touch $testroot/repo/ramdisk/Makefile
	touch $testroot/repo/ramdisk/list.local
	mkdir $testroot/repo/ramdisk_cd/
	touch $testroot/repo/ramdisk_cd/Makefile
	touch $testroot/repo/ramdisk_cd/list.local
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "first commit"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir $testroot/wt/cdfs/obj
	mkdir $testroot/wt/ramdisk/obj
	mkdir $testroot/wt/ramdisk_cd/obj
	mkdir $testroot/wt/iso/obj

	echo -n > $testroot/stdout.expected

	# This used to erroneously print:
	#
	# !  ramdisk_cd/Makefile
	# !  ramdisk_cd/list.local
	# ?  ramdisk_cd/Makefile
	# ?  ramdisk_cd/list.local
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_symlink() {
	local testroot=`test_init status_symlink`

	mkdir $testroot/repo/ramdisk/
	touch $testroot/repo/ramdisk/Makefile
	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "first commit"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ln -s /usr/obj/distrib/i386/ramdisk $testroot/wt/ramdisk/obj

	echo "?  ramdisk/obj" > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -sf beta alpha.link)
	(cd $testroot/wt && rm epsilon.link && ln -s gamma epsilon.link)

	(cd $testroot/wt && ln -s /etc/passwd passwd.link)
	(cd $testroot/wt && ln -s ../beta epsilon/beta.link)
	(cd $testroot/wt && got add passwd.link epsilon/beta.link > /dev/null)

	(cd $testroot/wt && got rm nonexistent.link > /dev/null)

	echo 'M  alpha.link' > $testroot/stdout.expected
	echo 'A  epsilon/beta.link' >> $testroot/stdout.expected
	echo 'M  epsilon.link' >> $testroot/stdout.expected
	echo 'D  nonexistent.link' >> $testroot/stdout.expected
	echo 'A  passwd.link' >> $testroot/stdout.expected
	echo "?  ramdisk/obj" >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_shows_no_mods_after_complete_merge() {
	local testroot=`test_init status_shows_no_mods_after_complete_merge 1`

	# make this file larger than the usual blob buffer size of 8192
	seq 16384 > $testroot/repo/numbers

	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/repo/numbers <<-\EOF
	,s/2/22/
	w
	EOF
	git_commit $testroot/repo -m "modified line 2"

	# modify line 2 again; no local changes are left after merge
	ed -s $testroot/wt/numbers <<-\EOF
	,s/2/22/
	w
	EOF

	echo "G  numbers" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

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

test_status_shows_conflict() {
	local testroot=`test_init status_shows_conflict 1`

	echo "1" > $testroot/repo/numbers
	echo "2" >> $testroot/repo/numbers
	echo "3" >> $testroot/repo/numbers
	echo "4" >> $testroot/repo/numbers
	echo "5" >> $testroot/repo/numbers
	echo "6" >> $testroot/repo/numbers
	echo "7" >> $testroot/repo/numbers
	echo "8" >> $testroot/repo/numbers
	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/repo/numbers <<-\EOF
	,s/2/22/
	w
	EOF
	git_commit $testroot/repo -m "modified line 2"

	# modify line 2 in a conflicting way
	ed -s $testroot/wt/numbers <<-\EOF
	,s/2/77/
	w
	EOF

	echo "C  numbers" > $testroot/stdout.expected
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

	echo 'C  numbers' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_empty_dir() {
	local testroot=`test_init status_empty_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/epsilon/zeta

	echo '!  epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got status epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_empty_dir_unversioned_file() {
	local testroot=`test_init status_empty_dir_unversioned_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/epsilon/unversioned

	echo '?  epsilon/unversioned' > $testroot/stdout.expected
	echo '!  epsilon/zeta' >> $testroot/stdout.expected

	(cd $testroot/wt && got status epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_many_paths() {
	local testroot=`test_init status_many_paths`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/beta
	echo "new file" > $testroot/wt/new
	mkdir $testroot/wt/newdir
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got status alpha > $testroot/stdout.expected)
	(cd $testroot/wt && got status beta >> $testroot/stdout.expected)
	(cd $testroot/wt && got status epsilon >> $testroot/stdout.expected)
	(cd $testroot/wt && got status foo >> $testroot/stdout.expected)
	(cd $testroot/wt && got status new >> $testroot/stdout.expected)
	(cd $testroot/wt && got status newdir >> $testroot/stdout.expected)
	(cd $testroot/wt && got status . >> $testroot/stdout.expected)

	(cd $testroot/wt && got status newdir alpha epsilon foo new beta . \
		> $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_cvsignore() {
	local testroot=`test_init status_cvsignore`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	echo "unversioned file" > $testroot/wt/foop
	echo "unversioned file" > $testroot/wt/epsilon/foo
	echo "unversioned file" > $testroot/wt/epsilon/bar
	echo "unversioned file" > $testroot/wt/epsilon/boo
	echo "unversioned file" > $testroot/wt/epsilon/moo
	mkdir -p $testroot/wt/epsilon/new/
	echo "unversioned file" > $testroot/wt/epsilon/new/foo
	echo "**/foo" > $testroot/wt/.cvsignore
	echo "**/gamma" >> $testroot/wt/.cvsignore
	echo "bar" > $testroot/wt/epsilon/.cvsignore
	echo "moo" >> $testroot/wt/epsilon/.cvsignore

	echo '?  .cvsignore' > $testroot/stdout.expected
	echo '?  epsilon/.cvsignore' >> $testroot/stdout.expected
	echo '?  epsilon/boo' >> $testroot/stdout.expected
	echo '?  foop' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '?  epsilon/.cvsignore' > $testroot/stdout.expected
	echo '?  epsilon/boo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	(cd $testroot/wt && got status epsilon/new > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '?  .cvsignore' > $testroot/stdout.expected
	echo '?  epsilon/.cvsignore' >> $testroot/stdout.expected
	echo '?  epsilon/boo' >> $testroot/stdout.expected
	echo '?  foop' >> $testroot/stdout.expected
	(cd $testroot/wt/gamma && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
?  .cvsignore
?  epsilon/.cvsignore
?  epsilon/bar
?  epsilon/boo
?  epsilon/foo
?  epsilon/moo
?  epsilon/new/foo
?  foo
?  foop
EOF
	(cd $testroot/wt && got status -I > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got status failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_gitignore() {
	local testroot=`test_init status_gitignore`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	echo "unversioned file" > $testroot/wt/foop
	echo "unversioned file" > $testroot/wt/barp
	echo "unversioned file" > $testroot/wt/epsilon/bar
	echo "unversioned file" > $testroot/wt/epsilon/boo
	echo "unversioned file" > $testroot/wt/epsilon/moo
	mkdir -p $testroot/wt/a/b/c/
	echo "git would ignore this" > $testroot/wt/a/foo
	echo "unversioned file" > $testroot/wt/a/b/c/foo
	echo "unversioned file" > $testroot/wt/a/b/c/zoo
	echo "foo" > $testroot/wt/.gitignore
	echo "bar*" >> $testroot/wt/.gitignore
	echo "epsilon/**" >> $testroot/wt/.gitignore
	echo "a/**/foo" >> $testroot/wt/.gitignore
	echo "**/zoo" >> $testroot/wt/.gitignore

	echo '?  .gitignore' > $testroot/stdout.expected
	echo '?  a/foo' >> $testroot/stdout.expected
	echo '?  foop' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '?  .gitignore' > $testroot/stdout.expected
	echo '?  a/foo' >> $testroot/stdout.expected
	echo '?  foop' >> $testroot/stdout.expected
	(cd $testroot/wt/gamma && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
?  .gitignore
?  a/b/c/foo
?  a/b/c/zoo
?  a/foo
?  barp
?  epsilon/bar
?  epsilon/boo
?  epsilon/moo
?  foo
?  foop
EOF
	(cd $testroot/wt && got status -I > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got status failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_gitignore_leading_slashes() {
	local testroot=`test_init status_gitignore_leading_slashes`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	echo "unversioned file" > $testroot/wt/epsilon/foo
	echo "unversioned file" > $testroot/wt/epsilon/bar
	mkdir -p $testroot/wt/nu
	echo "unversioned file" > $testroot/wt/nu/baz
	mkdir -p $testroot/wt/epsilon/nu
	echo "unversioned file" > $testroot/wt/epsilon/nu/baz

	echo "/foo" > $testroot/wt/.gitignore
	echo "//////////////////////////nu" >> $testroot/wt/.gitignore

	echo '?  .gitignore' > $testroot/stdout.expected
	echo '?  epsilon/bar' >> $testroot/stdout.expected
	echo '?  epsilon/foo' >> $testroot/stdout.expected
	echo '?  epsilon/nu/baz' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_gitignore_trailing_slashes() {
	local testroot=`test_init status_gitignore_trailing_slashes`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	echo "unversioned file" > $testroot/wt/epsilon/bar
	echo "unversioned file" > $testroot/wt/epsilon/boo
	echo "unversioned file" > $testroot/wt/epsilon/moo
	echo "unversioned file" > $testroot/wt/upsilon

	# Match the directory epsilon but not the regular file upsilon
	echo "*psilon/" > $testroot/wt/.gitignore

	echo '?  .gitignore' > $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	echo '?  upsilon' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_gitignore_comments() {
	local testroot=`test_init status_gitignore_comments`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	echo "unversioned file" > $testroot/wt/epsilon/bar
	echo "unversioned file" > $testroot/wt/epsilon/boo
	echo "unversioned file" > $testroot/wt/upsilon

	echo "# comment" > $testroot/wt/.gitignore
	echo "" >> $testroot/wt/.gitignore
	echo "foo" >> $testroot/wt/.gitignore
	echo "# comment" > $testroot/wt/epsilon/.gitignore
	echo "" >> $testroot/wt/epsilon/.gitignore
	echo "bar" >> $testroot/wt/epsilon/.gitignore

	echo '?  .gitignore' > $testroot/stdout.expected
	echo '?  epsilon/.gitignore' >> $testroot/stdout.expected
	echo '?  epsilon/boo' >> $testroot/stdout.expected
	echo '?  upsilon' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_multiple_gitignore_files() {
	local testroot=`test_init status_multiple_gitignore_files`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "unversioned file" > $testroot/wt/foo
	mkdir $testroot/wt/gamma/.abc/
	echo "unversioned file" > $testroot/wt/gamma/.abc/goo
	echo "unversioned file" > $testroot/wt/gamma/bar
	mkdir $testroot/wt/gamma/zzz/
	echo "unversioned file" > $testroot/wt/gamma/zzz/buzz
	echo "unversioned file" > $testroot/wt/epsilon/boo
	echo "unversioned file" > $testroot/wt/upsilon

	echo '?  epsilon/boo' >> $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	echo '?  gamma/.abc/goo' >> $testroot/stdout.expected
	echo '?  gamma/bar' >> $testroot/stdout.expected
	echo '?  gamma/zzz/buzz' >> $testroot/stdout.expected
	echo '?  upsilon' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
	fi

	echo "goo" > $testroot/wt/gamma/.abc/.gitignore
	echo "bar" > $testroot/wt/gamma/.gitignore
	echo "buzz" > $testroot/wt/gamma/zzz/.gitignore
	echo "boo" > $testroot/wt/epsilon/.gitignore

	echo '?  epsilon/.gitignore' > $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	echo '?  gamma/.abc/.gitignore' >> $testroot/stdout.expected
	echo '?  gamma/.gitignore' >> $testroot/stdout.expected
	echo '?  gamma/zzz/.gitignore' >> $testroot/stdout.expected
	echo '?  upsilon' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_gitignore_single_file() {
	local testroot=`test_init status_gitignore_single_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "foo" > $testroot/wt/epsilon/.gitignore
	echo "unversioned file" > $testroot/wt/epsilon/foo

	(cd $testroot/wt && got status epsilon/foo > $testroot/stdout)

	echo -n '' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_status_status_code() {
	local testroot=`test_init status_status_code`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/beta
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got status -s xDM \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "status succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: invalid status code 'x'" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status -s M > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status -s D > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '!  epsilon/zeta' > $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status -s !\? > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'A  new' > $testroot/stdout.expected
	(cd $testroot/wt && got status -s A > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage new > $testroot/stdout)

	echo ' A new' > $testroot/stdout.expected
	(cd $testroot/wt && got status -s A > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'changed file new' > $testroot/wt/new

	echo 'MA new' > $testroot/stdout.expected
	(cd $testroot/wt && got status -s A > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'MA new' >> $testroot/stdout.expected
	(cd $testroot/wt && got status -s M > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_status_suppress() {
	local testroot=`test_init status_suppress`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/beta
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got status -S A -s M \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "status succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: -s and -S options are mutually exclusive" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status -s A -S M \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "status succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: -S and -s options are mutually exclusive" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status -S xDM \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "status succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: invalid status code 'x'" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status -S D\?A! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status -S M\?A! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '!  epsilon/zeta' > $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status -S MDA > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'A  new' > $testroot/stdout.expected
	(cd $testroot/wt && got status -S MD\?! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage new > $testroot/stdout)

	echo ' A new' > $testroot/stdout.expected
	(cd $testroot/wt && got status -S MD\?! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'changed file new' > $testroot/wt/new

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'MA new' >> $testroot/stdout.expected
	(cd $testroot/wt && got status -S D\?! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	(cd $testroot/wt && got status -S AD\?! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/stdout.expected
	touch $testroot/stdout.expected

	(cd $testroot/wt && got status -S MD\?! > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_status_empty_file() {
	local testroot=`test_init status_empty_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "" > $testroot/wt/empty
	(cd $testroot/wt && got add empty >/dev/null)

	echo 'A  empty' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m "empty file" >/dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# update the timestamp; this used to make the file show up as:
	# M  empty
	# which should not happen
	touch $testroot/wt/empty

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_status_in_repo() {
	local testroot=`test_init status_in_repo`

	(cd $testroot/repo && got status > $testroot/stdout \
		2> $testroot/stderr)

	cat > $testroot/stderr.expected <<EOF
got: 'got status' needs a work tree in addition to a git repository
Work trees can be checked out from this Git repository with 'got checkout'.
The got(1) manual page contains more information.
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_status_basic
run_test test_status_subdir_no_mods
run_test test_status_subdir_no_mods2
run_test test_status_obstructed
run_test test_status_shows_local_mods_after_update
run_test test_status_unversioned_subdirs
run_test test_status_symlink
run_test test_status_shows_no_mods_after_complete_merge
run_test test_status_shows_conflict
run_test test_status_empty_dir
run_test test_status_empty_dir_unversioned_file
run_test test_status_many_paths
run_test test_status_cvsignore
run_test test_status_gitignore
run_test test_status_gitignore_leading_slashes
run_test test_status_gitignore_trailing_slashes
run_test test_status_gitignore_comments
run_test test_status_multiple_gitignore_files
run_test test_status_gitignore_single_file
run_test test_status_status_code
run_test test_status_suppress
run_test test_status_empty_file
run_test test_status_in_repo
