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

# disable automatic packing for these tests
export GOT_TEST_PACK=""

test_cleanup_unreferenced_loose_objects() {
	local testroot=`test_init cleanup_unreferenced_loose_objects`

	nloose0=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose0" != "8" ]; then
		echo "unexpected number of loose objects: $nloose0" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create a branch with some changes
	got branch -r $testroot/repo newbranch >/dev/null

	got checkout -b newbranch $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'foo' > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)
	echo 'modified alpha' > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'newbranch commit' > /dev/null)
	local commit1=`git_show_branch_head $testroot/repo newbranch`
	local tree1=`got cat -r $testroot/repo $newbranch_commit | \
		grep ^tree | cut -d ' ' -f2`
	local alpha1=`got tree -r $testroot/repo -i -c $commit1 | \
		grep "[0-9a-f] alpha$" | cut -d' ' -f 1`
	local foo1=`got tree -r $testroot/repo -i -c $commit1 | \
		grep "[0-9a-f] foo$" | cut -d' ' -f 1`

	nloose1=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose1" != "12" ]; then
		echo "unexpected number of loose objects: $nloose1" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# delete the branch
	got branch -r $testroot/repo -d newbranch >/dev/null

	# remove worktree's base commit reference, which points at the branch
	wt_uuid=`(cd $testroot/wt && got info | grep 'UUID:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	got ref -r $testroot/repo -d "refs/got/worktree/base-$wt_uuid" \
		> /dev/null

	# cleanup -n should not remove any objects
	ls -R $testroot/repo/.git/objects > $testroot/objects-before
	gotadmin cleanup -a -n -q -r $testroot/repo > $testroot/stdout
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	ls -R $testroot/repo/.git/objects > $testroot/objects-after
	cmp -s $testroot/objects-before $testroot/objects-after
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/objects-before $testroot/objects-after
		test_done "$testroot" "$ret"
		return 1
	fi

	# cleanup should remove all loose objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
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

	nloose2=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose2" != "0" ]; then
		echo "unexpected number of loose objects: $nloose2" >&2
		test_done "$testroot" "1"
		return 1
	fi

	for id in $commit1 $tree1 $alpha1 $foo1; do
		path=`get_loose_object_path $testroot/repo $id`
		if [ -e "$path" ]; then
			echo "loose object $path was not purged" >&2
			ret=1
			break
		fi
	done

	test_done "$testroot" "$ret"
}

test_cleanup_redundant_loose_objects() {
	local testroot=`test_init cleanup_redundant_loose_objects`

	# tags should also be packed
	got tag -r $testroot/repo -m 1.0 1.0 >/dev/null

	nloose0=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose0" != "9" ]; then
		echo "unexpected number of loose objects: $nloose0" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# no pack files should exist yet
	ls $testroot/repo/.git/objects/pack/ > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
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

	gotadmin pack -r $testroot/repo > /dev/null

	npacked0=`gotadmin info -r $testroot/repo | grep '^packed objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$npacked0" != "9" ]; then
		echo "unexpected number of loose objects: $npacked0" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# cleanup -n should not remove any objects
	ls -R $testroot/repo/.git/objects > $testroot/objects-before
	gotadmin cleanup -a -n -q -r $testroot/repo > $testroot/stdout
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	ls -R $testroot/repo/.git/objects > $testroot/objects-after
	cmp -s $testroot/objects-before $testroot/objects-after
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/objects-before $testroot/objects-after
		test_done "$testroot" "$ret"
		return 1
	fi

	nloose1=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose1" != "$nloose0" ]; then
		echo "unexpected number of loose objects: $nloose1" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# cleanup should remove all loose objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
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

	nloose2=`gotadmin info -r $testroot/repo | grep '^loose objects:' | \
		cut -d ':' -f 2 | tr -d ' '`
	if [ "$nloose2" != "0" ]; then
		echo "unexpected number of loose objects: $nloose2" >&2
		test_done "$testroot" "1"
		return 1
	fi

	for d in $testroot/repo/.git/objects/[0-9a-f][0-9a-f]; do
		id0=`basename $d`
		ret=0
		for e in `ls $d`; do
			obj_id=${id0}${e}
			echo "loose object $obj_id was not purged" >&2
			ret=1
			break
		done
		if [ $ret -eq 1 ]; then
			break
		fi
	done

	test_done "$testroot" "$ret"
}

test_cleanup_redundant_pack_files() {
	local testroot=`test_init cleanup_redundant_pack_files`

	# no pack files should exist yet

	n=$(gotadmin info -r "$testroot/repo" | awk '/^pack files/{print $3}')
	if [ "$n" -ne 0 ]; then
		echo "expected no pack file to exists, $n found" >&2
		test_done "$testroot" 1
		return 1
	fi

	# create a redundant pack with an associated .keep file
	hash=$(gotadmin pack -a -r "$testroot/repo" \
		| awk '/^Indexed/{print $2}')
	kpack="$testroot/repo/.git/objects/pack/pack-$hash"
	touch "${kpack%.pack}.keep"

	# create a few pack files with different objects
	for i in `seq 5`; do
		echo "alpha $i" > $testroot/repo/alpha
		git_commit "$testroot/repo" -m "edit #$i"
		gotadmin pack -r "$testroot/repo" >/dev/null
	done

	# create two packs with all the objects
	gotadmin pack -a -r "$testroot/repo" >/dev/null
	gotadmin pack -a -r "$testroot/repo" >/dev/null

	# create another one with unreachable objects
	git -C "$testroot/repo" checkout -q -b tempbranch
	echo "modified alpha on tempbranch" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "edit alpha on tempbranch"
	gotadmin pack -a -r "$testroot/repo" >/dev/null
	git -C "$testroot/repo" checkout -q master
	(cd "$testroot/repo" && got branch -d tempbranch) >/dev/null

	gotadmin cleanup -a -q -r "$testroot/repo"
	n=$(gotadmin info -r "$testroot/repo" | awk '/^pack files/{print $3}')
	if [ "$n" -ne 2 ]; then
		echo "expected 2 pack files left, $n found instead" >&2
		test_done "$testroot" 1
		return 1
	fi

	if [ ! -f "$kpack" ]; then
		echo "$kpack disappeared unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if [ ! -f "${kpack%.pack}.keep" ]; then
		echo "${kpack%.pack}.keep disappeared unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# create one more non-redundant pack
	for i in `seq 5`; do
		echo "alpha again $i" > $testroot/repo/alpha
		git_commit "$testroot/repo" -m "edit $i"
	done
	gotadmin pack -r "$testroot/repo" >/dev/null

	gotadmin cleanup -a -q -r "$testroot/repo"

	n=$(gotadmin info -r "$testroot/repo" | awk '/^pack files/{print $3}')
	if [ "$n" -ne 2 ]; then
		echo "expected 2 pack files left, $n found instead" >&2
		test_done "$testroot" 1
		return 1
	fi

	# remove the .keep file
	rm "${kpack%.pack}.keep"

	# create some commits on a separate branch
	git -C "$testroot/repo" checkout -q -b newbranch

	for i in `seq 5`; do
		echo "alpha $i" > $testroot/repo/alpha
		git_commit "$testroot/repo" -m "edit #$i"
		gotadmin pack -r "$testroot/repo" >/dev/null
	done

	gotadmin pack -a -x master -r "$testroot/repo" >/dev/null

	gotadmin cleanup -a -q -r "$testroot/repo"
	n=$(gotadmin info -r "$testroot/repo" | awk '/^pack files/{print $3}')
	if [ "$n" -ne 1 ]; then
		echo "expected 1 pack files left, $n found instead" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_cleanup_precious_objects() {
	local testroot=`test_init cleanup_precious_objects`

	# enable Git's preciousObjects extension
	git -C $testroot/repo config extensions.preciousObjects true

	# cleanup should now refuse to purge objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotadmin cleanup succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "gotadmin: the preciousObjects Git extension is enabled; " \
		> $testroot/stderr.expected
	echo "this implies that objects must not be deleted" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_cleanup_missing_pack_file() {
	local testroot=`test_init cleanup_missing_pack_file`

	# no pack files should exist yet
	ls $testroot/repo/.git/objects/pack/ > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
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

	gotadmin pack -r $testroot/repo > $testroot/stdout
	packname=`grep ^Wrote $testroot/stdout | cut -d ' ' -f2`
	packhash=`echo $packname | sed -e 's:^objects/pack/pack-::' \
		-e 's/.pack$//'`

	# Some freshly cloned Git repositories suffer from lonely pack index
	# files. Remove the pack file we just wrote to simulate this issue.
	rm -f $testroot/repo/.git/objects/pack/pack-$packname

	# cleanup should now refuse to purge objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "gotadmin cleanup succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "gotadmin: objects/pack/pack-${packhash}.idx: " \
		> $testroot/stderr.expected
	echo -n "pack index has no corresponding pack file; pack file must " \
		>> $testroot/stderr.expected
	echo "be restored or 'gotadmin cleanup -p' must be run" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	gotadmin cleanup -a -r $testroot/repo -p -n > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	packidx_path=$testroot/repo/.git/objects/pack/pack-${packhash}.idx
	echo "$packidx_path could be removed" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	gotadmin cleanup -a -r $testroot/repo -p > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "$packidx_path removed" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cleanup should now attempt to purge objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_cleanup_non_commit_ref() {
	local testroot=`test_init cleanup_non_commit_ref`
	local commit_id=`git_show_head $testroot/repo`

	mkdir -p $testroot/t
	echo foo > $testroot/t/foo

	foo_id=$(git -C $testroot/repo hash-object -t blob -w $testroot/t/foo)

	# verify that the blob object can be read
	got cat -r $testroot/repo "$foo_id" > $testroot/stdout
	cmp -s $testroot/t/foo $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/t/foo $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a reference which points at the blob
	got ref -r $testroot/repo -c $foo_id blobref

	# create a tree object
	printf "10644 blob $foo_id\tfoo\n" > $testroot/tree-desc
	tree_id=$(git -C $testroot/repo mktree < $testroot/tree-desc)

	# verify that the tree object can be read
	got cat -r $testroot/repo "$tree_id" > $testroot/stdout
	printf "$foo_id 0010644 foo\n" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a reference which points at the tree
	got ref -r $testroot/repo -c "$tree_id" treeref

	inner_tag_date=$(date +%s)

	# Create a nested tag of another tree.
	# Ensure that gotadmin cleanup follows chains of tags and
	# all objects referenced via this chain.

	echo bar > $testroot/t/bar
	bar_id=$(git -C $testroot/repo hash-object -t blob -w $testroot/t/bar)

	printf "10644 blob $foo_id\tfoo\n" > $testroot/tree-desc2
	printf "10644 blob $bar_id\tbar\n" >> $testroot/tree-desc2
	tree_id2=$(git -C $testroot/repo mktree < $testroot/tree-desc2)

	# verify that the second tree object can be read
	got cat -r $testroot/repo "$tree_id2" > $testroot/stdout
	printf "$bar_id 0010644 bar\n" > $testroot/stdout.expected
	printf "$foo_id 0010644 foo\n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/inner-tag-desc <<EOF
object $tree_id2
type tree
tag treetag
tagger $GOT_AUTHOR $inner_tag_date +0000

tagging a tree
EOF
	inner_tag_id=$(git -C $testroot/repo hash-object -t tag -w \
		$testroot/inner-tag-desc)

	# verify that the inner tag object can be read
	got cat -r $testroot/repo "$inner_tag_id" > $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
object $tree_id2
type tree
tag treetag
tagger $GOT_AUTHOR $inner_tag_date +0000
messagelen 16

tagging a tree
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_date=$(date +%s)

	cat > $testroot/tag-desc <<EOF
object $inner_tag_id
type tag
tag tagtag
tagger $GOT_AUTHOR $tag_date +0000

tagging a tag
EOF
	tag_id=$(git -C $testroot/repo hash-object -t tag -w $testroot/tag-desc)

	# verify that the tag object can be read
	got cat -r $testroot/repo "$tag_id" > $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
object $inner_tag_id
type tag
tag tagtag
tagger $GOT_AUTHOR $tag_date +0000
messagelen 15

tagging a tag
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a reference which points at the outer tag
	got ref -r $testroot/repo -c "$tag_id" tagref

	# list references
	got ref -r $testroot/repo -l > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/master
refs/blobref: $foo_id
refs/heads/master: $commit_id
refs/tagref: $tag_id
refs/treeref: $tree_id
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# gotadmin cleanup should not purge referenced objects
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# verify that the blob object can be read
	got cat -r $testroot/repo "$foo_id" > $testroot/stdout
	cmp -s $testroot/t/foo $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/t/foo $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# verify that the tree object can be read
	got cat -r $testroot/repo "$tree_id" > $testroot/stdout
	printf "$foo_id 0010644 foo\n" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# verify that the second tree object can be read
	got cat -r $testroot/repo "$tree_id2" > $testroot/stdout
	printf "$bar_id 0010644 bar\n" > $testroot/stdout.expected
	printf "$foo_id 0010644 foo\n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# verify that the inner tag object can be read
	got cat -r $testroot/repo "$inner_tag_id" > $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
object $tree_id2
type tree
tag treetag
tagger $GOT_AUTHOR $inner_tag_date +0000
messagelen 16

tagging a tree
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# verify that the outer tag object can be read
	got cat -r $testroot/repo "$tag_id" > $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
object $inner_tag_id
type tag
tag tagtag
tagger $GOT_AUTHOR $tag_date +0000
messagelen 15

tagging a tag
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

test_cleanup_no_head_branch() {
	local testroot=`test_init cleanup_no_head_branch`
	local commit_id=`git_show_head $testroot/repo`

	# create a dangling HEAD reference
	echo 'ref: refs/heads/main' > $testroot/repo/.git/HEAD

	# list references
	got ref -r $testroot/repo -l > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
HEAD: refs/heads/main
refs/heads/master: $commit_id
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# gotadmin cleanup should not fail if HEAD is pointing at
	# a reference which cannot be resolved.
	gotadmin cleanup -a -q -r $testroot/repo > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotadmin cleanup failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_cleanup_unreferenced_loose_objects
run_test test_cleanup_redundant_loose_objects
run_test test_cleanup_redundant_pack_files
run_test test_cleanup_precious_objects
run_test test_cleanup_missing_pack_file
run_test test_cleanup_non_commit_ref
run_test test_cleanup_no_head_branch
