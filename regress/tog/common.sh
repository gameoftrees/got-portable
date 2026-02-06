#!/bin/sh
#
# Copyright (c) 2019, 2020 Stefan Sperling <stsp@openbsd.org>
# Copyright (c) 2023 Mark Jamsek <mark@jamsek.dev>
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

. ../cmdline/common.sh

unset TOG_COLORS
unset TOG_DIFF_ALGORITHM
unset TOG_VIEW_SPLIT_MODE
unset LC_ALL
export TERM=vt220
export LC_ALL=C.UTF-8
export COLUMNS=80
export LINES=24

widechar_filename()
{
	echo "選り抜き記事"
}

widechar_file_content()
{
	cat <<-EOF
	ウィリアム・ユワート・グラッドストン（英語: William Ewart Gladstone PC FRS FSS、1809年12月29日 - 1898年5月19日）は、イギリスの政治家。

	ヴィクトリア朝中期から後期にかけて、自由党を指導して、4度にわたり首相を務めた。

	生涯を通じて敬虔なイングランド国教会の信徒であり、キリスト教の精神を政治に反映させることを目指した。多くの自由主義改革を行い、帝国主義にも批判的であった。好敵手である保守党党首ベンジャミン・ディズレーリとともにヴィクトリア朝イギリスの政党政治を代表する人物として知れる。……
	EOF
}

widechar_logmsg1()
{
cat <<-EOF
選り抜き記事ウィリアム・ユワート・グラッドストン（英語: William Ewart Gladstone PC FRS FSS、1809年12月29日 - 1898年5月19日）は、イギリスの政治家。
EOF
}

widechar_logmsg2()
{
cat <<-EOF
良質な記事 おまかせ表示 つまみ読み 選考
EOF
}

widechar_commit()
{
	local repo="$1"

	echo "$(widechar_file_content)" > $repo/$(widechar_filename)

	(cd $repo && git add $(widechar_filename) > /dev/null)
	widechar_logmsg1 > $testroot/logmsg
	echo >> $testroot/logmsg
	widechar_logmsg2 >> $testroot/logmsg
	(cd $repo && git commit -q --cleanup=verbatim -F $testroot/logmsg \
	    > /dev/null)
}

set_test_env()
{
	export TOG_TEST_SCRIPT=$1
	export TOG_SCR_DUMP=$2

	if [ -n "${3}" ]; then
		export COLUMNS=${3}
	fi

	if [ -n "${4}" ]; then
		export LINES=${4}
	fi
}

trim()
{
	expr "$2" : "\(.\{1,$1\}\)"
}

test_init()
{
	local testname="$1"
	local columns="$2"
	local lines="$3"
	local no_tree="$4"

	if [ -z "$testname" ]; then
		echo "No test name provided" >&2
		return 1
	fi

	testroot=`mktemp -d "$GOT_TEST_ROOT/tog-test-$testname-XXXXXXXXXX"`

	set_test_env $testroot/$testname $testroot/view $columns $lines

	mkdir $testroot/repo
	git_init $testroot/repo

	if [ -z "$no_tree" ]; then
		make_test_tree $testroot/repo
		cd $testroot/repo && git add .
		git_commit $testroot/repo -m "adding the test tree"
	fi
}

run_test()
{
	testfunc="$1"

	if [ -n "$regress_run_only" ]; then
		case "$regress_run_only" in
		*$testfunc*) ;;
		*) return ;;
		esac
	fi

	if [ -z "$GOT_TEST_QUIET" ]; then
		echo -n "$testfunc "
	fi

	# run test in subshell to keep defaults unchanged
	($testfunc)
}
