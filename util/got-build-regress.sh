#!/bin/sh
#
# Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

prog=`basename $0`
usage="$prog [-fG] [-b branch] [-R testroot] [-r from-address] [-w worktree] email-address ..."
branch=main
worktree=$HOME/got
fromaddr_arg=
force=0
gotd=0
webd=0
testroot="/tmp"

while getopts b:fGR:r:Ww: arg; do
	case $arg in
	b)
		branch="$OPTARG" ;;
	f)
		force=1 ;;
	G)
		gotd=1 ;;
	R)
		testroot="$OPTARG" ;;
	r)
		fromaddr_arg="-r $OPTARG" ;;
	W)
		webd=1 ;;
	w)
		worktree="$OPTARG" ;;
	?)
		echo "usage: $usage" >&2
		exit 1 ;;
	esac
done
shift $(($OPTIND - 1))

recipients="$@"
if [ -z "$recipients" ]; then
	echo "usage: $usage" >&2
	exit 1
fi

log_cmd() {
	logfile=$1
	shift
	echo \$ $@ >> $logfile
	$* >> $logfile 2>&1
}

ncpu=`sysctl -n hw.ncpuonline`
lockfile=$worktree/.${prog}.lock

cd "$worktree" || exit 1

lockfile -r 3 "$lockfile" || exit 1
trap "rm -f '$lockfile'" HUP INT QUIT KILL TERM EXIT

rm -f regress.log failures.log
echo -n "$prog for branch '$branch' on " > build.log
date -u >> build.log

printf "\nRunning on " >> build.log
sysctl -n kern.version >> build.log

printf "\n\tCleaning the work tree\n\n" >> build.log
log_cmd build.log got status
log_cmd build.log make clean

printf "\n\n\tUpdating the work tree\n\n" >> build.log
log_cmd build.log cat .got/base-commit
old_basecommit=`cat .got/base-commit`
log_cmd build.log /usr/local/bin/got update -b "$branch"
update_status="$?"
if [ "$update_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog update failure" $recipients < build.log
	exit 0
fi
new_basecommit=`cat .got/base-commit`

if [ "$force" -ne 1 -a "$old_basecommit" == "$new_basecommit" ]; then
	exit 0
fi

printf "\n\n\tTesting a regular dev build\n\n" >> build.log
log_cmd build.log make obj
log_cmd build.log make -j $ncpu
build_status="$?"
if [ "$build_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog build failure" $recipients < build.log
	exit 0
fi
log_cmd build.log make install
log_cmd build.log make -j $ncpu webd
build_status="$?"
if [ "$build_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog build failure" $recipients < build.log
	exit 0
fi
log_cmd build.log make -j $ncpu server
build_status="$?"
if [ "$build_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog build failure" $recipients < build.log
	exit 0
fi
log_cmd build.log make server-install

log_cmd build.log make -j $ncpu sysd
build_status="$?"
if [ "$build_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog build failure" $recipients < build.log
	exit 0
fi
log_cmd build.log make sysd-install

printf "\n\n\tRunning tests\n\n" >> build.log
log_cmd regress.log env PATH=$HOME/bin:$PATH make regress GOT_TEST_ROOT="$testroot"
regress_status="$?"
cat regress.log >> build.log
egrep "test.*failed" regress.log > failures.log
regress_failure_grep="$?"
if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
	printf "\n\n\t Test failures:\n\n" >> build.log
	cat failures.log >> build.log
	mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
	exit 0
fi

printf "\n\n\tRunning tests with pack files\n\n" >> build.log
log_cmd regress.log env PATH=$HOME/bin:$PATH make regress GOT_TEST_ROOT="$testroot" GOT_TEST_PACK=1
regress_status="$?"
cat regress.log >> build.log
egrep "test.*failed" regress.log > failures.log
regress_failure_grep="$?"
if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
	printf "\n\n\t Test failures:\n\n" >> build.log
	cat failures.log >> build.log
	mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
	exit 0
fi

printf "\n\n\tRunning tests with pack files using ref-delta\n\n" >> build.log
log_cmd regress.log env PATH=$HOME/bin:$PATH make regress GOT_TEST_ROOT="$testroot" GOT_TEST_PACK=ref-delta
regress_status="$?"
cat regress.log >> build.log
egrep "test.*failed" regress.log > failures.log
regress_failure_grep="$?"
if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
	printf "\n\n\t Test failures:\n\n" >> build.log
	cat failures.log >> build.log
	mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
	exit 0
fi

printf "\n\n\tRunning tests with sha256\n\n" >> build.log
log_cmd regress.log env PATH=$HOME/bin:$PATH make regress GOT_TEST_ROOT="$testroot" GOT_TEST_ALGO=sha256
regress_status="$?"
cat regress.log >> build.log
egrep "test.*failed" regress.log > failures.log
regress_failure_grep="$?"
if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
	printf "\n\n\t Test failures:\n\n" >> build.log
	cat failures.log >> build.log
	mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
	exit 0
fi

printf "\n\n\tRunning tests with sha256 and pack files\n\n" >> build.log
log_cmd regress.log env PATH=$HOME/bin:$PATH make regress GOT_TEST_ROOT="$testroot" GOT_TEST_ALGO=sha256 GOT_TEST_PACK=1
regress_status="$?"
cat regress.log >> build.log
egrep "test.*failed" regress.log > failures.log
regress_failure_grep="$?"
if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
	printf "\n\n\t Test failures:\n\n" >> build.log
	cat failures.log >> build.log
	mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
	exit 0
fi

if [ $gotd -ne 0 ]; then
	printf "\n\n\tRunning gotd tests\n\n" >> build.log
	log_cmd regress.log doas env PATH=$HOME/bin:$PATH make server-regress
	regress_status=$?
	cat regress.log >> build.log
	egrep "test.*failed" regress.log > failures.log
	regress_failure_grep="$?"
	if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
		printf "\n\n\t Test failures:\n\n" >> build.log
		cat failures.log >> build.log
		mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
		exit 0
	fi
fi

if [ $webd -ne 0 ]; then
	printf "\n\n\tRunning gotwebd tests\n\n" >> build.log
	log_cmd regress.log doas env PATH=$HOME/bin:$PATH make webd-regress
	regress_status=$?
	cat regress.log >> build.log
	egrep "test.*failed" regress.log > failures.log
	regress_failure_grep="$?"
	if [ "$regress_status" -ne 0 -o "$regress_failure_grep" -eq 0 ]; then
		printf "\n\n\t Test failures:\n\n" >> build.log
		cat failures.log >> build.log
		mail $fromaddr_arg -s "$prog regress failure" $recipients < build.log
		exit 0
	fi
fi

printf "\n\n\tTesting a release build\n\n" >> build.log
log_cmd build.log make clean
log_cmd build.log make obj
log_cmd build.log make -j $ncpu GOT_RELEASE=Yes
log_cmd build.log make -j $ncpu GOT_RELEASE=Yes webd
log_cmd build.log make -j $ncpu GOT_RELEASE=Yes server
build_status="$?"
if [ "$build_status" -ne 0 ]; then
	mail $fromaddr_arg -s "$prog release mode build failure" $recipients < build.log
	exit 0
fi

exit 0
