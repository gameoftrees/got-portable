#!/bin/sh
#
# Copyright (c) 2026 Stefan Sperling <stsp@openbsd.org>
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
. ./common.sh

zero_commit="0000000000000000000000000000000000000000"
basic_capabilities="multi_ack side-band-64k ofs-delta"
server_capabilities="ofs-delta report-status no-thin delete-refs"

if [ "$GOT_TEST_ALGO" = "sha256" ]; then
	zero_commit="${zero_commit}000000000000000000000000"
	capabilities="${basic_capabilities} object-format=sha256"
	server_capabilities="${server_capabilities} object-format=sha256"
else
	capabilities="$basic_capabilities"
fi

test_send_incompatible_hash_algo() {
	local testroot=`test_init send_incompatible_hash_algo`

	commit1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commit2="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	if [ "$GOT_TEST_ALGO" = "sha256" ]; then
		len="0087" 
		other_algo=sha1
		capabilities="${basic_capabilities}"
	else
		len="00b7"
		other_algo=sha256
		commit1="${commit1}aaaaaaaaaaaaaaaaaaaaaaaa"
		commit2="${commit2}bbbbbbbbbbbbbbbbbbbbbbbb"
	fi

	# The protocol requires an embedded NUL between reference name
	# and capabilities.
	echo "${len}$commit1 $commit2 refs/heads/mainX$capabilities" | \
		tr 'X' '\0' | \
		ssh ${GOTD_DEVUSER}@127.0.0.1 git-receive-pack '/test-repo' \
		> $testroot/stdout 2>$testroot/stderr

	# Remove embedded NUL from Git protocol with a space character.
	tr -d '\0' < $testroot/stdout > $testroot/stdout.filtered

	if [ "$GOT_TEST_ALGO" = "sha256" ]; then
		echo -n "00ae" > $testroot/stdout.expected
	else
		echo -n "0081" > $testroot/stdout.expected
	fi
	echo -n "$zero_commit capabilities^{} " >> $testroot/stdout.expected
	echo -n "agent=got/${GOT_VERSION_STR} ${server_capabilities}0000" \
		>> $testroot/stdout.expected

	if [ "$GOT_TEST_ALGO" = "sha256" ]; then
		echo -n "009aERR your Git client uses hash algorithm sha1 " \
			>> $testroot/stdout.expected
		echo -n "which is incompatible with the hash algorithm " \
			>> $testroot/stdout.expected
		echo -n "sha256 used by this repository: " \
			>> $testroot/stdout.expected
		echo -n "object format not supported" \
			>> $testroot/stdout.expected

		echo -n "gotsh: your Git client uses hash algorithm sha1 " \
			>> $testroot/stderr.expected
		echo -n "which is incompatible with the hash algorithm " \
			>> $testroot/stderr.expected
		echo -n "sha256 used by this repository: " \
			>> $testroot/stderr.expected
		echo "object format not supported" \
			>> $testroot/stderr.expected
	else
		echo -n "0025ERR ref-update with bad object ID" \
			>> $testroot/stdout.expected
		echo "gotsh: ref-update with bad object ID" \
			>> $testroot/stderr.expected
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "unexpected stdout" >&2
		diff -a -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "unexpected stderr" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

run_test test_send_incompatible_hash_algo
