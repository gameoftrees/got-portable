#!/bin/sh
#
# Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

test_file_changed() {
	local testroot=`test_init file_changed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 14\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " make changes\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_not_summarized() {
	local testroot=`test_init many_commits_not_summarized 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	for i in `seq 1 24`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local author_time=`git_show_author_time $testroot/repo-clone`
		d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
		set -- "$@" "$commit_id $d"
	done

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" \
		>> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	for i in `seq 1 24`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo "$s" | sed -e "s/^$commit_id //g")
		printf "commit $commit_id\n" >> $testroot/stdout.expected
		printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
		printf "date: $commit_time\n" >> $testroot/stdout.expected
		printf "messagelen: 14\n" >> $testroot/stdout.expected
		printf " \n" >> $testroot/stdout.expected
		printf " make changes\n \n" >> $testroot/stdout.expected
		printf " M  alpha  |  1+  1-\n\n"  \
			>> $testroot/stdout.expected
		printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
			>> $testroot/stdout.expected
	done
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_summarized() {
	local testroot=`test_init many_commits_summarized 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	for i in `seq 1 51`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local short_commit_id=`trim_obj_id 7 $commit_id`
		local author_time=`git_show_author_time $testroot/repo-clone`
		d=`date -u -r $author_time +"%F"`
		set -- "$@" "$short_commit_id $d"
	done

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" \
		>> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	for i in `seq 1 51`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo "$s" | sed -e "s/^$commit_id //g")
		printf "$commit_time $commit_id $GOT_AUTHOR_8 make changes\n" \
			>> $testroot/stdout.expected
	done
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_created() {
	local testroot=`test_init branch_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch newbranch > /dev/null)

	echo "change alpha on branch" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'change alpha on newbranch' \
		> /dev/null)
	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time=`git_show_author_time $testroot/repo-clone $commit_id`

	echo "change alpha again" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'change alpha again' > /dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time2=`git_show_author_time $testroot/repo-clone $commit_id`
	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b newbranch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id2=`trim_obj_id 12 $commit_id2`
	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} created refs/heads/newbranch: $short_commit_id2\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time2 +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 27\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " change alpha on newbranch\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "commit $commit_id2\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time2 +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 20\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " change alpha again\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_recreated() {
	local testroot=`test_init branch_recreated 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got branch -r $testroot/repo-clone -d newbranch > /dev/null

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch newbranch > /dev/null)

	echo "change beta on branch" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'change beta on newbranch' \
		> /dev/null)
	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time=`git_show_author_time $testroot/repo-clone $commit_id`

	echo "change beta again" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m 'change beta again' > /dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time2=`git_show_author_time $testroot/repo-clone $commit_id`
	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b newbranch -f -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id2=`trim_obj_id 12 $commit_id2`
	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/newbranch: $short_commit_id2\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time2 +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 26\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " change beta on newbranch\n \n" >> $testroot/stdout.expected
	printf " M  beta  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "commit $commit_id2\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time2 +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 19\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " change beta again\n \n" >> $testroot/stdout.expected
	printf " M  beta  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_removed() {
	local testroot=`test_init branch_removed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`
	local short_commit_id=`trim_obj_id 12 $commit_id`

	got send -d newbranch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} removed refs/heads/newbranch: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "Removed refs/heads/newbranch: $commit_id\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_created() {
	local testroot=`test_init tag_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local commit_id=`git_show_head $testroot/repo-clone`
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`
	local tag_id=`got ref -r $testroot/repo-clone -l \
		| grep "^refs/tags/1.0" | tr -d ' ' | cut -d: -f2`
	local short_tag_id=`trim_obj_id 12 $tag_id`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -t 1.0 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} created refs/tags/1.0: $short_tag_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "tag refs/tags/1.0\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "object: commit $commit_id\n" >> $testroot/stdout.expected
	printf "messagelen: 9\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " new tag\n \n" >> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_changed() {
	local testroot=`test_init tag_changed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`

	got ref -r $testroot/repo-clone -d refs/tags/1.0 >/dev/null
	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`
	local tag_id=`got ref -r $testroot/repo-clone -l \
		| grep "^refs/tags/1.0" | tr -d ' ' | cut -d: -f2`
	local short_tag_id=`trim_obj_id 12 $tag_id`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -f -t 1.0 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/tags/1.0: $short_tag_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "tag refs/tags/1.0\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "object: commit $commit_id\n" >> $testroot/stdout.expected
	printf "messagelen: 9\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " new tag\n \n" >> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_file_empty() {
	local testroot=`test_init file_empty 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo -n "" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'empty file' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	short_commit_id=`trim_obj_id 12 $commit_id`
	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 12\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " empty file\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  0+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 0 insertions(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_and_commit_created() {
	local testroot=`test_init tag_and_commit_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	got tag -r $testroot/repo-clone -m "new tag" 1.1 > /dev/null
	local commit_id=`git_show_head $testroot/repo-clone`
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.1`
	local tag_id=`got ref -r $testroot/repo-clone -l \
		| grep "^refs/tags/1.1" | tr -d ' ' | cut -d: -f2`
	local short_tag_id=`trim_obj_id 12 $tag_id`

	./smtp-server -p $GOTD_TEST_SMTP_PORT -r 2 \
		> $testroot/stdout 2>$testroot/stderr &

	sleep 1 # server starts up

	got send -t 1.1 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for smtp-server

	HOSTNAME=`hostname`
	short_commit_id=`trim_obj_id 12 $commit_id`

	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} created refs/tags/1.1: $short_tag_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "tag refs/tags/1.1\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "object: commit $commit_id\n" >> $testroot/stdout.expected
	printf "messagelen: 9\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " new tag\n \n" >> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected
	printf "HELO localhost\r\n" >> $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main: $short_commit_id\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 14\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " make changes\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  0-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 0 deletions(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_file_changed
run_test test_many_commits_not_summarized
run_test test_many_commits_summarized
run_test test_branch_created
run_test test_branch_recreated
run_test test_branch_removed
run_test test_tag_created
run_test test_tag_changed
run_test test_file_empty
run_test test_tag_and_commit_created
