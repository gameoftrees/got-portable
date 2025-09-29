#!/usr/bin/env bash

# Makes the release tarball for got-portable.
#
# Assumes that:
#
# * the CHANGELOG has been filed out.

PORTABLE_BRANCH=portable

die()
{
	echo "$@" >&2
	exit 1
}

# Wrap the nproc command found on Linux, to return the number of CPU cores.
# On non-Linux systems, the same value can be found via sysctl.  For
# everything else, just return "1".
nproc()
{
	NPROCCMD="nproc"

	command "$NPROCCMD" >/dev/null 2>&1 || {
		NPROCCMD="sysctl -n hw.ncpu"
	}

	result="$(eval command $NPROCCMD)"
	[ -z "$result" -o "$result" -le 0 ] && result="1"

	echo "$result"
}

{
	[ -z "$(git status --porcelain)" ] || [ "$1" != "--force" ]
} && die "Working tree is not clean"

source util/got-portable-ver.sh >/dev/null || die "Couldn't source file"

echo "Checking status of GOT_RELEASE..."
(
	[ "$GOT_RELEASE" = "no" ] || \
		die "GOT_RELEASE is not set to no: $GOT_RELEASE"

	echo "Setting status of GOT_RELEASE to yes..."
	ed -s util/got-portable-ver.sh <<<$',s/GOT_RELEASE=no/GOT_RELEASE=yes/\nw' || \
		die "Couldn't update value of GOT_RELEASE"
	echo "Next version of -portable will be: $GOT_PORTABLE_VER"
)

echo "Making release tarball..."
(
	echo "Running autogen.sh..."
	./autogen.sh >/dev/null 2>&1 || die "./autogen.sh failed"
	
	echo "Running ./configure..."
	./configure --enable-cvg >/dev/null 2>&1 || die "./configure failed"
	
	echo "Running make..."
	make -j $(nproc) >/dev/null 2>&1 || die "make failed"

	echo "Running make dist..."
	make dist >/dev/null 2>&1 || die "make dist failed"

	echo "Verifying tarball..."
	
	TEMPGV="/tmp/gv-$GOT_PORTABLE_VER"
	TEMPGV_TARBALL="got-portable-${GOT_PORTABLE_VER}.tar.gz"
	[ -d "$TEMPGV" ] || mkdir "$TEMPGV" && \
	cp ./"$TEMPGV_TARBALL" "$TEMPGV"
		(
			cd "$TEMPGV" && \
			tar xzf ./"$TEMPGV_TARBALL" && \
			cd ./got-portable-$GOT_PORTABLE_VER || die "Couldn't cd"

			./configure --enable-cvg >/dev/null 2>&1 || die "./configure failed"
			make -j $(nproc) >/dev/null 2>&1 || die "make failed"
		)
	echo "Done."
)
