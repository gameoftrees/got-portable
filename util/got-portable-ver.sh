#!/bin/sh
#
# got-portable-ver: emits the version of got which is building.
#		    If this is a release build, then the tag name is chomped
#		    to remove extraneous git information.
#
#		    If it's a developer build, it's left as-is.
#
# Intended to be called from configure.ac (via autogen.sh)
GOT_RELEASE=no
GOT_PORTABLE_VER=0.123

[ -d ".git" -a "$GOT_RELEASE" = "no" ] || { echo "$GOT_PORTABLE_VER" ; exit ; }

git describe --always --dirty 2>/dev/null || \
	echo "$GOT_PORTABLE_VER"
