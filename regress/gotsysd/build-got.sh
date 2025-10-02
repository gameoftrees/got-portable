#!/bin/sh

set -e

cd ~/src/got

# Because we copied this got src tree from the host the modified-timestamps
# on already compiled files might be off. Clean out any build artifacts.
# We cannot run the top-level clean target because some subdirs are missing,
# most notably the regress directory.
for d in got* git* lib* template tog; do
	if [ -d "${d}" ]; then
		make -s -C "${d}" clean > /dev/null
	fi
done

echo "Building gotsysd, gotd, gotwebd, and got:"
make -s GOT_RELEASE=Yes DEBUG="-O0 -g" sysd server webd all
