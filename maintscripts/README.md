MAINTSCRIPTS
============

This directory contains scripts to aid in the maintenance of -portable.

* `sync-upstream.sh`:  this script helps automate the syncing of upstream
  `GoT` with `-portable`.
* `mk-portable-release.sh`: prepares release notes, verifies a distribution
  with `make distcheck`, and creates a local release commit and annotated tag.
  See `--help` and the release instructions in `README.portable`.
