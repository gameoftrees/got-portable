README.portable
===============

**NOTE: This repository is read-only and is used only to mirror the
got-portable repository for CI purposes.**

This is the portable version of got[1] (Game of Trees), using autotools to
provide the library checks required for GoT's dependencies.

The following operating systems are supported:

* FreeBSD
* NetBSD
* DragonFlyBSD
* MacOS
* Linux

DEPENDENCIES
============

Note that the names of these libraries are indicative only; the names might
vary.

Linux:

* `libncurses` (for tog(1))
* `libbsd` (BSD's arc4random routines)
* `libmd` (SHA256 routines)
* `libuuid` (for UUID generation)
* `libz` (for Z compression)
* `pkg-config` (for searching libraries)
* `bison` (for configuration file grammar)
* `libevent` (for gotwebd)
* `libtls` (may be known as `libretls`)

FreeBSD:

* `automake`
* `pkgconf`
* `libretls`
* `libevent` (for gotwebd)

NetBSD:

* `automake`
* `libuuid`
* `ncuresesw`
* `libevent` (for gotwebd)
* `libretls`

DragonFlyBSD:

* `automake`
* `pkgconf`
* `openssl`
* `libevent` (for gotwebd)
* `libretls`

Darwin (MacOS):

* `automake`
* `bison`
* `pkg-config`
* `ncurses`
* `openssl`
* `ossp-uuid`
* `libevent` (for gotwebd)
* `libretls`

TESTS (REGRESS)
===============

To run the test suite:

```
 $ make tests
```

The tests depend on git and the HTTP::Daemon Perl module.

Got may have to be installed system-wide before the tests will run
successfully because paths to helper programs, such as got-read-pack,
are hard-coded in user-facing binaries, such as got and tog.

Operations such as clone and send which use the network will be trying to
connect to 127.0.0.1 over ssh, as the same user who invoked 'make tests'.
The command 'ssh 127.0.0.1' must succeed without any interactive prompting.
The host key may need to be manually accepted once before running tests.
An SSH key can be installed in ~/.ssh/authorized_keys for authentication.

The OpenBSD version of Got also has tests for gotd and gotwebd.
These tests cannot be run in -portable yet.

There are environment variables which control some test parameters:

GOT_TEST_PACK=1 will force tests to use pack files instead of loose
objects. GOT_TEST_PACK=ref-delta will force use of pack files with
ref-deltas rather than offset-deltas.

GOT_TEST_ALGO=sha256 will run tests with sha256 repositories.

GOT_TEST_ROOT can be set to a path where temporary test data gets stored.
This defaults to /tmp.

Dependencies
============

* ed

NOTE:  THIS ONLY WORKS AFTER `make install` DUE TO HOW PATHS TO LIBEXEC
       HELPERS ARE HARD-CODED INTO THE BINARIES.

INSTALLATION
============

```
 $ ./autogen.sh
 $ ./configure && make
 $ sudo make install
```

INSTALLING AND PACKAGING GITWRAPPER
===================================

The gotd server has an optional companion tool called gitwrapper.

A gotd server can be used without gitwrapper in the following cases:

1) The Git client's user account has gotsh configured as its login shell.

2) The Git client's user account sees gotsh installed under the names
   git-receive-pack and git-upload-pack, and these appear in $PATH before
   the corresponding Git binaries if Git is also installed. Setting up the
   user's $PATH in this way can require the use of SetEnv in sshd_config.

The above cases can be too restrictive. For example, users who have regular
shell access to the system may expect to be able to serve Git repositories
from their home directories while also accessing repositories served by gotd.

Once gitwrapper has been installed correctly it provides an out-of-the box
experience where both gotd and Git "just work".
However, this will require coordination with the system's Git installation
and/or distribution package because the names of two specific Git programs
will be overlapping: git-upload-pack and git-receive-pack

If the gitwrapper tool will be used then it must replace git-receive-pack
and git-upload-pack in /usr/bin. This is usually achieved by replacing the
regular Git binaries in /usr/bin with symlinks to gitwrapper:

```
-rwxr-xr-x 1 root root 1019928 Aug 24 00:16 /usr/bin/gitwrapper
lrwxrwxrwx 1 root root 10 Aug 20 12:40 /usr/bin/git-receive-pack -> gitwrapper
lrwxrwxrwx 1 root root 10 Aug 20 12:40 /usr/bin/git-upload-pack -> gitwrapper
```

The Git binaries remain available in Git's libexec directory, which is set
when Git gets compiled. On Debian it defaults to /usr/lib/git-core.
This same path must be given to Got's configure script at build time to
allow gitwrapper to find Git's binaries:

```
  ./configure --with-gitwrapper-git-libexec-path=/usr/lib/git-core
```

Once gitwrapper is found in /usr/bin under the names git-receive-pack and
git-upload-pack, any Git repositories listed in /etc/gotd.conf will be
automatically served by gotd, and any Git repositories not listed in
/etc/gotd.conf will be automatically served by regular Git's git-upload-pack
and git-receive-pack. The client's login shell or $PATH no longer matter,
and a peaceful co-existence of gotd and Git is possible.

We recommend that distribution packagers take appropriate steps to package
gitwrapper as a required dependency of gotd. It is also possible to install
gitwrapper without installing gotd. As long as /etc/gotd.conf does not exist
or no repositories are listed in /etc/gotd.conf there will be no visible
change in run-time behaviour for Git users since gitwrapper will simply run
the standard Git tools.
In the OpenBSD ports tree both the regular git package and the gotd package
are depending on gitwrapper, and the git package no longer installs the
git-receive-pack and git-upload-pack programs in /usr/local/bin.

BRANCHES + SUBMITTING PATCHES
=============================

`got-portable` has two key branches:

* `main` which tracks got upstream untainted.
* `portable` which provides the portable version of GoT based from code on `main`

Patches for portable code fixes should be based from the `portable` branch and
sent to the mailing list for review [2] or sent to me directly (see CONTACT).

Portable-specific patches should have a shortlog in the form of:

```
portable: AREA: description
```

Where `AREA` relates to the change in question (for example, `regress`,
`libexec`, etc).  In some cases, this can be omitted if it's a generic change.

This helps to delineate `-portable` changes from upstream `got`.

The read-only Github repository also runs CI checks using Cirrus-CI on Linux
and FreeBSD.

SYNCING UPSTREAM CHANGES WITH PORTABLE
======================================

The `-portable` GoT repository uses the following workflow:

```
                Github (gh)               GoT (upstream)
		  ^                              ^
		  |                              |
		  |                              |
		  |                              |
		  |                              |
		  +--------> GoT-portable <------+

```

Here, `got-portable` is a clone of the `-portable` repository, locally on
disk.  There are two remotes set up within that repository, via `git-remote`:

* `upstream` -- which points to the official GoT repository;
* `gh` -- which points to the mirrored `-portable` repository so that CI can
  be run for cross-platform/test purposes [3]
* `origin` -- our cloned copy from `-portable`

Within the `-portable` repository are two key branches (there may be other
topic branches which represent on-going work):

* `main` -- this is the branch that tracks (without modification) those
  changes from `upstream`.  This branch is continually reset to
  `upstream/main` whenever changes occur.

* `portable` -- this is the *default* branch of the `-portable` repository which
  contains portable-specific changes to make `GoT` compile across different
  OSes.

When updating `-portable` from upstream changes, the following actions happen:

1. Changes from `upstream` are fetched.  If there are no new changes, there's
   nothing else to do.
2. Changes from `gh` are fetch so that the result can be pushed out to `gh`.
3. The difference between the local copy of `main` and `origin/main` is used
   to represent the set of commits which have *NOT* yet been merged to
   `-portable`.
4. A topic-branch called `syncup` is created from the HEAD of the `portable`
   branch to hold the to-be-cherry-picked commits from step 3.
5. These commits are then cherry-picked to the `syncup` branch.
6. If there's any conflicts, they must be resolved.
7. Once done, a sanity build is done in-situ to check there's nothing amiss.
8. If that succeeds, the `syncup` branch is merged to `portable` and pushed to
   `gh` for verification against CI.
9. If that fails, fixes continue and pushed up to `gh` as required.
10. Once happy, both the `main` and `portable` branches can be merged to `origin`.

These steps are encapsulated in a script within `-portable`.  [Link](../maintscripts/sync-upstream.sh)

RELEASING A NEW VERSION
=======================

Release for `-portable` try and align as close to upstream GoT as much as
possible, even on the same day where that can happen.  That being said,
sometimes a release of `-portable` might happen outside of that cadence, where
a `-portable`-specific issue needs addressing, for example.

Before creating a new release, check the version of GoT as found in
`util/got-portable-ver.sh` -- as `GOT_PORTABLE_VER`:

```
GOT_PORTABLE_VER=0.75

```

Here, the *to be released* version of `got-portable` will be `0.75`.

The variable `GOT_RELEASE` needs be changed to `yes` so that the
GOT_PORTABLE_VER is asserted correctly.

The variable `GOT_RELEASE` needs be changed to `yes` so that the
GOT_PORTABLE_VER is asserted correctly.

Once the version is verified, the following should be run from the `portable`
branch -- and the repository should not have any outstanding modifications to
the source:

```
make clean ; ./autogen && ./configure && make distcheck
```

If this succeeds, the tarball is in the CWD, as: `got-portable-VERSION.tar.gz`

This can then be copied to the `got-www` repository and uploaded, along with
changing a couple of HTML pages therein to represent the new released version.
Additionally, the CHANGELOG file can be copied to the `got-www` and committed.

Once all of that has been done, the repository should be tagged to indicate
the release, hence:

```
git tag -a 0.75
```

This can then be pushed out to `gh` and `origin`.

After that point, the version of `GOT_PORTABLE_VER` in
`util/got-portable-ver.sh` should be changed to the next version, and
`GOT_RELEASE` should be setg back to `no`.

MAINTENANCE RELEASES
====================

The only exception to changing the `GOT_PORTABLE_VER` would be if there were
an out-of-band release to `-portable`.  In such cases, that would take the
form:

```
0.75.1
```

Where the suffix of `1`, `2`, etc., can be used to denote any sub-releases
from the `0.75` version.

Henceforth, all other instructions are the same as per `RELEASING A NEW VERSION`.

TODO
====

* configure.ac should start defining AC_ENABLE arguments to allow for
  finer-grained control of where to search for includes/libraries, etc.
* review the compat/ code.  Some of those functions are probably picked up in
  libbsd, so we should drop such implementations from compat/ where there's
  overlap between libbsd and what's natively available.

CONTACT
=======

Thomas Adam <thomas@xteddy.org><br />
thomas_adam (#gameoftrees on irc.libera.chat)

[1]  https://gameoftrees.org<br />
[2]  https://lists.openbsd.org/cgi-bin/mj_wwwusr?user=&passw=&func=lists-long-full&extra=gameoftrees<br />
[3]  https://github.com/ThomasAdam/got-portable
