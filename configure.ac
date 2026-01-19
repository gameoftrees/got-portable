# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([got-portable],
	m4_esyscmd_s(util/got-portable-ver.sh),
	[thomas@xteddy.org])
AC_CONFIG_AUX_DIR(etc)
AC_CONFIG_SRCDIR([lib/rcsutil.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_HEADERS([include/got_compat.h])

AC_DEFINE_UNQUOTED(VERSION, $VERSION)
AC_SUBST(VERSION)
AC_SUBST(GOT_RELEASE)

AC_DEFINE_UNQUOTED([GOT_VERSION], VERSION, [GoT version string])
AC_DEFINE_UNQUOTED([GOT_VERSION_NUMBER], VERSION, [Got version number])

AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

AC_CONFIG_SUBDIRS([template])
AC_ARG_ENABLE([cvg],
	       AS_HELP_STRING([--enable-cvg],
			      [EXPERIMENTAL: cvg - cvs-like-git]))

# Override gotd's empty_path location.
AC_ARG_WITH([gotd-empty-path],
	    [AS_HELP_STRING([--with-gotd-empty-path],
			    [gotd empty path])
	    ],
	    [GOTD_EMPTY_PATHC=$withval]
	    [])
AC_SUBST(GOTD_EMPTY_PATHC)

# Override where git's libexec helpers are located for gitwrapper.
AC_ARG_WITH([gitwrapper-git-libexec-path],
	    [AS_HELP_STRING([--with-gitwrapper-git-libexec-path],
			    [git libexec path for gitwrapper])
	    ],
	    [GITWRAPPER_LIBEXEC_PATHC=$withval]
	    [])
AC_SUBST(GITWRAPPER_LIBEXEC_PATHC)

# When CFLAGS isn't set at this stage and gcc is detected by the macro below,
# autoconf will automatically use CFLAGS="-O2 -g". Prevent that by using an
# empty default.
: ${CFLAGS=""}

# Save user CPPFLAGS, CFLAGS and LDFLAGS. We need to change them because
# AC_CHECK_HEADER doesn't give us any other way to update the include
# paths. But for Makefile.am we want to use AM_CPPFLAGS and friends.
SAVED_CFLAGS="$CFLAGS"
SAVED_CPPFLAGS="$CPPFLAGS"
SAVED_LDFLAGS="$LDFLAGS"

# YACC override
YACC_OVERRIDE="yes"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
if test -z "$YACC"; then
YACC_OVERRIDE="no"
AC_PROG_YACC
fi
AM_PROG_AR
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

if test "$YACC_OVERRIDE" = "yes"; then
	AC_MSG_NOTICE("Using YACC set from environment: $YACC")
fi

# Checks for header files.
AC_CHECK_HEADERS([ \
	fcntl.h \
	getopt.h \
	langinfo.h \
	libutil.h \
	limits.h \
	linux/landlock.h \
	locale.h \
	netdb.h \
	netinet/in.h \
	paths.h \
	poll.h \
	sha.h \
	sha1.h \
	sha2.h \
	sha256.h \
	stddef.h \
	stdint.h \
	stdlib.h \
	string.h \
	sys/ioctl.h \
	sys/param.h \
	sys/poll.h \
	sys/queue.h \
	sys/select.h \
	sys/socket.h \
	sys/time.h \
	sys/tree.h \
	tls.h \
	util.h \
	unistd.h \
	wchar.h \
])

AC_HEADER_DIRENT
AC_CHECK_DECL([F_CLOSEM],
	      HAVE_FCNTL_CLOSEM
	      AC_DEFINE([HAVE_FCNTL_CLOSEM], [1],
			[Use F_CLOSEM fcntl for closefrom]),
			[],
			[#include <limits.h>
			 #include <fcntl.h>
			]
)

AC_MSG_CHECKING([for /proc/pid/fd directory])
if test -d "/proc/$$/fd" ; then
	AC_DEFINE([HAVE_PROC_PID], [1], [Define if you have /proc/$pid/fd])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([whether program_invocation_short_name is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <argp.h>
]], [[
	program_invocation_short_name = "test";
]])], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([HAVE_PROGRAM_INVOCATION_SHORT_NAME], [1],
		[Define if program_invocation_short_name is defined])
], [
	AC_MSG_RESULT([no])
])

# Look for prctl(PR_SET_NAME).
AC_CHECK_DECL(
	[PR_SET_NAME],
	[AC_DEFINE([HAVE_PR_SET_NAME], [1], [Define if PR_SET_NAME is defined])],
	[],
	[#include <sys/prctl.h>]
)

AM_CONDITIONAL([HAVE_SHA2], [test "x$ac_cv_header_sha2_h" = xyes || \
	test "x$ac_cv_header_sha256_h" = xyes])

AC_CACHE_CHECK([whether getopt has optreset support],
		ac_cv_have_getopt_optreset, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <getopt.h> ]],
		[[ extern int optreset; optreset = 0; ]])],
	[ ac_cv_have_getopt_optreset="yes" ],
	[ ac_cv_have_getopt_optreset="no"
	])
])

AM_CONDITIONAL([HAVE_GETOPT], [test "x$ac_cv_have_getopt_optreset" = "xyes"])
if test "x$ac_cv_have_getopt_optreset" = "xyes" ; then
	AC_DEFINE([HAVE_GETOPT_OPTRESET], [1],
		[Define if your getopt(3) defines and uses optreset])
fi

AC_CHECK_MEMBERS([struct pollfd.fd], [], [], [[
#include <sys/types.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
]])

# Checks for typ edefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Check for ifgroupreq which is only available on BSD.
AC_CHECK_TYPES([struct ifgroupreq])

# Check for sockaddr_storage.  On some systems, ss_len is filled out, although
# this is not mandated by POSIX, and hence systems such as linux, don't have
# it.
AC_CHECK_TYPES([struct sockaddr_storage], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])

# Same thing as sockaddr_storage above, only now check if the member exists in
# the struct as well.
AC_CHECK_MEMBERS([struct sockaddr_storage.ss_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

# Both checks above will result in:
#
# HAVE_STRUCT_SOCKADDR_AS_LEN
# SS_LEN
#
# Either being defined or not.

# Look for library needed for flock.
AC_SEARCH_LIBS(flock, bsd)

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ \
	dup2 \
	flock \
	getcwd \
	localtime_r \
	memchr \
	memmove \
	memset \
	mergesort \
	mkdir \
	munmap \
	nl_langinfo \
	realpath \
	regcomp \
	rmdir \
	setlocale \
	socket \
	setresgid \
	setresuid \
	setproctitle \
	strcasecmp \
	strchr \
	strcspn \
	strdup \
	strerror \
	strncasecmp \
	strndup \
	strrchr \
	strspn \
	strstr \
	strtol \
	strtoul \
	sysconf \
	wcwidth \
])

AC_CHECK_DECL(
	RB_GENERATE_STATIC,
	found_sys_tree_h=yes,
	found_sys_tree_h=no,
	[#include <sys/tree.h>]
)

AM_CONDITIONAL([HAVE_SETPROCTITLE], [test "x$ac_cv_func_setproctitle" = xyes])

if test "x$ac_cv_func_sysconf" = xyes; then
	AC_DEFINE([HAVE_SYSCONF], [1], [Define to 1 if sysconf() present])
fi

# Siphash support.
AC_CHECK_FUNCS([SipHash])
AM_CONDITIONAL([HAVE_SIPHASH], [test "x$ac_cv_func_SipHash" = xyes])

# Check for functions with a compatibility implementation.
AC_REPLACE_FUNCS([ \
	asprintf \
	closefrom \
	explicit_bzero \
	fmt_scaled \
	freezero \
	getdtablecount \
	getline \
	getprogname \
	recallocarray \
	reallocarray \
	strlcat \
	strlcpy \
	strndup \
	strnlen \
	strsep \
	strtonum \
])
AM_CONDITIONAL([HAVE_CLOSEFROM], [test "x$ac_cv_func_closefrom" = xyes])

# Always use our getopt because 1) glibc's doesn't enforce argument order 2)
# musl does not set optarg to NULL for flags without arguments (although it is
# not required to, but it is helpful) 3) there are probably other weird
# implementations.
AC_LIBOBJ(getopt)

# Check for b64_ntop. If we have b64_ntop, we assume b64_pton as well.
AC_MSG_CHECKING(for b64_ntop)
	AC_LINK_IFELSE([AC_LANG_PROGRAM(
	[
		#include <sys/types.h>
		#include <netinet/in.h>
		#include <resolv.h>
	],
	[
		b64_ntop(NULL, 0, NULL, 0);
	])],
	found_b64_ntop=yes,
	found_b64_ntop=no
)
AC_MSG_RESULT($found_b64_ntop)
libresolv_LIBS=""
if test "x$found_b64_ntop" = xno; then
	AC_MSG_CHECKING(for b64_ntop with -lresolv)
	LIBS="-lresolv"
	AC_LINK_IFELSE([AC_LANG_PROGRAM(
		[
			#include <sys/types.h>
			#include <netinet/in.h>
			#include <resolv.h>
		],
		[
			b64_ntop(NULL, 0, NULL, 0);
		])],
		found_b64_ntop=yes,
		found_b64_ntop=no
	)
	AC_MSG_RESULT($found_b64_ntop)
	libresolv_LIBS="$LIBS"
fi
if test "x$found_b64_ntop" = xno; then
	AC_MSG_CHECKING(for b64_ntop with -lnetwork)
	LIBS="-lresolv -lnetwork"
	AC_LINK_IFELSE([AC_LANG_PROGRAM(
		[
			#include <sys/types.h>
			#include <netinet/in.h>
			#include <resolv.h>
		],
		[
			b64_ntop(NULL, 0, NULL, 0);
		])],
		found_b64_ntop=yes,
		found_b64_ntop=no
	)
	AC_MSG_RESULT($found_b64_ntop)
	libresolv_LIBS="$LIBS"
fi

AM_CONDITIONAL([HAVE_B64], [test "x$found_b64_ntop" = xyes])
if test "x$found_b64_ntop" = xyes; then
	AC_DEFINE([HAVE_B64_NTOP], [1], [define if b64_ntop is present])
	AC_SUBST(libresolv_LIBS)
else
	AC_LIBOBJ(base64)
fi

# Check the platform we're compiling on.
AC_MSG_CHECKING(platform)
case "$host_os" in
	*linux*)
		AC_MSG_RESULT(linux)
		PLATFORM=linux
		;;
	*freebsd*)
		AC_MSG_RESULT(freebsd)
		PLATFORM=freebsd
		;;
	*darwin*)
		AC_MSG_RESULT(darwin)
		PLATFORM=darwin
		;;
	*netbsd*)
		AC_MSG_RESULT(netbsd)
		PLATFORM=netbsd
		;;
	*openbsd*)
		AC_MSG_RESULT(openbsd)
		PLATFORM=openbsd
		;;
	*dragonfly*)
		AC_MSG_RESULT(dragonfly)
		PLATFORM=dragonflybsd
		;;
	*)
		AC_MSG_RESULT(unknown)
		PLATFORM=unknown
		;;
esac
AC_SUBST(PLATFORM)
AM_CONDITIONAL([HOST_FREEBSD], [test "$PLATFORM" = "freebsd"])
AM_CONDITIONAL([HOST_LINUX], [test "$PLATFORM" = "linux"])
AM_CONDITIONAL([HOST_DARWIN], [test "$PLATFORM" = "darwin"])
AM_CONDITIONAL([HOST_NETBSD], [test "$PLATFORM" = "netbsd"])
AM_CONDITIONAL([HOST_OPENBSD], [test "$PLATFORM" = "openbsd"])
AM_CONDITIONAL([HOST_DRAGONFLYBSD], [test "$PLATFORM" = "dragonflybsd"])

# On OpenBSD, these functions are already defined, yet looking for them in
# this way on OpenBSD breaks <sha2.h> inclusion.
# FIXME: this needs addressing.
if test "x$PLATFORM" != "xopenbsd"; then
	AC_CHECK_FUNCS([SHA256Update])
fi

# Look for yacc.
if test "YACC_OVERRIDE" = "yes" && test -n "$YACC" \
	&& ! command -v "$YACC" >/dev/null 2>&1; then
	AC_MSG_ERROR("yacc not found: $YACC")
fi

if test x"$PLATFORM" = "xdarwin"; then
	# Check for and/or set HOMEBREW_PREFIX.  brew is a common way of
	# installing applications.  The other is MacPorts.
	#
	# Before Apple Silicon existed (M1 onward), the paths for applications
	# installed via homebrew was typically /usr/local.  However, with M1
	# onward, this changed to a different path.
	#
	# Rather than hardcode this, check for HOMEBREW_PREFIX in the
	# environment if it's already set, and use it.  Otherwise, check for
	# brew(1) and use that.  If that fails, default to /usr/local
	#
	# This also means that MacPorts should continue to work.
	#
	# But with MacPorts, we should also check --prefix, and use that if it
	# has been supplied.
	#
	# In both cases, the variable HOMEBREW_PREFIX is used for both.
	HB_PREFIX=""
	FOUND_BISON="no"
	GNUBISON=""
	if test -z "$HOMEBREW_PREFIX" -o "$HOMEBREW_PREFIX" = "NONE"; then
		# HOMEBREW_PREFIX not set, check for brew(1)
		if command -v brew >/dev/null 2>&1; then
			AC_MSG_NOTICE("HOMEBREW_PREFIX set via 'brew --prefix'")
			export HOMEBREW_PREFIX="$(brew --prefix)"
		fi

		if test -z "$HOMEBREW_PREFIX" -o "$HOMEBREW_PREFIX" = "NONE"
		then
			# Default.
			if test -z "${prefix}" -o "${prefix}" = "NONE"; then
				export HOMEBREW_PREFIX="/usr/local"
				HB_PREFIX="/usr/local"
				AC_MSG_NOTICE("HOMEBREW_PREFIX defaulting to $HB_PREFIX")
			else
				HB_PREFIX="$(eval echo ${prefix})"
				if test "$HB_PREFIX" = "NONE"; then
					HB_PREFIX="/opt/local"
				else
					AC_MSG_NOTICE("HOMEBREW_PREFIX using --prefix")
				fi
				export HOMEBREW_PREFIX="$HB_PREFIX"
			fi
		fi
	fi

	AC_MSG_NOTICE("HOMEBREW_PREFIX determined as: $HOMEBREW_PREFIX")

	if test "$YACC_OVERRIDE" = "no" && \
		! test -x "${HOMEBREW_PREFIX}/opt/bison/bin/bison"; then
		AC_MSG_WARN([
			     "***********************************************************
			     GNU Bison not found: ${HOMEBREW_PREFIX}/opt/bison/bin/bison
			     ***********************************************************

			     Falling back to checking either /usr/local or \${prefix}"
		])

		FOUND_BISON="no"
		AC_MSG_WARN("Trying ${HB_PREFIX}/opt/bison/bin/bison")
		if test -x "${HB_PREFIX}/opt/bison/bin/bison"; then
			export HOMEBREW_PREFIX="/usr/local"
			FOUND_BISON="yes"
			GNUBISON="${HB_PREFIX}/opt/bison/bin/bison"
		fi

		if test "$FOUND_BISON" = "no"; then
			HB_PREFIX="/opt/local"
			AC_MSG_WARN("Trying ${HB_PREFIX}/bin/bison")

			if test -x "${HB_PREFIX}/bin/bison"; then
				export HOMEBREW_PREFIX="${HB_PREFIX}"
				GNUBISON="${HB_PREFIX}/bin/bison"
				FOUND_BISON="yes"
			fi
		fi
	else
		FOUND_BISON="yes"
		GNUBISON="${HOMEBREW_PREFIX}/opt/bison/bin/bison"
	fi

	if test "$FOUND_BISON" = "no" && test "$YACC_OVERRIDE" = "no"; then
		AC_MSG_ERROR("*** Couldn't find GNU BISON ***")
	fi

	# Override YACC here to point to the GNU version of bison.
	if test "$YACC_OVERRIDE" = "yes"; then
		export YACC="$YACC -y"
	else
		AC_MSG_NOTICE("Found GNU Bison as: $GNUBISON")
		export YACC="${GNUBISON} -y"
	fi
	export LDFLAGS="-L${HOMEBREW_PREFIX}/opt/ncurses/lib -L${HOMEBREW_PREFIX}/opt/openssl@3/lib $LDFLAGS"
	export CPPFLAGS="-I${HOMEBREW_PREFIX}/opt/ncurses/include -I${HOMEBREW_PREFIX}/opt/openssl@3/include $CPPFLAGS"
	export PKG_CONFIG_PATH="${HOMEBREW_PREFIX}/opt/ncurses/lib/pkgconfig"
	export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:${HOMEBREW_PREFIX}/opt/openssl@3/lib/pkgconfig"
fi

# Landlock detection.
AC_MSG_CHECKING([for landlock])
AM_CONDITIONAL([HAVE_LINUX_LANDLOCK],
    [test "x$ac_cv_header_linux_landlock_h" = "xyes"])
if test "x$ac_cv_header_linux_landlock_h" = "xyes"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# Clang sanitizers wrap reallocarray even if it isn't available on the target
# system. When compiled it always returns NULL and crashes the program. To
# detect this we need a more complicated test.
AC_MSG_CHECKING([for working reallocarray])
AC_RUN_IFELSE([AC_LANG_PROGRAM(
		[#include <stdlib.h>],
		[return (reallocarray(NULL, 1, 1) == NULL);]
	)],
	AC_MSG_RESULT(yes),
	[AC_LIBOBJ(reallocarray) AC_MSG_RESULT([no])],
	[AC_LIBOBJ(reallocarray) AC_MSG_RESULT([no])]
)
AC_MSG_CHECKING([for working recallocarray])
AC_RUN_IFELSE([AC_LANG_PROGRAM(
		[#include <stdlib.h>],
		[return (recallocarray(NULL, 1, 1, 1) == NULL);]
	)],
	AC_MSG_RESULT(yes),
	[AC_LIBOBJ(recallocarray) AC_MSG_RESULT([no])],
	[AC_LIBOBJ(recallocarray) AC_MSG_RESULT([no])]
)

# Look for imsg_init in libutil.
AC_SEARCH_LIBS(imsg_init, util, found_imsg_init=yes, found_imsg_init=no)
AM_CONDITIONAL([HAVE_IMSG], [test "x$found_imsg_init" = "xyes"])
if test "x$found_imsg_init" = "xyes"; then
	AC_DEFINE([HAVE_IMSG], [1], [Define to 1 if imsg is declared in libutil])
	libutil_LIBS="$ac_cv_search_imsg_init"
	AC_SUBST(libutil_LIBS)
fi

# libevent (for gotwebd).  Lifted from tmux.
# Look for libevent. Try libevent_core or libevent with pkg-config first then
# look for the library.
found_libevent=no
PKG_CHECK_MODULES(
	LIBEVENT_CORE,
	[libevent_core >= 2],
	[
		libevent_CFLAGS="$LIBEVENT_CORE_CFLAGS"
		libevent_LIBS="$LIBEVENT_CORE_LIBS"
		AC_SUBST(libevent_CFLAGS)
		AC_SUBST(libevent_LIBS)
		found_libevent=yes
	],
	found_libevent=no
)
if test x$found_libevent = xno; then
	PKG_CHECK_MODULES(
		LIBEVENT,
		[libevent >= 2],
		[
			libevent_CFLAGS="$LIBEVENT_CFLAGS"
			libevent_LIBS="$LIBEVENT_LIBS"
			AC_SUBST(libevent_CFLAGS)
			AC_SUBST(libevent_LIBS)
			found_libevent=yes
		],
		found_libevent=no
	)
fi
if test x$found_libevent = xno; then
	AC_SEARCH_LIBS(
		event_init,
		[event_core event event-1.4],
		found_libevent=yes,
		found_libevent=no
	)

	if test "x$found_libevent" = "xyes"; then
		libevent_LIBS="$ac_cv_search_event_init"
		AC_SUBST(libevent_LIBS)
	fi
fi

if test x$found_libevent = xno; then
AC_CHECK_HEADER(
	event2/event.h,
	AC_DEFINE([HAVE_EVENT2_EVENT_H], [1], [libevent2 has event.h]),
	[
		AC_CHECK_HEADER(
			event.h,
			AC_DEFINE([HAVE_EVENT_H], [0], [libevent]),
			found_libevent=no
		)
	]
)
fi

if test "x$found_libevent" = xno; then
	AC_MSG_ERROR("libevent not found")
fi

AC_CHECK_FUNC([uuid_create], [found_uuid=yes], [found_uuid=no])

# Don't define HAVE_BSD_UUID on darwin (Apple) as this breaks the BSD API.
# Instead, use the UUID implementation wrapper that's in compat/ plus uuid
# ossp
if test "x$found_uuid" = "xyes" -a "x$PLATFORM" != "darwin"; then
	AC_DEFINE([HAVE_BSD_UUID], [1], [BSD UUID])
else
	PKG_CHECK_MODULES(
		LIBUUID,
		uuid,
		[
			libuuid_CFLAGS="$LIBUUID_CFLAGS"
			libuuid_LIBS="$LIBUUID_LIBS"
			AC_SUBST(libuuid_CFLAGS)
			AC_SUBST(libuuid_LIBS)
			found_libuuid=yes
		],
		[
			found_libuuid=no
		]
	)

	if test "x$found_libuuid" = "xno"; then
		AC_CHECK_HEADER(
			uuid.h,
			found_libuuid=yes,
			found_libuuid=no)
	fi
fi

if test "x$found_libuuid" = "xno"; then
	AC_MSG_ERROR("*** couldn't find uuid ***")
fi

PKG_CHECK_MODULES(
	ZLIB,
	zlib,
	[
		zlib_CFLAGS="$ZLIB_CFLAGS"
		zlib_LIBS="$ZLIB_LIBS"
		AC_SUBST(zlib_CFLAGS)
		AC_SUBST(zlib_LIBS)
		found_zlib=yes
	],
	[
	 	found_zlib=no
	]
)

if test "x$found_zlib" = "xno"; then
	AC_CHECK_HEADER(
		zlib.h,
		,
		found_zlib=no)
fi

if test "x$found_zlib" = "xno"; then
	AC_MSG_ERROR("*** couldn't find zlib ***")
fi

if test "$PLATFORM" = "linux"; then
	PKG_CHECK_MODULES(
		LIBBSD,
		libbsd-overlay,
		[
		 	libbsd_CFLAGS="$LIBBSD_CFLAGS"
			libbsd_LIBS="$LIBBSD_LIBS"
			AC_SUBST(libbsd_CFLAGS)
			AC_SUBST(libbsd_LIBS)
			AC_DEFINE([HAVE_LIBBSD], [1], [BSD UUID])
			AC_DEFINE([HAVE_TREE_H], [test x"$found_sys_tree_h" = "xyes"], [HAVE_TREE_H])
		],
		[
			AC_MSG_ERROR("*** couldn't find libbsd-overlay via pkg-config")
		]

	)

	# Add LIBBSD_{CFLAGS,LIBS} to the environment here, as libbsd puts its
	# header files in a non-standard location, which means the overlay for
	# <sys/tree.h> and <sys/queue.h> won't be found.
	CFLAGS="$CFLAGS $LIBBSD_CFLAGS"
	LIBS="$LIBS $LIBBSD_LIBS"

	PKG_CHECK_MODULES(
		LIBMD,
		libmd,
		[
		     libmd_CFLAGS="$LIBMD_CFLAGS"
		     libmd_LIBS="$LIBMD_LIBS"
		     AC_SUBST(libmd_CFLAGS)
		     AC_SUBST(libmd_LIBS)
		], []
	)
	CFLAGS="$CFLAGS $LIBMD_CFLAGS"
	LIBS="$LIBS $LIBMD_LIBS"

fi

# Look for a suitable queue.h.  We hope libbsd is enough, but that is missing
# some declarations.
AC_CHECK_DECL(
	TAILQ_CONCAT,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_PREV,
	,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_FOREACH_SAFE,
	,
	found_queue_h=no,
	[#include <sys/queue.h>]
)

if test "x$found_queue_h" = xyes; then
	AC_DEFINE([HAVE_QUEUE_H], [1], [sys/queue.h])
else
	AC_MSG_ERROR("*** sys/queue.h missing key defines ***)
fi

# Look for crypto (part of openssl)
# Note:  libcrypto (via openssl) has a .pc file in pretty-much all distros and
# BSDs which we support.
PKG_CHECK_MODULES(
	LIBCRYPTO,
	[libcrypto],
	[
		libcrypto_CFLAGS="$LIBCRYPTO_CFLAGS"
		libcrypto_LIBS="$LIBCRYPTO_LIBS"
		AC_SUBST(libcrypto_CFLAGS)
		AC_SUBST(libcrypto_LIBS)
	],
	AC_MSG_ERROR(["*** Couldn't find libcrypto ***"])
)

if test "x$PLATFORM" != "xopenbsd"; then
PKG_CHECK_MODULES(
	LIBTLS,
	[libtls],
	[
		libtls_CFLAGS="$LIBTLS_CFLAGS"
		libtls_LIBS="$LIBTLS_LIBS"
		AC_SUBST(libtls_CFLAGS)
		AC_SUBST(libtls_LIBS)
	],
	AC_MSG_ERROR(["*** Couldn't find libtls ***"])
)
fi

# Look for __progname.
AC_MSG_CHECKING(for __progname)
AC_LINK_IFELSE([AC_LANG_SOURCE(
	[
		#include <stdio.h>
		#include <stdlib.h>
		extern char *__progname;
		int main(void) {
			const char *cp = __progname;
			printf("%s\n", cp);
			exit(0);
		}
	])],
	[AC_DEFINE([HAVE___PROGNAME], [1], [___progname]) AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

PKG_CHECK_MODULES(
	LIBPANELW,
	panelw,
	LIBPANELW_LIBS="$LIBPANELW_LIBS"
	found_panel=yes,
	found_panel=no
)

if test "x$found_panel" = "xno"; then
PKG_CHECK_MODULES(
	LIBPANELW,
	gnupanelw,
	[
		LIBPANELW_LIBS="$LIBPANELW_LIBS"
		found_panel=yes
	],
	found_panel=no
)
fi

if test "x$found_panel" = "xno"; then
PKG_CHECK_MODULES(
	LIBPANELW,
	panel,
	[
		LIBPANELW_LIBS="$LIBPANELW_LIBS"
		found_panel=yes
	],
	found_panel=no
)
fi

if test "x$found_panel" = "xno"; then
	AC_CHECK_LIB(panelw, update_panels, [],
		AC_MSG_ERROR([ "*** panelw not found for ncurses. ***"]),
		[-lncurses]
	)

fi

PKG_CHECK_MODULES(
	LIBNCURSES,
	ncursesw,
	found_ncurses=yes,
	found_ncurses=no
)
if test "x$found_ncurses" = xyes; then
	libncurses_CFLAGS="$LIBNCURSES_CFLAGS $LIBTINFO_CFLAGS $LIBPANELW_CFLAGS"
	libncurses_LIBS="$LIBNCURSES_LIBS $LIBTINFO_LIBS $LIBPANELW_LIBS"
	AC_SUBST(libncurses_CFLAGS)
	AC_SUBST(libncurses_LIBS)
else
	AC_SEARCH_LIBS(
		setupterm,
		found_ncurses=yes,
		found_ncurses=no
	)
	if test "x$found_ncurses" = xyes; then
		AC_CHECK_HEADER(
			ncurses.h,
			libncurses_CFLAGS="$LIBPANELW_CFLAGS $LIBPANEL_CFLAGS"
			libncurses_LIBS="$LIBPANELW_LIBS -lncursesw"
			AC_SUBST(libncurses_CFLAGS)
			AC_SUBST(libncurses_LIBS)
		)
	fi
fi
if test "x$found_ncurses" = xyes; then
	AC_DEFINE([HAVE_NCURSES_H], [1], [NCurses])
else
	# No ncurses, try curses.
	AC_CHECK_FUNC(
		setupterm,
		found_curses=yes,
		found_curses=no
	)
	AC_CHECK_HEADER(
		curses.h,
		found_curses=yes,
		found_curses=no)
	if test "x$found_curses" = xyes; then
		libncurses_CFLAGS="$LIBPANELW_CFLAGS $LIBPANEL_CFLAGS"
		libncurses_LIBS="$LIBPANELW_LIBS -lncursesw -lpanelw"
		AC_SUBST(libncurses_CFLAGS)
		AC_SUBST(libncurses_LIBS)
		AC_DEFINE([HAVE_CURSES_H], [1], [Curses_h])
	else
		AC_MSG_ERROR("curses not found")
	fi
fi

# Save our CFLAGS/CPPFLAGS/LDFLAGS for the Makefile and restore the old user
# variables.
AC_SUBST(AM_CPPFLAGS)
CPPFLAGS="$SAVED_CPPFLAGS"
AC_SUBST(AM_CFLAGS)
CFLAGS="$SAVED_CFLAGS"
AC_SUBST(AM_LDFLAGS)
LDFLAGS="$SAVED_LDFLAGS"

# LIBS is designed to accumulate library dependencies as checks for them are
# peformed, so that this can be included directly to ld(1).
#
# However, this hinders the splitting up of the library dependencies so that
# they're targetted just where they're needed.  Flatting LIBS here ensures
# that this happens appropriately.
LIBS=""

AH_BOTTOM([#include "got_compat2.h"])

AM_CONDITIONAL([CVG_ENABLED], [test "x$enable_cvg" = xyes])

AC_CONFIG_FILES([Makefile
		 compat/Makefile
		 gitwrapper/Makefile
		 got/Makefile
		 gotadmin/Makefile
		 gotctl/Makefile
		 gotd/Makefile
		 gotd/libexec/Makefile
		 gotd/libexec/got-notify-email/Makefile
		 gotd/libexec/got-notify-http/Makefile
		 gotsh/Makefile
		 gotwebctl/Makefile
		 gotwebd/Makefile
		 libexec/Makefile
		 libexec/got-fetch-http/Makefile
		 libexec/got-fetch-pack/Makefile
		 libexec/got-index-pack/Makefile
		 libexec/got-read-blob/Makefile
		 libexec/got-read-commit/Makefile
		 libexec/got-read-gitconfig/Makefile
		 libexec/got-read-gotconfig/Makefile
		 libexec/got-read-object/Makefile
		 libexec/got-read-pack/Makefile
		 libexec/got-read-patch/Makefile
		 libexec/got-read-tag/Makefile
		 libexec/got-read-tree/Makefile
		 libexec/got-send-pack/Makefile
		 tog/Makefile
		 Makefile.common:Makefile.common.in])

if test "x$enable_cvg" = "xyes"; then
	AC_CONFIG_FILES([cvg/Makefile])
fi

AC_OUTPUT

executables="$(eval echo ${exec_prefix}/bin)"
helpers="$(eval echo ${libexecdir})"
manpages="$(eval echo ${mandir})"
gotdep="$GOTD_EMPTY_PATHC"
gotgwlep="$GITWRAPPER_LIBEXEC_PATHC"

if test -z "$enable_cvg"; then
	enable_cvg="no"
fi

if test -z "$gotdep"; then
	gotdep="N/A"
fi

if test -z "$gotgwlep"; then
	gotgwlep="N/A"
fi

echo "
Configured got-portable with:

 Version:	   $VERSION

 Prefix:           ${prefix}
 Executables:      ${executables}
 Bison:            $YACC
 CFlags:           $CFLAGS
 cvg:		   ${enable_cvg}
 Gotd:
   Empty Path:     ${gotdep}
   Gitwrapper:     ${gotgwlep}
 Helpers:          ${helpers}
 Man pages:        ${manpages}
"
