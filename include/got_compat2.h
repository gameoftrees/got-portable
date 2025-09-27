/*
 * Copyright (c) 2023 Thomas Adam <thomas@xteddy.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GOT_COMPAT_H_2
#define _GOT_COMPAT_H_2

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#include <inttypes.h>
#endif

#include <limits.h>
#include <sys/uio.h>

#if defined(__FreeBSD__)
#include <sys/endian.h>
#include <sys/capsicum.h>
#elif defined(__APPLE__)
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#include "compat/bsd-poll.h"

#define FMT_SCALED_STRSIZE	7  /* minus sign, 4 digits, suffix, null byte */

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec

#else /* Linux, etc... */
#include <endian.h>
#include <grp.h>
#include <stdlib.h>
#endif

#ifndef __GNUC__
#define __attribute__(a)
#endif

#ifndef _PW_NAME_LEN
#define	_PW_NAME_LEN		31	/* max length, not counting NUL */
#endif

#ifndef UID_MAX
# define UID_MAX	UINT_MAX	/* max value for a uid_t */
#endif
#ifndef GID_MAX
# define GID_MAX	UINT_MAX	/* max value for a gid_t */
#endif

/* For flock. */
#ifndef O_EXLOCK
#define O_EXLOCK 0
#endif

#ifndef HAVE_FLOCK
#define LOCK_SH 0
#define LOCK_EX 0
#define LOCK_NB 0
#define flock(fd, op) (0)
#else
#include <sys/file.h>
#endif

/* POSIX doesn't define WAIT_ANY, so provide it if it's not found. */
#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

/* On FreeBSD (and possibly others), EAI_NODATA was removed, in favour of
 * using EAI_NONAME.
 */
#ifndef EAI_NODATA
#define EAI_NODATA EAI_NONAME
#endif

#ifndef __dead
#define __dead __attribute__ ((__noreturn__))
#endif

#ifndef __unused
#define __unused __attribute__ ((__unused__))
#endif

#if !defined(__bounded__) && !defined(__OpenBSD__)
#define __bounded__(a, b, c)
#endif

#ifndef __OpenBSD__
#define pledge(s, p) (0)
#define unveil(s, p) (0)
#endif

#ifndef __FreeBSD__
#define cap_enter() (0)
#endif

#ifndef HAVE_B64_NTOP
#undef b64_ntop
#undef b64_pton
int              b64_ntop(u_char const *, size_t, char *, size_t);
int              b64_pton(char const *, u_char *, size_t);
#endif

#ifndef HAVE_SETRESGID
#define setresgid(a, b, c) (0)
#endif

#ifndef HAVE_SETRESUID
#define setresuid(a, b, c) (0)
#endif

#ifndef HAVE_LINUX_LANDLOCK_H
#define landlock_no_fs() (0)
#else
int	landlock_no_fs(void);
#endif

#ifndef INFTIM
#define INFTIM -1
#endif

#ifndef HAVE_BSD_UUID
#include <uuid/uuid.h>
#define uuid_s_ok 0
#define uuid_s_bad_version  1
#define uuid_s_invalid_string_uuid 2
#define uuid_s_no_memory  3

/* Length of a node address (an IEEE 802 address). */
#define _UUID_NODE_LEN  6

struct uuid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t  clock_seq_hi_and_reserved;
	uint8_t  clock_seq_low;
	uint8_t  node[_UUID_NODE_LEN];
};

int32_t uuid_equal(struct uuid *, struct uuid *, uint32_t *);
int32_t uuid_is_nil(struct uuid *, uint32_t *);
void uuid_create(uuid_t *, uint32_t *);
void uuid_create_nil(struct uuid *, uint32_t *);
void uuid_from_string(const char *, uuid_t *, uint32_t *);
void uuid_to_string(uuid_t *, char **, uint32_t *);
#else
#include <uuid.h>
#endif

#ifdef HAVE_QUEUE_H
#include <sys/queue.h>
#endif

#ifndef HAVE_TREE_H
#include "compat/tree.h"
#else
#include <sys/tree.h>
#endif

#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifndef IOV_MAX
# define IOV_MAX 1024
#endif

#ifndef HAVE_IMSG
#include "compat/imsg.h"
#else
#include <imsg.h>
#endif

#ifndef HAVE_SIPHASH
#include "compat/siphash.h"
#else
#include <siphash.h>
#endif

/* Include Apple-specific headers.  Mostly for crypto.*/
#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
#define SHA256Init SHA256_Init
#define SHA256Update SHA256_Update
#define SHA256Final SHA256_Final
#define SHA2_CTX SHA256_CTX
#endif

#ifndef __APPLE__
#ifdef HAVE_SHA_H
#  include <sha.h>
#endif
#ifdef HAVE_SHA1_H
#      include <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#    include <sha2.h>
#endif
#ifdef HAVE_SHA256_H
#    include <sha256.h>
#endif
#endif

/* Catch-all for systems where the header files don't exist and/or the below
 * still are not defined.
 */
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef SHA256_DIGEST_STRING_LENGTH
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)
#endif

#if defined(__DragonFly__)
#include <openssl/sha.h>
#endif

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH		SHA_DIGEST_LENGTH
#define SHA1_DIGEST_STRING_LENGTH	(SHA1_DIGEST_LENGTH * 2 + 1)

#define SHA1_CTX	SHA_CTX
#define SHA1Init	SHA1_Init
#define SHA1Update	SHA1_Update
#define SHA1Final	SHA1_Final
#endif

/* SOCK_NONBLOCK isn't available across BSDs... */
#if !defined(SOCK_NONBLOCK) && !defined(__linux__)
#define SOCK_NONBLOCK 00004000
#endif

#ifndef HAVE_ASPRINTF
/* asprintf.c */
int		 asprintf(char **, const char *, ...);
int		 vasprintf(char **, const char *, va_list);
#endif

#ifndef HAVE_EXPLICIT_BZERO
/* explicit_bzero.c */
void		 explicit_bzero(void *, size_t);
#endif

#ifndef HAVE_GETDTABLECOUNT
/* getdtablecount.c */
int		 getdtablecount(void);
#endif

#ifndef HAVE_CLOSEFROM
/* closefrom.c */
void		 closefrom(int);
#endif

#ifndef HAVE_STRSEP
/* strsep.c */
char		*strsep(char **, const char *);
#endif

#ifndef HAVE_STRTONUM
/* strtonum.c */
long long	 strtonum(const char *, long long, long long, const char **);
#endif

#ifndef HAVE_STRLCPY
/* strlcpy.c */
size_t	 	 strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
/* strlcat.c */
size_t	 	 strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRNLEN
/* strnlen.c */
size_t		 strnlen(const char *, size_t);
#endif

#ifndef HAVE_STRNDUP
/* strndup.c */
char		*strndup(const char *, size_t);
#endif

#ifndef HAVE_GETPROGNAME
/* getprogname.c */
const char	*getprogname(void);
#endif

#ifndef HAVE_GETLINE
/* getline.c */
ssize_t		 getline(char **, size_t *, FILE *);
#endif

#ifndef HAVE_FREEZERO
/* freezero.c */
void		 freezero(void *, size_t);
#endif

#ifndef HAVE_GETDTABLECOUNT
/* getdtablecount.c */
int		 getdtablecount(void);
#endif

#ifndef HAVE_REALLOCARRAY
/* reallocarray.c */
void		*reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
/* recallocarray.c */
void		*recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_SETPROCTITLE
/* setproctitle.c */
void 		 setproctitle(const char *, ...);
#endif

#ifndef HAVE_FMT_SCALED
/* fmt_scaled.c */
int fmt_scaled(long long, char *);
int scan_scaled(char *, long long *);
#define FMT_SCALED_STRSIZE	7  /* minus sign, 4 digits, suffix, null byte */
#endif

#if !defined(HAVE_LIBBSD) && !defined(HAVE_GETOPT_OPTRESET)
/* getopt.c */
extern int	BSDopterr;
extern int	BSDoptind;
extern int	BSDoptopt;
extern int	BSDoptreset;
extern char    *BSDoptarg;
int	BSDgetopt(int, char *const *, const char *);
#define getopt(ac, av, o)  BSDgetopt(ac, av, o)
#define opterr             BSDopterr
#define optind             BSDoptind
#define optopt             BSDoptopt
#define optreset           BSDoptreset
#define optarg             BSDoptarg
#endif

/* Check for some of the non-portable timespec*() functions.
 * This should largely come from libbsd for systems which
 * aren't BSD, but this will depend on how old the library
 * is.
 */
#ifndef timespecisset
#define	timespecisset(tsp) \
	((tsp)->tv_sec || (tsp)->tv_nsec)
#endif

#ifndef timespecsub
#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (0)
#endif

#ifndef timespeccmp
#define timespeccmp(tvp, uvp, cmp) 					\
(((tvp)->tv_sec == (uvp)->tv_sec) ? 					\
	((tvp)->tv_nsec cmp (uvp)->tv_nsec) : 				\
	((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef HAVE_MERGESORT
/* mergesort.c */
int mergesort(void *, size_t, size_t, int (*)(const void *, const void *));
#endif
#endif

/* got_object.h */
#define GOT_OBJECT_ID_MAXLEN SHA256_DIGEST_LENGTH
#define GOT_OBJECT_ID_HEX_MAXLEN SHA256_DIGEST_STRING_LENGTH

