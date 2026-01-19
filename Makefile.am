# When creating a distribution tarball, make sure we enable all current
# configure flags so that no files are missing.  This is irrespective of
# whether the end-user will enable this; this step is here so that all the
# relevant files are included in the distribution.
AM_DISTCHECK_CONFIGURE_FLAGS= --enable-cvg

SUBDIRS = compat \
	  gitwrapper \
	  got \
	  gotadmin \
	  gotctl \
	  gotd \
	  gotsh \
	  gotwebctl \
	  gotwebd \
	  libexec \
	  template \
	  tog

# -portable: re-enable once upstream is happy:  cvg
# TODO: gotd gotsh template

if CVG_ENABLED
SUBDIRS += cvg
endif

include $(top_builddir)/Makefile.common

EXTRA_DIST = CHANGES \
	     CHANGELOG \
	     LICENCE \
	     README.portable \
	     regress \
	     util/got-portable-ver.sh

LDADD = $(LIBOBJS)
if HOST_FREEBSD
LDADD += -lmd
LIBS += -lmd
endif

LIBS += -lm $(zlib_LIBS) $(libbsd_LIBS) $(libmd_LIBS)
AM_CPPFLAGS += $(libbsd_CFLAGS) $(libmd_CFLAGS)

TEST_TARGETS=compat regress-delta regress-deltify regress-fetch regress-idset \
	     regress-path regress-tog regress-cmdline
GOT_TEST_ROOT=/tmp

.PHONY: compat
compat:
	$(MAKE) -C compat

tests: $(TEST_TARGETS)

regress-cmdline:
	(export PLATFORM=@PLATFORM@; 				\
	cd $(top_builddir)/regress/cmdline || exit $$?; 	\
	./checkout.sh -q -r "$(GOT_TEST_ROOT)";			\
	./update.sh -q -r "$(GOT_TEST_ROOT)";			\
	./status.sh -q -r "$(GOT_TEST_ROOT)";			\
	./log.sh -q -r "$(GOT_TEST_ROOT)";			\
	./add.sh -q -r "$(GOT_TEST_ROOT)";			\
	./rm.sh -q -r "$(GOT_TEST_ROOT)";			\
	./diff.sh -q -r "$(GOT_TEST_ROOT)";			\
	./blame.sh -q -r "$(GOT_TEST_ROOT)";			\
	./branch.sh -q -r "$(GOT_TEST_ROOT)";			\
	./tag.sh -q -r "$(GOT_TEST_ROOT)";			\
	./ref.sh -q -r "$(GOT_TEST_ROOT)";			\
	./commit.sh -q -r "$(GOT_TEST_ROOT)";			\
	./revert.sh -q -r "$(GOT_TEST_ROOT)";			\
	./cherrypick.sh -q -r "$(GOT_TEST_ROOT)";		\
	./backout.sh -q -r "$(GOT_TEST_ROOT)";			\
	./rebase.sh -q -r "$(GOT_TEST_ROOT)";			\
	./import.sh -q -r "$(GOT_TEST_ROOT)";			\
	./histedit.sh -q -r "$(GOT_TEST_ROOT)";			\
	./integrate.sh -q -r "$(GOT_TEST_ROOT)";		\
	./merge.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./stage.sh -q -r "$(GOT_TEST_ROOT)";			\
	./unstage.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./cat.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./clone.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./fetch.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./send.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./tree.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./patch.sh -q -r "$(GOT_TEST_ROOT)" 			\
	./pack.sh -q -r "$(GOT_TEST_ROOT)"; 			\
	./cleanup.sh -q -r "$(GOT_TEST_ROOT)")

regress-delta:
	$(CC) $(DEFS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		-o $(top_builddir)/regress/delta/delta_test \
		$(top_srcdir)/lib/bloom.c \
		$(top_srcdir)/lib/buf.c \
		$(top_srcdir)/lib/date.c \
		$(top_srcdir)/lib/deflate.c \
		$(top_srcdir)/lib/delta.c \
		$(top_srcdir)/lib/delta_cache.c \
		$(top_srcdir)/lib/deltify.c \
		$(top_srcdir)/lib/error.c \
		$(top_srcdir)/lib/gotconfig.c \
		$(top_srcdir)/lib/hash.c \
		$(top_srcdir)/lib/inflate.c \
		$(top_srcdir)/lib/lockfile.c \
		$(top_srcdir)/lib/murmurhash2.c \
		$(top_srcdir)/lib/object.c \
		$(top_srcdir)/lib/object_cache.c \
		$(top_srcdir)/lib/object_create.c \
		$(top_srcdir)/lib/object_idset.c \
		$(top_srcdir)/lib/object_open_privsep.c \
		$(top_srcdir)/lib/object_parse.c \
		$(top_srcdir)/lib/object_qid.c \
		$(top_srcdir)/lib/opentemp.c \
		$(top_srcdir)/lib/pack.c \
		$(top_srcdir)/lib/pack_create.c \
		$(top_srcdir)/lib/pack_create_privsep.c \
		$(top_srcdir)/lib/path.c \
		$(top_srcdir)/lib/pollfd.c \
		$(top_srcdir)/lib/privsep.c \
		$(top_srcdir)/lib/ratelimit.c \
		$(top_srcdir)/lib/read_gitconfig_privsep.c \
		$(top_srcdir)/lib/read_gotconfig_privsep.c \
		$(top_srcdir)/lib/reference.c \
		$(top_srcdir)/lib/reference_parse.c \
		$(top_srcdir)/lib/repository.c \
		$(top_srcdir)/lib/sigs.c \
		$(top_srcdir)/regress/delta/delta_test.c \
		-L$(top_builddir)/compat -lopenbsd-compat $(LIBS) && \
			$(top_builddir)/regress/delta/delta_test

regress-deltify:
	$(CC) $(DEFS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		-o $(top_builddir)/regress/deltify/deltify_test \
		$(top_srcdir)/lib/bloom.c \
		$(top_srcdir)/lib/buf.c \
		$(top_srcdir)/lib/date.c \
		$(top_srcdir)/lib/deflate.c \
		$(top_srcdir)/lib/delta.c \
		$(top_srcdir)/lib/delta_cache.c \
		$(top_srcdir)/lib/deltify.c \
		$(top_srcdir)/lib/error.c \
		$(top_srcdir)/lib/gotconfig.c \
		$(top_srcdir)/lib/hash.c \
		$(top_srcdir)/lib/inflate.c \
		$(top_srcdir)/lib/lockfile.c \
		$(top_srcdir)/lib/murmurhash2.c \
		$(top_srcdir)/lib/object.c \
		$(top_srcdir)/lib/object_cache.c \
		$(top_srcdir)/lib/object_create.c \
		$(top_srcdir)/lib/object_idset.c \
		$(top_srcdir)/lib/object_open_privsep.c \
		$(top_srcdir)/lib/object_parse.c \
		$(top_srcdir)/lib/object_qid.c \
		$(top_srcdir)/lib/opentemp.c \
		$(top_srcdir)/lib/pack.c \
		$(top_srcdir)/lib/pack_create.c \
		$(top_srcdir)/lib/pack_create_privsep.c \
		$(top_srcdir)/lib/path.c \
		$(top_srcdir)/lib/pollfd.c \
		$(top_srcdir)/lib/privsep.c \
		$(top_srcdir)/lib/ratelimit.c \
		$(top_srcdir)/lib/read_gitconfig_privsep.c \
		$(top_srcdir)/lib/read_gotconfig_privsep.c \
		$(top_srcdir)/lib/reference.c \
		$(top_srcdir)/lib/reference_parse.c \
		$(top_srcdir)/lib/repository.c \
		$(top_srcdir)/lib/sigs.c \
		$(top_srcdir)/regress/deltify/deltify_test.c \
		-L$(top_builddir)/compat -lopenbsd-compat $(LIBS) && \
			$(top_builddir)/regress/deltify/deltify_test

regress-fetch:
	$(CC) $(DEFS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		-o $(top_builddir)/regress/fetch/fetch_test \
		$(top_srcdir)/lib/bloom.c \
		$(top_srcdir)/lib/buf.c \
		$(top_srcdir)/lib/date.c \
		$(top_srcdir)/lib/deflate.c \
		$(top_srcdir)/lib/delta.c \
		$(top_srcdir)/lib/delta_cache.c \
		$(top_srcdir)/lib/deltify.c \
		$(top_srcdir)/lib/dial.c \
		$(top_srcdir)/lib/error.c \
		$(top_srcdir)/lib/fetch.c \
		$(top_srcdir)/lib/gotconfig.c \
		$(top_srcdir)/lib/hash.c \
		$(top_srcdir)/lib/inflate.c \
		$(top_srcdir)/lib/lockfile.c \
		$(top_srcdir)/lib/murmurhash2.c \
		$(top_srcdir)/lib/object.c \
		$(top_srcdir)/lib/object_cache.c \
		$(top_srcdir)/lib/object_create.c \
		$(top_srcdir)/lib/object_idset.c \
		$(top_srcdir)/lib/object_open_privsep.c \
		$(top_srcdir)/lib/object_parse.c \
		$(top_srcdir)/lib/object_qid.c \
		$(top_srcdir)/lib/opentemp.c \
		$(top_srcdir)/lib/pack.c \
		$(top_srcdir)/lib/pack_create.c \
		$(top_srcdir)/lib/pack_create_privsep.c \
		$(top_srcdir)/lib/path.c \
		$(top_srcdir)/lib/pollfd.c \
		$(top_srcdir)/lib/privsep.c \
		$(top_srcdir)/lib/ratelimit.c \
		$(top_srcdir)/lib/read_gitconfig_privsep.c \
		$(top_srcdir)/lib/read_gotconfig_privsep.c \
		$(top_srcdir)/lib/reference.c \
		$(top_srcdir)/lib/reference_parse.c \
		$(top_srcdir)/lib/repository.c \
		$(top_srcdir)/lib/sigs.c \
		$(top_srcdir)/regress/fetch/fetch_test.c \
		-L$(top_builddir)/compat -lopenbsd-compat $(LIBS) -lm && \
			$(top_builddir)/regress/fetch/fetch_test

regress-idset:
	$(CC) $(DEFS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		-o $(top_builddir)/regress/idset/idset_test \
		$(top_srcdir)/lib/bloom.c \
		$(top_srcdir)/lib/buf.c \
		$(top_srcdir)/lib/date.c \
		$(top_srcdir)/lib/deflate.c \
		$(top_srcdir)/lib/delta.c \
		$(top_srcdir)/lib/delta_cache.c \
		$(top_srcdir)/lib/deltify.c \
		$(top_srcdir)/lib/dial.c \
		$(top_srcdir)/lib/error.c \
		$(top_srcdir)/lib/fetch.c \
		$(top_srcdir)/lib/gotconfig.c \
		$(top_srcdir)/lib/hash.c \
		$(top_srcdir)/lib/inflate.c \
		$(top_srcdir)/lib/lockfile.c \
		$(top_srcdir)/lib/murmurhash2.c \
		$(top_srcdir)/lib/object.c \
		$(top_srcdir)/lib/object_cache.c \
		$(top_srcdir)/lib/object_create.c \
		$(top_srcdir)/lib/object_idset.c \
		$(top_srcdir)/lib/object_open_privsep.c \
		$(top_srcdir)/lib/object_parse.c \
		$(top_srcdir)/lib/object_qid.c \
		$(top_srcdir)/lib/opentemp.c \
		$(top_srcdir)/lib/pack.c \
		$(top_srcdir)/lib/pack_create.c \
		$(top_srcdir)/lib/pack_create_privsep.c \
		$(top_srcdir)/lib/path.c \
		$(top_srcdir)/lib/pollfd.c \
		$(top_srcdir)/lib/privsep.c \
		$(top_srcdir)/lib/ratelimit.c \
		$(top_srcdir)/lib/read_gitconfig_privsep.c \
		$(top_srcdir)/lib/read_gotconfig_privsep.c \
		$(top_srcdir)/lib/reference.c \
		$(top_srcdir)/lib/reference_parse.c \
		$(top_srcdir)/lib/repository.c \
		$(top_srcdir)/lib/sigs.c \
		$(top_srcdir)/regress/idset/idset_test.c \
		-L$(top_builddir)/compat -lopenbsd-compat $(LIBS) && \
			$(top_builddir)/regress/idset/idset_test

regress-path:
	$(CC) $(DEFS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		-o $(top_builddir)/regress/path/path_test \
		$(top_srcdir)/lib/bloom.c \
		$(top_srcdir)/lib/buf.c \
		$(top_srcdir)/lib/date.c \
		$(top_srcdir)/lib/deflate.c \
		$(top_srcdir)/lib/delta.c \
		$(top_srcdir)/lib/delta_cache.c \
		$(top_srcdir)/lib/deltify.c \
		$(top_srcdir)/lib/dial.c \
		$(top_srcdir)/lib/error.c \
		$(top_srcdir)/lib/fetch.c \
		$(top_srcdir)/lib/gotconfig.c \
		$(top_srcdir)/lib/hash.c \
		$(top_srcdir)/lib/inflate.c \
		$(top_srcdir)/lib/lockfile.c \
		$(top_srcdir)/lib/murmurhash2.c \
		$(top_srcdir)/lib/object.c \
		$(top_srcdir)/lib/object_cache.c \
		$(top_srcdir)/lib/object_create.c \
		$(top_srcdir)/lib/object_idset.c \
		$(top_srcdir)/lib/object_open_privsep.c \
		$(top_srcdir)/lib/object_parse.c \
		$(top_srcdir)/lib/object_qid.c \
		$(top_srcdir)/lib/opentemp.c \
		$(top_srcdir)/lib/pack.c \
		$(top_srcdir)/lib/pack_create.c \
		$(top_srcdir)/lib/pack_create_privsep.c \
		$(top_srcdir)/lib/path.c \
		$(top_srcdir)/lib/pollfd.c \
		$(top_srcdir)/lib/privsep.c \
		$(top_srcdir)/lib/ratelimit.c \
		$(top_srcdir)/lib/read_gitconfig_privsep.c \
		$(top_srcdir)/lib/read_gotconfig_privsep.c \
		$(top_srcdir)/lib/reference.c \
		$(top_srcdir)/lib/reference_parse.c \
		$(top_srcdir)/lib/repository.c \
		$(top_srcdir)/lib/sigs.c \
		$(top_srcdir)/regress/path/path_test.c \
		-L$(top_builddir)/compat -lopenbsd-compat $(LIBS) && \
			$(top_builddir)/regress/path/path_test

regress-tog:
	(cd $(top_builddir)/regress/tog || exit $$?; 	\
	./log.sh -q -r "$(GOT_TEST_ROOT)");
