AM_CPPFLAGS = -I$(top_srcdir)

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

noinst_PROGRAMS = aes-test arcfour-test arctwo-test \
	   blowfish-test cast128-test \
           base16-test base64-test \
	   des-test des3-test des-compat-test \
	   md2-test md4-test md5-test md5-compat-test \
	   sha1-test sha256-test \
	   serpent-test twofish-test \
	   buffer-test sexp-test sexp-format-test \
	   rsa2sexp-test sexp2rsa-test \
	   knuth-lfib-test \
	   cbc-test hmac-test bignum-test \
	   pkcs1-test \
	   rsa-test rsa-encrypt-test rsa-keygen-test \
	   dsa-test dsa-keygen-test \
	   yarrow-test

TS_PROGS = $(noinst_PROGRAMS)
TS_SH = sexp-conv-test symbols-test

TS_ALL = $(TS_PROGS) $(TS_SH)

# Workaround to get automake to keep dependencies for testutils.o
EXTRA_PROGRAMS = testutils

# libnettle.a is added at the end to make sure all programs depend on it.
# It seems there's no DEPENDENCIES variable that affects all programs.

LDADD = testutils.o -lnettle ../libnettle.a
EXTRA_DIST = $(TS_SH) testutils.h \
	     run-tests rfc1750.txt

CLEANFILES = test.in test1.out test2.out

.PHONY: check 
check: $(TS_ALL) $(srcdir)/run-tests
	LD_LIBRARY_PATH=../.lib srcdir="$(srcdir)" \
	  $(srcdir)/run-tests $(TS_ALL)
