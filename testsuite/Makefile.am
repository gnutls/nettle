CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

TS_PROGS = aes-test arcfour-test blowfish-test cast128-test \
	   des-test des3-test des-compat-test \
	   md5-test md5-compat-test sha1-test sha256-test \
	   serpent-test twofish-test \
	   knuth-lfib-test \
	   cbc-test hmac-test bignum-test \
	   rsa-test rsa-keygen-test yarrow-test

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libnettle.a
EXTRA_DIST = testutils.c testutils.h \
	     run-tests rfc1750.txt

.PHONY: check run-tests

check: run-tests

run-tests: $(TS_PROGS)
	srcdir="$(srcdir)" "$(srcdir)"/run-tests $^

