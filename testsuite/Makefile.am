CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

TS_PROGS = aes-test arcfour-test blowfish-test cast128-test \
	   des-test des3-test des-compat-test \
	   md5-test md5-compat-test sha1-test sha256-test \
	   serpent-test twofish-test \
	   cbc-test bignum-test yarrow-test

# M4_FILES = aes-test.m4 arcfour-test.m4 blowfish-test.m4 cast128-test.m4 \
# 	   des-test.m4 des3-test.m4 \
# 	   md5-test.m4 md5-compat-test.m4 sha1-test.m4 sha256-test.m4 \
# 	   serpent-test.m4 twofish-test.m4 \
# 	   cbc-test.m4 bignum-test.m4

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libnettle.a
EXTRA_DIST = testutils.c testutils.h \
	     run-tests rfc1750.txt

# # M4FLAGS = -P -s
# M4FLAGS = -P
# $(M4_FILES:.m4=.c): %.c: macros.m4 %.m4
# 	$(M4) $(M4FLAGS) $^ > $@T
# 	test -s $@T && mv -f $@T $@

.PHONY: check run-tests

check: run-tests

run-tests: $(TS_PROGS)
	srcdir="$(srcdir)" "$(srcdir)"/run-tests $^

