CFLAGS = -I$(top_srcdir) @CFLAGS@ -O0
CPPFLAGS = @CPPFLAGS@

TS_PROGS = aes-test arcfour-test blowfish-test cast128-test des-test \
	   md5-test sha1-test \
	   serpent-test twofish-test

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libnettle.a
EXTRA_DIST = $(SOURCES:.c=.m4) testutils.c testutils.h run-tests

M4FLAGS = -P -s
%.c: macros.m4 %.m4
	$(M4) $(M4FLAGS) $^ > $@T
	test -s $@T && mv -f $@T $@

.PNONY: check run-tests

check: run-tests

run-tests: $(TS_PROGS)
	$(srcdir)/run-tests $^

