
TS_PROGS = aes-test arcfour-test md5-test

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libnettle.a
EXTRA_DIST = macros.h $(SOURCES:.c=.m4)

M4FLAGS = -P -s
%.c: macros.m4 %.m4
	$(M4) $(M4FLAGS) $^ > $@T
	test -s $@T && mv -f $@T $@

.PNONY: check run-tests

check: run-tests

run-tests: $(TS_PROGS)
	./run-tests $^

