CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

EXTRA_PROGRAMS = rsa-keygen rsa-sign rsa-verify
noinst_PROGRAMS = nettle-benchmark @RSA_EXAMPLES@

LDADD = io.o ../libnettle.a
nettle_benchmark_LDADD = ../libnettle.a

TS_PROGS = rsa-sign-test rsa-verify-test

EXTRA_DIST = io.c io.h run-tests setup-env teardown-env $(TS_PROGS)

.PHONY: run-tests
run-tests: $(TS_PROGS)
	srcdir="$(srcdir)" "$(srcdir)"/run-tests $(TS_PROGS)

check: run-tests
