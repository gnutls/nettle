CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

EXTRA_PROGRAMS = rsa-keygen rsa-sign rsa-verify
noinst_PROGRAMS = nettle-benchmark sexp-conv @RSA_EXAMPLES@

LDADD = io.o -lnettle
nettle_benchmark_LDADD = -lnettle

TS_PROGS = rsa-sign-test rsa-verify-test sexp-conv-test

EXTRA_DIST = io.c io.h run-tests setup-env teardown-env $(TS_PROGS)

.PHONY: run-tests
run-tests: $(TS_PROGS)
	LD_LIBRARY_PATH=../.lib srcdir="$(srcdir)" \
	  "$(srcdir)"/run-tests $(TS_PROGS)

check: run-tests
