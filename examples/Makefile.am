
OPENSSL_LIBFLAGS = @OPENSSL_LIBFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

EXTRA_PROGRAMS = rsa-keygen rsa-sign rsa-verify
noinst_PROGRAMS = nettle-benchmark @RSA_EXAMPLES@

LDADD = io.o -lnettle
nettle_benchmark_LDADD = -lnettle $(OPENSSL_LIBFLAGS)

nettle_benchmark_SOURCES = nettle-benchmark.c nettle-openssl.c

TS_PROGS = rsa-sign-test rsa-verify-test
EXTRA_DIST = io.c io.h run-tests setup-env teardown-env $(TS_PROGS)

.PHONY: run-tests
run-tests: $(TS_PROGS)
	LD_LIBRARY_PATH=../.lib srcdir="$(srcdir)" \
	  "$(srcdir)"/run-tests $(TS_PROGS)

check: run-tests
