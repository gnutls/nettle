
OPENSSL_LIBFLAGS = @OPENSSL_LIBFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

# There's no program "io", it's just a trick to get automake to keep track
# of dependencies for io.o.
EXTRA_PROGRAMS = rsa-keygen rsa-sign rsa-verify io
noinst_PROGRAMS = nettle-benchmark @RSA_EXAMPLES@

nettle_benchmark_SOURCES = nettle-benchmark.c nettle-openssl.c

# libnettle.a for the dependency
LDADD = io.o -lnettle ../libnettle.a

nettle_benchmark_LDADD = -lnettle ../libnettle.a $(OPENSSL_LIBFLAGS)

TS_PROGS = rsa-sign-test rsa-verify-test
EXTRA_DIST = io.h run-tests setup-env teardown-env $(TS_PROGS)

.PHONY: run-tests
run-tests: $(TS_PROGS)
	LD_LIBRARY_PATH=../.lib srcdir="$(srcdir)" \
	  "$(srcdir)"/run-tests $(TS_PROGS)

check: run-tests
