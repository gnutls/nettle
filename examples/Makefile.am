CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

EXTRA_PROGRAMS = rsa-keygen rsa-sign rsa-verify
noinst_PROGRAMS = nettle-benchmark @RSA_EXAMPLES@

LDADD = io.o ../libnettle.a
nettle_benchmark_LDADD = ../libnettle.a
