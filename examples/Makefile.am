CFLAGS = -I$(top_srcdir) @CFLAGS@
CPPFLAGS = @CPPFLAGS@

noinst_PROGRAMS = nettle-benchmark rsa-keygen rsa-sign rsa-verify

LDADD = io.o ../libnettle.a
nettle_benchmark_LDADD = ../libnettle.a
