AM_CFLAGS = -I$(top_srcdir)

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

bin_PROGRAMS = sexp-conv nettle-lfib-stream

# libnettle.a is added at the end to make sure all programs depend on it.
# It seems there's no DEPENDENCIES variable that affects all programs.
LDADD = -lnettle ../libnettle.a

# Explicit use of DEPENDENCIES is more correct, but scales badly to a
# large number of programs.

# sexp_conv_DEPENDENCIES = ../libnettle.a
# nettle_lfib_stream_DEPENDENCIES = ../libnettle.a

EXTRA_DIST = misc.h input.h output.h parse.h getopt.h

sexp_conv_SOURCES = sexp-conv.c input.c output.c parse.c \
	getopt.c getopt1.c misc.c
