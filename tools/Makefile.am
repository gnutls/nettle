AM_CFLAGS = -I$(top_srcdir)

# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

bin_PROGRAMS = sexp-conv

LDADD = -lnettle

EXTRA_DIST = misc.h input.h output.h parse.h

sexp_conv_SOURCES = sexp-conv.c input.c output.c parse.c \
	getopt.c getopt1.c misc.c
