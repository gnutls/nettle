# We need .. to be searched before standard places, in order to pick
# up the newly built libnettle.a/libnettle.so, rather than any
# installed version.
AM_LDFLAGS = -L..

bin_PROGRAMS = sexp-conv

LDADD = -lnettle

sexp_conv_SOURCES = sexp-conv.c getopt.c getopt1.c
