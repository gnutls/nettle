SUBDIRS = . testsuite

lib_LIBRARIES = libnettle.a
include_HEADERS = arcfour.h

libnettleincludedir = $(includedir)/nettle
libnettle_a_SOURCES = aes.c aes.h arcfour.c arcfour.h md5.c md5.h

libnettle_a_LIBADD = @LIBOBJS@

EXTRA_DIST = macros.h
