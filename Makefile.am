SUBDIRS = . testsuite

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = arcfour.h

libnettle_a_SOURCES = aes.c aes.h arcfour.c arcfour.h md5.c md5.h

libnettle_a_LIBADD = @LIBOBJS@

EXTRA_DIST = macros.h memxor.h
