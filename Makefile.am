SUBDIRS = . testsuite

noinst_PROGRAMS = desdata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h des.h md5.h sha1.h

libnettle_a_SOURCES = aes.c aes.h arcfour.c arcfour.h blowfish.h blowfish.c \
		      des.c des.h \
		      md5.c md5.h sha1.c sha1.h \
		      serpent.c serpent.h serpent_sboxes.h \
		      twofish.c twofish.h

libnettle_a_LIBADD = @LIBOBJS@

EXTRA_DIST = macros.h memxor.h $(des_headers) descore.README
# BUILT_SOURCE = $(des_headers)

# desCore rules
des_headers = $(srcdir)/parity.h $(srcdir)/rotors.h $(srcdir)/keymap.h 

# Generate DES headers.
$(des_headers): desdata
	./desdata $(@F) > $@T
	test -s $@T && mv -f $@T $@

des.o: des.c des.h $(des_headers)
