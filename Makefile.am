SUBDIRS = . testsuite

noinst_PROGRAMS = desdata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h des.h md5.h sha1.h

libnettle_a_SOURCES = aes.c aes.h arcfour.c arcfour.h \
		      cast128.c cast128.h cast128_sboxes.h \
		      blowfish.h blowfish.c \
		      des.c des.h desinfo.h desCode.h \
		      md5.c md5.h sha1.c sha1.h \
		      serpent.c serpent.h serpent_sboxes.h \
		      twofish.c twofish.h

libnettle_a_LIBADD = @LIBOBJS@

info_TEXINFOS = nettle.texinfo

all-local: nettle.html

EXTRA_DIST = macros.h memxor.h $(des_headers) descore.README nettle.html

# BUILT_SOURCE = $(des_headers)

%.html : %.texinfo
	(cd $(srcdir) \
	 && $(MAKEINFO) --html --no-split --output $@T $(<F) \
	 ; test -s $@T && mv -f $@T $@)

# desCore rules
# It seems using $(srcdir)/ doesn't work with GNU make 3.79.1
# des_headers = $(srcdir)/parity.h $(srcdir)/rotors.h $(srcdir)/keymap.h 
des_headers = parity.h rotors.h keymap.h 

# Generate DES headers.
$(des_headers): desdata
	./desdata $(@F) > $@T
	test -s $@T && mv -f $@T $@

des.o: des.c des.h $(des_headers)
