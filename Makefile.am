SUBDIRS = . testsuite examples

noinst_PROGRAMS = desdata shadata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h blowfish.h cast128.h \
			   des.h des-compat.h \
			   serpent.h twofish.h \
			   md5.h md5-compat.h sha.h \
			   cbc.h yarrow.h \
			   rsa.h

libnettle_a_SOURCES = aes.c aes.h arcfour.c arcfour.h \
		      cast128.c cast128.h cast128_sboxes.h \
		      blowfish.h blowfish.c \
		      cbc.c \
		      des.c des.h desinfo.h desCode.h \
		      des3.c des-compat.c des-compat.h \
		      md5.c md5.h md5-compat.c md5-compat.h \
		      sha.h sha1.c sha256.c \
		      serpent.c serpent.h serpent_sboxes.h \
		      twofish.c twofish.h \
		      yarrow.h yarrow256.c yarrow_key_event.c \
		      bignum.h bignum.c \
		      rsa.h rsa.c rsa_md5.c rsa_sha1.c \
		      rsa-compat.h rsa-compat.c

libnettle_a_LIBADD = @LIBOBJS@

shadata_LDADD = -lm

info_TEXINFOS = nettle.texinfo

all-local: nettle.html

EXTRA_DIST = macros.h memxor.h $(des_headers) descore.README nettle.html \
	.bootstrap $(des_headers)

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
$(des_headers): desdata.c
	$(MAKE) desdata
	./desdata $(@F) > $@T
	test -s $@T && mv -f $@T $@

des.o: des.c des.h $(des_headers)
