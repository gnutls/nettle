SUBDIRS = . testsuite examples

noinst_PROGRAMS = aesdata desdata shadata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h blowfish.h \
			   base64.h cast128.h \
			   cbc.h \
			   des.h des-compat.h \
			   hmac.h \
			   knuth-lfib.h \
			   md5.h md5-compat.h \
			   nettle-meta.h rsa.h \
			   serpent.h sha.h twofish.h \
			   yarrow.h
			   
libnettle_a_SOURCES = aes.c aes-encrypt.c aes-decrypt.c aes.h \
		      aes-set-encrypt-key.c aes-set-decrypt-key.c aes-meta.c \
		      arcfour.c arcfour.h arcfour-meta.c \
                      base64.c base64-meta.c base64.h \
		      cast128.c cast128.h cast128_sboxes.h cast128-meta.c \
		      blowfish.h blowfish.c \
		      cbc.c cbc.h \
		      des.c des.h desinfo.h desCode.h \
		      des3.c des-compat.c des-compat.h \
		      hmac.c hmac.h hmac-md5.c hmac-sha1.c \
		      knuth-lfib.c knuth-lfib.h \
		      md5.c md5.h md5-compat.c md5-compat.h md5-meta.c \
		      sha.h sha1.c sha1-meta.c sha256.c sha256-meta.c \
		      serpent.c serpent.h serpent_sboxes.h serpent-meta.c \
		      twofish.c twofish.h twofish-meta.c \
		      yarrow.h yarrow256.c yarrow_key_event.c \
		      bignum.h bignum.c \
		      rsa.h rsa.c rsa_md5.c rsa_sha1.c \
		      rsa-encrypt.c rsa-decrypt.c \
		      rsa-keygen.c rsa-compat.h rsa-compat.c \
		      nettle-internal.c nettle-internal.h nettle-meta.h

libnettle_a_LIBADD = @LIBOBJS@

shadata_LDADD = -lm

info_TEXINFOS = nettle.texinfo

all-local: nettle.html

EXTRA_DIST = macros.h memxor.h $(des_headers) descore.README nettle.html \
	.bootstrap $(des_headers)

# Using assembler files. Should get precedence before the .c.o rule.
SUFFIXES = .asm

# can be overridden during development, eg. "make RM_TMP=: aes.o"
RM_TMP = rm -f

.asm.o:
	$(M4) `test -f $< || echo '$(srcdir)/'`$< >tmp-$*.s
	$(COMPILE) -c tmp-$*.s -o $@
	$(RM_TMP) tmp-$*.s

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
