SUBDIRS = . tools testsuite examples

noinst_PROGRAMS = aesdata desdata shadata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h arctwo.h bignum.h blowfish.h \
			   base16.h base64.h buffer.h cast128.h \
			   cbc.h \
			   des.h des-compat.h dsa.h \
			   hmac.h \
			   knuth-lfib.h \
			   macros.h \
			   md2.h md4.h \
			   md5.h md5-compat.h \
			   memxor.h \
			   nettle-meta.h \
			   pgp.h pkcs1.h realloc.h rsa.h rsa-compat.h \
			   sexp.h \
			   serpent.h sha.h twofish.h \
			   yarrow.h

nodist_libnettleinclude_HEADERS = nettle-types.h
noinst_HEADERS = aes-internal.h cast128_sboxes.h desinfo.h desCode.h \
		 serpent_sboxes.h nettle-internal.h

libnettle_a_SOURCES = aes.c \
		      aes-decrypt-table.c aes-decrypt.c \
		      aes-encrypt-table.c aes-encrypt.c \
		      aes-set-encrypt-key.c aes-set-decrypt-key.c aes-meta.c \
		      arcfour.c arcfour-crypt.c arcfour-meta.c \
		      arctwo.c arctwo-meta.c \
		      base16-encode.c base16-decode.c base16-meta.c \
                      base64-encode.c base64-decode.c base64-meta.c \
		      cast128.c cast128-meta.c \
		      blowfish.c \
		      cbc.c \
		      des.c \
		      des3.c des-compat.c \
		      hmac.c hmac-md5.c hmac-sha1.c hmac-sha256.c \
		      knuth-lfib.c \
		      md2.c md2-meta.c md4.c md4-meta.c \
		      md5.c md5-compat.c md5-meta.c \
		      sha1.c sha1-compress.c sha1-meta.c sha256.c sha256-meta.c \
		      serpent.c serpent-meta.c \
		      twofish.c twofish-meta.c \
		      yarrow256.c yarrow_key_event.c \
		      sexp.c sexp-format.c \
		      sexp-transport.c sexp-transport-format.c \
		      bignum.c bignum-random.c sexp2bignum.c \
		      pkcs1.c pkcs1-rsa-md5.c pkcs1-rsa-sha1.c \
		      rsa.c rsa-sign.c rsa-verify.c \
		      rsa-md5-sign.c rsa-md5-verify.c \
		      rsa-sha1-sign.c rsa-sha1-verify.c \
		      rsa-encrypt.c rsa-decrypt.c \
		      rsa-keygen.c rsa-compat.c \
		      rsa2sexp.c sexp2rsa.c \
		      dsa.c dsa-sign.c dsa-verify.c dsa-keygen.c \
		      sexp2dsa.c \
		      pgp-encode.c rsa2openpgp.c \
		      buffer.c buffer-init.c realloc.c \
		      nettle-internal.c

libnettle_a_CFLAGS = $(CCPIC)

LIBOBJS = @LIBOBJS@
libnettle_a_LIBADD = $(LIBOBJS)

shadata_LDADD = -lm

info_TEXINFOS = nettle.texinfo

all-local: nettle.html

EXTRA_DIST = $(des_headers) descore.README nettle.html \
	sha-example.c .bootstrap $(des_headers) \
	sparc/aes.asm sparc/machine.m4 \
	x86/aes.asm x86/aes-encrypt.asm x86/aes-decrypt.asm \
	x86/aes_tables.asm x86/arcfour-crypt.asm x86/sha1-compress.asm

DISTCLEANFILES = aes.asm aes.s \
	aes-decrypt.asm aes-decrypt.s aes-encrypt.asm aes-encrypt.s \
	arcfour-crypt.asm arcfour-crypt.s sha1-compress.asm sha1-compress.s \
	machine.m4 nettle-types.h

CLEANFILES = $(SHLIBFORLINK)
clean-local:
	rm -rf .lib

# Using assembler files. Should get precedence before the .c.o rule.
SUFFIXES = .asm .html

# can be overridden during development, eg. "make RM_TMP=: aes.o"
RM_TMP = rm -f

# FIXME: How to write this without using GNU make features?
# For now, use automake to disable these rules when they are not needed.

if ENABLE_ASSEMBLER

# NOTE: We have to use an explicit rule .asm -> .o, to override the .c
# -> .o rule. Using rules involving .s doesn't seem to work.
# %.s: %.asm asm.m4 machine.m4 config.m4
# 	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
# 		`test -f $< || echo '$(srcdir)/'`$< >$@

# FIXME: For some reason, this rule breaks builds on Tru64 5.1B (on
# alpha), with the system make. It fails with "Don't know how to make
# aes.asm", which is very strange, since the make program on this
# system is not supposed to know about %-style pattern rules, and
# "aes.asm" doesn't not occur explicitly in any target or dependency.

# NOTE: We create an empty .deps-file, to make the make/automake
# dependency tracking happier.
%.$(OBJEXT): %.asm asm.m4 machine.m4 config.m4
	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
		`test -f $< || echo '$(srcdir)/'`$< >$*.s
	$(COMPILE) -c $*.s -o $@
	echo >.deps/$*.Po

# Assembler files must contain only PIC-clean code.
%_p.$(OBJEXT): %.asm asm.m4 machine.m4 config.m4
	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
		`test -f $< || echo '$(srcdir)/'`$< >$*.s
	$(COMPILE) -c $*.s -o $@
	echo >.deps/$*.Po
endif

if ENABLE_SHARED
# FIXME: This rule doesn't get dependencies right.
%_p.$(OBJEXT): %.c
	$(COMPILE) $(SHLIBCFLAGS) -c $< -o $@

SHLIBOBJECTS = $(patsubst %.c,%_p.$(OBJEXT),$(libnettle_a_SOURCES)) \
               $(patsubst %.$(OBJEXT),%_p.$(OBJEXT),$(LIBOBJS))

# The point of the sym links is to use -Lnettle-dir at linktime,
# and LD_LIBRARY_PATH=nettle-dir/.lib at run time.
$(SHLIBFORLINK): $(SHLIBOBJECTS)
	$(SHLIBLINK) $^ -o $@ $(SHLIBLIBS)
	-mkdir .lib 2>/dev/null
	[ -z "$(SHLIBSONAME)" ] || (cd .lib \
          && ln -sf ../$(SHLIBFORLINK) $(SHLIBSONAME))

endif

# Shared library rules
all-local: $(SHLIBTARGET)
install-data-local: $(SHLIBINSTALL)

install-shared: $(SHLIBFORLINK)
	$(INSTALL_DATA) $(SHLIBFORLINK) $(DESTDIR)$(libdir)/$(SHLIBFILE)
	[ -z "$(SHLIBSONAME)" ] \
                || (cd $(DESTDIR)$(libdir) \
		&& ln -sf $(SHLIBFILE) $(SHLIBSONAME) \
		&& ln -sf $(SHLIBFILE) $(SHLIBFORLINK) )

.texinfo.html:
	(cd $(srcdir) \
	 && $(MAKEINFO) --html --no-split --output $@T $(<F) \
	 ; test -s $@T && mv -f $@T $@)

# desCore rules
# It seems using $(srcdir)/ doesn't work with GNU make 3.79.1
# des_headers = $(srcdir)/parity.h $(srcdir)/rotors.h $(srcdir)/keymap.h 
des_headers = parity.h rotors.h keymap.h 

# Generate DES headers.
$(des_headers): desdata.c
	$(MAKE) desdata$(EXEEXT)
	./desdata$(EXEEXT) $(@F) > $@T
	test -s $@T && mv -f $@T $@

des.o: des.c des.h $(des_headers)
