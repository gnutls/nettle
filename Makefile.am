SUBDIRS = . tools testsuite examples

noinst_PROGRAMS = aesdata desdata shadata

libnettleincludedir = $(includedir)/nettle

lib_LIBRARIES = libnettle.a
libnettleinclude_HEADERS = aes.h arcfour.h blowfish.h \
			   base16.h base64.h buffer.h cast128.h \
			   cbc.h \
			   des.h des-compat.h dsa.h \
			   hmac.h \
			   knuth-lfib.h \
			   md5.h md5-compat.h \
			   nettle-meta.h \
			   pgp.h realloc.h rsa.h \
			   sexp.h \
			   serpent.h sha.h twofish.h \
			   yarrow.h

libnettle_a_SOURCES = aes.c aes.h aes-internal.h \
		      aes-decrypt-table.c aes-decrypt.c \
		      aes-encrypt-table.c aes-encrypt.c \
		      aes-set-encrypt-key.c aes-set-decrypt-key.c aes-meta.c \
		      arcfour.c arcfour.h arcfour-meta.c \
		      base16-encode.c base16-decode.c base16-meta.c \
                      base64-encode.c base64-decode.c base64-meta.c base64.h \
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
		      sexp.h sexp.c sexp-format.c \
		      sexp-transport.c sexp-transport-format.c \
		      bignum.h bignum.c bignum-random.c sexp2bignum.c \
		      pkcs1.h pkcs1.c pkcs1-rsa-md5.c pkcs1-rsa-sha1.c \
		      rsa.h rsa.c rsa-sign.c rsa-verify.c \
		      rsa-md5-sign.c rsa-md5-verify.c \
		      rsa-sha1-sign.c rsa-sha1-verify.c \
		      rsa-encrypt.c rsa-decrypt.c \
		      rsa-keygen.c rsa-compat.h rsa-compat.c \
		      rsa2sexp.c sexp2rsa.c \
		      dsa.c dsa-sign.c dsa-verify.c dsa-keygen.c \
		      sexp2dsa.c \
		      pgp.h pgp-encode.c rsa2openpgp.c \
		      buffer.h buffer.c buffer-init.c realloc.c \
		      nettle-meta.h \
		      nettle-internal.c nettle-internal.h

LIBOBJS = @LIBOBJS@
libnettle_a_LIBADD = $(LIBOBJS)

shadata_LDADD = -lm

info_TEXINFOS = nettle.texinfo

all-local: nettle.html print-path
.PHONY: print-path
print-path:
	echo PATH: $$PATH

EXTRA_DIST = macros.h memxor.h $(des_headers) descore.README nettle.html \
	.bootstrap $(des_headers) \
	sparc/aes.asm sparc/machine.m4 \
	x86/aes.asm x86/aes_tables.asm

DISTCLEANFILES = aes.asm aes-decrypt.asm aes-encrypt.asm machine.m4
CLEANFILES = $(SHLIBFORLINK)
clean-local:
	rm -rf .lib

# Using assembler files. Should get precedence before the .c.o rule.
SUFFIXES = .asm

# can be overridden during development, eg. "make RM_TMP=: aes.o"
RM_TMP = rm -f

# FIXME: How to write this without using GNU make features?

# NOTE: We have to use an explicit rule .asm -> .o, to override the .c
# -> .o rule. Using rules involving .s doesn't seem to work.
# %.s: %.asm asm.m4 machine.m4 config.m4
# 	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
# 		`test -f $< || echo '$(srcdir)/'`$< >$@

# NOTE: We create an empty .deps-file, to make the make/automake
# dependency tracking happier.
%.$(OBJEXT): %.asm asm.m4 machine.m4 config.m4
	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
		`test -f $< || echo '$(srcdir)/'`$< >$*.s
	$(COMPILE) -c $*.s -o $@
	echo >.deps/$*.Po

# Shared library rules
all-local: $(SHLIBTARGET)
install-data-local: $(SHLIBINSTALL)

# Assembler files must contain only PIC-clean code.
%_p.$(OBJEXT): %.asm asm.m4 machine.m4 config.m4
	$(M4) $(srcdir)/asm.m4 machine.m4 config.m4 \
		`test -f $< || echo '$(srcdir)/'`$< >$*.s
	$(COMPILE) -c $*.s -o $@
	echo >.deps/$*.Po

%_p.$(OBJEXT): %.c
	$(COMPILE) $(SHLIBCFLAGS) -c $< -o $@

SHLIBOBJECTS = $(patsubst %.$(OBJEXT),%_p.$(OBJEXT),$(am_libnettle_a_OBJECTS) $(LIBOBJS))

# The point of the linking is to use -Lnettle-dir at linktime,
# and LD_LIBRARY_PATH=nettle-dir/.lib at run time.
$(SHLIBFORLINK): $(SHLIBOBJECTS)
	$(SHLIBLINK) $^ -o $@
	-mkdir .lib 2>/dev/null
	(cd .lib && ln -sf ../$(SHLIBFORLINK) $(SHLIBSONAME))

install-shared: $(SHLIBFORLINK)
	$(INSTALL_DATA) $(SHLIBFORLINK) $(DESTDIR)$(libdir)/$(SHLIBFILE)
	(cd $(DESTDIR)$(libdir) \
		&& ln -sf $(SHLIBFILE) $(SHLIBSONAME) \
		&& ln -sf $(SHLIBFILE) $(SHLIBFORLINK) )

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
	$(MAKE) desdata$(EXEEXT)
	./desdata$(EXEEXT) $(@F) > $@T
	test -s $@T && mv -f $@T $@

des.o: des.c des.h $(des_headers)
