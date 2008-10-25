dnl -*- mode: shell-script; sh-indentation: 2; -*-

dnl Process this file with autoconf to produce a configure script.

AC_INIT([nettle], [2.0rc1], [nettle-bugs@lists.lysator.liu.se])
AC_PREREQ(2.61)
AC_CONFIG_SRCDIR([arcfour.c])
# Needed to stop autoconf from looking for files in parent directories.
AC_CONFIG_AUX_DIR([.])

AC_CONFIG_HEADER([config.h])

LIBNETTLE_MAJOR=3
LIBNETTLE_MINOR=0

LIBHOGWEED_MAJOR=1
LIBHOGWEED_MINOR=0

AC_CANONICAL_HOST

# Command line options
AC_ARG_WITH(include-path,
  AC_HELP_STRING([--with-include-path], [A colon-separated list of directories to search for include files]),,
  [with_include_path=''])

if test x$with_include_path != x ; then
  CPPFLAGS="$CPPFLAGS -I`echo $with_include_path | sed 's/:/ -I/g'`"
fi

AC_ARG_WITH(lib-path,
  AC_HELP_STRING([--with-lib-path], [A colon-separated list of directories to search for libraries]),,
  [with_lib_path=''])

if test x$with_lib_path != x ; then
  LDFLAGS="$LDFLAGS -L`echo $with_lib_path | sed 's/:/ -L/g'`"
fi

AC_ARG_ENABLE(public-key,
  AC_HELP_STRING([--disable-public-key], [Disable public key algorithms]),,
  [enable_public_key=yes])

AC_ARG_ENABLE(assembler,
  AC_HELP_STRING([--disable-assembler],[Disable assembler code]),,
  [enable_assembler=yes])

AC_ARG_ENABLE(shared,
  AC_HELP_STRING([--enable-shared], [Build a shared library]),,
  [enable_shared=no])

AC_ARG_ENABLE(pic,
  AC_HELP_STRING([--disable-pic],
  [Do not try to compile library files as position independent code]),,
  [enable_pic=yes])

AC_ARG_ENABLE(openssl,
  AC_HELP_STRING([--disable-openssl], [Do not include openssl glue in the benchmark program]),,
  [enable_openssl=yes])
  
LSH_RPATH_INIT([`echo $with_lib_path | sed 's/:/ /g'` \
    `echo $exec_prefix | sed "s@^NONE@$prefix/lib@g" | sed "s@^NONE@$ac_default_prefix/lib@g"` \
    /usr/local/lib /sw/local/lib /sw/lib \
    /usr/gnu/lib /opt/gnu/lib /sw/gnu/lib /usr/freeware/lib /usr/pkg/lib])

# Checks for programs.
AC_PROG_CC

# When $CC foo.c -o foo creates both foo and foo.exe, autoconf picks
# up the foo.exe and sets exeext to .exe. That is correct for cygwin,
# which has some kind of magic link from foo to foo.exe, but not for
# rntcl. A better check for the cygwin case would check if the
# contents of foo and foo.exe are equal; in the rntcl case, foo is a
# sh script, and foo.exe is a windows executable.

if test "x$CC" = xrntcl ; then
    AC_MSG_NOTICE([Compiling with rntcl; clearing EXEEXT and disabling assembler])
    ac_exeext=''
    ac_cv_exeext=''
    EXEEXT=''
    enable_assembler=no
fi

# Used by the testsuite only
AC_PROG_CXX

AC_LANG_PUSH(C++)
AC_TRY_COMPILE([],[return 0;],[CXX_TESTS='cxx-test$(EXEEXT)'], [CXX_TESTS=''])
AC_SUBST([CXX_TESTS])
AC_LANG_POP

AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_CHECK_TOOL(NM, nm, strings)
# Used only for the GNU-stack configure test.
AC_CHECK_TOOL(OBJDUMP, objdump, false)

if test "x$ac_cv_prog_cc_stdc" = xno ; then
  AC_ERROR([the C compiler doesn't handle ANSI-C])
fi

AC_PROG_INSTALL

# According to the autoconf manual, needs install-sh from
# autoconf-2.60 or automake-1.10 to avoid races.
AC_PROG_MKDIR_P

LSH_DEPENDENCY_TRACKING

if test x$enable_dependency_tracking = xyes ; then
  # Since the makefiles use include to get the dependency files, we must
  # make sure that the files exist. We generate some more files than are
  # actually needed.

  AC_CONFIG_COMMANDS([dummy-dep-files],
  [(cd "$srcdir" && find . -name '*.c' -print) \
 | sed 's/\.c$//' | (while read f; do echo > "$f.o.d"; echo > "$f.po.d"; done)
])
fi

# Select assembler code
asm_path=
case "$host_cpu" in
  [i?86* | k[5-8]* | pentium* | athlon])
    asm_path=x86
    ;;
  [x86_64 | amd64])
    asm_path=x86_64
    ;;
  *sparc*)
    AC_TRY_COMPILE([
#if defined(__sparcv9) || defined(__arch64__)
#error 64-bit sparc
#endif
    ], [], [
      asm_path=sparc32
    ], [
      asm_path=sparc64
    ])
    ;;
  *)
    enable_assembler=no
    ;;
esac

# echo "enable_assembler: $enable_assembler, asm_path: $asm_path"

if test "x$enable_assembler" = xyes ; then
  if test -n "$asm_path"; then
    AC_MSG_NOTICE([Looking for assembler files in $asm_path/.])
    found=no
    for tmp_f in aes-encrypt-internal.asm aes-decrypt-internal.asm \
		 arcfour-crypt.asm md5-compress.asm sha1-compress.asm machine.m4; do
#       echo "Looking for $srcdir/$asm_path/$tmp_f"
      if test -f "$srcdir/$asm_path/$tmp_f"; then
#        echo found
        found=yes
        AC_CONFIG_LINKS($tmp_f:$asm_path/$tmp_f)
      fi
    done
    if test "$found" = no; then
      enable_assembler=no
      AC_MSG_WARN([No assembler files found.])
    fi
  fi
fi

LSH_CCPIC

SHLIBCFLAGS="$CCPIC"

case "$host_os" in
  cygwin*)
    LIBNETTLE_FORLINK='cygnettle-$(LIBNETTLE_MAJOR)-$(LIBNETTLE_MINOR).dll'
    LIBNETTLE_SONAME=''
    LIBNETTLE_FILE='libnettle.dll.a'
    LIBNETTLE_LINK='$(CC) $(LDFLAGS) -shared -Wl,--out-implib=$(LIBNETTLE_LIBFILE) -Wl,--export-all-symbols -Wl,--enable-auto-import -Wl,--whole-archive'
    LIBNETTLE_LIBS='-Wl,--no-whole-archive $(LIBS)'

    LIBHOGWEED_FORLINK='cyghogweed-$(LIBHOGWEED_MAJOR)-$(LIBHOGWEED_MINOR).dll'
    LIBHOGWEED_SONAME=''
    LIBHOGWEED_FILE='libhogweed.dll.a'
    LIBHOGWEED_LINK='$(CC) $(LDFLAGS) -shared -Wl,--out-implib=$(LIBHOGWEED_LIBFILE) -Wl,--export-all-symbols -Wl,--enable-auto-import -Wl,--whole-archive'
    LIBHOGWEED_LIBS='-Wl,--no-whole-archive $(LIBS)'
    ;;
  darwin*)
    LIBNETTLE_FORLINK=libnettle.dylib
    LIBNETTLE_SONAME='$(LIBNETTLE_FORLINK).$(LIBNETTLE_MAJOR)'
    LIBNETTLE_FILE='$(LIBNETTLE_SONAME).$(LIBNETTLE_MINOR)'
    LIBNETTLE_LINK='$(CC) -dynamiclib $(LDFLAGS)'
    LIBNETTLE_LIBS=''

    LIBHOGWEED_FORLINK=libhogweed.dylib
    LIBHOGWEED_SONAME='$(LIBHOGWEED_FORLINK).$(LIBHOGWEED_MAJOR)'
    LIBHOGWEED_FILE='$(LIBHOGWEED_SONAME).$(LIBHOGWEED_MINOR)'
    LIBHOGWEED_LINK='$(CC) -dynamiclib $(LDFLAGS)'
    LIBHOGWEED_LIBS=''
    ;;
  *)
    LIBNETTLE_FORLINK=libnettle.so
    LIBNETTLE_SONAME='$(LIBNETTLE_FORLINK).$(LIBNETTLE_MAJOR)'
    LIBNETTLE_FILE='$(LIBNETTLE_SONAME).$(LIBNETTLE_MINOR)'
    LIBNETTLE_LINK='$(CC) $(LDFLAGS) -shared -Wl,-soname=$(LIBNETTLE_SONAME)'
    LIBNETTLE_LIBS=''

    LIBHOGWEED_FORLINK=libhogweed.so
    LIBHOGWEED_SONAME='$(LIBHOGWEED_FORLINK).$(LIBHOGWEED_MAJOR)'
    LIBHOGWEED_FILE='$(LIBHOGWEED_SONAME).$(LIBHOGWEED_MINOR)'
    LIBHOGWEED_LINK='$(CC) $(LDFLAGS) -shared -Wl,-soname=$(LIBHOGWEED_SONAME)'
    # FIXME: It might make some sense to link with -lnettle -lgmp
    LIBHOGWEED_LIBS=''
    ;;
esac

if test "x$enable_pic" = xyes; then
  CCPIC_MAYBE="$CCPIC"
else
  CCPIC_MAYBE=''
fi
AC_SUBST([CCPIC_MAYBE])

ASM_SYMBOL_PREFIX=''
ASM_ELF_STYLE='no'
ASM_TYPE_FUNCTION=''
ASM_MARK_NOEXEC_STACK=''
ASM_ALIGN_LOG=''

if test x$enable_assembler = xyes ; then
  AC_CACHE_CHECK([if globals are prefixed by underscore],
  nettle_cv_asm_underscore,
  [ # Default is no underscore
    nettle_cv_asm_underscore=no
    AC_COMPILE_IFELSE(
      [int a_global_symbol;],
      [ $NM conftest.$OBJEXT >conftest.out
        if grep _a_global_symbol conftest.out >/dev/null ; then
          nettle_cv_asm_underscore=yes
        elif grep a_global_symbol conftest.out >/dev/null ; then
          nettle_cv_asm_underscore=no
        else
          AC_MSG_WARN([nm doesn't list a_global_symbol at all])
	fi],
      [AC_MSG_WARN([test program with a single global could not be compiled!?])])])
  if test x$nettle_cv_asm_underscore = xyes ; then
    ASM_SYMBOL_PREFIX='_'
  fi

  AC_CACHE_CHECK([if we should use a .note.GNU-stack section],
  nettle_cv_asm_gnu_stack,
  [ # Default
    nettle_cv_asm_gnu_stack=no

    cat >conftest.c <<EOF
int foo() { return 0; }
EOF
    nettle_compile="$CC $CFLAGS $CPPFLAGS -c conftest.c >conftest.out 2>&1"
    if AC_TRY_EVAL(nettle_compile); then
      cat conftest.out >&AC_FD_CC
      $OBJDUMP -x conftest.o | grep '\.note\.GNU-stack' > /dev/null \
      && nettle_cv_asm_gnu_stack=yes
    else
      cat conftest.out >&AC_FD_CC
      echo "configure: failed program was:" >&AC_FD_CC
      cat conftest.s >&AC_FD_CC
    fi
    rm -f conftest.*])
  if test x$nettle_cv_asm_gnu_stack = xyes ; then
    ASM_MARK_NOEXEC_STACK='.section .note.GNU-stack,"",@progbits'
  fi

  AC_CACHE_CHECK([for ELF-style .type,%function pseudo-ops],
    [nettle_cv_asm_type_percent_function],
    [GMP_TRY_ASSEMBLE([
.text
.globl foo
.type foo,%function
foo:
.Lend:

.size foo, .Lend - foo
],
       [nettle_cv_asm_type_percent_function=yes],
       [nettle_cv_asm_type_percent_function=no])])

dnl Needs double quote for the # character
  AC_CACHE_CHECK([[for ELF-style .type,#function pseudo-ops]],
    [nettle_cv_asm_type_hash_function],
    [GMP_TRY_ASSEMBLE([
.text
.globl foo
.type foo,#function
foo:
.Lend:

.size foo, .Lend - foo
],
       [nettle_cv_asm_type_hash_function=yes],
       [nettle_cv_asm_type_hash_function=no])])

  if test x$nettle_cv_asm_type_percent_function = xyes ; then
    ASM_ELF_STYLE='yes'
    ASM_TYPE_FUNCTION='%function'
  else
    if test x$nettle_cv_asm_type_hash_function = xyes ; then
      ASM_ELF_STYLE='yes'
      ASM_TYPE_FUNCTION='#function'
    fi
  fi
  AC_CACHE_CHECK([if .align assembly directive is logarithmic],
    [nettle_cv_asm_align_log],
    [GMP_TRY_ASSEMBLE([
.align 3
],
       [nettle_cv_asm_align_log=yes],
       [nettle_cv_asm_align_log=no])])
  if test x$nettle_cv_asm_align_log = xyes ; then
    ASM_ALIGN_LOG='yes'
  fi
fi

AC_SUBST(ASM_SYMBOL_PREFIX)
AC_SUBST(ASM_ELF_STYLE)
AC_SUBST(ASM_TYPE_FUNCTION)
AC_SUBST(ASM_MARK_NOEXEC_STACK)
AC_SUBST(ASM_ALIGN_LOG)

AC_SUBST(SHLIBCFLAGS)

AC_SUBST(LIBNETTLE_MAJOR)
AC_SUBST(LIBNETTLE_MINOR)
AC_SUBST(LIBNETTLE_FORLINK)
AC_SUBST(LIBNETTLE_SONAME)
AC_SUBST(LIBNETTLE_FILE)
AC_SUBST(LIBNETTLE_LINK)
AC_SUBST(LIBNETTLE_LIBS)

AC_SUBST(LIBHOGWEED_MAJOR)
AC_SUBST(LIBHOGWEED_MINOR)
AC_SUBST(LIBHOGWEED_FORLINK)
AC_SUBST(LIBHOGWEED_SONAME)
AC_SUBST(LIBHOGWEED_FILE)
AC_SUBST(LIBHOGWEED_LINK)
AC_SUBST(LIBHOGWEED_LIBS)

AC_PATH_PROG(M4, m4, m4)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
# Used by eratosthenes.c
AC_CHECK_SIZEOF(long)

AC_CHECK_HEADERS([openssl/blowfish.h openssl/des.h openssl/cast.h openssl/aes.h],,
[enable_openssl=no
 break])

LSH_FUNC_ALLOCA

# Needed by the supplied memcmp.c
AC_C_BIGENDIAN
AC_REPLACE_FUNCS(memxor)

LSH_GCC_ATTRIBUTES

# According to Simon Josefsson, looking for uint32_t and friends in
# sys/types.h is needed on some systems, in particular cygwin.
AX_CREATE_STDINT_H([nettle-stdint.h], [sys/types.h])

# Check for file locking. We (AC_PROG_CC?) have already checked for
# sys/types.h and unistd.h.
AC_CACHE_CHECK([for fcntl file locking],
		nettle_cv_fcntl_locking,
[AC_TRY_COMPILE([
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <fcntl.h>
],[
int op = F_SETLKW;
struct flock fl;
],
nettle_cv_fcntl_locking=yes,
nettle_cv_fcntl_locking=no)])

AH_TEMPLATE([HAVE_FCNTL_LOCKING], [Define if fcntl file locking is available])
if test "x$nettle_cv_fcntl_locking" = "xyes" ; then
  AC_DEFINE(HAVE_FCNTL_LOCKING)
fi

# Checks for libraries
AC_CHECK_LIB(gmp, __gmpz_getlimbn,,
    [AC_MSG_WARN(
[GNU MP not found, or not 3.1 or up, see http://www.swox.com/gmp.
Support for public key algorithms will be unavailable.])]
    enable_public_key=no)

AH_TEMPLATE([WITH_HOGWEED], [Defined if public key features are enabled])

if test "x$enable_public_key" = xyes ; then
  AC_DEFINE(WITH_HOGWEED)
  IF_HOGWEED=''
else
  IF_HOGWEED='#'
fi

if test "x$enable_shared" = xyes ; then
  IF_SHARED=''
else
  IF_SHARED='#'
fi

AC_SUBST(IF_HOGWEED)
AC_SUBST(IF_SHARED)

# Add -R flags needed to run programs linked with gmp
LSH_RPATH_FIX

OPENSSL_LIBFLAGS=''

# Check for openssl's libcrypto (used only for benchmarking)
if test x$enable_openssl = xyes ; then
  AC_CHECK_LIB(crypto, BF_ecb_encrypt,
    [OPENSSL_LIBFLAGS='-lcrypto'],
    [enable_openssl=no])
fi

AH_TEMPLATE([WITH_OPENSSL],
	    [Define if you have openssl's libcrypto (used for benchmarking)])

if test x$enable_openssl = xyes ; then
  AC_DEFINE(WITH_OPENSSL)
fi

AC_SUBST(OPENSSL_LIBFLAGS)

# Set these flags *last*, or else the test programs won't compile
if test x$GCC = xyes ; then
  # Using -ggdb3 makes (some versions of) Redhat's gcc-2.96 dump core
  if "$CC" --version | grep '^2\.96$' 1>/dev/null 2>&1; then
    true
  else
    CFLAGS="$CFLAGS -ggdb3"
  fi
  # FIXME: It would be better to actually test if this option works and/or is needed.
  # Or perhaps use -funsigned-char.
  if "$CC" --version | grep 'gcc.* 4\.' 1>/dev/null 2>&1; then
    CFLAGS="$CFLAGS -Wno-pointer-sign"
  fi
  CFLAGS="$CFLAGS -Wall -W \
  -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes \
  -Wpointer-arith -Wbad-function-cast -Wnested-externs"

# Don't enable -Wcast-align as it results in tons of warnings in the
# DES code. And when using stdio.
# Don't enable -Waggregate-return, as that causes warnings for glibc
# inttypes.h.
fi

AC_CONFIG_FILES([config.make config.m4 Makefile])
AC_CONFIG_FILES([tools/Makefile testsuite/Makefile examples/Makefile])

AC_OUTPUT

