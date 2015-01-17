/* fat-x86_64.c

   Copyright (C) 2015 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nettle-types.h"

#include "aes-internal.h"

/* Fat library initialization works as follows. The main function is
   fat_init. It tries to do initialization only once, but since it is
   idempotent and pointer updates are atomic on x86_64, there's no
   harm if it is in some cases called multiple times from several
   threads.

   The fat_init function checks the cpuid flags, and sets function
   pointers, e.g, _nettle_aes_encrypt_vec, to point to the appropriate
   implementation.

   To get everything hooked in, we use a belt-and-suspenders approach.

   We try to register fat_init as a constructor function to be called
   at load time. If this is unavailable or non-working, we instead
   arrange fat_init to be called lazily.

   For the actual indirection, there are two cases. 

   If ifunc support is available, function pointers are statically
   initialized to NULL, and we register resolver functions, e.g.,
   _nettle_aes_encrypt_resolve, which call fat_init, and then return
   the function pointer, e.g., the value of _nettle_aes_encrypt_vec.

   If ifunc is not available, we have to define a wrapper function to
   jump via the function pointer. (FIXME: For internal calls, we could
   do this as a macro). We statically initialize each function pointer
   to point to a special initialization function, e.g.,
   _nettle_aes_encrypt_init, which calls fat_init, and then invokes
   the right function. This way, all pointers are setup correctly at
   the first call to any fat function.
*/

#if HAVE_LINK_IFUNC
# define IFUNC(resolve) __attribute__ ((ifunc (resolve)))
# define vec_init(f) NULL
# define FAT_BOILERPLATE()
#else
# define IFUNC(resolve)
# define vec_init(f) f##_init
#endif

#if HAVE_GCC_ATTRIBUTE
# define CONSTRUCTOR __attribute__ ((constructor))
#else
# define CONSTRUCTOR
# if defined (__sun)
#  pragma init(fat_init)
# endif
#endif

/* DECLARE_FAT_FUNC(name, ftype)
 *
 *   name is the public function, e.g., _nettle_aes_encrypt.
 *   ftype is its type, e.g., aes_crypt_internal_func.
 *
 * DECLARE_FAT_VAR(name, type, var)
 *
 *   name is name without _nettle prefix.
 *   type is its type.
 *   var is the variant, used as a suffix on the symbol name.
 *
 * DEFINE_FAT_FUNC(name, rtype, prototype, args)
 *
 *   name is the public function.
 *   rtype its return type.
 *   prototype is the list of formal arguments, with types.
 *   args contain the argument list without any types.
 */

#if HAVE_LINK_IFUNC
#define DECLARE_FAT_FUNC(name, ftype)	\
  ftype name IFUNC(#name"_resolve");	\
  static ftype *name##_vec = NULL;

#define DEFINE_FAT_FUNC(name, rtype, prototype, args)	\
  static void_func * name##_resolve(void) \
  {								  \
    if (getenv ("NETTLE_FAT_VERBOSE"))				  \
      fprintf (stderr, "libnettle: "#name"_resolve\n");		  \
    fat_init();							  \
    return (void_func *) name##_vec;				  \
  }

#else /* !HAVE_LINK_IFUNC */
#define DECLARE_FAT_FUNC(name, ftype)		\
  ftype name;					\
  static ftype name##_init;			\
  static ftype *name##_vec = name##_init;				

#define DEFINE_FAT_FUNC(name, rtype, prototype, args)		\
  rtype name prototype						\
  {								\
    return name##_vec args;					\
  }								\
  static rtype name##_init prototype {			\
    if (getenv ("NETTLE_FAT_VERBOSE"))				\
      fprintf (stderr, "libnettle: "#name"_init\n");		\
    fat_init();							\
    assert (name##_vec != name##_init);				\
    return name##_vec args;					\
  }
#endif /* !HAVE_LINK_IFUNC */

#define DECLARE_FAT_FUNC_VAR(name, type, var)	\
       type _nettle_##name##_##var;

void _nettle_cpuid (uint32_t input, uint32_t regs[4]);

typedef void void_func (void);

typedef void aes_crypt_internal_func (unsigned rounds, const uint32_t *keys,
				      const struct aes_table *T,
				      size_t length, uint8_t *dst,
				      const uint8_t *src);
DECLARE_FAT_FUNC(_nettle_aes_encrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, x86_64)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, aesni)

DECLARE_FAT_FUNC(_nettle_aes_decrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, x86_64)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, aesni)

typedef void *(memxor_func)(void *dst, const void *src, size_t n);

DECLARE_FAT_FUNC(nettle_memxor, memxor_func)
DECLARE_FAT_FUNC_VAR(memxor, memxor_func, x86_64)
DECLARE_FAT_FUNC_VAR(memxor, memxor_func, sse2)

/* This function should usually be called only once, at startup. But
   it is idempotent, and on x86, pointer updates are atomic, so
   there's no danger if it is called simultaneously from multiple
   threads. */
static void CONSTRUCTOR
fat_init (void)
{
  static volatile int initialized = 0;
  uint32_t cpuid_data[4];
  int verbose;
  if (initialized)
    return;

  /* FIXME: Replace all getenv calls by getenv_secure? */
  verbose = getenv ("NETTLE_FAT_VERBOSE") != NULL;
  if (verbose)
    fprintf (stderr, "libnettle: fat library initialization.\n");

  _nettle_cpuid (1, cpuid_data);
  if (verbose)
    fprintf (stderr, "libnettle: cpuid 1: %08x, %08x, %08x, %08x\n",
	     cpuid_data[0], cpuid_data[1], cpuid_data[2], cpuid_data[3]);

  if (cpuid_data[2] & 0x02000000)
    {
      if (verbose)
	fprintf (stderr, "libnettle: aes instructions available.\n");
      _nettle_aes_encrypt_vec = _nettle_aes_encrypt_aesni;
      _nettle_aes_decrypt_vec = _nettle_aes_decrypt_aesni;
    }
  else
    {
      if (verbose)
	fprintf (stderr, "libnettle: aes instructions not available.\n");
      _nettle_aes_encrypt_vec = _nettle_aes_encrypt_x86_64;
      _nettle_aes_decrypt_vec = _nettle_aes_decrypt_x86_64;
    }

  _nettle_cpuid (0, cpuid_data);
  if (memcmp(&cpuid_data[1], "Genu", 4) == 0 &&
      memcmp(&cpuid_data[3], "ineI", 4) == 0 &&
      memcmp(&cpuid_data[2], "ntel", 4) == 0)
    {
      if (verbose)
	fprintf (stderr, "libnettle: intel SSE2 will be used for XOR.\n");
      nettle_memxor_vec = _nettle_memxor_sse2;
    }
  else
    {
      if (verbose)
	fprintf (stderr, "libnettle: intel SSE2 will not be used for XOR.\n");
      nettle_memxor_vec = _nettle_memxor_x86_64;
    }

  /* The x86_64 architecture should always make stores visible in the
     right order to other processors (except for non-temporal stores
     and the like). So we don't need any memory barrier. */
  initialized = 1;
}

DEFINE_FAT_FUNC(_nettle_aes_encrypt, void,
		(unsigned rounds, const uint32_t *keys,
		 const struct aes_table *T,
		 size_t length, uint8_t *dst,
		 const uint8_t *src),
		(rounds, keys, T, length, dst, src))

DEFINE_FAT_FUNC(_nettle_aes_decrypt, void,
		(unsigned rounds, const uint32_t *keys,
		 const struct aes_table *T,
		 size_t length, uint8_t *dst,
		 const uint8_t *src),
		(rounds, keys, T, length, dst, src))

DEFINE_FAT_FUNC(nettle_memxor, void *,
		(void *dst, const void *src, size_t n),
		(dst, src, n))
