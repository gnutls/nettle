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

#include "nettle-types.h"

#include "aes-internal.h"

/* Fat library initialization works as follows. The main function is
   fat_init. It tries to do initialization only once, but since it is
   idempotent and pointer updates are atomic on x86_64, there's no
   harm if it is in some cases called multiple times from several
   threads.

   The fat_init function checks the cpuid flags, and sets function
   pointers, e.g, _aes_encrypt_vec, to point to the appropriate
   implementation.

   To get everything hooked in, we use a belt-and-suspenders approach.

   We try to register fat_init as a constructor function to be called
   at load time. If this is unavailable or non-working, we instead
   arrange fat_init to be called lazily.

   For the actual indirection, there are two cases. 

   If ifunc support is available, function pointers are statically
   initialized to NULL, and we register resolver functions, e.g.,
   _aes_encrypt_resolve, which call fat_init, and then return the
   function pointer, e.g., the value of _aes_encrypt_vec.

   If ifunc is not available, we have to define a wrapper function to
   jump via the function pointer. (FIXME: For internal calls, we could
   do this as a macro). We statically initialize each function pointer
   to point to a special initialization function, e.g.,
   _aes_encrypt_init, which calls fat_init, and then invokes the right
   function. This way, all pointers are setup correctly at the first
   call to any fat function.
*/

#if HAVE_LINK_IFUNC
# define IFUNC(resolve) __attribute__ ((ifunc (resolve)))
#else
# define IFUNC(resolve)
#endif

#if HAVE_GCC_ATTRIBUTE
# define CONSTRUCTOR __attribute__ ((constructor))
#elif defined (__sun)
# pragma init(fat_init)
# define CONSTRUCTOR
#endif

void _nettle_cpuid (uint32_t input, uint32_t regs[4]);

typedef void void_func (void);

typedef void aes_crypt_internal_func (unsigned rounds, const uint32_t *keys,
				      const struct aes_table *T,
				      size_t length, uint8_t *dst,
				      const uint8_t *src);
aes_crypt_internal_func _aes_encrypt IFUNC ("_aes_encrypt_resolve");
aes_crypt_internal_func _nettle_aes_encrypt_x86_64;
aes_crypt_internal_func _nettle_aes_encrypt_aesni;

aes_crypt_internal_func _aes_decrypt IFUNC ("_aes_decrypt_resolve");
aes_crypt_internal_func _nettle_aes_decrypt_x86_64;
aes_crypt_internal_func _nettle_aes_decrypt_aesni;

#if HAVE_LINK_IFUNC
#define _aes_encrypt_init NULL
#define _aes_decrypt_init NULL
#else
static aes_crypt_internal_func _aes_encrypt_init;
static aes_crypt_internal_func _aes_decrypt_init;
#endif

static aes_crypt_internal_func *_aes_encrypt_vec = _aes_encrypt_init;
static aes_crypt_internal_func *_aes_decrypt_vec = _aes_decrypt_init;

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
      _aes_encrypt_vec = _nettle_aes_encrypt_aesni;
      _aes_decrypt_vec = _nettle_aes_decrypt_aesni;
    }
  else
    {
      if (verbose)
	fprintf (stderr, "libnettle: aes instructions not available.\n");
      _aes_encrypt_vec = _nettle_aes_encrypt_x86_64;
      _aes_decrypt_vec = _nettle_aes_decrypt_x86_64;
    }

  /* The x86_64 architecture should always make stores visible in the
     right order to other processors (except for non-temporal stores
     and the like). So we don't need any memory barrier. */
  initialized = 1;
}

#if HAVE_LINK_IFUNC

static void_func *
_aes_encrypt_resolve (void)
{
  if (getenv ("NETTLE_FAT_VERBOSE"))
    fprintf (stderr, "libnettle: _aes_encrypt_resolve\n");
  fat_init ();
  return (void_func *) _aes_encrypt_vec;
}

static void_func *
_aes_decrypt_resolve (void)
{
  if (getenv ("NETTLE_FAT_VERBOSE"))
    fprintf (stderr, "libnettle: _aes_decrypt_resolve\n");
  fat_init ();
  return (void_func *) _aes_decrypt_vec;
}

#else /* !HAVE_LINK_IFUNC */

/* We need wrapper functions jumping via the function pointer. */
void
_aes_encrypt (unsigned rounds, const uint32_t *keys,
	      const struct aes_table *T,
	      size_t length, uint8_t *dst,
	      const uint8_t *src)
{
  _aes_encrypt_vec (rounds, keys, T, length, dst, src);
}

static void
_aes_encrypt_init (unsigned rounds, const uint32_t *keys,
		   const struct aes_table *T,
		   size_t length, uint8_t *dst,
		   const uint8_t *src)
{
  if (getenv ("NETTLE_FAT_VERBOSE"))
    fprintf (stderr, "libnettle: _aes_encrypt_init\n");
  fat_init ();
  assert (_aes_encrypt_vec != _aes_encrypt_init);
  _aes_encrypt (rounds, keys, T, length, dst, src);
}

void
_aes_decrypt (unsigned rounds, const uint32_t *keys,
	      const struct aes_table *T,
	      size_t length, uint8_t *dst,
	      const uint8_t *src)
{
  _aes_decrypt_vec (rounds, keys, T, length, dst, src);
}

static void
_aes_decrypt_init (unsigned rounds, const uint32_t *keys,
		   const struct aes_table *T,
		   size_t length, uint8_t *dst,
		   const uint8_t *src)
{
  if (getenv ("NETTLE_FAT_VERBOSE"))
    fprintf (stderr, "libnettle: _aes_decrypt_init\n");
  fat_init ();
  assert (_aes_decrypt_vec != _aes_decrypt_init);
  _aes_decrypt (rounds, keys, T, length, dst, src);
}

#endif /* !HAVE_LINK_IFUNC */
