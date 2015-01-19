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
#include "memxor.h"
#include "fat-setup.h"

void _nettle_cpuid (uint32_t input, uint32_t regs[4]);

DECLARE_FAT_FUNC(_nettle_aes_encrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, x86_64)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, aesni)

DECLARE_FAT_FUNC(_nettle_aes_decrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, x86_64)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, aesni)

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
  verbose = getenv (ENV_VERBOSE) != NULL;
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
