/* fat-ppc.c

   Copyright (C) 2020 Mamone Tarsha

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

#define _GNU_SOURCE

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__FreeBSD__) && __FreeBSD__ < 12
#include <sys/sysctl.h>
#else
#include <sys/auxv.h>
#endif

#include "nettle-types.h"

#include "aes-internal.h"
#include "gcm.h"
#include "fat-setup.h"

/* Define from arch/powerpc/include/uapi/asm/cputable.h in Linux kernel */
#ifndef PPC_FEATURE2_VEC_CRYPTO
#define PPC_FEATURE2_VEC_CRYPTO 0x02000000
#endif

struct ppc_features
{
  int have_crypto_ext;
};

static void
get_ppc_features (struct ppc_features *features)
{
  unsigned long hwcap2 = 0;
#if defined(__FreeBSD__)
#if __FreeBSD__ < 12
  size_t len = sizeof(hwcap2);
  sysctlbyname("hw.cpu_features2", &hwcap2, &len, NULL, 0);
#else
  elf_aux_info(AT_HWCAP2, &hwcap2, sizeof(hwcap2));
#endif
#else
  hwcap2 = getauxval(AT_HWCAP2);
#endif
  features->have_crypto_ext =
   (hwcap2 & PPC_FEATURE2_VEC_CRYPTO) == PPC_FEATURE2_VEC_CRYPTO ? 1 : 0;
}

DECLARE_FAT_FUNC(_nettle_aes_encrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, c)
DECLARE_FAT_FUNC_VAR(aes_encrypt, aes_crypt_internal_func, ppc64)

DECLARE_FAT_FUNC(_nettle_aes_decrypt, aes_crypt_internal_func)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, c)
DECLARE_FAT_FUNC_VAR(aes_decrypt, aes_crypt_internal_func, ppc64)

static void CONSTRUCTOR
fat_init (void)
{
  struct ppc_features features;
  int verbose;

  get_ppc_features (&features);

  verbose = getenv (ENV_VERBOSE) != NULL;
  if (verbose)
    fprintf (stderr, "libnettle: cpu features: %s\n",
     features.have_crypto_ext ? "crypto extensions" : "");

  if (features.have_crypto_ext)
  {
     if (verbose)
        fprintf (stderr, "libnettle: enabling arch 2.07 code.\n");
     _nettle_aes_encrypt_vec = _nettle_aes_encrypt_ppc64;
     _nettle_aes_decrypt_vec = _nettle_aes_decrypt_ppc64;
  }
  else
  {
     _nettle_aes_encrypt_vec = _nettle_aes_encrypt_c;
     _nettle_aes_decrypt_vec = _nettle_aes_decrypt_c;
  }
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
