/* fat-s390x.c

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

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
# if __GLIBC_PREREQ(2, 16)
#  define USE_GETAUXVAL 1
#  include <sys/auxv.h>
# endif
#endif

#include "nettle-types.h"

#include "memxor.h"
#include "aes.h"
#include "gcm.h"
#include "gcm-internal.h"
#include "fat-setup.h"

/* Max number of doublewords returned by STFLE */
#define FACILITY_DOUBLEWORDS_MAX 3
#define FACILITY_INDEX(bit) ((bit) / 64)
/* STFLE and cipher query store doublewords as bit-reversed.
   reverse facility bit or function code in doubleword */
#define FACILITY_BIT(bit) (1ULL << (63 - (bit) % 64))

/* Define from arch/s390/include/asm/elf.h in Linux kernel */
#ifndef HWCAP_S390_STFLE
#define HWCAP_S390_STFLE 4
#endif

/* Facility bits */
#define FAC_VF 129      /* vector facility */
#define FAC_MSA 17      /* message-security assist */
#define FAC_MSA_X4 77   /* message-security-assist extension 4 */

/* Function codes */
#define AES_128_CODE 18
#define AES_192_CODE 19
#define AES_256_CODE 20
#define GHASH_CODE 65

struct s390x_features
{
  int have_vector_facility;
  int have_km_aes128;
  int have_km_aes192;
  int have_km_aes256;
  int have_kmid_ghash;
};

void _nettle_stfle(uint64_t *facility, uint64_t facility_size);
void _nettle_km_status(uint64_t *status);
void _nettle_kimd_status(uint64_t *status);

#define MATCH(s, slen, literal, llen) \
  ((slen) == (llen) && memcmp ((s), (literal), llen) == 0)

static void
get_s390x_features (struct s390x_features *features)
{
  features->have_vector_facility = 0;
  features->have_km_aes128 = 0;
  features->have_km_aes192 = 0;
  features->have_km_aes256 = 0;
  features->have_kmid_ghash = 0;

  const char *s = secure_getenv (ENV_OVERRIDE);
  if (s)
    for (;;)
    {
      const char *sep = strchr (s, ',');
      size_t length = sep ? (size_t) (sep - s) : strlen(s);

      if (MATCH (s, length, "vf", 2))
        features->have_vector_facility = 1;
      else if (MATCH (s, length, "msa_x1", 6))
      {
        features->have_km_aes128 = 1;
      }
      else if (MATCH (s, length, "msa_x2", 6))
      {
        features->have_km_aes192 = 1;
        features->have_km_aes256 = 1;
      }
      else if (MATCH (s, length, "msa_x4", 6))
      {
        features->have_kmid_ghash = 1;
      }
      if (!sep)
        break;
      s = sep + 1;
    }
  else
  {
#if USE_GETAUXVAL
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_S390_STFLE)
    {
      uint64_t facilities[FACILITY_DOUBLEWORDS_MAX] = {0};
      _nettle_stfle(facilities, FACILITY_DOUBLEWORDS_MAX);

      if (facilities[FACILITY_INDEX(FAC_VF)] & FACILITY_BIT(FAC_VF))
        features->have_vector_facility = 1;

      if (facilities[FACILITY_INDEX(FAC_MSA)] & FACILITY_BIT(FAC_MSA))
      {
        uint64_t query_status[2] = {0};
        _nettle_km_status(query_status);
        if (query_status[FACILITY_INDEX(AES_128_CODE)] & FACILITY_BIT(AES_128_CODE))
          features->have_km_aes128 = 1;
        if (query_status[FACILITY_INDEX(AES_192_CODE)] & FACILITY_BIT(AES_192_CODE))
          features->have_km_aes192 = 1;
        if (query_status[FACILITY_INDEX(AES_256_CODE)] & FACILITY_BIT(AES_256_CODE))
          features->have_km_aes256 = 1;
      }

      if (facilities[FACILITY_INDEX(FAC_MSA_X4)] & FACILITY_BIT(FAC_MSA_X4))
      {
        uint64_t query_status[2] = {0};
        _nettle_kimd_status(query_status);
        if (query_status[FACILITY_INDEX(GHASH_CODE)] & FACILITY_BIT(GHASH_CODE))
          features->have_kmid_ghash = 1;
      }
    }
#endif
  }
}

/* MEMXOR3 */
DECLARE_FAT_FUNC(nettle_memxor3, memxor3_func)
DECLARE_FAT_FUNC_VAR(memxor3, memxor3_func, c)
DECLARE_FAT_FUNC_VAR(memxor3, memxor3_func, s390x)

/* AES128 */
DECLARE_FAT_FUNC(nettle_aes128_set_encrypt_key, aes128_set_key_func)
DECLARE_FAT_FUNC_VAR(aes128_set_encrypt_key, aes128_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes128_set_encrypt_key, aes128_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes128_set_decrypt_key, aes128_set_key_func)
DECLARE_FAT_FUNC_VAR(aes128_set_decrypt_key, aes128_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes128_set_decrypt_key, aes128_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes128_invert_key, aes128_invert_key_func)
DECLARE_FAT_FUNC_VAR(aes128_invert_key, aes128_invert_key_func, c)
DECLARE_FAT_FUNC_VAR(aes128_invert_key, aes128_invert_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes128_encrypt, aes128_crypt_func)
DECLARE_FAT_FUNC_VAR(aes128_encrypt, aes128_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes128_encrypt, aes128_crypt_func, s390x)
DECLARE_FAT_FUNC(nettle_aes128_decrypt, aes128_crypt_func)
DECLARE_FAT_FUNC_VAR(aes128_decrypt, aes128_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes128_decrypt, aes128_crypt_func, s390x)

/* AES192 */
DECLARE_FAT_FUNC(nettle_aes192_set_encrypt_key, aes192_set_key_func)
DECLARE_FAT_FUNC_VAR(aes192_set_encrypt_key, aes192_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes192_set_encrypt_key, aes192_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes192_set_decrypt_key, aes192_set_key_func)
DECLARE_FAT_FUNC_VAR(aes192_set_decrypt_key, aes192_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes192_set_decrypt_key, aes192_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes192_invert_key, aes192_invert_key_func)
DECLARE_FAT_FUNC_VAR(aes192_invert_key, aes192_invert_key_func, c)
DECLARE_FAT_FUNC_VAR(aes192_invert_key, aes192_invert_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes192_encrypt, aes192_crypt_func)
DECLARE_FAT_FUNC_VAR(aes192_encrypt, aes192_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes192_encrypt, aes192_crypt_func, s390x)
DECLARE_FAT_FUNC(nettle_aes192_decrypt, aes192_crypt_func)
DECLARE_FAT_FUNC_VAR(aes192_decrypt, aes192_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes192_decrypt, aes192_crypt_func, s390x)

/* AES256 */
DECLARE_FAT_FUNC(nettle_aes256_set_encrypt_key, aes256_set_key_func)
DECLARE_FAT_FUNC_VAR(aes256_set_encrypt_key, aes256_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes256_set_encrypt_key, aes256_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes256_set_decrypt_key, aes256_set_key_func)
DECLARE_FAT_FUNC_VAR(aes256_set_decrypt_key, aes256_set_key_func, c)
DECLARE_FAT_FUNC_VAR(aes256_set_decrypt_key, aes256_set_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes256_invert_key, aes256_invert_key_func)
DECLARE_FAT_FUNC_VAR(aes256_invert_key, aes256_invert_key_func, c)
DECLARE_FAT_FUNC_VAR(aes256_invert_key, aes256_invert_key_func, s390x)
DECLARE_FAT_FUNC(nettle_aes256_encrypt, aes256_crypt_func)
DECLARE_FAT_FUNC_VAR(aes256_encrypt, aes256_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes256_encrypt, aes256_crypt_func, s390x)
DECLARE_FAT_FUNC(nettle_aes256_decrypt, aes256_crypt_func)
DECLARE_FAT_FUNC_VAR(aes256_decrypt, aes256_crypt_func, c)
DECLARE_FAT_FUNC_VAR(aes256_decrypt, aes256_crypt_func, s390x)

/* GHASH */
#if GCM_TABLE_BITS == 8
DECLARE_FAT_FUNC(_nettle_gcm_init_key, gcm_init_key_func)
DECLARE_FAT_FUNC_VAR(gcm_init_key, gcm_init_key_func, c)
DECLARE_FAT_FUNC_VAR(gcm_init_key, gcm_init_key_func, s390x)

DECLARE_FAT_FUNC(_nettle_gcm_hash, gcm_hash_func)
DECLARE_FAT_FUNC_VAR(gcm_hash, gcm_hash_func, c)
DECLARE_FAT_FUNC_VAR(gcm_hash, gcm_hash_func, s390x)
#endif /* GCM_TABLE_BITS == 8 */

static void CONSTRUCTOR
fat_init (void)
{
  struct s390x_features features;
  int verbose;

  get_s390x_features (&features);
  verbose = getenv (ENV_VERBOSE) != NULL;

  /* MEMXOR3 */
  if (features.have_vector_facility)
  {
    if (verbose)
      fprintf (stderr, "libnettle: enabling vectorized memxor3.\n");
    nettle_memxor3_vec = _nettle_memxor3_s390x;
  }
  else
  {
    nettle_memxor3_vec = _nettle_memxor3_c;
  }

  /* AES128 */
  if (features.have_km_aes128)
  {
    if (verbose)
      fprintf (stderr, "libnettle: enabling hardware accelerated AES128 EBC mode.\n");
    nettle_aes128_set_encrypt_key_vec = _nettle_aes128_set_encrypt_key_s390x;
    nettle_aes128_set_decrypt_key_vec = _nettle_aes128_set_decrypt_key_s390x;
    nettle_aes128_invert_key_vec = _nettle_aes128_invert_key_s390x;
    nettle_aes128_encrypt_vec = _nettle_aes128_encrypt_s390x;
    nettle_aes128_decrypt_vec = _nettle_aes128_decrypt_s390x;
  }
  else
  {
    nettle_aes128_set_encrypt_key_vec = _nettle_aes128_set_encrypt_key_c;
    nettle_aes128_set_decrypt_key_vec = _nettle_aes128_set_decrypt_key_c;
    nettle_aes128_invert_key_vec = _nettle_aes128_invert_key_c;
    nettle_aes128_encrypt_vec = _nettle_aes128_encrypt_c;
    nettle_aes128_decrypt_vec = _nettle_aes128_decrypt_c;
  }

  /* AES192 */
  if (features.have_km_aes192)
  {
    if (verbose)
      fprintf (stderr, "libnettle: enabling hardware accelerated AES192 EBC mode.\n");
    nettle_aes192_set_encrypt_key_vec = _nettle_aes192_set_encrypt_key_s390x;
    nettle_aes192_set_decrypt_key_vec = _nettle_aes192_set_decrypt_key_s390x;
    nettle_aes192_invert_key_vec = _nettle_aes192_invert_key_s390x;
    nettle_aes192_encrypt_vec = _nettle_aes192_encrypt_s390x;
    nettle_aes192_decrypt_vec = _nettle_aes192_decrypt_s390x;
  }
  else
  {
    nettle_aes192_set_encrypt_key_vec = _nettle_aes192_set_encrypt_key_c;
    nettle_aes192_set_decrypt_key_vec = _nettle_aes192_set_decrypt_key_c;
    nettle_aes192_invert_key_vec = _nettle_aes192_invert_key_c;
    nettle_aes192_encrypt_vec = _nettle_aes192_encrypt_c;
    nettle_aes192_decrypt_vec = _nettle_aes192_decrypt_c;
  }

  /* AES256 */
  if (features.have_km_aes256)
  {
    if (verbose)
      fprintf (stderr, "libnettle: enabling hardware accelerated AES256 EBC mode.\n");
    nettle_aes256_set_encrypt_key_vec = _nettle_aes256_set_encrypt_key_s390x;
    nettle_aes256_set_decrypt_key_vec = _nettle_aes256_set_decrypt_key_s390x;
    nettle_aes256_invert_key_vec = _nettle_aes256_invert_key_s390x;
    nettle_aes256_encrypt_vec = _nettle_aes256_encrypt_s390x;
    nettle_aes256_decrypt_vec = _nettle_aes256_decrypt_s390x;
  }
  else
  {
    nettle_aes256_set_encrypt_key_vec = _nettle_aes256_set_encrypt_key_c;
    nettle_aes256_set_decrypt_key_vec = _nettle_aes256_set_decrypt_key_c;
    nettle_aes256_invert_key_vec = _nettle_aes256_invert_key_c;
    nettle_aes256_encrypt_vec = _nettle_aes256_encrypt_c;
    nettle_aes256_decrypt_vec = _nettle_aes256_decrypt_c;
  }

  /* GHASH */
  if (features.have_kmid_ghash)
  {
    if (verbose)
      fprintf (stderr, "libnettle: enabling hardware accelerated GHASH.\n");
    _nettle_gcm_init_key_vec = _nettle_gcm_init_key_s390x;
    _nettle_gcm_hash_vec = _nettle_gcm_hash_s390x;
  }
  else
  {
    _nettle_gcm_init_key_vec = _nettle_gcm_init_key_c;
    _nettle_gcm_hash_vec = _nettle_gcm_hash_c;
  }
}

/* MEMXOR3 */
DEFINE_FAT_FUNC(nettle_memxor3, void *,
		(void *dst_in, const void *a_in, const void *b_in, size_t n),
		(dst_in, a_in, b_in, n))

/* AES128 */
DEFINE_FAT_FUNC(nettle_aes128_set_encrypt_key, void,
 (struct aes128_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes128_set_decrypt_key, void,
 (struct aes128_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes128_invert_key, void,
 (struct aes128_ctx *dst, const struct aes128_ctx *src),
 (dst, src))
DEFINE_FAT_FUNC(nettle_aes128_encrypt, void,
 (const struct aes128_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))
DEFINE_FAT_FUNC(nettle_aes128_decrypt, void,
 (const struct aes128_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))

/* AES192 */
DEFINE_FAT_FUNC(nettle_aes192_set_encrypt_key, void,
 (struct aes192_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes192_set_decrypt_key, void,
 (struct aes192_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes192_invert_key, void,
 (struct aes192_ctx *dst, const struct aes192_ctx *src),
 (dst, src))
DEFINE_FAT_FUNC(nettle_aes192_encrypt, void,
 (const struct aes192_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))
DEFINE_FAT_FUNC(nettle_aes192_decrypt, void,
 (const struct aes192_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))

/* AES256 */
DEFINE_FAT_FUNC(nettle_aes256_set_encrypt_key, void,
 (struct aes256_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes256_set_decrypt_key, void,
 (struct aes256_ctx *ctx, const uint8_t *key),
 (ctx, key))
DEFINE_FAT_FUNC(nettle_aes256_invert_key, void,
 (struct aes256_ctx *dst, const struct aes256_ctx *src),
 (dst, src))
DEFINE_FAT_FUNC(nettle_aes256_encrypt, void,
 (const struct aes256_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))
DEFINE_FAT_FUNC(nettle_aes256_decrypt, void,
 (const struct aes256_ctx *ctx, size_t length,
  uint8_t *dst,const uint8_t *src),
 (ctx, length, dst, src))

/* GHASH */
#if GCM_TABLE_BITS == 8
DEFINE_FAT_FUNC(_nettle_gcm_init_key, void,
		(union nettle_block16 *table),
		(table))
DEFINE_FAT_FUNC(_nettle_gcm_hash, void,
		(const struct gcm_key *key, union nettle_block16 *x,
		 size_t length, const uint8_t *data),
		(key, x, length, data))
#endif /* GCM_TABLE_BITS == 8 */
