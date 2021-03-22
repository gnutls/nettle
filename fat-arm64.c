/* fat-arm64.c

   Copyright (C) 2021 Mamone Tarsha

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

#if defined(__linux__) && defined(__GLIBC__) && defined(__GLIBC_PREREQ)
# if __GLIBC_PREREQ(2, 16)
#  define USE_GETAUXVAL 1
#  include <asm/hwcap.h>
#  include <sys/auxv.h>
# endif
#endif

#include "nettle-types.h"

#include "gcm.h"
#include "gcm-internal.h"
#include "fat-setup.h"

/* Defines from arch/arm64/include/uapi/asm/hwcap.h in Linux kernel */
#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif

struct arm64_features
{
  int have_pmull;
};

#define MATCH(s, slen, literal, llen) \
  ((slen) == (llen) && memcmp ((s), (literal), llen) == 0)

static void
get_arm64_features (struct arm64_features *features)
{
  const char *s;
  features->have_pmull = 0;

  s = secure_getenv (ENV_OVERRIDE);
  if (s)
    for (;;)
      {
	const char *sep = strchr (s, ',');
	size_t length = sep ? (size_t) (sep - s) : strlen(s);

	if (MATCH (s, length, "pmull", 5))
	  features->have_pmull = 1;
	if (!sep)
	  break;
	s = sep + 1;
      }
  else
    {
#if USE_GETAUXVAL
      unsigned long hwcap = getauxval(AT_HWCAP);
      features->have_pmull
	= ((hwcap & (HWCAP_ASIMD | HWCAP_PMULL)) == (HWCAP_ASIMD | HWCAP_PMULL));
#endif
    }
}

#if GCM_TABLE_BITS == 8
DECLARE_FAT_FUNC(_nettle_gcm_init_key, gcm_init_key_func)
DECLARE_FAT_FUNC_VAR(gcm_init_key, gcm_init_key_func, c)
DECLARE_FAT_FUNC_VAR(gcm_init_key, gcm_init_key_func, arm64)

DECLARE_FAT_FUNC(_nettle_gcm_hash, gcm_hash_func)
DECLARE_FAT_FUNC_VAR(gcm_hash, gcm_hash_func, c)
DECLARE_FAT_FUNC_VAR(gcm_hash, gcm_hash_func, arm64)
#endif /* GCM_TABLE_BITS == 8 */

static void CONSTRUCTOR
fat_init (void)
{
  struct arm64_features features;
  int verbose;

  get_arm64_features (&features);

  verbose = getenv (ENV_VERBOSE) != NULL;
  if (verbose)
    fprintf (stderr, "libnettle: cpu features: %s\n",
	     features.have_pmull ? "polynomial multiply long instructions (PMULL/PMULL2)" : "");

  if (features.have_pmull)
    {
      if (verbose)
	fprintf (stderr, "libnettle: enabling hardware-accelerated polynomial multiply code.\n");
#if GCM_TABLE_BITS == 8
      /* Make sure _nettle_gcm_init_key_vec function is compatible
         with _nettle_gcm_hash_vec function e.g. _nettle_gcm_init_key_c()
         fills gcm_key table with values that are incompatible with
         _nettle_gcm_hash_arm64() */
      _nettle_gcm_init_key_vec = _nettle_gcm_init_key_arm64;
      _nettle_gcm_hash_vec = _nettle_gcm_hash_arm64;
#endif /* GCM_TABLE_BITS == 8 */
    }
  else
    {
#if GCM_TABLE_BITS == 8
      _nettle_gcm_init_key_vec = _nettle_gcm_init_key_c;
      _nettle_gcm_hash_vec = _nettle_gcm_hash_c;
#endif /* GCM_TABLE_BITS == 8 */
    }
}

#if GCM_TABLE_BITS == 8
DEFINE_FAT_FUNC(_nettle_gcm_init_key, void,
		(union nettle_block16 *table),
		(table))

DEFINE_FAT_FUNC(_nettle_gcm_hash, void,
		(const struct gcm_key *key, union nettle_block16 *x,
		 size_t length, const uint8_t *data),
		(key, x, length, data))
#endif /* GCM_TABLE_BITS == 8 */
