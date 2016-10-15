/* skein.h

   The skein hash function.

   Copyright (C) 2016 Niels Möller

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

#ifndef NETTLE_SKEIN_H_INCLUDED
#define NETTLE_SKEIN_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define skein256_init nettle_skein256_init
#define skein256_update nettle_skein256_update
#define skein256_digest nettle_skein256_digest
#define _skein256_expand _nettle_skein256_expand
#define _skein256_block _nettle_skein256_block

#define SKEIN256_BLOCK_SIZE 32
#define SKEIN256_DIGEST_SIZE 32

/* Internal lengths, as 64-bit words. We use *two* redundant words for
   the key, to reduce the number of index mod operations. On the other
   hand, tweak words are expanded on the fly. */
#define _SKEIN256_LENGTH 4
#define _SKEIN256_NKEYS 6
#define _SKEIN_NTWEAK 2

struct skein256_ctx {
  uint64_t state[_SKEIN256_NKEYS];

  /* Current implementation limited to message size <= 2^69 - 32 bytes,
     while the specification allows up to 2^96 -1 bytes.*/
  uint64_t count;               /* Block count */
  uint8_t block[SKEIN256_BLOCK_SIZE];
  unsigned index;
};

void
skein256_init(struct skein256_ctx *ctx);

void
skein256_update(struct skein256_ctx *ctx,
		size_t length,
		const uint8_t *data);

void
skein256_digest(struct skein256_ctx *ctx,
		size_t length,
		uint8_t *digest);

#define _SKEIN_C240 0x1BD11BDAA9FC1A22ULL

void
_skein256_expand(uint64_t keys[_SKEIN256_NKEYS]);

void
_skein256_block (uint64_t dst[_SKEIN256_LENGTH],
		 const uint64_t keys[_SKEIN256_NKEYS],
		 const uint64_t tweak[_SKEIN_NTWEAK],
		 const uint8_t src[SKEIN256_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_SKEIN_H_INCLUDED */
