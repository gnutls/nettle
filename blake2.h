/* blake2.h

   The blake2 hash function, see RFC 7693

   Copyright (C) 2025 Niels Möller

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

#ifndef NETTLE_BLAKE2_H_INCLUDED
#define NETTLE_BLAKE2_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define blake2b_init nettle_blake2b_init
#define blake2b_update nettle_blake2b_update
#define blake2b_digest nettle_blake2b_digest
#define blake2b_512_init nettle_blake2b_512_init
#define blake2s_init nettle_blake2s_init
#define blake2s_update nettle_blake2s_update
#define blake2s_digest nettle_blake2s_digest
#define blake2s_256_init nettle_blake2s_256_init

#define BLAKE2B_DIGEST_SIZE 64
#define BLAKE2B_BLOCK_SIZE 128

struct blake2b_ctx
{
  uint64_t state[8];
  uint64_t count_low, count_high;	/* 128-bit byte count */
  unsigned short digest_size;
  unsigned short index;			/* index into buffer */
  uint8_t block[BLAKE2B_BLOCK_SIZE];	/* data buffer */
};

void
blake2b_init (struct blake2b_ctx *ctx, unsigned digest_size);

void
blake2b_update (struct blake2b_ctx *ctx,
		size_t length, const uint8_t *data);

void
blake2b_digest (struct blake2b_ctx *ctx, uint8_t *digest);

void
blake2b_512_init (struct blake2b_ctx *ctx);

#define BLAKE2S_DIGEST_SIZE 32
#define BLAKE2S_BLOCK_SIZE 64

struct blake2s_ctx
{
  uint32_t state[8];
  uint64_t count;			/* 64-bit byte count */
  unsigned short digest_size;
  unsigned short index;			/* index into buffer */
  uint8_t block[BLAKE2S_BLOCK_SIZE];	/* data buffer */
};

void
blake2s_init (struct blake2s_ctx *ctx, unsigned digest_size);

void
blake2s_update (struct blake2s_ctx *ctx,
		size_t length, const uint8_t *data);

void
blake2s_digest (struct blake2s_ctx *ctx, uint8_t *digest);

void
blake2s_256_init (struct blake2s_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_BLAKE2_H_INCLUDED */
