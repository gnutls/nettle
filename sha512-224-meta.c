/* sha512-224-meta.c */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2014 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "nettle-meta.h"

#include "sha2.h"

const struct nettle_hash nettle_sha512_224 =
  {
    "sha512-224", sizeof(struct sha512_ctx),
    SHA512_224_DIGEST_SIZE,
    SHA512_224_DATA_SIZE,
    (nettle_hash_init_func *) sha512_224_init,
    (nettle_hash_update_func *) sha512_224_update,
    (nettle_hash_digest_func *) sha512_224_digest
  };

