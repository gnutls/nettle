/* serpent-meta.c */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002, 2014 Niels Möller
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

#include "serpent.h"

#define SERPENT(bits) {					\
  "serpent" #bits,					\
  sizeof(struct serpent_ctx),				\
  SERPENT_BLOCK_SIZE,					\
  SERPENT ## bits ##_KEY_SIZE,				\
  (nettle_set_key_func *) serpent ## bits ## _set_key,	\
  (nettle_set_key_func *) serpent ## bits ## _set_key,	\
  (nettle_crypt_func *) serpent_encrypt,		\
  (nettle_crypt_func *) serpent_decrypt			\
}

const struct nettle_cipher nettle_serpent128
= SERPENT(128);
const struct nettle_cipher nettle_serpent192
= SERPENT(192);
const struct nettle_cipher nettle_serpent256
= SERPENT(256);
