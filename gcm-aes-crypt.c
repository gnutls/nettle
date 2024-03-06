/* gcm-aes-crypt.c

   Galois counter mode using AES as the underlying cipher.

   Copyright (C) 2011, 2014 Niels Möller

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

#include "gcm.h"

/* For fat builds */
#if HAVE_NATIVE_gcm_aes_encrypt
size_t
_gcm_aes_encrypt (struct gcm_key *key, size_t rounds,
                  size_t len, uint8_t *dst, const uint8_t *src);
#define _nettle_gcm_aes_encrypt _nettle_gcm_aes_encrypt_c
#endif

#if HAVE_NATIVE_gcm_aes_decrypt
size_t
_gcm_aes_decrypt (struct gcm_key *key, size_t rounds,
                  size_t len, uint8_t *dst, const uint8_t *src);
#define _nettle_gcm_aes_decrypt _nettle_gcm_aes_decrypt_c
#endif

size_t
_gcm_aes_encrypt (struct gcm_key *key, size_t rounds,
                  size_t len, uint8_t *dst, const uint8_t *src)
{
  return 0;
}

size_t
_gcm_aes_decrypt (struct gcm_key *key, size_t rounds,
                  size_t len, uint8_t *dst, const uint8_t *src)
{
  return 0;
}
