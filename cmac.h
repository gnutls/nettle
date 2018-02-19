/* cmac.h

   CMAC mode, as specified in RFC4493

   Copyright (C) 2017 Red Hat, Inc.

   Contributed by Nikos Mavrogiannopoulos

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

#ifndef NETTLE_CMAC_H_INCLUDED
#define NETTLE_CMAC_H_INCLUDED

#include "aes.h"
#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMAC128_DIGEST_SIZE 16

#define cmac128_set_key nettle_cmac128_set_key
#define cmac128_update nettle_cmac128_update
#define cmac128_digest nettle_cmac128_digest
#define cmac_aes128_set_key nettle_cmac_aes128_set_key
#define cmac_aes128_update nettle_cmac_aes128_update
#define cmac_aes128_digest nettle_cmac_aes128_digest
#define cmac_aes256_set_key nettle_cmac_aes256_set_key
#define cmac_aes256_update nettle_cmac_aes256_update
#define cmac_aes256_digest nettle_cmac_aes256_digest

struct cmac128
{
  union nettle_block16 K1;
  union nettle_block16 K2;

  union nettle_block16 X;

  union nettle_block16 block;
  size_t index;
};

void
cmac128_set_key(struct cmac128 *ctx, void *cipher,
		nettle_cipher_func *encrypt);
void
cmac128_update(struct cmac128 *ctx, void *cipher,
	       nettle_cipher_func *encrypt,
	       size_t msg_len, const uint8_t *msg);
void
cmac128_digest(struct cmac128 *ctx, void *cipher,
	       nettle_cipher_func *encrypt,
	       unsigned length,
	       uint8_t *out);


#define CMAC128_CTX(type) \
  { struct cmac128 data; type cipher; }

/* NOTE: Avoid using NULL, as we don't include anything defining it. */
#define CMAC128_SET_KEY(ctx, set_key, encrypt, cmac_key)	\
  do {								\
    (set_key)(&(ctx)->cipher, (cmac_key));			\
    if (0) (encrypt)(&(ctx)->cipher, ~(size_t) 0,		\
		     (uint8_t *) 0, (const uint8_t *) 0);	\
    cmac128_set_key(&(ctx)->data, &(ctx)->cipher,		\
		(nettle_cipher_func *) (encrypt));		\
  } while (0)

#define CMAC128_UPDATE(ctx, encrypt, length, src)		\
  cmac128_update(&(ctx)->data, &(ctx)->cipher,			\
	      (nettle_cipher_func *)encrypt, (length), (src))

#define CMAC128_DIGEST(ctx, encrypt, length, digest)		\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,			\
		 (uint8_t *) 0, (const uint8_t *) 0)		\
     : cmac128_digest(&(ctx)->data, &(ctx)->cipher,		\
		  (nettle_cipher_func *) (encrypt),		\
		  (length), (digest)))

struct cmac_aes128_ctx CMAC128_CTX(struct aes128_ctx);

void
cmac_aes128_set_key(struct cmac_aes128_ctx *ctx, const uint8_t *key);

void
cmac_aes128_update(struct cmac_aes128_ctx *ctx,
		   size_t length, const uint8_t *data);

void
cmac_aes128_digest(struct cmac_aes128_ctx *ctx,
		   size_t length, uint8_t *digest);

struct cmac_aes256_ctx CMAC128_CTX(struct aes256_ctx);

void
cmac_aes256_set_key(struct cmac_aes256_ctx *ctx, const uint8_t *key);

void
cmac_aes256_update(struct cmac_aes256_ctx *ctx,
		   size_t length, const uint8_t *data);

void
cmac_aes256_digest(struct cmac_aes256_ctx *ctx,
		   size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* CMAC_H_INCLUDED */