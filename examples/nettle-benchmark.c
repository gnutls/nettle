/* nettle-benchmark.c
 *
 * Tries the performance of the various algorithms.
 *
 */
 
/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "aes.h"
#include "arcfour.h"
#include "blowfish.h"
#include "cast128.h"
#include "des.h"
#include "serpent.h"
#include "twofish.h"

#include "cbc.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

/* Encrypt 100MB, 1K at a time. */
#define BENCH_BLOCK 1024
#define BENCH_COUNT 10240

typedef void (*crypt_func)(void *ctx,
			   unsigned length, uint8_t *dst,
			   const uint8_t *src);

typedef void (*setkey_func)(void *ctx,
                            unsigned length,
                            const uint8_t *key);

static double
time_function(void (*f)(void *arg), void *arg)
{
  clock_t before;
  clock_t after;

  before = clock();
  
  f(arg);
  
  after = clock();

  return ((double)(after - before)) / CLOCKS_PER_SEC;
}

struct bench_cipher_info
{
  void *ctx;
  crypt_func crypt;
  uint8_t *data;
};

static void
bench_cipher(void *arg)
{
  struct bench_cipher_info *info = arg;
  unsigned i;
  
  for (i = 0; i<BENCH_COUNT; i++)
    info->crypt(info->ctx, BENCH_BLOCK, info->data, info->data);
}

struct bench_cbc_info
{
  void *ctx;
  crypt_func crypt;

  uint8_t *data;

  unsigned block_size;
  uint8_t *iv;
};

static void
bench_cbc_encrypt(void *arg)
{
  struct bench_cbc_info *info = arg;
  unsigned i;

  for (i = 0; i<BENCH_COUNT; i++)
    cbc_encrypt(info->ctx, info->crypt,
		info->block_size, info->iv,
		BENCH_BLOCK, info->data, info->data);
}

static void
bench_cbc_decrypt(void *arg)
{
  struct bench_cbc_info *info = arg;
  unsigned i;

  for (i = 0; i<BENCH_COUNT; i++)
    cbc_decrypt(info->ctx, info->crypt,
		info->block_size, info->iv,
		BENCH_BLOCK, info->data, info->data);
}

/* Set data[i] = floor(sqrt(i)) */
static void
init_data(uint8_t *data)
{
  unsigned i,j;
  for (i = j = 0; i<BENCH_BLOCK;  i++)
    {
      if (j*j < i)
	j++;
      data[i] = j;
    }
}

static void
init_key(unsigned length,
         uint8_t *key)
{
  unsigned i;
  for (i = 0; i<length; i++)
    key[i] = i;
}

struct cipher
{
  const char *name;
  unsigned context_size;
  
  unsigned block_size;
  unsigned key_size;

  setkey_func setkey;
  crypt_func encrypt;
  crypt_func decrypt;
};
  

static void
time_cipher(struct cipher *cipher)
{
  void *ctx = alloca(cipher->context_size);
  uint8_t *key = alloca(cipher->key_size);

  uint8_t data[BENCH_BLOCK];

  printf("\n");
  
  init_data(data);

  {
    struct bench_cipher_info info
      = { ctx, cipher->encrypt, data };
    
    init_key(cipher->key_size, key);
    cipher->setkey(ctx, cipher->key_size, key);
    
    printf("%13s (ECB encrypt): %f\n", cipher->name,
           time_function(bench_cipher, &info));
  }
  
  {
    struct bench_cipher_info info
      = { ctx, cipher->decrypt, data };
    
    init_key(cipher->key_size, key);
    cipher->setkey(ctx, cipher->key_size, key);
    
    printf("%13s (ECB decrypt): %f\n", cipher->name,
           time_function(bench_cipher, &info));
  }

  if (cipher->block_size)
    {
      uint8_t *iv = alloca(cipher->block_size);
      
      /* Do CBC mode */
      {
        struct bench_cbc_info info
          = { ctx, cipher->encrypt, data, cipher->block_size, iv };
    
        memset(iv, 0, sizeof(iv));
    
        cipher->setkey(ctx, cipher->key_size, key);

        printf("%13s (CBC encrypt): %f\n", cipher->name,
               time_function(bench_cbc_encrypt,
                             &info));
      }

      {
        struct bench_cbc_info info
          = { ctx, cipher->decrypt, data, cipher->block_size, iv };
    
        memset(iv, 0, sizeof(iv));

        cipher->setkey(ctx, cipher->key_size, key);

        printf("%13s (CBC decrypt): %f\n", cipher->name,
               time_function(bench_cbc_decrypt,
                             &info));
      }
    }
}

/* DES uses a different signature for the key set function.
 * And we have to adjust parity. */
static void
des_set_key_hack(void *c, unsigned length, const uint8_t *key)
{
  struct des_ctx *ctx = c;
  uint8_t pkey[DES_KEY_SIZE];
  
  assert(length == DES_KEY_SIZE);
  des_fix_parity(DES_KEY_SIZE, pkey, key);
  if (!des_set_key(ctx, pkey))
    abort();
}

static void
des3_set_key_hack(void *c, unsigned length, const uint8_t *key)
{
  struct des3_ctx *ctx = c;
  uint8_t pkey[DES3_KEY_SIZE];
  
  assert(length == DES3_KEY_SIZE);
  des_fix_parity(DES3_KEY_SIZE, pkey, key);
  if (!des3_set_key(ctx, pkey))
    abort();
}

#define NCIPHERS 12

int
main(int argc, char **argv)
{
  unsigned i;
  struct cipher ciphers[NCIPHERS] =
    {
      { "AES-128", sizeof(struct aes_ctx),
        AES_BLOCK_SIZE, 16,
        (setkey_func) aes_set_key,
        (crypt_func) aes_encrypt,
        (crypt_func) aes_decrypt
      },
      { "AES-192", sizeof(struct aes_ctx),
        AES_BLOCK_SIZE, 24,
        (setkey_func) aes_set_key,
        (crypt_func) aes_encrypt,
        (crypt_func) aes_decrypt
      },
      { "AES-256", sizeof(struct aes_ctx),
        AES_BLOCK_SIZE, 32,
        (setkey_func) aes_set_key,
        (crypt_func) aes_encrypt,
        (crypt_func) aes_decrypt
      },
      { "ARCFOUR-128", sizeof(struct arcfour_ctx),
        0, ARCFOUR_KEY_SIZE,
        (setkey_func) arcfour_set_key,
        (crypt_func) arcfour_crypt,
        (crypt_func) arcfour_crypt
      },
      { "BLOWFISH-128", sizeof(struct blowfish_ctx),
        BLOWFISH_BLOCK_SIZE, BLOWFISH_KEY_SIZE,
        (setkey_func) blowfish_set_key,
        (crypt_func) blowfish_encrypt,
        (crypt_func) blowfish_decrypt
      },
      { "CAST-128", sizeof(struct cast128_ctx),
        CAST128_BLOCK_SIZE, CAST128_KEY_SIZE,
        (setkey_func) cast128_set_key,
        (crypt_func) cast128_encrypt,
        (crypt_func) cast128_decrypt
      },
      { "DES", sizeof(struct des_ctx),
        DES_BLOCK_SIZE, DES_KEY_SIZE,
        des_set_key_hack,
        (crypt_func) des_encrypt,
        (crypt_func) des_decrypt
      },
      { "DES3", sizeof(struct des3_ctx),
        DES3_BLOCK_SIZE, DES3_KEY_SIZE,
        des3_set_key_hack,
        (crypt_func) des3_encrypt,
        (crypt_func) des3_decrypt
      },
      { "SERPENT-256", sizeof(struct serpent_ctx),
        SERPENT_BLOCK_SIZE, SERPENT_KEY_SIZE,
        (setkey_func) serpent_set_key,
        (crypt_func) serpent_encrypt,
        (crypt_func) serpent_decrypt
      },
      { "TWOFISH-128", sizeof(struct twofish_ctx),
        TWOFISH_BLOCK_SIZE, 16,
        (setkey_func) twofish_set_key,
        (crypt_func) twofish_encrypt,
        (crypt_func) twofish_decrypt
      },
      { "TWOFISH-192", sizeof(struct twofish_ctx),
        TWOFISH_BLOCK_SIZE, 24,
        (setkey_func) twofish_set_key,
        (crypt_func) twofish_encrypt,
        (crypt_func) twofish_decrypt
      },
      { "TWOFISH-256", sizeof(struct twofish_ctx),
        TWOFISH_BLOCK_SIZE, 32,
        (setkey_func) twofish_set_key,
        (crypt_func) twofish_encrypt,
        (crypt_func) twofish_decrypt
      },
    };

  for (i = 0; i<NCIPHERS; i++)
    time_cipher(ciphers + i);
  
  return 0;
}
