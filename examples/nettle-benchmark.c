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
#include "cbc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

/* Encrypt 1MB, 1K at a time. */
#define BENCH_SIZE 1024

typedef void (*crypt_func)(void *ctx,
			   unsigned length, uint8_t *dst,
			   const uint8_t *src);
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
  
  for (i = 0; i<BENCH_SIZE; i++)
    info->crypt(info->ctx, BENCH_SIZE, info->data, info->data);
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

  for (i = 0; i<BENCH_SIZE; i++)
    cbc_encrypt(info->ctx, info->crypt,
		info->block_size, info->iv,
		BENCH_SIZE, info->data, info->data);
}

static void
bench_cbc_decrypt(void *arg)
{
  struct bench_cbc_info *info = arg;
  unsigned i;

  for (i = 0; i<BENCH_SIZE; i++)
    cbc_decrypt(info->ctx, info->crypt,
		info->block_size, info->iv,
		BENCH_SIZE, info->data, info->data);
}

/* Set data[i] = floor(sqrt(i)) */
static void
init_data(uint8_t *data)
{
  unsigned i,j;
  for (i = j = 0; i<BENCH_SIZE;  i++)
    {
      if (j*j < i)
	j++;
      data[i] = j;
    }
}

static void
bench(const char *name, void (*f)(void *), void *arg)
{
  printf("%15s: %f\n", name, time_function(f, arg));
}

int
main(int argc, char **argv)
{
  /* Time block ciphers */
  uint8_t iv[AES_BLOCK_SIZE];
  uint8_t key[AES_MAX_KEY_SIZE];
  
  uint8_t data[BENCH_SIZE];

  {
    struct aes_ctx ctx;
    struct bench_cipher_info info
      = { &ctx, (crypt_func) aes_encrypt, data };
    
    memset(key, 0, sizeof(key));

    aes_set_key(&ctx, sizeof(key), key);
    init_data(data);

    bench("AES (ECB encrypt)", bench_cipher, &info);
  }

  {
    struct aes_ctx ctx;
    struct bench_cipher_info info
      = { &ctx, (crypt_func) aes_decrypt, data };
    
    memset(key, 0, sizeof(key));

    aes_set_key(&ctx, sizeof(key), key);
    init_data(data);

    bench("AES (ECB decrypt)", bench_cipher, &info);
  }

  {
    struct aes_ctx ctx;
    struct bench_cbc_info info
      = { &ctx, (crypt_func) aes_encrypt, data, AES_BLOCK_SIZE, iv };
    
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    aes_set_key(&ctx, sizeof(key), key);
    init_data(data);

    bench("AES (CBC encrypt)", bench_cbc_encrypt, &info);
  }

  {
    struct aes_ctx ctx;
    struct bench_cbc_info info
      = { &ctx, (crypt_func) aes_decrypt, data, AES_BLOCK_SIZE, iv };
    
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    aes_set_key(&ctx, sizeof(key), key);
    init_data(data);

    bench("AES (CBC decrypt)", bench_cbc_decrypt, &info);
  }

  return 0;
}
