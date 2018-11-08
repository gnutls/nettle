/* pkcs1-sec-decrypt.c

   The RSA publickey algorithm. Side channel resistant PKCS#1 decryption.

   Copyright (C) 2001, 2012 Niels Möller
   Copyright (C) 2018 Red Hat, Inc.

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

#include <string.h>

#include "memops.h"

#include "gmp-glue.h"
#include "rsa.h"
#include "rsa-internal.h"

/* Inputs are always cast to uint32_t values. But all values used in this
 * function should never exceed the maximum value of a uint32_t anyway.
 * these macros returns 1 on success, 0 on failure */
#define NOT_EQUAL(a, b) \
    ((0U - ((uint32_t)(a) ^ (uint32_t)(b))) >> 31)
#define EQUAL(a, b) \
    ((((uint32_t)(a) ^ (uint32_t)(b)) - 1U) >> 31)

int
_pkcs1_sec_decrypt (size_t length, uint8_t *message,
                    size_t padded_message_length,
                    const volatile uint8_t *padded_message)
{
  volatile int ok;
  size_t i, t;

  assert (padded_message_length >= length);

  t = padded_message_length - length - 1;

  /* Check format, padding, message_size */
  ok = EQUAL(padded_message[0], 0);       /* ok if padded_message[0] == 0 */
  ok &= EQUAL(padded_message[1], 2);      /* ok if padded_message[1] == 2 */
  for (i = 2; i < t; i++)      /* check padding has no zeros */
    {
      ok &= NOT_EQUAL(padded_message[i], 0);
    }
  ok &= EQUAL(padded_message[t], 0);      /* ok if terminator == 0 */

  /* fill destination buffer regardless of outcome */
  cnd_memcpy(ok, message, padded_message + t + 1, length);

  return ok;
}
