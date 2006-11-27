/* pkcs1.c
 *
 * PKCS1 embedding.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2003 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if WITH_PUBLIC_KEY

#include <assert.h>
#include <string.h>

#include "pkcs1.h"

/* Formats the PKCS#1 padding, of the form
 *
 *   0x01 0xff ... 0xff 0x00 id
 *
 * where the 0xff ... 0xff part consists of at least 8 octets.
 */
void
pkcs1_signature_prefix(unsigned length,
		       uint8_t *buffer,
		       unsigned id_length,
		       const uint8_t *id)
{
  assert(length >= id_length);
  length -= id_length;
  memcpy(buffer + length, id, id_length);

  assert(length);
  buffer[--length] = 0;

  assert(length >= 9);
  memset(buffer + 1, 0xff, length - 1);
  buffer[0] = 1;
}
		     
#endif /* WITH_PUBLIC_KEY */
