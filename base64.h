/* armor.h
 *
 * "ASCII armor" codecs.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller, Dan Egnor
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
 
#ifndef NETTLE_ARMOR_H_INCLUDED
#define NETTLE_ARMOR_H_INCLUDED

#include <inttypes.h>

/* Base64 encoding */

#define BASE64_ASCII_BLOCK_SIZE 4
#define BASE64_RAW_BLOCK_SIZE   3

unsigned /* Returns the length of encoded data */
base64_encode(uint8_t *dst,
              unsigned src_length,
              const uint8_t *src);

unsigned /* Returns the length of decoded data */
base64_decode(uint8_t *dst,
              unsigned src_length,
              const uint8_t *src);

#endif /* NETTLE_ARMOR_H_INCLUDED */
