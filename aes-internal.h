/* aes-internal.h
 *
 * The aes/rijndael block cipher.
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

#ifndef NETTLE_AES_INTERNAL_H_INCLUDED
#define NETTLE_AES_INTERNAL_H_INCLUDED

#include "aes.h"

/* Define to use only small tables. */
#ifndef AES_SMALL
# define AES_SMALL 1
#endif

/* Macros */
#define ROTBYTE(x) (((x) >> 8) | (((x) & 0xff) << 24))
#define ROTRBYTE(x) (((x) << 8) | (((x) >> 24) & 0xff))
#define SUBBYTE(x, box) (((box)[((x) & 0xff)]) | \
                        ((box)[(((x) >> 8) & 0xff)] << 8) | \
                        ((box)[(((x) >> 16) & 0xff)] << 16) | \
                        ((box)[(((x) >> 24) & 0xff)] << 24))

/* Don't pollute global namespace too much */
#if AES_SMALL
# define dtbl _aes_dtbl_small
# define _AES_TABLE_SIZE 1
#else
# define dtbl _aes_dtbl
# define _AES_TABLE_SIZE 4
#endif

#define itbl _aes_itbl
#define sbox _aes_sbox
#define isbox _aes_isbox

/* Internal tables */
extern const uint32_t dtbl[_AES_TABLE_SIZE][0x100];
extern const uint32_t itbl[];
extern const uint8_t sbox[0x100];
extern const uint8_t isbox[0x100];

#endif /* NETTLE_AES_INTERNAL_H_INCLUDED */
