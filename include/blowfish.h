/* blowfish.h
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * Modifications for lsh by Ray Dassen
 */

#ifndef G10_BLOWFISH_H
#define G10_BLOWFISH_H

#include "crypto_types.h"

/* Use lsh types */
typedef UINT8 byte;
typedef UINT16 u16;
typedef UINT32 u32;

/* FIXME: A search&replace on the type names would be better, but I
 * keep GPG names for now to make it easier to get smaller diffs. */

#if 0
#define CIPHER_ALGO_BLOWFISH     4  /* blowfish 128 bit key */
#endif

#define BLOWFISH_BLOCKSIZE 8
#define BLOWFISH_ROUNDS 16

/* Other key lengths are possible, but 128 bits is the default. */
#define BLOWFISH_KEYSIZE 16

/* Allow keys of size 64 <= bits <= 448 */
#define BLOWFISH_MIN_KEYSIZE 8
#define BLOWFISH_MAX_KEYSIZE 56

#define G10ERR_WEAK_KEY 43

typedef struct {
    u32 s0[256];
    u32 s1[256];
    u32 s2[256];
    u32 s3[256];
    u32 p[BLOWFISH_ROUNDS+2];
} BLOWFISH_context;


/* Returns 0 if the key is ok */

int  bf_set_key( BLOWFISH_context *c, const byte *key, unsigned keylen );
void bf_encrypt_block( BLOWFISH_context *bc, byte *outbuf, const byte *inbuf );
void bf_decrypt_block( BLOWFISH_context *bc, byte *outbuf, const byte *inbuf );

int bf_selftest(void);

#if 0
const char *
blowfish_get_info( int algo, size_t *keylen,
		   size_t *blocksize, size_t *contextsize,
		   int	(**setkey)( void *c, const byte *key, unsigned keylen ),
		   void (**encrypt)( void *c, byte *outbuf, const byte *inbuf ),
		   void (**decrypt)( void *c, byte *outbuf, const byte *inbuf )
		 );
#endif
		 
#endif /*G10_BLOWFISH_H*/
