/*
 * $Id$
 */

/*
 * Please be aware that IDEA IS PATENT ENCUMBERED; see the note in idea.c.
 *                      -------------------------
 */

#ifndef IDEA_H_INCLUDED
#define IDEA_H_INCLUDED

#define IDEA_KEYSIZE 16
#define IDEA_BLOCKSIZE 8

#define IDEA_ROUNDS 8
#define IDEA_KEYLEN (6*IDEA_ROUNDS+4)

#include "crypto_types.h"

void idea_expand(UINT16 *ctx,
		 const UINT8 *key);

void idea_invert(UINT16 *d,
		 const UINT16 *e);

void idea_crypt(const UINT16 *ctx,
		UINT8 *dest,
		const UINT8 *src);

#endif /* IDEA_H_INCLUDED */
