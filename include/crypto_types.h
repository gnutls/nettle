/* $Id$
 *
 * Defines the types UINT32, UINT16 and UINT8 */

#ifndef CRYPTO_TYPES_H_INCLUDED
#define CRYPTO_TYPES_H_INCLUDED

#ifdef PIKE
#include "pike_types.h"
#include "global.h"
#define UINT32 unsigned INT32
#define UINT16 unsigned INT16
#define UINT8 unsigned INT8
#else  /* !PIKE */
#ifdef LSH
#include "lsh_types.h"
#else /* !LSH */
#define UINT32 unsigned long
#define UINT16 unsigned short
#define UINT8 unsigned char
#endif
#endif

#endif /* CRYPTO_TYPES_H_INCLUDED */
