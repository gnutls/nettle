/*
 *	des - fast & portable DES encryption & decryption.
 *	Copyright (C) 1992  Dana L. How
 *	Please see the file `../lib/descore.README' for the complete copyright
 *	notice.
 *
 * Slightly edited by Niels Möller, 1997
 */

#ifndef DES_H_INCLUDED
#define DES_H_INCLUDED

#include "crypto_types.h"

#include "RCSID.h"
RCSID2(desCore_hRcs, "$Id$");

#define DES_KEYSIZE 8
#define DES_BLOCKSIZE 8
#define DES_EXPANDED_KEYLEN 32

/* FIXME: typedef on arrays is ugly. */
typedef UINT8 DesData[DES_BLOCKSIZE];
typedef UINT32 DesKeys[DES_EXPANDED_KEYLEN];

typedef void DesFunc(UINT8 *d, const UINT32 *r, const UINT8 *s);

extern int DesMethod(UINT32 *method, const UINT8 *k);
extern void DesQuickInit(void);
extern void DesQuickDone(void);
extern DesFunc DesQuickCoreEncrypt;
extern DesFunc DesQuickFipsEncrypt;
extern DesFunc DesQuickCoreDecrypt;
extern DesFunc DesQuickFipsDecrypt;
extern DesFunc DesSmallCoreEncrypt;
extern DesFunc DesSmallFipsEncrypt;
extern DesFunc DesSmallCoreDecrypt;
extern DesFunc DesSmallFipsDecrypt;

extern DesFunc *DesCryptFuncs[2];
extern int des_key_sched(const UINT8 *k, UINT32 *s);
extern int des_ecb_encrypt(const UINT8 *s, UINT8 *d, const UINT32 *r, int e);

#endif /*  DES_H_INCLUDED */
