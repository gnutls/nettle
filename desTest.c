/* desTest.c
 *
 * Exercise the DES routines and collect performance statistics.
 *
 * $ID:$ */

/*	des - fast & portable DES encryption & decryption.
 *	Copyright (C) 1992  Dana L. How
 *	Please see the file `descore.README' for the complete copyright notice.
 */

#ifndef	lint
char desTest_cRcs[] = "$Id$";
#endif

#include "des.h"
#include <stdio.h>

#if 0
/* define now(w) to be the elapsed time in hundredths of a second */

#ifndef __NT__
# include	<sys/time.h>
# include	<sys/resource.h>
# include	<unistd.h>

/* extern getrusage(); */
static struct rusage usage;
# define	now(w)	(				\
		getrusage(RUSAGE_SELF, &usage),		\
		usage.ru_utime.tv_sec  * 100 +		\
		usage.ru_utime.tv_usec / 10000		\
	)
#else
# include       <windows.h>
# define now(w) 0
#endif
#endif /* 0 */
     
/* test data
 * the tests (key0-3, text0-3) are cribbed from code which is (c) 1988 MIT
 */

UINT8 keyt[8]  = {0x5d, 0x85, 0x91, 0x73, 0xcb, 0x49, 0xdf, 0x2f};
UINT8 key0[8]  = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80};
UINT8 key1[8]  = {0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
UINT8 key2[8]  = {0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f};
UINT8 key3[8]  = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
UINT8 textt[8] = {0x67, 0x1f, 0xc8, 0x93, 0x46, 0x5e, 0xab, 0x1e};
UINT8 text0[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
UINT8 text1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40};
UINT8 text2[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
UINT8 text3[8] = {'N',  'o',  'w',  ' ',  'i',  's',  ' ',  't' };

/* work areas */

DesKeys keys;
UINT8 cipher[8], output[8];

/* noisy interfaces to the routines under test */

static void method(const UINT8 *key)
{
	int j;

	printf("\nkey:\t");
	for ( j = 0; j < 8; j++ )
		printf("%02X ", key[j]);
	if ( des_key_sched(key, keys) )
		printf("W");
	printf("\t");
}

static void
encode(const UINT8 *src, UINT8 *dst)
{
	int j;

	printf("clear:\t");
	for (j = 0; j < 8; j++)
		printf("%02X ", src[j]);

	des_ecb_encrypt(src, dst, keys, 1);

	printf("\tcipher:\t");
	for (j = 0; j < 8; j++)
		printf("%02X ", dst[j]);
	printf("\n");
}

static void
decode(const UINT8 *src, UINT8 *dst, const UINT8 *check)
{
	int j;

	printf("cipher:\t");
	for (j = 0; j < 8; j++)
		printf("%02X ", src[j]);

	des_ecb_encrypt(src, dst, keys, 0);

	printf("\tclear:\t");
	for (j = 0; j < 8; j++)
		printf("%02X ", dst[j]);

        if(!memcmp(dst,check,8))
           printf("Ok\n");
        else
           printf("FAIL\n");
}

/* run the tests */

int
main(int argc UNUSED, char **argv UNUSED)
{
	int j, n;
#if 0
	int m, e;
#endif
	DesFunc *f;
	static char * expect[] = {
		"57 99 F7 2A D2 3F AE 4C", "9C C6 2D F4 3B 6E ED 74",
		"90 E6 96 A2 AD 56 50 0D", "A3 80 E0 2A 6B E5 46 96",
		"43 5C FF C5 68 B3 70 1D", "25 DD AC 3E 96 17 64 67",
		"80 B5 07 E1 E6 A7 47 3D", "3F A4 0E 8A 98 4D 48 15",
	};

	static DesFunc *funcs[] = {
	  DesQuickCoreEncrypt, DesQuickFipsEncrypt,
	  DesSmallCoreEncrypt, DesSmallFipsEncrypt,
	  DesQuickCoreDecrypt, DesQuickFipsDecrypt,
	  DesSmallCoreDecrypt, DesSmallFipsDecrypt };
#if 0
	static char * names[] = {
	  "QuickCore", "QuickFips",
	  "SmallCore", "SmallFips" };
#endif
	n = 0;
	DesQuickInit();

	/* do timing info first */

	j = 10000;
#if 0
	m = now(0);
#endif
	do
		DesMethod(keys, keyt);
	while ( --j );
#if 0
	m = now(1) - m;
#endif
	do {
		    DesCryptFuncs[0] = funcs[n+4];
		f = DesCryptFuncs[1] = funcs[n  ];
		j = 100000;
#if 0
		e = now(0);
#endif
		do
			(*f)(cipher, keys, textt);
		while ( --j );
#if 0
		e = now(1) - e;
		printf(	"%s:  setkey,%5duS;  encode,%3d.%1duS.\n",
			names[n], m , e/10, e%10);
#endif
		/* now check functionality */

		method(key0);
		printf("cipher?\t%s\n", expect[(n % 2) + 0]);
		encode(text0, cipher);
		decode(cipher, output, text0);

		method(key1);
		printf("cipher?\t%s\n", expect[(n % 2) + 2]);
		encode(text1, cipher);
		decode(cipher, output, text1);

		method(key2);
		printf("cipher?\t%s\n", expect[(n % 2) + 4]);
		encode(text2, cipher);
		decode(cipher, output, text2);

		method(key3);
		printf("cipher?\t%s\n", expect[(n % 2) + 6]);
		encode(text3, cipher);
		decode(cipher, output, text3);

		printf("%c", "\n\f\n\0"[n]);

	} while ( ++n < 4 );

	DesQuickDone();
	return 0;
}
