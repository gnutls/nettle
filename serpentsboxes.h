/* serpentsboxes.h
 *
 * $Id$
 *
 * For more details on this algorithm, see the Serpent website at
 * http://www.cl.cam.ac.uk/~rja14/serpent.html
 */

/* Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* I've modified this code a bit so that it interoperates with lsh
 * properly. 2000-9-5, Rafael R. Sevilla <dido@pacific.net.ph>
 */

/* NOTE: The copyright notice for the original version of this code
 * said "All rights reserved. This code is freely distributed for AES
 * selection process. No other use is allowed." However, the authors
 * later decided to GPL the code. /nisse */
 
#if !defined(SERPENTSBOXES_H)
#define SERPENTSBOXES_H

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */
#define RND00(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t05, t06, t07, t08, t09, t11, t12, t13, t14, t15, t17, t01;\
	t01 = b   ^ c  ; \
	t02 = a   | d  ; \
	t03 = a   ^ b  ; \
	z   = t02 ^ t01; \
	t05 = c   | z  ; \
	t06 = a   ^ d  ; \
	t07 = b   | c  ; \
	t08 = d   & t05; \
	t09 = t03 & t07; \
	y   = t09 ^ t08; \
	t11 = t09 & y  ; \
	t12 = c   ^ d  ; \
	t13 = t07 ^ t11; \
	t14 = b   & t06; \
	t15 = t06 ^ t13; \
	w   =     ~ t15; \
	t17 = w   ^ t14; \
	x   = t12 ^ t17; }

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */
#define InvRND00(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t08, t09, t10, t12, t13, t14, t15, t17, t18, t01;\
	t01 = c   ^ d  ; \
	t02 = a   | b  ; \
	t03 = b   | c  ; \
	t04 = c   & t01; \
	t05 = t02 ^ t01; \
	t06 = a   | t04; \
	y   =     ~ t05; \
	t08 = b   ^ d  ; \
	t09 = t03 & t08; \
	t10 = d   | y  ; \
	x   = t09 ^ t06; \
	t12 = a   | t05; \
	t13 = x   ^ t12; \
	t14 = t03 ^ t10; \
	t15 = a   ^ c  ; \
	z   = t14 ^ t13; \
	t17 = t05 & t13; \
	t18 = t14 | t17; \
	w   = t15 ^ t18; }

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */
#define RND01(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t08, t10, t11, t12, t13, t16, t17, t01;\
	t01 = a   | d  ; \
	t02 = c   ^ d  ; \
	t03 =     ~ b  ; \
	t04 = a   ^ c  ; \
	t05 = a   | t03; \
	t06 = d   & t04; \
	t07 = t01 & t02; \
	t08 = b   | t06; \
	y   = t02 ^ t05; \
	t10 = t07 ^ t08; \
	t11 = t01 ^ t10; \
	t12 = y   ^ t11; \
	t13 = b   & d  ; \
	z   =     ~ t10; \
	x   = t13 ^ t12; \
	t16 = t10 | x  ; \
	t17 = t05 & t16; \
	w   = c   ^ t17; }

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */
#define InvRND01(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t14, t15, t17, t01;\
	t01 = a   ^ b  ; \
	t02 = b   | d  ; \
	t03 = a   & c  ; \
	t04 = c   ^ t02; \
	t05 = a   | t04; \
	t06 = t01 & t05; \
	t07 = d   | t03; \
	t08 = b   ^ t06; \
	t09 = t07 ^ t06; \
	t10 = t04 | t03; \
	t11 = d   & t08; \
	y   =     ~ t09; \
	x   = t10 ^ t11; \
	t14 = a   | y  ; \
	t15 = t06 ^ x  ; \
	z   = t01 ^ t04; \
	t17 = c   ^ t15; \
	w   = t14 ^ t17; }

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */
#define RND02(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t05, t06, t07, t08, t09, t10, t12, t13, t14, t01;\
	t01 = a   | c  ; \
	t02 = a   ^ b  ; \
	t03 = d   ^ t01; \
	w   = t02 ^ t03; \
	t05 = c   ^ w  ; \
	t06 = b   ^ t05; \
	t07 = b   | t05; \
	t08 = t01 & t06; \
	t09 = t03 ^ t07; \
	t10 = t02 | t09; \
	x   = t10 ^ t08; \
	t12 = a   | d  ; \
	t13 = t09 ^ x  ; \
	t14 = b   ^ t13; \
	z   =     ~ t09; \
	y   = t12 ^ t14; }

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */
#define InvRND02(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t06, t07, t08, t09, t10, t11, t12, t15, t16, t17, t01;\
	t01 = a   ^ d  ; \
	t02 = c   ^ d  ; \
	t03 = a   & c  ; \
	t04 = b   | t02; \
	w   = t01 ^ t04; \
	t06 = a   | c  ; \
	t07 = d   | w  ; \
	t08 =     ~ d  ; \
	t09 = b   & t06; \
	t10 = t08 | t03; \
	t11 = b   & t07; \
	t12 = t06 & t02; \
	z   = t09 ^ t10; \
	x   = t12 ^ t11; \
	t15 = c   & z  ; \
	t16 = w   ^ x  ; \
	t17 = t10 ^ t15; \
	y   = t16 ^ t17; }

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */
#define RND03(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t13, t14, t15, t01;\
	t01 = a   ^ c  ; \
	t02 = a   | d  ; \
	t03 = a   & d  ; \
	t04 = t01 & t02; \
	t05 = b   | t03; \
	t06 = a   & b  ; \
	t07 = d   ^ t04; \
	t08 = c   | t06; \
	t09 = b   ^ t07; \
	t10 = d   & t05; \
	t11 = t02 ^ t10; \
	z   = t08 ^ t09; \
	t13 = d   | z  ; \
	t14 = a   | t07; \
	t15 = b   & t13; \
	y   = t08 ^ t11; \
	w   = t14 ^ t15; \
	x   = t05 ^ t04; }

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */
#define InvRND03(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t09, t11, t12, t13, t14, t16, t01;\
	t01 = c   | d  ; \
	t02 = a   | d  ; \
	t03 = c   ^ t02; \
	t04 = b   ^ t02; \
	t05 = a   ^ d  ; \
	t06 = t04 & t03; \
	t07 = b   & t01; \
	y   = t05 ^ t06; \
	t09 = a   ^ t03; \
	w   = t07 ^ t03; \
	t11 = w   | t05; \
	t12 = t09 & t11; \
	t13 = a   & y  ; \
	t14 = t01 ^ t05; \
	x   = b   ^ t12; \
	t16 = b   | t13; \
	z   = t14 ^ t16; }

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */
#define RND04(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t08, t09, t10, t11, t12, t13, t14, t15, t16, t01;\
	t01 = a   | b  ; \
	t02 = b   | c  ; \
	t03 = a   ^ t02; \
	t04 = b   ^ d  ; \
	t05 = d   | t03; \
	t06 = d   & t01; \
	z   = t03 ^ t06; \
	t08 = z   & t04; \
	t09 = t04 & t05; \
	t10 = c   ^ t06; \
	t11 = b   & c  ; \
	t12 = t04 ^ t08; \
	t13 = t11 | t03; \
	t14 = t10 ^ t09; \
	t15 = a   & t05; \
	t16 = t11 | t12; \
	y   = t13 ^ t08; \
	x   = t15 ^ t16; \
	w   =     ~ t14; }

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */
#define InvRND04(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t09, t10, t11, t12, t13, t15, t01;\
	t01 = b   | d  ; \
	t02 = c   | d  ; \
	t03 = a   & t01; \
	t04 = b   ^ t02; \
	t05 = c   ^ d  ; \
	t06 =     ~ t03; \
	t07 = a   & t04; \
	x   = t05 ^ t07; \
	t09 = x   | t06; \
	t10 = a   ^ t07; \
	t11 = t01 ^ t09; \
	t12 = d   ^ t04; \
	t13 = c   | t10; \
	z   = t03 ^ t12; \
	t15 = a   ^ t04; \
	y   = t11 ^ t13; \
	w   = t15 ^ t09; }

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */
#define RND05(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t14, t01;\
	t01 = b   ^ d  ; \
	t02 = b   | d  ; \
	t03 = a   & t01; \
	t04 = c   ^ t02; \
	t05 = t03 ^ t04; \
	w   =     ~ t05; \
	t07 = a   ^ t01; \
	t08 = d   | w  ; \
	t09 = b   | t05; \
	t10 = d   ^ t08; \
	t11 = b   | t07; \
	t12 = t03 | w  ; \
	t13 = t07 | t10; \
	t14 = t01 ^ t11; \
	y   = t09 ^ t13; \
	x   = t07 ^ t08; \
	z   = t12 ^ t14; }

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */
#define InvRND05(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t07, t08, t09, t10, t12, t13, t15, t16, t01;\
	t01 = a   & d  ; \
	t02 = c   ^ t01; \
	t03 = a   ^ d  ; \
	t04 = b   & t02; \
	t05 = a   & c  ; \
	w   = t03 ^ t04; \
	t07 = a   & w  ; \
	t08 = t01 ^ w  ; \
	t09 = b   | t05; \
	t10 =     ~ b  ; \
	x   = t08 ^ t09; \
	t12 = t10 | t07; \
	t13 = w   | x  ; \
	z   = t02 ^ t12; \
	t15 = t02 ^ t13; \
	t16 = b   ^ d  ; \
	y   = t16 ^ t15; }

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */
#define RND06(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t15, t17, t18, t01;\
	t01 = a   & d  ; \
	t02 = b   ^ c  ; \
	t03 = a   ^ d  ; \
	t04 = t01 ^ t02; \
	t05 = b   | c  ; \
	x   =     ~ t04; \
	t07 = t03 & t05; \
	t08 = b   & x  ; \
	t09 = a   | c  ; \
	t10 = t07 ^ t08; \
	t11 = b   | d  ; \
	t12 = c   ^ t11; \
	t13 = t09 ^ t10; \
	y   =     ~ t13; \
	t15 = x   & t03; \
	z   = t12 ^ t07; \
	t17 = a   ^ b  ; \
	t18 = y   ^ t15; \
	w   = t17 ^ t18; }

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */
#define InvRND06(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t07, t08, t09, t12, t13, t14, t15, t16, t17, t01;\
	t01 = a   ^ c  ; \
	t02 =     ~ c  ; \
	t03 = b   & t01; \
	t04 = b   | t02; \
	t05 = d   | t03; \
	t06 = b   ^ d  ; \
	t07 = a   & t04; \
	t08 = a   | t02; \
	t09 = t07 ^ t05; \
	x   = t06 ^ t08; \
	w   =     ~ t09; \
	t12 = b   & w  ; \
	t13 = t01 & t05; \
	t14 = t01 ^ t12; \
	t15 = t07 ^ t13; \
	t16 = d   | t02; \
	t17 = a   ^ x  ; \
	z   = t17 ^ t15; \
	y   = t16 ^ t14; }

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */
#define RND07(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t05, t06, t08, t09, t10, t11, t13, t14, t15, t16, t17, t01;\
	t01 = a   & c  ; \
	t02 =     ~ d  ; \
	t03 = a   & t02; \
	t04 = b   | t01; \
	t05 = a   & b  ; \
	t06 = c   ^ t04; \
	z   = t03 ^ t06; \
	t08 = c   | z  ; \
	t09 = d   | t05; \
	t10 = a   ^ t08; \
	t11 = t04 & z  ; \
	x   = t09 ^ t10; \
	t13 = b   ^ x  ; \
	t14 = t01 ^ x  ; \
	t15 = c   ^ t05; \
	t16 = t11 | t13; \
	t17 = t02 | t14; \
	w   = t15 ^ t17; \
	y   = a   ^ t16; }

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */
#define InvRND07(a,b,c,d,w,x,y,z) \
	{ register UINT32 t02, t03, t04, t06, t07, t08, t09, t10, t11, t13, t14, t15, t16, t01;\
	t01 = a   & b  ; \
	t02 = a   | b  ; \
	t03 = c   | t01; \
	t04 = d   & t02; \
	z   = t03 ^ t04; \
	t06 = b   ^ t04; \
	t07 = d   ^ z  ; \
	t08 =     ~ t07; \
	t09 = t06 | t08; \
	t10 = b   ^ d  ; \
	t11 = a   | d  ; \
	x   = a   ^ t09; \
	t13 = c   ^ t06; \
	t14 = c   & t11; \
	t15 = d   | x  ; \
	t16 = t01 | t10; \
	w   = t13 ^ t15; \
	y   = t14 ^ t16; }

#define RND08(a,b,c,d,e,f,g,h) RND00(a,b,c,d,e,f,g,h)
#define RND09(a,b,c,d,e,f,g,h) RND01(a,b,c,d,e,f,g,h)
#define RND10(a,b,c,d,e,f,g,h) RND02(a,b,c,d,e,f,g,h)
#define RND11(a,b,c,d,e,f,g,h) RND03(a,b,c,d,e,f,g,h)
#define RND12(a,b,c,d,e,f,g,h) RND04(a,b,c,d,e,f,g,h)
#define RND13(a,b,c,d,e,f,g,h) RND05(a,b,c,d,e,f,g,h)
#define RND14(a,b,c,d,e,f,g,h) RND06(a,b,c,d,e,f,g,h)
#define RND15(a,b,c,d,e,f,g,h) RND07(a,b,c,d,e,f,g,h)
#define RND16(a,b,c,d,e,f,g,h) RND00(a,b,c,d,e,f,g,h)
#define RND17(a,b,c,d,e,f,g,h) RND01(a,b,c,d,e,f,g,h)
#define RND18(a,b,c,d,e,f,g,h) RND02(a,b,c,d,e,f,g,h)
#define RND19(a,b,c,d,e,f,g,h) RND03(a,b,c,d,e,f,g,h)
#define RND20(a,b,c,d,e,f,g,h) RND04(a,b,c,d,e,f,g,h)
#define RND21(a,b,c,d,e,f,g,h) RND05(a,b,c,d,e,f,g,h)
#define RND22(a,b,c,d,e,f,g,h) RND06(a,b,c,d,e,f,g,h)
#define RND23(a,b,c,d,e,f,g,h) RND07(a,b,c,d,e,f,g,h)
#define RND24(a,b,c,d,e,f,g,h) RND00(a,b,c,d,e,f,g,h)
#define RND25(a,b,c,d,e,f,g,h) RND01(a,b,c,d,e,f,g,h)
#define RND26(a,b,c,d,e,f,g,h) RND02(a,b,c,d,e,f,g,h)
#define RND27(a,b,c,d,e,f,g,h) RND03(a,b,c,d,e,f,g,h)
#define RND28(a,b,c,d,e,f,g,h) RND04(a,b,c,d,e,f,g,h)
#define RND29(a,b,c,d,e,f,g,h) RND05(a,b,c,d,e,f,g,h)
#define RND30(a,b,c,d,e,f,g,h) RND06(a,b,c,d,e,f,g,h)
#define RND31(a,b,c,d,e,f,g,h) RND07(a,b,c,d,e,f,g,h)

#define InvRND08(a,b,c,d,e,f,g,h) InvRND00(a,b,c,d,e,f,g,h)
#define InvRND09(a,b,c,d,e,f,g,h) InvRND01(a,b,c,d,e,f,g,h)
#define InvRND10(a,b,c,d,e,f,g,h) InvRND02(a,b,c,d,e,f,g,h)
#define InvRND11(a,b,c,d,e,f,g,h) InvRND03(a,b,c,d,e,f,g,h)
#define InvRND12(a,b,c,d,e,f,g,h) InvRND04(a,b,c,d,e,f,g,h)
#define InvRND13(a,b,c,d,e,f,g,h) InvRND05(a,b,c,d,e,f,g,h)
#define InvRND14(a,b,c,d,e,f,g,h) InvRND06(a,b,c,d,e,f,g,h)
#define InvRND15(a,b,c,d,e,f,g,h) InvRND07(a,b,c,d,e,f,g,h)
#define InvRND16(a,b,c,d,e,f,g,h) InvRND00(a,b,c,d,e,f,g,h)
#define InvRND17(a,b,c,d,e,f,g,h) InvRND01(a,b,c,d,e,f,g,h)
#define InvRND18(a,b,c,d,e,f,g,h) InvRND02(a,b,c,d,e,f,g,h)
#define InvRND19(a,b,c,d,e,f,g,h) InvRND03(a,b,c,d,e,f,g,h)
#define InvRND20(a,b,c,d,e,f,g,h) InvRND04(a,b,c,d,e,f,g,h)
#define InvRND21(a,b,c,d,e,f,g,h) InvRND05(a,b,c,d,e,f,g,h)
#define InvRND22(a,b,c,d,e,f,g,h) InvRND06(a,b,c,d,e,f,g,h)
#define InvRND23(a,b,c,d,e,f,g,h) InvRND07(a,b,c,d,e,f,g,h)
#define InvRND24(a,b,c,d,e,f,g,h) InvRND00(a,b,c,d,e,f,g,h)
#define InvRND25(a,b,c,d,e,f,g,h) InvRND01(a,b,c,d,e,f,g,h)
#define InvRND26(a,b,c,d,e,f,g,h) InvRND02(a,b,c,d,e,f,g,h)
#define InvRND27(a,b,c,d,e,f,g,h) InvRND03(a,b,c,d,e,f,g,h)
#define InvRND28(a,b,c,d,e,f,g,h) InvRND04(a,b,c,d,e,f,g,h)
#define InvRND29(a,b,c,d,e,f,g,h) InvRND05(a,b,c,d,e,f,g,h)
#define InvRND30(a,b,c,d,e,f,g,h) InvRND06(a,b,c,d,e,f,g,h)
#define InvRND31(a,b,c,d,e,f,g,h) InvRND07(a,b,c,d,e,f,g,h)

/* Linear transformations and key mixing: */

#define ROL(x,n) ((((UINT32)(x))<<(n))| \
                  (((UINT32)(x))>>(32-(n))))
#define ROR(x,n) ((((UINT32)(x))<<(32-(n)))| \
                  (((UINT32)(x))>>(n)))

#define transform(x0, x1, x2, x3, y0, y1, y2, y3) \
      y0 = ROL(x0, 13); \
      y2 = ROL(x2, 3); \
      y1 = x1 ^ y0 ^ y2; \
      y3 = x3 ^ y2 ^ ((UINT32)y0)<<3; \
      y1 = ROL(y1, 1); \
      y3 = ROL(y3, 7); \
      y0 = y0 ^ y1 ^ y3; \
      y2 = y2 ^ y3 ^ ((UINT32)y1<<7); \
      y0 = ROL(y0, 5); \
      y2 = ROL(y2, 22)

#define inv_transform(x0, x1, x2, x3, y0, y1, y2, y3) \
      y2 = ROR(x2, 22);\
      y0 = ROR(x0, 5); \
      y2 = y2 ^ x3 ^ ((UINT32)x1<<7); \
      y0 = y0 ^ x1 ^ x3; \
      y3 = ROR(x3, 7); \
      y1 = ROR(x1, 1); \
      y3 = y3 ^ y2 ^ ((UINT32)y0)<<3; \
      y1 = y1 ^ y0 ^ y2; \
      y2 = ROR(y2, 3); \
      y0 = ROR(y0, 13)

#define keying(x0, x1, x2, x3, subkey) \
                         x0^=subkey[0];x1^=subkey[1]; \
                         x2^=subkey[2];x3^=subkey[3]

/* PHI: Constant used in the key schedule */
#define PHI 0x9e3779b9L

#endif /* SERPENTSBOXES_H */
