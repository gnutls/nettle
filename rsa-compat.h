/* rsa-compat.h
 *
 * The RSA publickey algorithm, RSAREF compatible interface.
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
 
#ifndef NETTLE_RSA_COMPAT_H_INCLUDED
#define NETTLE_RSA_COMPAT_H_INCLUDED

         R_SignInit,     computes a digital signature on data of
       R_SignUpdate,       arbitrary length, processing in parts
     and R_SignFinal

       R_VerifyInit,     verifies a digital signature, processing in
     R_VerifyUpdate,       parts
   and R_VerifyFinal

#endif /* NETTLE_RSA_COMPAT_H_INCLUDED */

