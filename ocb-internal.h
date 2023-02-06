/* ocb-internal.c

   Copyright (C) 2023 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#ifndef NETTLE_OCB_INTERNAL_H_INCLUDED
#define NETTLE_OCB_INTERNAL_H_INCLUDED

#include "ocb.h"

#define OCB_NONCE_SIZE 12

struct ocb_aes128_ctx
{
  struct ocb_ctx ocb;
  struct ocb_aes128_encrypt_key key;
  struct aes128_ctx decrypt;
};

#endif /*NETTLE_OCB_INTERNAL_H_INCLUDED */
