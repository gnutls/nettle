/* gcm-internal.h

   Copyright (C) 2020 Niels Möller

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

#ifndef NETTLE_GCM_INTERNAL_H_INCLUDED
#define NETTLE_GCM_INTERNAL_H_INCLUDED

/* Arrange so that _gcm_hash is an alias for the right implementation. */
#if HAVE_NATIVE_gcm_hash || HAVE_NATIVE_fat_gcm_hash
# define _gcm_hash _nettle_gcm_hash
#elif HAVE_NATIVE_gcm_hash8
# define _gcm_hash _nettle_gcm_hash8
#else
# define _gcm_hash _nettle_gcm_hash_c
#endif

/* Declare all variants, if defined depends on configuration. */
void
_nettle_gcm_set_key (struct gcm_key *gcm, const uint8_t *key);

void
_nettle_gcm_hash(const struct gcm_key *key, union nettle_block16 *x,
		 size_t length, const uint8_t *data);

void
_nettle_gcm_hash8(const struct gcm_key *key, union nettle_block16 *x,
		  size_t length, const uint8_t *data);

void
_nettle_gcm_hash_c(const struct gcm_key *key, union nettle_block16 *x,
		  size_t length, const uint8_t *data);

void
_nettle_gcm_init_key (union nettle_block16 *table);

#if HAVE_NATIVE_fat_gcm_init_key
void
_nettle_gcm_init_key_c (union nettle_block16 *table);
#endif

#endif /* NETTLE_GCM_INTERNAL_H_INCLUDED */
