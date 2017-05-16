/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Functions for the HKDF handling.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
/* Needed for alloca on freebsd */
#include <stdlib.h>
#include <string.h>

#include "hmac.h"

#include "memxor.h"
#include "nettle-internal.h"
#include "hkdf.h"

/* hkdf_extract: Outputs a PRK of digest_size
 */
void
hkdf_extract(void *mac_ctx,
	     nettle_hash_update_func *update,
	     nettle_hash_digest_func *digest,
	     size_t digest_size,
	     size_t secret_size, const uint8_t *secret,
	     uint8_t *dst)
{
	update(mac_ctx, secret_size, secret);
	digest(mac_ctx, digest_size, dst);
}

/* hkdf_expand: Outputs an arbitrary key of size specified by length
 */
void
hkdf_expand(void *mac_ctx,
	     nettle_hash_update_func *update,
	     nettle_hash_digest_func *digest,
	     size_t digest_size,
	     size_t info_size, const uint8_t *info,
	     size_t length, uint8_t *dst)
{
	uint8_t i = 1;
	ssize_t left = length;

	if (!left)
		return;

	for (;; dst += digest_size, left -= digest_size, i++) {
		update(mac_ctx, info_size, info);
		update(mac_ctx, 1, &i);
		if (left <= digest_size) {
			if (left > 0)
				digest(mac_ctx, left, dst);
			return;
		}

		digest(mac_ctx, digest_size, dst);
		update(mac_ctx, digest_size, dst);
	}

	return;
}
