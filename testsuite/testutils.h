#ifndef NETTLE_TESTUTILS_H_INCLUDED
#define NETTLE_TESTUTILS_H_INCLUDED

#include <inttypes.h>

/* Decodes a NUL-terminated hex string. */
int
decode_hex(uint8_t *dst, const char *hex);

/* Allocates space */
const uint8_t *
decode_hex_dup(const char *hex);


#endif /* NETTLE_TESTUTILS_H_INCLUDED */
