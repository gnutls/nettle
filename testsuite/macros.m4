m4_dnl nettle testsuite driver
m4_changecom(/*, */)m4_dnl
m4_dnl End of the C code
m4_divert(1)m4_dnl
  /* Avoid warnings for argc and argv unused */
  (void) argc; (void) argv;
  return 0;
}
m4_divert
m4_define(`BEGIN_TEST',
`
m4_dnl Start of the C code.
#include "testutils.h"

#include <string.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
')m4_dnl
m4_define(`H', `m4_ifelse(`$#',1,
			  `decode_hex_dup($1)',
			  `decode_hex($1, $2)')')m4_dnl
m4_define(`MEMEQ', `(!memcmp ($2, $3, $1))')m4_dnl
m4_define(`FAIL', `abort()')m4_dnl


