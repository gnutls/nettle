/* $Id$
 *
 * Defines the types UINT32, UINT16 and UINT8 */

#ifndef CRYPTO_TYPES_H_INCLUDED
#define CRYPTO_TYPES_H_INCLUDED

#ifdef PIKE
# include "pike_types.h"
# include "global.h"
# define UINT32 unsigned INT32
# define UINT16 unsigned INT16
# define UINT8 unsigned INT8
#else  /* !PIKE */

# ifdef LSH
#  ifdef HAVE_CONFIG_H
#   include "config.h"
#  endif
#  if SIZEOF_SHORT >= 4
#   define UINT32 unsigned short
#  elif SIZEOF_INT >= 4
#   define UINT32 unsigned int
#  elif SIZEOF_LONG >= 4
#   define UINT32 unsigned long
#  else
#   error No suitable type found to use for UINT32
#  endif /* UINT32 */

#  if SIZEOF_SHORT >= 2
#   define UINT16 unsigned short
#  elif SIZEOF_INT >= 2
#   define UINT16 unsigned int
#  else
#   error No suitable type found to use for UINT16
#  endif  /* UINT16 */

#  define UINT8 unsigned char

# else /* !LSH */
#  define UINT32 unsigned long
#  define UINT16 unsigned short
#  define UINT8 unsigned char
# endif /* !PIKE */
#endif

#endif /* CRYPTO_TYPES_H_INCLUDED */
