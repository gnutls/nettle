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

/* FIXME: Reorganize the header files for definitions. This stuff
 * should probably live in lsh_types.h, and object definitions should
 * move into a separate header file.
 *
 * FIXME: some of the crypto implementations could well use the
 * READ_UINT32 and WRITE_UINT32 macros. */

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

#ifdef __GNUC__
#define NORETURN __attribute__ ((noreturn))
#define PRINTF_STYLE(f, a) __attribute__ ((format(printf, f, a)))
#define UNUSED __attribute__ ((unused))
#else
#define NORETURN
#define PRINTF_STYLE(f, a)
#define UNUSED
#endif

#endif /* CRYPTO_TYPES_H_INCLUDED */
