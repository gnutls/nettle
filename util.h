#ifndef _UTIL_H
#define _UTIL_H

#warning Don't use lib/util.h

/* Bridge from GPG style to lsh style */
#include "lsh_types.h"

/* Report a bug (TODO: do what afterwards? ) */
void log_bug(const char *fmt, ... ) PRINTF_STYLE(1,2);

/* Report an error */
void log_error(const char *fmt, ... ) PRINTF_STYLE(1,2);

/* Report a fatal error and die */
void log_fatal(const char *fmt, ... ) PRINTF_STYLE(1,2) NORETURN;

#ifndef G10ERR_WEAK_KEY
  #define G10ERR_WEAK_KEY 43
#elif G10ERR_WEAK_KEY != 43
  #error G10ERR_WEAK_KEY is defined to a wrong value.
#endif

#endif /* _UTIL_H */
