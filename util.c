#include "util.h"

#include <stdarg.h>	/* For the va_* stuff */
#include <stdlib.h>	/* For EXIT_FAILURE */
#include "../werror.h"

void log_bug(const char *format, ... ) {
	va_list args;
	  
	va_start(args, format);
	werror(format, args);
	va_end(args);
}

void log_error(const char *format, ... ) {
	va_list args;
	  
	va_start(args, format);
	werror(format, args);
	va_end(args);
}

void log_fatal(const char *format, ... ) {
	va_list args;
	  
	va_start(args, format);
	log_error(format, args);
	va_end(args);
	
	exit(EXIT_FAILURE);
}
