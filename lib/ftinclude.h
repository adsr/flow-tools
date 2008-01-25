#ifndef FTINCLUDE_H
#define FTINCLUDE_H 1

#include "ftconfig.h"

#if HAVE_INTTYPES_H
#  include <inttypes.h> /* C99 uint8_t uint16_t uint32_t uint64_t */
#elif HAVE_STDINT_H
#  include <stdint.h> /* or here */
#endif /* else commit suicide. later */

#if HAVE_STRINGS_H
#  include <strings.h>
#endif

#if HAVE_STRING_H
#  include <string.h>
#endif

#endif
