#include "common.h"

void fuzz_init(void)
{
    static int initialized = 0;

    if (!initialized) {
      initialized = 1;
        /*
         * Future:
         *
         * - initialize Nsock
         * - suppress logging
         * - initialize OpenSSL
         * - initialize Lua
         * - etc.
         */
    }
}
