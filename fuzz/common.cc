#include "common.h"

#include <mutex>

void fuzz_init(void)
{
    static std::once_flag initialized;

    std::call_once(initialized, []() {
        /*
         * Future:
         *
         * - initialize Nsock
         * - suppress logging
         * - initialize OpenSSL
         * - initialize Lua
         * - etc.
         */
    });
}
