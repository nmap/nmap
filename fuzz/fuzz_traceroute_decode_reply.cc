#include "common.h"
#include "../traceroute.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  static volatile bool ret;
  ret = fuzz_decode_reply(data, size);
  (void) ret;

  return 0;
}
