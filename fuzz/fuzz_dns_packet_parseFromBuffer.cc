#include "common.h"
#include "../libnetutil/massdns.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  DNS::Packet p;
  volatile size_t plen = p.parseFromBuffer(data, size);
  (void) plen;

  return 0;
}
