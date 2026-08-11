#include "common.h"
#include "../libnetutil/massdns.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  DNS::Packet p;
  size_t plen = p.parseFromBuffer(data, size);

  return size >= plen ? 0 : -1;
}
