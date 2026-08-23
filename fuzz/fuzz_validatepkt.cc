#include "common.h"
#include "../tcpip.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();
  unsigned int len = size;

  volatile bool v = validatepkt(data, &len);
  (void) v;
  return 0;
}
