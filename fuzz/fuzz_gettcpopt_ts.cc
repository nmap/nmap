#include "common.h"
#include "../tcpip.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  volatile int ret;
  ret = gettcpopt_ts(data, size, NULL, NULL);
  (void) ret;

  return 0;
}
