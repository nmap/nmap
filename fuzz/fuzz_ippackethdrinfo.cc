#include "common.h"
#include "../libnetutil/netutil.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  const int levels[] = {
    LOW_DETAIL,
    MEDIUM_DETAIL,
    HIGH_DETAIL
  };
  const char *buf = NULL;
  static volatile size_t len = 0;
  for (int i = 0; i < sizeof(levels)/sizeof(levels[0]); i++) {
    buf = ippackethdrinfo(data, size, levels[i]);
    len = strlen(buf);
    if (strncmp(buf, "BOGUS", 5) == 0)
      return -1;
  }

  return 0;
}
