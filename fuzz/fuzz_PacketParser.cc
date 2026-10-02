#include "common.h"
#include "../libnetutil/PacketParser.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();

  PacketParser pp;
  PacketElement *pe = NULL;
  pe = pp.split(data, size);

  pp.test_packet_parser(pe);
  pp.freePacketChain(pe);
  return 0;
}
