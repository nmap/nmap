#include <iostream>
#include <string>

#include "../libnetutil/netutil.h"

#define TEST_INCR(pred, acc) \
if (!(pred)) \
{ \
  std::cout << "Test " << #pred << " failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
  ++acc; \
}

static std::string packet_info(const u8 *packet, u32 len)
{
  return ippackethdrinfo(packet, len, LOW_DETAIL);
}

int main()
{
  int ret = 0;

  const u8 ipv4_ipip[] = {
    0x45, 0x00, 0x00, 0x14,
    0x12, 0x34, 0x00, 0x00,
    0x40, 0x04, 0x00, 0x00,
    0xc0, 0x00, 0x02, 0x01,
    0xc6, 0x33, 0x64, 0x02,
  };

  const u8 ipv6_ipip[] = {
    0x60, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x40,
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
  };

  const std::string ipv4_info = packet_info(ipv4_ipip, sizeof(ipv4_ipip));
  const std::string ipv6_info = packet_info(ipv6_ipip, sizeof(ipv6_ipip));

  TEST_INCR(ipv4_info.find("ipv4 (4) 192.0.2.1 > 198.51.100.2") == 0, ret);
  TEST_INCR(ipv4_info.find("IPv6/") == std::string::npos, ret);
  TEST_INCR(ipv6_info.find("IPv6/ipv4 (4) 2001:db8::1 > 2001:db8::2") == 0, ret);

  if (ret)
    std::cout << "Testing packettrace finished with errors" << std::endl;
  else
    std::cout << "Testing packettrace finished without errors" << std::endl;

  return ret;
}
