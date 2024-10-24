#include "../libnetutil/PacketParser.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(1000)) {
		int len = __AFL_FUZZ_TESTCASE_LEN;
		if (len < 1) continue;

		PacketElement *p = PacketParser::split(buf, len, true /*eth_included*/);
		PacketParser::freePacketChain(p);
	}

	return 0;
}
