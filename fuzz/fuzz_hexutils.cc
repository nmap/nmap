#include "common.h"
#include "../output.h"
#include "../utils.h"

#include <stddef.h>
#include <stdint.h>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();
  unsigned int newlen = 0;
  char *cbuf = new char[size + 1];
  memcpy(cbuf, data, size);
  cbuf[size] = '\0';
  char *cdata = cstring_unescape(cbuf, &newlen);
  int bufsize = newlen * 4 + newlen / 8 + 1;
  char *buf = new char[bufsize];

  bintohexstr(buf, bufsize, cdata, (int)newlen);
  size_t phs_len = 0;
  u8 *phs_buf = parse_hex_string(buf, &phs_len);
  if (phs_buf != NULL) {
    volatile std::string safe = protect_xml(std::string((char *)phs_buf, phs_len));
    (void) safe;
  }

  delete[] buf;
  delete[] cbuf;
  return 0;
}
