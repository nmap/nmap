#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include "../utils.h"
#include "../output.h"

struct unescape_test {
  const char *src;
  const char *result;
  unsigned int len;
  bool valid;
};
// All chars except '\0' and '\\'
static const char allchars[] =
  "\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
  "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`"
  "abcdefghijklmnopqrstuvwxyz{|}~\x7f"
  "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
  "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
  "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
  "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
  "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
  "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
static const char *escaped_allchars = strdup(protect_xml(allchars).c_str());
const struct unescape_test tests[] = {
  {"", "", 0, true},
  {"test", "test", 4, true},
  {"\\0\\n\\r\\t\\x33\\\\", "\0\n\r\t3\\", 6, true},
  {"test\\0", "test\0", 5, true},
  {"\\0test", "\0test", 5, true},
  {"test\\0more", "test\0more", 9, true},
  {"\\012", "\0""12", 3, true},
  {"\x20test", " test", 5, true},
  {"\\r\\ntest", "\r\ntest", 6, true},
  {"\\", "", 0, false},
  {"test\\", "", 0, false},
  {"\\\\n", "\\n", 2, true},
  {"\\\\x41", "\\x41", 4, true},
  {"\\\\\\x41", "\\A", 2, true},
  {"\\a", "", 0, false},
  {"\\b", "", 0, false},
  {"\\\xff", "", 0, false},
  {"\xff\b", "\xff\b", 2, true},
  {"\\x0041", "\0""41", 3, true},
  {"\\xFe", "\xfe", 1, true},
  {"\\xeD", "\xed", 1, true},
  {"\\x0g", "", 0, false},
  {"\\x", "", 0, false},
  {"\\xn", "", 0, false},
  {"\\xF", "", 0, false},
  {"\\xFn", "", 0, false},
  {"\\xFFFF", "\xff""FF", 3, true},
  {"\\x\\0", "", 0, false},
  {"\\xF\\0", "", 0, false},
  {allchars, allchars, sizeof(allchars) - 1, true},
  {escaped_allchars, allchars, sizeof(allchars) - 1, true},
};

int main(int argc, char **argv)
{
  size_t num_tests = sizeof(tests) / sizeof(unescape_test);
  size_t num_fail = 0;
  size_t num_run = 0;
  for (size_t i=0; i < num_tests; i++) {
    const unescape_test &test = tests[i];
    char *src = strdup(test.src);
    if (!src)
      exit(1);
    unsigned int len = 0;
    std::cout << i << '\r';
    num_run++;
    if (cstring_unescape(src, &len)) {
      if (!test.valid) {
        std::cout << "FAIL test " << i << ": " << test.src <<
          "not rejected" << std::endl;
        num_fail++;
      }
      else if ( len != test.len) {
        std::cout << "FAIL test " << i << " length: expected " << test.len <<
          " but got " << len << std::endl;
        num_fail++;
      }
      else {
        int r = memcmp(src, test.result, test.len);
        if (r != 0) {
          std::cout << "FAIL test " << i << ": memcmp returned " << r << std::endl;
          num_fail++;
        }
      }
    }
    else if (test.valid) {
      std::cout << "FAIL test " << i << ": " << test.src <<
        "rejected" << std::endl;
      num_fail++;
    }
    free(src);
  }
  std::cout << "Ran " << num_run << " tests. " << num_fail << " failures." << std::endl;
  return num_fail;
}
