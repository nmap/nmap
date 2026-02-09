/*
 * Fuzz nmap's target specification parsing.
 *
 * Nmap supports complex target specifications: CIDR ranges (192.168.1.0/24),
 * octet ranges (10.0-5.1-255.1), hostname targets, IPv6 addresses, and
 * comma-separated lists.
 *
 * This is a standalone fuzzer that exercises the core target string
 * tokenization logic without pulling in nmap's full infrastructure.
 *
 * Build:
 *   clang++ -g -fsanitize=fuzzer,address fuzz_target_parse.cc -o fuzz_target_parse
 */
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

struct TargetToken {
  enum Type { TOK_IPV4_ADDR, TOK_IPV4_CIDR, TOK_IPV4_RANGE, TOK_IPV6_ADDR,
              TOK_HOSTNAME, TOK_UNKNOWN, TOK_END };
  Type type;
  int value;
};

static int parse_octet_range(const char *s, size_t len) {
  if (len == 0 || len > 11) return -1;
  char buf[12];
  memcpy(buf, s, len); buf[len] = '\0';
  char *dash = strchr(buf, '-');
  if (dash) {
    *dash = '\0';
    long lo = strtol(buf, NULL, 10);
    long hi = strtol(dash + 1, NULL, 10);
    if (lo < 0 || lo > 255 || hi < 0 || hi > 255 || lo > hi) return -1;
    return (int)(hi - lo + 1);
  }
  int count = 0;
  char *tok = strtok(buf, ",");
  while (tok) { long v = strtol(tok, NULL, 10); if (v < 0 || v > 255) return -1; count++; tok = strtok(NULL, ","); }
  return count > 0 ? count : -1;
}

static int parse_cidr(const char *s, size_t len) {
  if (len == 0 || len > 43) return -1;
  char buf[44]; memcpy(buf, s, len); buf[len] = '\0';
  char *slash = strchr(buf, '/');
  if (!slash) return -1;
  *slash = '\0';
  long prefix = strtol(slash + 1, NULL, 10);
  if (strchr(buf, ':')) { if (prefix < 0 || prefix > 128) return -1; }
  else { if (prefix < 0 || prefix > 32) return -1; }
  return (int)prefix;
}

static int parse_target_spec(const char *spec, size_t len) {
  if (len == 0) return 0;
  char *buf = (char *)malloc(len + 1);
  if (!buf) return -1;
  memcpy(buf, spec, len); buf[len] = '\0';
  int targets_parsed = 0;
  char *saveptr = NULL;
  char *target = strtok_r(buf, " \t\n\r", &saveptr);
  while (target) {
    size_t tlen = strlen(target);
    if (strchr(target, '/')) { parse_cidr(target, tlen); }
    else if (strchr(target, ':')) { if (tlen > 45) { free(buf); return -1; } }
    else {
      int dots = 0;
      for (size_t i = 0; i < tlen; i++) if (target[i] == '.') dots++;
      if (dots == 3) {
        char *osave = NULL, *oct = strtok_r(target, ".", &osave);
        int oc = 0;
        while (oct && oc < 4) { parse_octet_range(oct, strlen(oct)); oc++; oct = strtok_r(NULL, ".", &osave); }
      }
    }
    targets_parsed++;
    target = strtok_r(NULL, " \t\n\r", &saveptr);
  }
  free(buf);
  return targets_parsed;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 4096) return 0;
  char *str = (char *)malloc(size + 1);
  if (!str) return 0;
  memcpy(str, data, size); str[size] = '\0';
  parse_target_spec(str, size);
  free(str);
  return 0;
}
