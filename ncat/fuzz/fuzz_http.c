#include "common.h"
#include "../http.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_init();
  char *buf = malloc(size + 1);
  if (!buf)
    return -1;
  memcpy(buf, data, size);
  buf[size] = '\0';
  struct http_request req = {};
  struct http_response resp = {};
  struct http_header *hdr = NULL;
  char *out = NULL;
  size_t n = 0;

  http_request_init(&req);
  int r = http_parse_request_line(buf, &req);
  if (r == 0) {
    out = http_request_to_string(&req, &n);
    free(out);
    http_request_free(&req);
    free(buf);
    return 0;
  }
  http_request_free(&req);

  http_response_init(&resp);
  r = http_parse_status_line(buf, &resp);
  if (r == 0) {
    out = http_response_to_string(&resp, &n);
    free(out);
    http_response_free(&resp);
    free(buf);
    return 0;
  }
  http_response_free(&resp);

  r = http_parse_header(&hdr, buf);
  if (r == 0) {
    for (struct http_header *h = hdr; h != NULL; h = h->next) {
      out = http_header_to_string(h, &n);
      free(out);
    }
    http_header_free(hdr);
    free(buf);
    return 0;
  }
  if (hdr != NULL) {
    http_header_free(hdr);
  }

  free(buf);
  return -1;
}
