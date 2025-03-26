#ifndef REVERSE_DNS_H
#define REVERSE_DNS_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// Perform reverse DNS lookup for a single IP
const char *reverse_dns_lookup(const char *ip);

#ifdef __cplusplus
}
#endif

#endif