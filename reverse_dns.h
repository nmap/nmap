#ifndef REVERSE_DNS_H
#define REVERSE_DNS_H

#include <sys/socket.h>

char *reverse_dns_resolve(const struct sockaddr_storage *ss, size_t ss_len);

#endif /* REVERSE_DNS_H */