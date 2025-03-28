#include "reverse_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <errno.h>

char *reverse_dns_resolve(const struct sockaddr_storage *ss, size_t ss_len) {
    char ip_str[INET6_ADDRSTRLEN];
    unsigned char response[NS_PACKETSZ];  // response buffer
    char domain[NS_MAXDNAME];

    if (!ss || ss_len == 0) {
        return strdup("ERROR: Invalid sockaddr_storage input");
    }

    // Convert IP to string
    if (!inet_ntop(ss->ss_family,
                   (ss->ss_family == AF_INET) ?
                   (void *)&((struct sockaddr_in *)ss)->sin_addr :
                   (void *)&((struct sockaddr_in6 *)ss)->sin6_addr,
                   ip_str, sizeof(ip_str))) {
        return strdup("ERROR: Failed to convert IP address");
    }

    // Construct PTR domain
    if (ss->ss_family == AF_INET) {
        int octets[4];
        sscanf(ip_str, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
        snprintf(domain, sizeof(domain), "%d.%d.%d.%d.in-addr.arpa", 
                 octets[3], octets[2], octets[1], octets[0]);
    } else {
        return strdup("ERROR: IPv6 not fully implemented");
    }

    // Perform DNS query
    int len = res_query(domain, ns_c_in, ns_t_ptr, response, sizeof(response));
    if (len < 0) {
        char *error_msg = (char *)malloc(strlen("ERROR: Failed to resolve ") + strlen(ip_str) + 1);
        if (error_msg) sprintf(error_msg, "ERROR: Failed to resolve %s", ip_str);
        return error_msg ? error_msg : NULL;
    }

    // Parse the response
    ns_msg handle;
    if (ns_initparse(response, len, &handle) < 0) {
        return strdup("ERROR: Failed to parse DNS response");
    }

    // Process PTR records into a single string
    int count = ns_msg_count(handle, ns_s_an);
    char *result = NULL;
    size_t result_len = 0;

    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0 && ns_rr_type(rr) == ns_t_ptr) {
            char hostname[NS_MAXDNAME] = {0};

            if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
                                   ns_rr_rdata(rr), hostname, sizeof(hostname)) > 0) {
                size_t new_len = result_len + strlen(hostname) + (result_len ? 2 : 0);
                char *new_result = (char *)realloc(result, new_len + 1);

                if (!new_result) {
                    free(result);
                    return strdup("ERROR: Memory allocation failed");
                }

                result = new_result;
                if (result_len) strcat(result, ", ");
                else result[0] = '\0';  // Initialize for first hostname
                strcat(result, hostname);
                result_len = new_len;
            }
        }
    }

    if (!result) {
        return strdup("ERROR: No PTR records found");
    }

    return result;
}