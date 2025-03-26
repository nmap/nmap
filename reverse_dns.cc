#include "reverse_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define BUFFER_SIZE 512

struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

// Convert IPv4 to reverse DNS format (e.g., 8.8.8.8 -> 8.8.8.8.in-addr.arpa)
void ipv4_to_arpa(const char *ip, char *output) {
    int octets[4];
    sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    sprintf(output, "%d.%d.%d.%d.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
}

// Convert IPv6 to reverse DNS format (e.g., 2001:db8::1 -> 1.0.0...ip6.arpa)
void ipv6_to_arpa(const char *ip, char *output) {
    unsigned char addr[16];
    char full_hex[33] = {0};  // 32 hex digits + null terminator

    if (inet_pton(AF_INET6, ip, addr) != 1) {
        strcpy(output, "Invalid IPv6 address");
        return;
    }
    for (int i = 0; i < 16; i++) {
        sprintf(full_hex + i * 2, "%02x", addr[i]);
    }
    char reversed[128] = {0};
    int pos = 0;
    for (int i = 31; i >= 0; i--) {
        reversed[pos++] = full_hex[i];
        reversed[pos++] = '.';
    }
    sprintf(output, "%sip6.arpa", reversed);
}

// Determine whether an IP is IPv4 or IPv6 and convert accordingly.
void ip_to_arpa(const char *ip, char *output) {
    if (strchr(ip, ':') != NULL) {
        ipv6_to_arpa(ip, output);
    } else {
        ipv4_to_arpa(ip, output);
    }
}

// Build a DNS query for PTR lookup
int build_query(unsigned char *buffer, char *domain) {
    struct dns_header *dns = (struct dns_header *)buffer;
    dns->id = htons(0x1234);
    dns->flags = htons(0x0100);  // standard query with recursion desired
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // Convert domain name into DNS query format
    unsigned char *qname = buffer + sizeof(struct dns_header);
    char domain_copy[256];
    strncpy(domain_copy, domain, sizeof(domain_copy));
    domain_copy[sizeof(domain_copy) - 1] = '\0';

    char *token = strtok(domain_copy, ".");
    while (token) {
        size_t len = strlen(token);
        *qname++ = len;
        memcpy(qname, token, len);
        qname += len;
        token = strtok(NULL, ".");
    }
    *qname++ = 0;

    // Set QTYPE to PTR (12) and QCLASS to IN (1)
    unsigned short *qtype = (unsigned short *)qname;
    *qtype++ = htons(12);
    *qtype++ = htons(1);

    return (qname - buffer) + 4;
}

// Send the DNS query and get a response
int send_dns_query(unsigned char *query, int query_size, unsigned char *response) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &server.sin_addr);

    if (sendto(sock, query, query_size, 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int response_size = recvfrom(sock, response, BUFFER_SIZE, 0, (struct sockaddr *)&from, &fromlen);
    if (response_size < 0) {
        perror("recvfrom");
    }
    close(sock);

    return response_size;
}

// Decode domain names from compressed format in the DNS response.
void read_name(unsigned char *buffer, unsigned char *ptr, char *output) {
    char name[256] = {0};
    int name_len = 0;
    int jumped = 0;
    unsigned char *orig_ptr = ptr;

    while (*ptr) {
        if ((*ptr & 0xC0) == 0xC0) {
            int offset = ((*ptr & 0x3F) << 8) + ptr[1];
            ptr = buffer + offset;
            jumped = 1;
        } else {
            int len = *ptr++;
            if (len == 0) break;
            if (name_len != 0) {
                name[name_len++] = '.';
            }
            strncpy(name + name_len, (char *)ptr, len);
            name_len += len;
            ptr += len;
        }
    }
    name[name_len] = '\0';
    strcpy(output, name);
    if (jumped) {
        ptr = orig_ptr + 2;
    }
}

// Modified parse_response to return result instead of printing
static void parse_response(unsigned char *response, const char *input_ip, char *result) {
    struct dns_header *dns = (struct dns_header *)response;
    unsigned char *ptr = response + sizeof(struct dns_header);
    int qdcount = ntohs(dns->qdcount);
    int ancount = ntohs(dns->ancount);

    // Skip question section
    for (int i = 0; i < qdcount; i++) {
        while (*ptr) ptr++;
        ptr += 5; // skip null + QTYPE/QCLASS
    }
    for (int i = 0; i < ancount; i++) {
        char name[256];
        read_name(response, ptr, name);
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2;
        } else {
            while (*ptr) ptr++;
            ptr++;
        }
        unsigned short type = ntohs(*(unsigned short *)ptr);
        ptr += 2; // QTYPE
        ptr += 2; // QCLASS
        ptr += 4; // TTL
        unsigned short rdlength = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        if (type == 12) {  // PTR record
            read_name(response, ptr, result);
            return;
        }
        ptr += rdlength;
    }
    strcpy(result, "No PTR record found");
}

// Entry point for reverse DNS lookup
const char *reverse_dns_lookup(const char *ip) {
    static char result[256];
    char domain[512];
    unsigned char query[BUFFER_SIZE], response[BUFFER_SIZE];

    // Validate IP
    struct in_addr ipv4addr;
    struct in6_addr ipv6addr;
    if (strchr(ip, ':') ? 
        inet_pton(AF_INET6, ip, &ipv6addr) != 1 :
        inet_pton(AF_INET, ip, &ipv4addr) != 1) {
        return "Invalid IP address";
    }

    ip_to_arpa(ip, domain);
    int query_size = build_query(query, domain);
    int response_size = send_dns_query(query, query_size, response);

    if (response_size > 0) {
        parse_response(response, ip, result);
    } else {
        strcpy(result, "No DNS response");
    }

    return result;
}