#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

#include "nsock.h"
#include "nbase.h"


typedef struct service_lookup {
	char *name;
	u8 proto;
	u16 portno;
} service_lookup;



typedef struct m_data {
	nsock_pool nsp;
	nsock_iod nsi;
	int state;
	int protocol;
	unsigned short port;
	struct in_addr ip;
	int attempts;
	int max_attempts;	/* how many attempts in one connection */
	char *username;
	char *password;
	char *buf;
	int bufsize;
} m_data;



#endif
