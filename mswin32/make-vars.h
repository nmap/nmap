define IGNORE
#include "../nmap.h"
endef

#define EXPORT(_var) export $(name)##_var:= $(patsubst "%",%,$(subst " ",,NMAP##_var))

name = NMAP
EXPORT(_VERSION)
EXPORT(_NUM_VERSION)
