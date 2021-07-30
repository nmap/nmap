define IGNORE
#include "../nmap.h"
endef

#define EXPORT(_var) export $(name)##_var:= $(patsubst "%,%,$(patsubst %",%,$(subst " ",,NMAP##_var)))

name = NMAP
EXPORT(_NAME)
EXPORT(_VERSION)
EXPORT(_NUM_VERSION)
#undef NMAP_NAME
#include "../../nmap-build/nmap-oem.h"
#define NMAP_OEM_NAME NMAP_NAME
EXPORT(_OEM_NAME)
