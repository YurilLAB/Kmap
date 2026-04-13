define IGNORE
#include "../kmap.h"
endef

#define EXPORT(_var) export $(name)##_var:= $(patsubst "%,%,$(patsubst %",%,$(subst " ",,KMAP##_var)))

name = KMAP
EXPORT(_NAME)
EXPORT(_VERSION)
EXPORT(_NUM_VERSION)
#undef KMAP_NAME
#include "../../kmap-build/kmap-oem.h"
#define KMAP_OEM_NAME KMAP_NAME
EXPORT(_OEM_NAME)
