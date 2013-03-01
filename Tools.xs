#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ip-tools.h"

MODULE=IP::Tools PACKAGE=IP::Tools

PROTOTYPES: ENABLE

unsigned int ip_to_int (ip)
	const char * ip;
	CODE:
        RETVAL = ip_tools_ip_to_int (ip);
        OUTPUT:
	RETVAL

