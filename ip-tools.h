/* This is a Cfunctions (version 0.28) generated header file.
   Cfunctions is a free program for extracting headers from C files.
   Get Cfunctions from 'http://www.lemoda.net/cfunctions/'. */

/* This file was generated with:
'cfunctions -inc ip-tools.c' */
#ifndef CFH_IP_TOOLS_H
#define CFH_IP_TOOLS_H

/* From 'ip-tools.c': */

#line 6 "ip-tools.c"
#define INVALID_IP 0
#define NOTFOUND -1
typedef struct {
    unsigned start;
    unsigned end;
}
ip_block_t;

#line 27 "ip-tools.c"
unsigned int ip_tools_ip_to_int (const char * ip );

#line 71 "ip-tools.c"
int ip_tools_ip_range (ip_block_t * ip_blocks , int n_ip_ranges , unsigned ip );

#endif /* CFH_IP_TOOLS_H */
