/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _IP_NETWORK_H_
#define _IP_NETWORK_H_

/* includes */
#include "common.h"

/* missing types */
#ifndef HAVE_UINT8_T
typedef unsigned char uint8_t;
#endif
#ifndef HAVE_UINT32_T
typedef unsigned int  uint32_t;
#endif

struct netinfo
{
  int     af;           /* address family */
  int     masklen;      /* netmask length */
  uint8_t prefix[16];   /* address in network byte order */
};

/* prototypes */
int addrstring_to_ni PROTO( ( char *addstr, struct netinfo *ni ) );

void mask_addr_to_len PROTO( ( struct netinfo *ni, int len ) );

int compare_addr PROTO( ( struct netinfo *a, struct netinfo *b ) );

int is_network_valid_for_searching PROTO((char *value));

int is_network_valid_for_index PROTO((char *line));

int is_cidr_network PROTO((char *value));

int determine_network_len_from_policy PROTO( ( struct netinfo *ni ) );

int determine_network_len_from_octets PROTO( ( struct netinfo *ni ) );

int get_network_prefix_and_len PROTO( ( char *str, struct netinfo *ni ) );

int write_network PROTO( ( char *str, struct netinfo *ni ) );

/* convert a netinfo address into a canonical address string.  It
   places the results in 'str', which must be at least 15 bytes long
   for IPv4 addresses and 39 bytes long for IPv6.  It returns 'str' or
   NULL if the conversion did not work. */
char *ni_to_addrstring PROTO( (struct netinfo *ni, char *str, int str_len) );

/* convert a netinfo address into a canonical address string.  Not
   thread safe. It returns a statically allocated string. */
char *natop PROTO( ( struct netinfo *ni ) );

#endif /* _IP_NETWORK_H_ */
