/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "ip_network.h"

#include "common_regexps.h"
#include "misc.h"
#include "defines.h"

/* Given an ipv4 string, remove zero padding (in place).  If this
   doesn't look like an IPv4 string, it will do nothing. */
static void
clean_ipv4_addr( str )
  char *str;
{
  int o[4];
  int n;
  int i;

  /* If there are no dots, this is either an IPv6 address or not an
     address. */
  if ((strchr(str, '.') == NULL) || (strchr(str, ':') != NULL)) return;

  n = sscanf(str, "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3]);
  
  for (i = 0; i < n; i++)
  {
    if (o[i] < 0 || o[i] > 255) return;
  }

  switch (n)
  {
  case 4:
    sprintf(str, "%d.%d.%d.%d", o[0], o[1], o[2], o[3]);
    break;
  case 3:
    sprintf(str, "%d.%d.%d", o[0], o[1], o[2]);
    break;
  case 2:
    sprintf(str, "%d.%d", o[0], o[1]);
    break;
  }
}

/* address convert from ascii ip network string to netinfo structure */
int
addrstring_to_ni( addstr, ni )
  char *addstr;
  struct netinfo *ni;
{
#ifdef HAVE_IPV6
  /* neither inet_pton nor inet_addr will convert zero-padded ipv4
     addresses, so un-zero-pad. */
  clean_ipv4_addr(addstr);
  

  if ( inet_pton( AF_INET, addstr, &(ni->prefix) ) == 1 ) {
    ni->af = AF_INET;
    ni->masklen = 32;
    return( 0 );
  }

  else if ( inet_pton( AF_INET6, addstr, &(ni->prefix) ) == 1 ) {
    ni->af = AF_INET6;
    ni->masklen = 128;
    return( 0 );
  }

  else return( -1 );

#else

  long addr;

  clean_ipv4_addr(addstr);

  addr = inet_addr(addstr);
  if (addr == -1) return( -1 );
  ni->af = AF_INET;
  ni->masklen = 32;
  memcpy(ni->prefix, &addr, sizeof(struct in_addr));

  return( 0 );

#endif
}

/* Mask addr to prefix */
void
mask_addr_to_len( ni, len )
  struct netinfo *ni;
  int           len;
{
  int numbytes, i;

  numbytes = (ni->af == AF_INET) ? 4 : 16;

  if (numbytes * 8 == len) return;
  
  for (i = 0; i < numbytes; i++, len -= 8)
  {
    if (len <= 0)
    {
      ni->prefix[i] = 0;
    }
    else if ((len > 0) && (len < 8))
    {
      ni->prefix[i] &= 0xff << ( 8 - len );
    }
  }

  return;
}


                
/* compares two numerical IP addresses in network byte order (big endian)
   (-2 if address family mismatch, -1 if a < b, 0 if a = b, 1 if a > b) */
int
compare_addr(a, b)
  struct netinfo *a;
  struct netinfo *b;
{
  int i, numbytes;

  if ( a->af != b->af ) return( -2 );

  numbytes = (a->af == AF_INET) ? 4 : 16;

  for (i = 0; i < numbytes; i++)
  {
    if ( a->prefix[i] < b->prefix[i] )
    {
      return(-1);
    }
    if ( a->prefix[i] > b->prefix[i] )
    {
      return(1);
    }
  }

  return(0);
}

int
is_network_valid_for_searching(value)
  char *value;
{
  static regexp *net_prog = NULL;

  if (!net_prog)
  {
    net_prog = regcomp(NETWORK_REGEXP);
  }

  if (regexec(net_prog, value))
  {
    return(TRUE);
  }
  else
  {
    return(FALSE);
  }
}

int
is_network_valid_for_index(line)
  char *line;
{
  static regexp *strict_net_prog = NULL;
  struct netinfo prefix;

  if (!strict_net_prog)
  {
    strict_net_prog = regcomp(NETWORK_REGEXP);
  }

  if (regexec(strict_net_prog, line))
  {
    if ( get_network_prefix_and_len( line, &prefix ) )
    {
      return TRUE;
    }
  }

  return FALSE;
}

int
is_cidr_network(value)
  char *value;
{
  static regexp *net_prog = NULL;

  if (!net_prog)
  {
    net_prog = regcomp(STRICT_CIDR_NET_REGEXP);
  }

  if (regexec(net_prog, value))
  {
    return(TRUE);
  }
  else
  {
    return(FALSE);
  }
}

/* determine_network_len_from_policy: given a network IP number
   without an explicit prefix length, determine the prefix length by
   the first octet and presence of 0 octets. */
int
determine_network_len_from_policy(addr)
  struct netinfo *addr;
{
  uint32_t *prefix;
  int      len = 32;

  if ( addr->af != AF_INET ) return( -1 );

  if ( addr->prefix[0] < 128 )
  {
    len = 8;
  }
  else if ( addr->prefix[0] < 192 )
  {
    len = 16;
  }
  else if ( addr->prefix[0] < 224 )
  {
    len = 24;
  }

  /* if the calculated host part has anything in it, something is wrong,
     so we will assume that it is a host address */
  prefix = (uint32_t *) &(addr->prefix);
  if ( ( *prefix & ( 0xffffffff << ( 32 - len ) ) ) != *prefix )
  {
    len = 32;
  }

  return(len);
}

/* calculates the network length by looking at the number of contiguous
   low-order non-zero octets.  128.0.0.0 would yield 8, 128.1.0.0 would
   yield 16, 128.0.1.0 would yield 24, and so on */

int
determine_network_len_from_octets(addr)
  struct netinfo *addr;
{
  int len = 32;
  int i;

  if ( addr->af != AF_INET ) return( -1 );

  for (i = 3; i >= 0; i--)
  {
    if ( addr->prefix[i] > 0 ) break;
    len -= 8;
  }

  return(len);
}

/* get_network_prefix_prefix_len_and_mask: This function parses
   network prefix and prefix length, given a string in quad-octet
   prefix/prefix length format */
int
get_network_prefix_and_len( str, ni )
  char          *str;
  struct netinfo *ni;
{
  char *buf;
  char *p;
  int  len = -1;
  int  maxlength;

  if ( NOT_STR_EXISTS( str ) || !ni )
  {
    return FALSE;
  }

  buf = xstrdup(str);

  /* Parse prefix and prefix length */
  if ((p = strrchr(buf, '/')) != NULL)
  {
    *p = '\0';
    p++;
    len = atoi(p);
  }

  if ( addrstring_to_ni( buf, ni ) )
  {
    free(buf);
    return( FALSE );
  }

  free(buf);

  if ( ni->af == AF_INET ) maxlength = 32;
  else maxlength = 128;

  if ( len >= 0 ) {
    /* check the length */
    if ( len > maxlength )
    {
      return(FALSE);
    }

    ni->masklen = len;
  }
  else { /* unspecified length so assume the maximum */
    ni->masklen = maxlength;
  }

  /* fix any bit masking problems */
  mask_addr_to_len( ni, ni->masklen );

  return(TRUE);
}

int
write_network( str, ni )
  char *str;
  struct netinfo *ni;
{
  if (!str)
  {
    return FALSE;
  }

  sprintf( str, "%s/%d", natop( ni ), ni->masklen );

  return TRUE;
}


char *
ni_to_addrstring(ni, str, str_len)
  struct netinfo        *ni;
  char                  *str;
  int                    str_len;
{
  if (ni->af == AF_INET)
  {
    if (str_len < 15) return NULL;
    sprintf(str, "%03hu.%03hu.%03hu.%03hu",
            ni->prefix[0], ni->prefix[1],
            ni->prefix[2], ni->prefix[3]);
    return str;
  }

#ifdef HAVE_IPV6
  if (ni->af == AF_INET6)
  {
    char *r;
    int i;
    
    if (str_len < 39) return NULL;

    r = str;
    for (i = 0; i < 16; i++)
    {
      sprintf(r, "%02x", ni->prefix[i]);
      r += 2;
      if (((i+1) % 2) == 0 && (i+1) < 16)
      {
        *r = ':';
        r++;
      }
    }
    *r = '\0';

    return str;
  }
#endif
  
  return NULL;
}

char *
natop( ni )
  struct netinfo *ni;
{
  static char str[MAX_LINE];

  return ni_to_addrstring(ni, str, sizeof(str));
}
