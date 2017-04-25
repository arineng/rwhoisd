/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

/* a listing of regular expressions that are used */
#ifndef _COMMON_REGEXPS_H_
#define _COMMON_REGEXPS_H_

/* these conform to Henry Spencer's library (V8) */

#define AUTH_AREA_REGEXP    "^([.]?[a-zA-Z0-9-]+)+[.]?|([.:]?[a-fA-F0-9]+)+/[0-9]+$"

#define DOMAIN_NAME_REGEXP  "^([a-zA-Z0-9-]+[.])+[a-zA-Z]+$" /* domain-like */
#define IP_ADDR_REGEXP      "^([a-fA-F0-9]+[.:])+[a-fA-F0-9]+$" /* IP-addr-like */
#define URL_REGEXP          "^([a-zA-Z]+)://([a-zA-Z0-9-.]+):?([0-9]*)/?([^ \t]*)"
#define OLD_REF_REGEXP      "^([a-zA-Z0-9-.]+):([0-9]+):([a-zA-Z]+)[ \t]*(.*)"

#define NETWORK_REGEXP "^[a-fA-F0-9]+([.:][a-fA-F0-9]*)*(/[0-9]+)?$"
#define DOMAIN_REGEXP  "^(([.]?[a-zA-Z0-9-]+)+|.+([.][a-zA-Z0-9-]+)*[.][a-zA-Z]+)$|^[.]$"
#define EMAIL_REGEXP   "^(.+@[a-zA-Z0-9-]+([.][a-zA-Z0-9-]+)*[.][a-zA-Z]+)$"

#define STRICT_IP_NET_REGEXP "^[0-9]+.[0-9]+.[0-9]+.[0-9](/[0-9]+)?"
#define STRICT_CIDR_NET_REGEXP "^[0-9]+.[0-9]+.[0-9]+.[0-9]/[0-9]+"

#define ADMIN_PUNTREF_REGEXP "^([a-zA-Z0-9.-]+):([0-9]*):([a-zA-Z]+)"
#define ADMIN_PUNTURL_REGEXP "^([a-zA-Z]+)://([a-zA-Z0-9.-]+):?([0-9]*)/?(.*)"

#endif /* _COMMON_REGEXPS_H_ */
