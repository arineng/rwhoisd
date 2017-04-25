/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _STRUTIL_H_
#define _STRUTIL_H_

/* includes */

#include "common.h"

/* prototypes */

char *stripchar PROTO((char *str, char ch));

char *strip_trailing PROTO((char *str, char ch));

char *strip_leading PROTO((char *str, char ch));

char *strip_control PROTO((char *str));

char *rtrim PROTO((char *str));

char *ltrim PROTO((char *str)   );

char *trim PROTO((char *str));

char *strrev PROTO((char *str));

char *skip_whitespace PROTO((char *str));

int  count_char PROTO((char *str, char c));

int  count_spaces PROTO((char *str));

char *strSTR PROTO((char *str1, char *str2));

char *strupr PROTO((char *a));

char *compact_whitespace PROTO((char *str));

int is_not_empty_str PROTO((char *str));

int is_no_whitespace_str PROTO((char *str));

int is_number_str PROTO((char *str));

int is_dns_char PROTO((char value));

int is_id_str PROTO((char *value));

#endif /* _STRUTIL_H_ */
