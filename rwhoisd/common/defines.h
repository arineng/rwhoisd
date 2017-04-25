/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


#ifndef _DEFINES_H_
#define _DEFINES_H_

#include "common.h"

#ifndef TRUE
#define TRUE                1
#endif
#ifndef FALSE
#define FALSE               0
#endif

#define MAX_FILENAME        256
#define MAX_LINE            512
#define MAX_FILE            512
#define MAX_ATTRIBUTES      512
#define MAX_COMMANDS        512
#define MAX_BUF             4096
#define MAX_REFERRAL_LINES  20
#define MAX_TEMPLATE_NAME   256
#define MAX_TEMPLATE_DESC   256
#define CONTROL(char)       (char ^ 0100)
#define ABORT_CHAR          CONTROL('G')
#define STATUS_CHAR         CONTROL('E')
#define CRLF                "\015\012"
#define QUIT                2   /* this should be moved somewhere */
#define USLEEP_WAIT_PERIOD  400000
#define USLEEP_SEC_CONV     1000000 / USLEEP_WAIT_PERIOD


/* Global string manipulation macros */
/* Safe(ish) strdup. */
/* NOTE: the variable passed to this routine must be legal */
#define NEW_STRING(s)   xstrdup(s)

#define NEW_STRING_SIZE(s,size) (char *)xcalloc(1, size + 1)

/* NOTE: the variables passed to this routine must be legal (i.e.,
   terminated) C strings */
#ifndef STR_EQ
#define STR_EQ(str1,str2) \
    (strcasecmp((char *)(str1), (char *)(str2)) ? FALSE : TRUE)
#endif /* ! STR_EQ */
#ifndef STRN_EQ
#define STRN_EQ(str1,str2,size) \
    (strncasecmp((char *)(str1), (char *)(str2), (size)) ? FALSE : TRUE)
#endif /* ! STRN_EQ */

#ifndef STR_EXISTS
#define STR_EXISTS(str) ((str) && *(str))
#endif /* ! STR_EXISTS */
#ifndef NOT_STR_EXISTS
#define NOT_STR_EXISTS(str) (!(str) || !*(str))
#endif /* ! NOT_STR_EXISTS */
  
/* NOTE: the 'str' variable must be a literal string or locally defined
   character array. */
#define STR_COPY(str,val) \
    strncpy((char *)(str), (char *)(val), sizeof(str) - 1)

#define SAFE_STR(str,def) \
  (str ? str : def)

#define SAFE_STR_NONE(str) \
  SAFE_STR(str, "none")
  
/*
 *  global_flag-diddling macros
 */

#define SET(flag,offset)       flag = flag |= (1 << offset)
#define CLEAR(flag,offset)     flag = flag &= ~(1<<offset)
#define ON(flag,offset)        (flag & (1<<offset))
#define OFF(flag,offset)       (!(flag & (1<<offset)))

/********************************************
  flag macros for display types
********************************************/
#define DUMP_DISPLAY 1
#define FULL_DISPLAY 2
#define SUMMARY_DISPLAY 3

/********************************************
  flag macros for queries
********************************************/
#define HANDLE_QUERY 1
#define SCAN_FOR_USERS 2
#define EXIT_QUERY 3
#define HELP_QUERY 4

/********************************************
  local changes
*********************************************/

#endif /* DEFINES */
