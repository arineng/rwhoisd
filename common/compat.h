/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _COMPAT_H_
#define _COMPAT_H_

/* includes */
#include "common.h"

/* this is in case this particular constant isn't defined in
   sys/param.h or netdb.h */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef MAX_HOSTNAME
#define MAX_HOSTNAME MAXHOSTNAMELEN
#endif

#ifndef strerror
char *strerror PROTO((int errnum));
#endif

typedef enum {
  FILE_LOCK,
  FILE_UNLOCK,
  FILE_TEST
} file_lock_t;

/* prototypes */

char *sys_gethostname PROTO((void));

int sys_file_lock PROTO((int fd, file_lock_t op));

#endif /* _COMPAT_H_ */
