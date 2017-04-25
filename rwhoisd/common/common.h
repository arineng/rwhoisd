/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

/* This header file describes common macros and defines for
   cross-platform support */

#ifndef _COMMON_H_
#define _COMMON_H_

/* the name 'log' conflicts with gcc-3.1 builtin
 * Bill Campbell <bill@celestial.com>
 */
#define log rwhoisd_log

/* Add prototype support.  */
#ifndef PROTO
#if defined (USE_PROTOTYPES) ? USE_PROTOTYPES : defined (__STDC__)
#define PROTO(ARGS) ARGS
#else
#define PROTO(ARGS) ()
#endif
#endif

/* global includes */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system includes -- all files should just include this file, rather
   than include stdio.h, et al. themselves. */

/* I guess that everyonse has these... */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>
#include <arpa/inet.h>

#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>

/* not sure what do about the variable arg stuff yet. */
#ifdef HAVE_VPRINTF
# ifdef SGI  /* keep IRIX from complaining */
# undef va_list
# undef _VA_ALIGN
# undef __va_stack_arg
# endif
#ifdef HAVE_STDARG_H
#	include <stdarg.h>
#else
#	include <varargs.h>
#endif /* HAVE_STDARG_H */
#endif /* HAVE_VPRINTF */

/* this should probably be #ifdef USG */
#ifndef HAVE_GETHOSTNAME
#include <sys/utsname.h>
#endif /* ! HAVE_GETHOSTNAME */

#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif /* TIME_WITH_SYS_TIME */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /* HAVE_SYS_FILE_H */

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif /* HAVE_CRYPT_H */

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
# ifdef HAVE_STDINT_H
# include <stdint.h>
# endif /* HAVE_STDINT_H */
#endif /* HAVE_INTTYPES_H */

/* dirent stuff */
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

/* use mem* routines, if available.  Code is standardized on bzero, bcopy */

#ifdef HAVE_MEMSET
#define bzero(a, b) memset((a), 0, (b))
#endif /* HAVE_MEMSET */

#ifdef HAVE_MEMCPY
#define bcopy(a, b, c) memcpy((b), (a), (c))
#endif /* HAVE_MEMCPY */

#ifndef HAVE_IPV6
#undef HAVE_SOCKADDR_STORAGE
#endif


#endif /* _COMMON_H_ */

