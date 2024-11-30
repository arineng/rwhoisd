/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DIRECTIVE_CONF_H_
#define _DIRECTIVE_CONF_H_

/* includes */

#include "common.h"
#include "types.h"
#include "dl_list.h"

/* defines */

#define D_COMMAND               "command"
#define D_COMMAND_LEN           "command-len"
#define D_COMMAND_PROGRAM       "program"
#define D_COMMAND_DESCRIPTION   "description"

/* directives */
#define DIR_RWHOIS      "rwhois"
#define DIR_CLASS	"class"
#define DIR_DIRECTIVE   "directive"
#define DIR_DISPLAY     "display"
#define DIR_FORWARD     "forward"
#define DIR_HOLDCONNECT "holdconnect"
#define DIR_LIMIT       "limit"
#define DIR_NOTIFY      "notify"
#define DIR_SECURITY     "security"
#define DIR_QUIT        "quit"
#define DIR_REGISTER    "register"
#define DIR_SCHEMA      "schema"
#define DIR_SOA         "soa"
#define DIR_STATUS      "status"
#define DIR_XFER        "xfer"

#define CAP_CLASS       0x000001
#define CAP_DIRECTIVE   0x000002
#define CAP_DISPLAY     0x000004
#define CAP_FORWARD     0x000008
#define CAP_HOLDCONNECT 0x000010
#define CAP_LIMIT       0x000020
#define CAP_NOTIFY      0x000040
#define CAP_QUIT        0x000080
#define CAP_REGISTER    0x000100
#define CAP_SCHEMA      0x000200
#define CAP_SECURITY    0x000400
#define CAP_SOA         0x000800
#define CAP_STATUS      0x001000
#define CAP_XFER        0x002000
#define CAP_X           0x004000



/* prototypes */

int read_directive_file PROTO((char *file));

int read_extended_directive_file PROTO((char *file));

void initialize_directive_list PROTO((void));

directive_struct *find_directive PROTO((char *name));

int add_directive PROTO((char *name, int len, char *description,
                         int (*func)(), char *program, int disabled_flag));

void destroy_directive_list PROTO((void));

dl_list_type *get_directive_list PROTO((void));

long find_cap(char *directive);

int default_directive_list PROTO((void));

int write_directive_file PROTO((char *file, char *suffix, 
                                dl_list_type *paths_list));

int write_extended_directive_file PROTO((char *file, char *suffix,
                                         dl_list_type *paths_list));

int examin_xdirective_program PROTO((char *path));

int verify_all_directives PROTO((void));

#endif /* _DIRECTIVE_CONF_H_ */
