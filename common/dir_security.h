/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#ifndef _DIR_SECURITY_H_
#define _DIR_SECURITY_H_

/* includes */

#include "common.h"
#include "config_types.h"
#include "dl_list.h"

/* prototypes */

int examin_tcp_wrapper PROTO((char *wrapper));

int read_dir_security_file PROTO((char         *file,
                                  dl_list_type **wrap_list,
                                  char         *wrap_type));

int write_dir_security_file PROTO((char         *file,
                                   char         *suffix,
                                   dl_list_type *wrap_list,
                                   char         *wrap_type,
                                   dl_list_type *paths_list));

int verify_dir_security_list PROTO((dl_list_type *wrap_list, char *wrap_type));

void destroy_dir_security_list PROTO((dl_list_type **wrap_list));

int def_dir_allow_security_list PROTO((dl_list_type **wrap_list));

int def_dir_deny_security_list PROTO((dl_list_type **wrap_list));

int add_dir_security PROTO((dl_list_type **wrap_list,
                            char         *wrap_str,
                            char         *wrap_type));

dir_security_struct *find_dir_security PROTO((dl_list_type *wrap_list,
                                              char         *wrap));

int del_dir_security PROTO((dl_list_type **wrap_list,
                            char         *wrap_str,
                            char         *wrap_type));

int destroy_dir_security_data PROTO((dir_security_struct *dir_wrap));


#endif /* _DIR_SECURITY_H_ */
