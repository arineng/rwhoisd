/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#ifndef _PUNT_REF_H_
#define _PUNT_REF_H_

/* includes */

#include "common.h"
#include "config_types.h"
#include "dl_list.h"

/* prototypes */

int examin_punt_ref PROTO((char *punt_str));

int read_punt_file PROTO((char *file, dl_list_type **ref_list));

int write_punt_file PROTO((char         *file,
                           char         *suffix,
                           dl_list_type *ref_list,
                           dl_list_type *paths_list));

int verify_punt_ref_list PROTO((dl_list_type *ref_list));

int def_init_punt_ref PROTO((dl_list_type **ref_list));

int destroy_punt_ref_data PROTO((punt_ref_struct *referral));

int destroy_punt_ref_data PROTO((punt_ref_struct *referral));

void destroy_punt_ref_list PROTO((dl_list_type **ref_list));

int add_punt_ref PROTO((dl_list_type **ref_list, char *punt_str));

punt_ref_struct *find_punt_ref PROTO((dl_list_type *ref_list, char *punt));

int del_punt_ref PROTO((dl_list_type **ref_list, char *punt));

#endif /* _PUNT_REF_H_ */
