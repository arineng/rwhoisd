/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _SEARCH_H_
#define _SEARCH_H_

/* includes */

#include "common.h"

#include "dl_list.h"
#include "mkdb_types.h"
#include "search_prim.h"
#include "types.h"

/* prototypes */

int is_cidr_valid_for_searching PROTO((char *value));

int search PROTO((query_struct  *query,
                  dl_list_type  *record_list,
                  int           max_hits,
                  ret_code_type *ret_code));

 
int check_query_complexity PROTO((query_struct *query));

#endif /* _SEARCH_H_ */
