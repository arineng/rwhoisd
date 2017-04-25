/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DELETE_H_
#define _DELETE_H_

/* includes */

#include "common.h"
#include "mkdb_types.h"
#include "dl_list.h"

/* prototypes */

int mkdb_delete_record_list PROTO((dl_list_type *record_list));

int mkdb_delete_record PROTO((dl_list_type  *file_list,
                              record_struct *hit_item,
                              dl_list_type  *changed_fi_list));

#endif /* _DELETE_H_ */
