/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _SEARCH_PRIM_H_
#define _SEARCH_PRIM_H_

#include "common.h"

#include "dl_list.h"
#include "mkdb_types.h"
#include "types.h"

/* types */

/* function return codes and their meanings:
   return codes less than 0 are fatal, 0 means success               
   return codes greater than 0 are not fatal but non-normal */
typedef enum
{
  UNKNOWN_SEARCH_ERROR = -3,
  FILE_NOT_FOUND_ERRO  = -2,
  INVALID_SEARCH_TYPE  = -1,
  SEARCH_SUCCESSFUL    =  0,
  HIT_LIMIT_EXCEEDED   =  1
} ret_code_type;

/* prototypes */

void set_hit_count PROTO((int value));
void inc_hit_count PROTO((void));
int  get_hit_count PROTO((void));

/* This function performs a binary search of an index file. It returns
   the file position that points to the first hit in the index. The
   business of actually checking AND operations and such is done in
   the linear scan which should be called next. */
off_t binary_search PROTO((file_struct *file, query_term_struct *query_item));

/* perform a linear search on the index, starting at start_pos, and
   ending either when the EOF is reached, or a key doesn't match (if
   find_all_flag is false).  This routine does the boolean AND
   processing.  Returns the number of hits it added to 'hit_list', -1
   on error. */
ret_code_type full_scan PROTO((class_struct      *class,
                               auth_area_struct  *auth_area,
                               file_struct       *file,
                               dl_list_type      *data_fi_list,
                               query_term_struct *query_item,
                               dl_list_type      *record_list,
                               int               max_hits,
                               off_t             start_pos,
                               int               find_all_flag));

/* scan_for_bol: search backwards for newline - if none found then
   reverse direction and start over. */
int scan_for_bol PROTO((FILE *fp, off_t low, off_t *offset, off_t high));

int search_compare PROTO((query_term_struct *query_item, char *index_value));

#endif /* _SEARCH_PRIM_H_ */
