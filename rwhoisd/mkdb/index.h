/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _INDEX_H_
#define _INDEX_H_

/* includes */
#include "common.h"
#include "mkdb_types.h"

/* prototypes */
long index_data_file PROTO((class_struct *class,
                            auth_area_struct *auth_area,
                            file_struct *data_file,
                            dl_list_type *files,
                            int validate_flag,
                            int *status));

int decode_index_line PROTO((char *line, index_struct *item));

int encode_index_line PROTO((char *line, index_struct *item));

int index_files PROTO((class_struct     *class,
                       auth_area_struct *auth_area,
                       dl_list_type     *index_file_list,
                       dl_list_type     *data_file_list,
                       int              validate_flag,
                       int              hold_lock_flag));

int index_files_by_name PROTO((char *class_name,
                               char *auth_area_name,
                               char *base_dir,
                               int  num_data_files,
                               char **file_names,
                               int  validate_flag));

int index_files_by_suffix PROTO((char *class_name,
                                 char *auth_area_name,
                                 char *suffix,
                                 int  validate_flag));

int destroy_index_item PROTO((index_struct *item));

char *soundex_index_to_var PROTO((char      *result,
                                  char      *value));

int is_soundexable PROTO((char *str));

int sort_index_files PROTO((dl_list_type *files));

#endif /* _INDEX_H_ */
