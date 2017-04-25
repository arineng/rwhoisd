/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _INDEX_FILE_H_
#define _INDEX_FILE_H_

#include "common.h"
#include "dl_list.h"
#include "mkdb_types.h"
#include "types.h"

/* prototypes */

/* generate the template for use as the real, final filename */
char *generate_index_file_basename PROTO((mkdb_file_type type,
                                          char           *spool_directory,
                                          char           *prefix));

/* map attribute indexing schemes to mkdb index files */
mkdb_file_type convert_file_type PROTO((attr_index_type attr_index));

/* find the (first) instance of 'type' in the list of index files
   'files' */
index_fp_struct *find_index_file_by_type PROTO((dl_list_type   *files,
                                                mkdb_file_type type));

/* create a standard list of index files based on what attribute index
   types exist in the class.  This routine generates index file names,
   and sets the types, but it is up the the caller to use the
   generated list in indexing. */
int build_index_list PROTO((class_struct     *class,
                            auth_area_struct *auth_area,
                            dl_list_type     *index_file_list,
                            char             *base_dir,
                            char             *base_name));

/* deletes all temporary files contained in 'index_file_list' */
int unlink_index_tmp_files PROTO((dl_list_type *index_file_list));

/* the destructor */
int destroy_index_fp_data PROTO((index_fp_struct *data));

#endif /* _INDEX_FILE_H_ */
