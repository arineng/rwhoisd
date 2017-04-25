/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _FILE_INFO_H_
#define _FILE_INFO_H_

/* includes */

#include "common.h"
#include "dl_list.h"
#include "mkdb_types.h"

/* defines */


/* tags for parsing definitions */
#define MKDB_TYPE_TAG       "type"
#define MKDB_FILE_TAG       "file"
#define MKDB_FILE_NO_TAG    "file_no"
#define MKDB_SIZE_TAG       "size"
#define MKDB_NUMRECS_TAG    "num_recs"
#define MKDB_LOCK_TAG       "lock"


/* for types of files */
#define MKDB_EXACT_INDEX_STR        "EXACT"
#define MKDB_CIDR_INDEX_STR         "CIDR"
#define MKDB_SOUNDEX_INDEX_STR      "SOUNDEX"
#define MKDB_DATA_FILE_STR          "DATA"
#define MKDB_OLD_INDEX_STR          "INDEX"
#define MKDB_OLD_INDEX_FIRST_STR    "FIRST"
#define MKDB_OLD_INDEX_WORD_STR     "WORD_ONLY"

/* templates for filenames */
#define INDEX_DEFAULT_BASE_NAME  "index"
#define INDEX_EXACT_FILE_TEMPL   "-exact-%d.ndx"
#define INDEX_CIDR_FILE_TEMPL    "-cidr-%d.ndx"
#define INDEX_SOUNDEX_FILE_TEMPL "-soundex-%d.ndx"


/* prototypes */

/* given two file types, return TRUE if they are considered equal,
   false if not */
int mkdb_file_type_equals PROTO((mkdb_file_type type1, mkdb_file_type type2));

/* given a file_struct, copy it into newly allocated space and return */
file_struct *copy_file_struct PROTO((file_struct *fi));

/* given a list of file_structs, copy it into another list (will
   append to the target list */
int copy_file_list PROTO((dl_list_type *target_file_list,
                          dl_list_type *source_file_list));

/* given a class_name and auth_area_name, or just auth_area_name,
   return the data directory in 'dir'.  Returns TRUE on success. */
int get_dir PROTO((char  *class_name,
                   char  *auth_area_name,
                   char  *dir));

/* reads in records from the master file list(s) pointed to by class &
   auth_area, and appends them to file_list, which should already be
   primed. */
int get_file_list PROTO((class_struct     *class,
                         auth_area_struct *auth_area,
                         dl_list_type     *file_list));

/* given a class_name and auth_area_name, or just auth_area_name, and
   a type, return the master file list. */
int get_file PROTO((char            *class_name,
                    char            *auth_area_name,
                    dl_list_type    *file_list));

/* given a full (master) file list, produce a reduced list based on
   type and lock status.  The head of the result should already be
   allocated. */
int filter_file_list PROTO((dl_list_type   *result_list,
                            mkdb_file_type type,
                            dl_list_type   *master_list));

/* delete the master file list associated with a particular class an
   authority area */
int unlink_master_file_list PROTO((class_struct     *class,
                                   auth_area_struct *auth_area));

/* add a file described by the parameters to the file_list.  Returns the
   file_no.  The add is committed to disk immediately. */
file_struct *add_single_file PROTO((class_struct     *class,
                                    auth_area_struct *auth_area,
                                    char             *file_name,
                                    mkdb_file_type   type,
                                    long             num_recs));

/* changes the the master file list pointed to by the class and
   auth_area parameters.  It does this in one synchronous step to
   avoid inconsistent states. */
int
modify_file_list PROTO((class_struct     *class,
                        auth_area_struct *auth_area,
                        dl_list_type     *add_list,
                        dl_list_type     *delete_list,
                        dl_list_type     *mod_list,
                        dl_list_type     *unlock_list,
                        dl_list_type     *lock_list));

/* actually deletes (unlinks) the files listed in file_list.  Should
   be used with care */
void unlink_file_list PROTO((dl_list_type *file_list));

/* Given an ID (file number) and type, return the node that matches */
file_struct *find_file_by_id PROTO((dl_list_type   *list,
                                    int            id,
                                    mkdb_file_type type));

/* Given a file name (generally a relative path), return the node that
   matches */
file_struct *find_file_by_name PROTO((dl_list_type   *list,
                                      char           *name,
                                      mkdb_file_type type));


/* returns the total number of records found in an authority area */
long records_in_auth_area PROTO((auth_area_struct *auth_area));

/* given the parameters, allocate and fill out a file_struct. */
file_struct *build_base_file_struct PROTO((char           *file_name,
                                           mkdb_file_type type,
                                           long           num_recs));

/* given the parameters, allocate and fill out a file_struct that will be
   renamed based on a template at actual MKDB insertion time */
file_struct *build_tmp_base_file_struct PROTO((char           *tmp_filename,
                                               char           *base_template,
                                               mkdb_file_type type,
                                               long           num_recs));

/* fills file_list with files constructed from names, which are
   considered to be relative to base_dir. */
int build_file_list_by_names PROTO((dl_list_type   *file_list,
                                    mkdb_file_type type,
                                    char           *base_dir,
                                    int            num_names,
                                    char           **names));

/* fills file_list with files found in the base_dir ending with
   suffix. */
int build_file_list_by_suffix PROTO((dl_list_type   *file_list,
                                     mkdb_file_type type,
                                     char           *base_dir,
                                     char           *suffix));


/* de-allocated the memory assocated with 'data' */
int destroy_file_struct_data PROTO((file_struct *data));

#endif /* _FILEINFO_H_ */

