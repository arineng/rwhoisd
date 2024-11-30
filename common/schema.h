/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#ifndef _SCHEMA_H_
#define _SCHEMA_H_

#include "common.h"
#include "types.h"

/* defines */

#define O_SCHEMA_VERSION    "schema-version"
#define O_NAME              "name"
#define O_CLASS_ALIAS       "alias"
#define O_ATTRIBUTEDEF      "attributedef"
#define O_DBDIR             "dbdir"
#define O_DISPLAY           "display"
#define O_DESCRIPTION       "description"
#define O_COMMAND           "command"
#define O_PARSE_PROG        "parse-program"

/* prototypes */

int read_schema PROTO((auth_area_struct *aa));

int add_class PROTO((schema_struct  *schema,
                     class_struct   *class,
                     auth_area_struct *aa) );

dl_list_type *get_class_list PROTO((schema_struct *schema));

dl_list_type *get_schema_global_attr_list PROTO((schema_struct *schema));

class_struct *
find_class_by_name PROTO((schema_struct *schema,
                          char          *name));
class_struct *
find_class_by_id PROTO((schema_struct   *schema,
                        int             id));

void display_class PROTO((class_struct *class));

void display_schema PROTO((schema_struct *schema));

int destroy_class_data PROTO((class_struct *class));

int destroy_schema_data PROTO((schema_struct *schema));

int add_global_class PROTO((class_struct *class, auth_area_struct *aa));

class_ref_struct *
find_global_class_by_name PROTO(( char *name));

int destroy_class_ref_data PROTO(( class_ref_struct *class_ref ));

int destroy_class_ref_list PROTO((void));

dl_list_type *get_schema_attribute_ref_list PROTO((schema_struct *schema));

int write_schema_file PROTO((char *file, char *suffix, auth_area_struct *aa,
                             dl_list_type *paths_list));

int examin_schema_version PROTO((char *version));

int examin_class_name PROTO((char *name));

int examin_class_db_dir PROTO((char *path));

int examin_class_attr_file PROTO((char *path));

int examin_class_parse_prog PROTO((char *path));

int verify_schema PROTO((auth_area_struct *aa));

int create_class PROTO((class_struct *class, auth_area_struct *aa));

int update_schema_version PROTO((class_struct *class));

int add_new_class_alias PROTO((auth_area_struct *aa, class_struct *class,
                               char *alias));

int verify_all_class_paths PROTO((dl_list_type *paths_list,
                                  auth_area_struct *aa));

int verify_class_parse_progs PROTO((dl_list_type *paths_list,
                                    auth_area_struct *aa));

#endif /* _SCHEMA_H_ */

