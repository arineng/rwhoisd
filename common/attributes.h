/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _ATTRIBUTES_H_
#define _ATTRIBUTES_H_

/* includes */

#include "common.h"
#include "dl_list.h"
#include "types.h"

/* defines */

/* tags for parsing definitions */
#define A_ATTRIBUTE      "attribute"
#define A_ATTRIB_ALIAS   "attribute-alias"
#define A_DESCRIPTION    "description"
#define A_FORMAT         "format"
#define A_IS_PRIMARY_KEY "is-primary-key"
#define A_IS_REQUIRED    "is-required"
#define A_IS_REPEAT      "is-repeatable"
#define A_IS_MULTI_LINE  "is-multi-line"
#define A_IS_HIERARCHICAL  "is-hierarchical"
#define A_IS_PRIVATE     "is-private"
#define A_INDEX          "index"
#define A_DEF_OBJECT     "def_object"
#define A_TYPE           "type"

/* for indexing */
#define A_INDEX_ALL     "ALL"               /* ALL includes soundex! */
#define A_INDEX_EXACT   "EXACT"
#define A_INDEX_CIDR    "CIDR"
#define A_INDEX_SOUNDEX "SOUNDEX"
#define A_INDEX_NONE    "NONE"


/* attribute types */

#define A_TYPE_TEXT     "TEXT"
#define A_SEE_ALSO      "SEE-ALSO"
#define A_ID            "ID"

/* base class identifiers */

#define BC_CLASS_NAME           "Class-Name"
#define BC_CLASS_NAME_A1        "CN"
#define BC_CLASS_NAME_A2        "Object-Type" /* from rwhois 1.0 */
#define BC_CLASS_NAME_A3        "Schema-Name" /* from early 1.5 */
#define BC_ID                   "ID"
#define BC_AUTH_AREA            "Auth-Area"
#define BC_AUTH_AREA_A1         "AA"
#define BC_UPDATED              "Updated"
#define BC_UPDATED_A1           "UP"
#define BC_GUARDIAN             "Guardian"
#define BC_GUARDIAN_A1          "GRD"
#define BC_PRIVATE              "Private"
#define BC_PRIVATE_A1           "PVT"
#define BC_TTL                  "TTL"

/* prototypes */

int read_attributes PROTO((class_struct *class,
                           dl_list_type *attr_ref_list));

int add_attribute PROTO((attribute_struct   *attr,
                         class_struct       *class,
                         dl_list_type       *attr_ref_list));

int add_global_attribute PROTO((attribute_struct    *attr,
                                class_struct        *class,
                                dl_list_type        *attr_ref_list,
                                int                 *global_id));

int add_base_schema PROTO((class_struct *class,
                           dl_list_type *attr_ref_list));

attribute_struct *find_attribute_by_name PROTO((class_struct    *class,
                                                char            *name));

attribute_struct *find_attribute_by_id PROTO((class_struct  *class,
                                              int           id));

attribute_struct *
find_attribute_by_global_id PROTO((class_struct *class,
                                   int          global_id));
attribute_ref_struct *
find_global_attr_by_name PROTO((dl_list_type    *attr_ref_list,
                                char            *name));

attribute_ref_struct *
find_global_attr_by_id PROTO((dl_list_type  *attr_ref_list,
                              int           id));

void display_attribute PROTO((attribute_struct  *attr));

void display_attribute_list PROTO((dl_list_type *list));

int destroy_attr_data PROTO((attribute_struct *attr));

int destroy_attr_ref_data PROTO((attribute_ref_struct *attr_ref));

attr_index_type translate_index_type PROTO((char *itype));

attr_type translate_attr_type PROTO((char *type));

char *show_attribute_type PROTO((attr_type type));

char *show_index_type PROTO((attr_index_type index));

int write_class_attributes PROTO((char *file, char *suffix,
                           class_struct *class, dl_list_type *paths_list));

int create_attribute_def PROTO((attribute_struct *attr,
                             class_struct *class, auth_area_struct *aa));

int verify_attribute_list PROTO((auth_area_struct *aa, class_struct *class));

int is_base_attr PROTO((attribute_struct *attr));

int examin_attribute_name PROTO((char *name));

int examin_attribute_format PROTO((char *fmt));

int add_new_attribute_alias PROTO((auth_area_struct *aa, 
                                   class_struct *class, 
                                   attribute_struct *attr, char *alias));

#endif /* _ATTRIBUTES_H_ */
