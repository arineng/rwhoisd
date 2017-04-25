/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _REG_UTILS_H_
#define _REG_UTILS_H_

/* includes */

#include "common.h"
#include "types.h"
#include "mkdb_types.h"

/* types */

typedef enum
{
  UNKNOWN_ACTION,
  ADD,
  MOD,
  DEL
} register_action_type;

/* prototypes */

/* convert an action string (add, mod, del) to the enumerated type */
register_action_type translate_action_str PROTO((char *action));

/* convert the action enumerated type to the string form.  The result
   is statically allocated. */
char *action_to_string PROTO((register_action_type action));

/* a generic id generation routine; this one generates a date/time
   stamp for the ID. It allocates space for the result string. */
char *generate_id PROTO((char *auth_area_name));

/* generate the contents of the 'Updated' field.  Basically, the
   current time in the correct format.  It allocates space for the
   result string. */
char *generate_updated PROTO((void));


/* given an anonymous record, extract and look up the authority area
   and class information.  Returns FALSE if either the aa or the class
   cannot be correctly determined */
int get_class_and_aa_from_anon_rec PROTO((anon_record_struct *anon_rec,
                                          class_struct       **class_p,
                                          auth_area_struct   **auth_area_p));

/* returns TRUE if the file stream contains a record separator
   sequence ("_NEW_" or "---").  It rewinds the stream after it is
   finished. */
int has_record_separator PROTO((FILE *fp));

/* given a new updated string, rewrite the soa file to update the
   serial number */
int update_soa_record PROTO((auth_area_struct *auth_area,
                             char             *updated_str));

/* given an updated string, set the record's 'Updated' attribute to it  */
void set_updated_attr PROTO((record_struct *record,
                             char          *updated_str));

/* given two records and an attribute name, compare the attribute
   values, and return TRUE if they are the same, FALSE otherwise.
   Probably doesn't work well on repeatable attributes */
int compare_record_attr_by_name PROTO((record_struct *rec1,
                                       record_struct *rec2,
                                       char          *attr_name));

int get_id_and_updated_from_anon PROTO((anon_record_struct *anon_rec,
                                        char               **id,
                                        char               **updated));

/* build a query structure that looks for a specific object,
   identified by id and possibly updated */
int build_object_query PROTO((query_struct *query, char *id, char *updated));


/* given a record, build a query structure that looks for all primary
   keys */
int build_primary_key_query PROTO((query_struct  *query,
                                   record_struct *record));

/* given a spool file pointer for an ADD registration action, allocate
   and fill out the record structure of the new record */
int read_add_spool PROTO((FILE *spool_fp, record_struct **new_record_p));

/* given a spool file pointer for a MOD registration action, allocate
   and fill out the replacement (new) record, and the (probably
   minimal) original record identifier. */
int read_mod_spool PROTO((FILE               *spool_fp,
                          record_struct      **new_record_p,
                          anon_record_struct **old_record_p));

/* given a spool file pointer for a DEL registration action, allocate
   and fill out the (old) record indentifier information. */
int read_del_spool PROTO((FILE               *spool_fp,
                          anon_record_struct **old_record_p));

#endif /* _REG_UTILS_H_ */
