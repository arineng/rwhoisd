/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "register.h"

#include "anon_record.h"
#include "client_msgs.h"
#include "delete.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "guardian.h"
#include "index.h"
#include "index_file.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "parse.h"
#include "records.h"
#include "reg_ext.h"
#include "search.h"
#include "state.h"
#include "validate_rec.h"

#define DB_FILE_TEMPLATE    "%s/%s.XXXXXX"

/* local prototypes */

/* returns a list of records that match the identity contained in the
   anonymous record.  The list is normally either empty, or of length
   1, but the use of a list allows us to handle cases where, due to
   database mismanagment, there are two copies of a record with the
   same identity */
static int get_real_object_from_anon PROTO((anon_record_struct *anon_rec,
                                            dl_list_type       *record_list));

/* checks the record for uniqueness in the database; basically, it
   searches on the primary keys (*not* ID) to determine this. */
static int check_uniq_record PROTO((record_struct *record));

/* determines if the new and old records essentially point to the same
   object, thus allowing the new object to replace the old object. It
   should probably check primary keys, but does not */
static int ensure_objects_match PROTO((record_struct *new_record,
                                       record_struct *old_record));

/* given a record, write it into the database and index it. */
static int index_new_record PROTO((record_struct *record));

/* checks the record contained in the record handle for suitability
   for addition to the database.  Since it contains a possible call to
   an application specific external parse routine, the add record may
   change, hence the handle and need of the email address */
static int check_add PROTO((record_struct  **record_p, char *reg_email));

/* checks the records contained in the old and new record handles for
   suitability for a database MOD operation.  The routine may change
   the new and old record specifications, and it returns a list of
   records to be deleted as part of the del-add operation that forms a
   mod. */
static int check_mod PROTO((record_struct      **new_record_p,
                            anon_record_struct **old_record_p,
                            dl_list_type       *old_record_list,
                            char               *reg_email));

/* checks the anonymous record for suitability for deletion.  It
   returns in 'record_list' a list of records to actually be deleted */
static int check_del PROTO((anon_record_struct *old_rec,
                           dl_list_type       *record_list,
                           char               *reg_email));

/* given a record, add it to the database */
static int add_record PROTO((record_struct *rec));

/* given a list of records (to deal with multiple copies of the same
   record), delete the records from the database.  The update_soa flag
   to allow the caller to not update the SOA record if it is
   unnessary. */
static int del_record PROTO((dl_list_type *record_list, int update_soa));

/* given a list of old records to delete (usually just one, though),
   and a record to replace it with, modify (del-add) the record */
static int mod_record PROTO((record_struct *new_record,
                             dl_list_type  *old_record_list));


/* print the add response (the assigned values for ID and Updated) */
static int print_add_result PROTO((record_struct *rec));

/* ------------------- Local Functions -------------------- */


static int
get_real_object_from_anon(anon_rec, record_list)
  anon_record_struct *anon_rec;
  dl_list_type       *record_list;
{
  query_struct   *query;
  record_struct  *rec;
  av_pair_struct *av;
  char           *id;
  char           *updated;
  int            num_recs;
  int            not_done;
  ret_code_type  ret_code;
  
  /* First, establish that the anonymous record has the minimum
     attribute set to identify it */
  if (!get_id_and_updated_from_anon(anon_rec, &id, &updated))
  {
    if (!id)
    {
      print_error(MISSING_REQ_ATTRIB, "ID");
      log(L_LOG_NOTICE, CLIENT, "delete/mod object missing ID");
      return FALSE;
    }
    else if (! updated)
    {
      print_error(MISSING_REQ_ATTRIB, "Updated");
      log(L_LOG_NOTICE, CLIENT, "delete/mod object missing Updated");
      /* for now, this routine is use in del and mod
         operations, where missing 'Updated' violates the protocol
         spec */
      return FALSE;
    }
  }
  
  /* Find the record referred to by the deletion criteria (at
     minimum ID and Updated).  This will both establish that there is
     something to delete as well as get the actual record in hand */

  query = xcalloc(1, sizeof(*query));

  /* find the object(s) just by ID, so we can tell the difference
     between objects that just aren't there, and attempts to
     modify/delete objects that have been modified in the meantime. */
  if (!build_object_query(query, id, NULL))
  {
    print_error(UNIDENT_ERROR, "could not generate query to find object");
    log(L_LOG_NOTICE, CLIENT, "could not generate query to find object");
    return FALSE;
  }

  num_recs = search(query, record_list, get_max_hits_ceiling(), &ret_code);
  destroy_query(query);
  
  if (num_recs == 0 || dl_list_empty(record_list))
  {
    print_error(NO_OBJECT_FOUND, "");
    log(L_LOG_INFO, CLIENT, "get_real_object: no object found");
    return FALSE;
  }

  /* it is possible that the search returned more than one result.  If
     that is true, then there is a duplication of data in the database */
  if (num_recs > 1)
  {
    log(L_LOG_WARNING, DIRECTIVES, "multiple objects found for ID: %s",
        id);
  }

  /* remove objects that don't match the 'Updated' criteria */
  not_done = dl_list_first(record_list);
  while (not_done)
  {
    rec = dl_list_value(record_list);
    av = find_attr_in_record_by_name(rec, "Updated");
    if (!STR_EQ(updated, (char *)av->value))
    {
      dl_list_delete(record_list);
    }
    not_done = dl_list_next(record_list);

  }

  /* at this point, if the list was empty then all the objects were
     outdated. */
  if (dl_list_empty(record_list))
  {
    print_error(OUTDATED_OBJ, "");
    log(L_LOG_NOTICE, CLIENT, "attempt to update/delete outdated object %s",
        id);
    return FALSE;
  }
  
  return TRUE;
}

/* generates a search str and validates that no record exists for this
     auth area. Returns TRUE if success, FALSE if failure. */
static int
check_uniq_record(record)
  record_struct *record;
{
  query_struct  *query;
  dl_list_type  record_list;
  int           num_recs;
  ret_code_type ret_code;
  
  query = xcalloc(1, sizeof(*query));
  dl_list_default(&record_list, FALSE, (int(*)(void *))destroy_record_data);
  
  if (!build_primary_key_query(query, record))
  {
    return FALSE;
  }

  /* empty query structs are OK (class had no keys, which is allowed) */
  if (!query->query_tree)
  {
    return TRUE;
  }
  
  num_recs = search(query, &record_list, 1, &ret_code);
  destroy_query(query);
  
  if (num_recs == 0 || dl_list_empty(&record_list))
  {
    return TRUE;
  }

  /* we found something, so we have a duplicate key */
  dl_list_destroy(&record_list);
  return FALSE;
}


/* makes sure that the new record can legitimately replace the new
   record (i.e., ID and updated fields match).  Note that this should
   probably make sure that the other primary keys match, too, but
   doesn't. */
static int
ensure_objects_match(new_record, old_record)
  record_struct *new_record;
  record_struct *old_record;
{
  av_pair_struct *new_av;
  av_pair_struct *old_av;

  log(L_LOG_INFO, UNKNOWN, "in ensure_objects_match()"); /* debug */
  if (!new_record || !old_record)
  {
    log(L_LOG_ERR, DIRECTIVES, "ensure_objects_match: null data detected");
    return FALSE;
  }

  /* First check the IDs */
  new_av = find_attr_in_record_by_name(new_record, "ID");
  old_av = find_attr_in_record_by_name(old_record, "ID");

  /* debug */
  if (new_av) {
    log(L_LOG_INFO, UNKNOWN, "ensure_objects_match: new id %s",
        (char *)new_av->value);
  }
  if (old_av) {
    log(L_LOG_INFO, UNKNOWN, "ensure_objects_match: old id %s",
        (char *)old_av->value);
  }
  /*end debug */
  
  /* don't need to check if the old record has an ID; that should have
     been checked much earlier */
  if (!new_av)
  {
    log(L_LOG_NOTICE, CLIENT,
        "modify object (new) missing ID; using ID from old");
    append_attribute_to_record(new_record, new_record->class, "ID",
                               old_av->value);
  }
  else if (!STR_EQ((char *)new_av->value, (char *)old_av->value))
  {
    print_error(INVALID_DIRECTIVE_PARAM, "ID's must match");
    log(L_LOG_NOTICE, CLIENT, "ensure_objects_match: ID's failed to match");
    return FALSE;
  }

  new_av = find_attr_in_record_by_name(new_record, "Updated");
  old_av = find_attr_in_record_by_name(old_record, "Updated");
  
  if (!new_av)
  {
    log(L_LOG_NOTICE, CLIENT,
        "modify object (new) missing updated; using old updated");
    append_attribute_to_record(new_record, new_record->class, "Updated",
                               old_av->value);
  }
  else if (!STR_EQ((char *)new_av->value, (char *)old_av->value))
  {
    print_error(OUTDATED_OBJ, "");
    log(L_LOG_NOTICE, CLIENT,
        "ensure_objects_match: new object was outdated");
    return FALSE;
  }

  return TRUE;
}

/* indexes the file from a new record structure. Returns TRUE if
     success, FALSE if failure. */
static int
index_new_record(record)
  record_struct *record;
{
  char             store_fname[MAX_FILE];
  dl_list_type     index_file_list;
  int              status;
  int              validate_flag;
  dl_list_type     dl_file_list;
  file_struct      *file_ptr;
  class_struct     *class;
  auth_area_struct *aa;
  FILE             *fp;

  validate_flag = encode_validate_flag(FALSE, TRUE, FALSE);

  class = record->class;
  aa = record->auth_area;
  
  /* generate the new filename */
  create_filename(store_fname, DB_FILE_TEMPLATE, class->db_dir);

  dl_list_default(&index_file_list, FALSE, (int(*)(void *))destroy_index_fp_data);
  if (!build_index_list(class, aa, &index_file_list, class->db_dir,
                        "addind"))
  {
      log(L_LOG_ERR, MKDB,
          "index_files_by_name: could not generate list of index files");
    return FALSE;
  }

  /* open the DATA file and append the record to it. */
  strcat(store_fname, ".txt");
  fp = fopen(store_fname, "a");
  if (!fp)
  {
    log(L_LOG_ERR, DIRECTIVES, "failed to create data file '%s': %s",
        store_fname, strerror(errno));
    return FALSE;
  }
  mkdb_write_record(record, fp);
  fclose(fp);
  

  /* index the file */
  file_ptr = build_base_file_struct(store_fname, MKDB_DATA_FILE, 1);
  dl_list_default(&dl_file_list, FALSE, (int(*)(void *))destroy_file_struct_data);
  dl_list_append(&dl_file_list, file_ptr);
  
  status = index_files(class, aa, &index_file_list, &dl_file_list,
                       validate_flag, FALSE);

  dl_list_destroy(&dl_file_list);
  dl_list_destroy(&index_file_list);

  return(status);
}



/* check the add record for validity */
static int
check_add(record_p, reg_email)
  record_struct **record_p;
  char          *reg_email;
{
  record_struct           *rec;
  ext_parse_response_type resp      = EXT_PARSE_OK;
  int                     validate_flag;
  
  if (!record_p || !*record_p || !(*record_p)->auth_area)
  {
    log(L_LOG_ERR, DIRECTIVES, "check_add: null data detected");
    return FALSE;
  }

  /* quiet mode OFF, protocol errors ON, find all flag OFF */
  validate_flag = encode_validate_flag(FALSE, TRUE, FALSE);
  rec = *record_p;

  /* check the authority area to see if we can modify it */
  if (rec->auth_area->type != AUTH_AREA_PRIMARY)
  {
    print_error(NOT_MASTER_AUTH_AREA, rec->auth_area->name);
    log(L_LOG_ERR, CLIENT, "check_add: not master auth area (%s)",
        rec->auth_area->name);
    return FALSE;
  }
  
  /* remove any IDs, as it *must* be assigned by the server */
  delete_attribute_from_record(rec, "ID");
  
  if (!check_record(rec, validate_flag))
  {
    return FALSE;
  }

  /* make sure that the record isn't duplicate */
  if (!check_uniq_record(rec))
  {
    print_error(NON_UNIQ_KEY, "");
    return FALSE;
  }
  
  /* possibly rewrite some guardian-specific parameters */
  transform_guardian_record(rec);

  /* if there is a external parser, run it */
  if (rec->class->parse_program && *rec->class->parse_program)
  {
    resp = run_external_parser(rec->class->parse_program,
                               ADD, reg_email,
                               NULL, record_p);
    if (resp != EXT_PARSE_OK)
    {
      /* external parse routine should have already issued the error
         code */
      return FALSE;
    }
  }

  return TRUE;
}

/* check the mod records for validity */
static int
check_mod(new_record_p, old_record_p, old_record_list, reg_email)
  record_struct      **new_record_p;
  anon_record_struct **old_record_p;
  dl_list_type       *old_record_list;
  char               *reg_email;
{
  int                     validate_flag;
  record_struct           *new_rec;
  record_struct           *old_rec;
  anon_record_struct      *old_anon_rec;
  ext_parse_response_type resp = EXT_PARSE_OK;
  
  
  /* quiet mode OFF, protocol errors ON, find all errors OFF */
  validate_flag = encode_validate_flag(FALSE, TRUE, FALSE);
  
  if (!new_record_p || !*new_record_p || !old_record_p || !*old_record_p)
  {
    log(L_LOG_ERR, DIRECTIVES, "check_mod: null data detected");
    return FALSE;
  }

  new_rec = *new_record_p; old_anon_rec = *old_record_p;

  /* make sure we can modify in this auth area */
  if (new_rec->auth_area->type != AUTH_AREA_PRIMARY)
  {
    print_error(NOT_MASTER_AUTH_AREA, new_rec->auth_area->name);
    log(L_LOG_NOTICE, CLIENT,
        "check_mod: cannot modify in secondary auth-area (%s)",
        new_rec->auth_area->name);
    return FALSE;
  }

  /* get the actual old record */
  if (! get_real_object_from_anon(old_anon_rec, old_record_list))
  {
    return FALSE;
  }

  if (!old_record_list || dl_list_empty(old_record_list))
  {
    return FALSE;
  }
  
  /* get the first record in the list */
  dl_list_first(old_record_list);
  old_rec = dl_list_value(old_record_list);

  /* validate new record first before calling delete */
  if (!check_record(new_rec, validate_flag) || 
      !ensure_objects_match(new_rec, old_rec))
  {
    dl_list_destroy(old_record_list);
    return FALSE;
  }

  /* now that we've determined that there is something to mod, lets
     check for permission, shall we? (we could just let the delete
     action handle it but for the external parse step) */
  if (!check_guardian(old_rec))
  {
    print_error(UNAUTH_REGIST, "");
    dl_list_destroy(old_record_list);
    return FALSE;
  }

  /* possibly rewrite some guardian-specific parameters; if the
     guard-scheme and guard-info parameters haven't changed, don't
     transform them.  This protects us from possibly encrypting a
     password twice, or something. */
  if (!compare_record_attr_by_name(old_rec, new_rec, "Guard-Scheme") ||
      !compare_record_attr_by_name(old_rec, new_rec, "Guard-Info"))
  {
    transform_guardian_record(new_rec);
  }
  
  if (new_rec->class->parse_program && *new_rec->class->parse_program)
  {
    resp = run_external_parser(new_rec->class->parse_program, MOD,
                               reg_email, old_rec, new_record_p);
  }

  if (resp != EXT_PARSE_OK)
  {
    return FALSE;
  }

  return TRUE;
}

/* checks the delete record for validity (i.e., does the record
   exists, do you have permission to delete it, etc.). Returns TRUE if
   deletion is valid.  Also fills 'record_list' with the actual
   record(s) matching the delete criteria. */
static int
check_del(old_rec, record_list, reg_email)
  anon_record_struct *old_rec;
  dl_list_type       *record_list;
  char               *reg_email;
{
  record_struct           *rec;
  ext_parse_response_type resp = EXT_PARSE_OK;

  if (! get_real_object_from_anon(old_rec, record_list))
  {
    /* logging done internal to the routine */
    return FALSE;
  }

  if (!record_list || dl_list_empty(record_list))
  {
    return FALSE;
  }
  
  /* we will perform the remaining checks on the first in the list,
     and assume, because getting more than one in a database error,
     that the others are equivalent */
  dl_list_first(record_list);
  rec = dl_list_value(record_list);

  /* check to see if we can work on this auth-area at all */
  if (rec->auth_area->type != AUTH_AREA_PRIMARY)
  {
    print_error(NOT_MASTER_AUTH_AREA, rec->auth_area->name);
    dl_list_destroy(record_list);
    return FALSE;
  }
  
  /* now that we've determined that there is something to delete, lets
     check for permission, shall we? */
  if (!check_guardian(rec))
  {
    print_error(UNAUTH_REGIST, "");
    dl_list_destroy(record_list);
    return FALSE;
  }

  /* if update_soa is FALSE, this is being called as part of a mod
     operation, thus the external parser would have already been
     run. */
  if (rec->class->parse_program && *rec->class->parse_program)
  {
    resp = run_external_parser(rec->class->parse_program, DEL,
                               reg_email, rec, NULL);
  }     

  if (resp != EXT_PARSE_OK)
  {
    dl_list_destroy(record_list);
    return FALSE;
  }

  return TRUE;
}


static int 
add_record(rec)
  record_struct  *rec;
{
  av_pair_struct *av;
  int            status;
  char           *id;
  char           *updated;

  if (!rec)
  {
    log(L_LOG_ERR, DIRECTIVES, "add_record: null data detected");
    return FALSE;
  }
  
  /* Since this action used both in add and mod operations, only add
     an ID if there isn't one */
  av = find_attr_in_record_by_name(rec, "ID");
  if (!av)
  {
    id = generate_id(rec->auth_area->name);
    append_attribute_to_record(rec, rec->class, "ID", id);
  }

  /* create/replace the 'Updated' attribute in the object itself, and
     update the SOA record */
  updated = generate_updated();
  set_updated_attr(rec, updated);
  update_soa_record(rec->auth_area, updated);
  free(updated);
  
  status = index_new_record(rec);

  return(status);
}


/* deletes a record from a file.  Returns TRUE if success, FALSE if
     failure */
static int
del_record(record_list, update_soa)
  dl_list_type *record_list;
  int          update_soa;
{
  auth_area_struct  *aa;
  record_struct     *rec;
  char              *updated;
  
  if (dl_list_empty(record_list))
  {
    return TRUE;
  }

  dl_list_first(record_list);
  rec = dl_list_value(record_list);
  aa = rec->auth_area;
  
  mkdb_delete_record_list(record_list);
  
  dl_list_destroy(record_list);

  if (update_soa)
  {
    updated = generate_updated();
    update_soa_record(aa, updated);
    free(updated);
  }

  return TRUE;
}

/* modifies a record from a file. Returns TRUE if success, FALSE if
     failure */
static int 
mod_record(new_record, old_record_list)
  record_struct    *new_record;
  dl_list_type     *old_record_list;
{
  char *updated_str;
  
  /* call delete record, if cool, call add record delete record, if
     cool, call add record delete record, if cool, call add record */
  if (!del_record(old_record_list, FALSE))
  {
    return FALSE;
  }

  /* deal with the 'Updated' attribute and SOA */
  updated_str = generate_updated();
  set_updated_attr(new_record, updated_str);
  update_soa_record(new_record->auth_area, updated_str);
  free(updated_str);
  
  return(add_record(new_record));
}

static int
print_add_result(rec)
  record_struct  *rec;
{
  av_pair_struct *av;
  char           *id;
  char           *updated;
  
  if (!rec) return FALSE;

  av = find_attr_in_record_by_name(rec, "ID");
  if (!av || NOT_STR_EXISTS((char *)av->value)) return FALSE;
  id = (char *)av->value;

  av = find_attr_in_record_by_name(rec, "Updated");
  if (!av || NOT_STR_EXISTS((char *)av->value)) return FALSE;
  updated = (char *)av->value;

  
  print_response(RESP_REGISTER, "ID: %s", id);
  print_response(RESP_REGISTER, "Updated: %s", updated);

  return TRUE;
}

/* ------------------- Public Functions -------------------- */

int
process_registration(reg_email, action)
  char                 *reg_email;
  register_action_type action;
{
  FILE                 *spool_fp;
  anon_record_struct   *old_rec = NULL;
  record_struct        *new_rec = NULL;
  dl_list_type         del_record_list;
  int                  status;
  
  /* READ phase -- read the spool file into the appropriate data structures.
     some contextual syntax checking is done in this phase */

  if (! (spool_fp = open_spool_file("r")) )
  {
    print_error(UNIDENT_ERROR, "");
    return FALSE;
  }

  switch (action)
  {
  case ADD:
    status = read_add_spool(spool_fp, &new_rec);
    break;
  case MOD:
    status = read_mod_spool(spool_fp, &new_rec, &old_rec);
    break;
  case DEL:
    status = read_del_spool(spool_fp, &old_rec);
    break;
  default:
    log(L_LOG_WARNING, DIRECTIVES, "unknown action: %s",
        action_to_string(action));
    status = FALSE;
    break;
  }

  close_spool_file();

  if (!status)
  {
    if (new_rec) destroy_record_data(new_rec);
    if (old_rec) destroy_anon_record_data(old_rec);
    return FALSE;
  }
  /* CHECK phase -- check for syntactical and usage problems */

  dl_list_default(&del_record_list, FALSE, (int(*)(void *))destroy_record_data);
  
  switch (action)
  {
  case ADD:
    status = check_add(&new_rec, reg_email);
    break;
  case MOD:
    status = check_mod(&new_rec, &old_rec, &del_record_list, reg_email);
    break;
  case DEL:
    status = check_del(old_rec, &del_record_list, reg_email);
    break;
  default:
    break;
  }
  
  if (!status)
  {
    if (new_rec) destroy_record_data(new_rec);
    if (old_rec) destroy_anon_record_data(old_rec);
    dl_list_destroy(&del_record_list);
    return FALSE;
  }     
  
  /* COMMIT phase -- apply the changes to the database */

  switch (action)
  {
  case ADD:
    status = add_record(new_rec);
    if (status)
    {
      status = print_add_result(new_rec);
    }
    break;
  case MOD:
    status = mod_record(new_rec, &del_record_list);
    break;
  case DEL:
    status = del_record(&del_record_list, TRUE);
    break;
  default:
    break;
  }

  if (new_rec) destroy_record_data(new_rec);
  if (old_rec) destroy_anon_record_data(old_rec);
  dl_list_destroy(&del_record_list);
  
  if (!status) return FALSE;
  
  return TRUE;
}
