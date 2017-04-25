/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "reg_utils.h"

#include "anon_record.h"
#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "delete.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "guardian.h"
#include "index.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "parse.h"
#include "procutils.h"
#include "records.h"
#include "schema.h"
#include "search.h"
#include "state.h"
#include "validate_rec.h"

#define CLEARTEXT_SPOOL_FILE_TEMPLATE   "%s/cleartext.%s.XXXXXX"

/* local prototypes */

/* given a record parsing result (from a mkdb_read action on real or
   anon records), log and display an appropriate error message */
static void report_rec_parse_error PROTO((char             *function_name,
                                          rec_parse_result status));

/* get the name of the class contained in an anonymous record */
static char *get_classname_from_anon_rec PROTO((anon_record_struct *anon_rec));

/* get the name of the authority area contained in an anonymous record */
static char *get_aaname_from_anon_rec PROTO((anon_record_struct *anon_rec));

/* --------------------- Local Functions ------------------- */

static void
report_rec_parse_error(function_name, status)
  char             *function_name;
  rec_parse_result status;
{
  switch (status)
  {
  case REC_NULL:
  case REC_EOF:
    print_error(INVALID_DIRECTIVE_PARAM,
                "record to be registered not found");
    log(L_LOG_NOTICE, CLIENT, "%s: no body found", function_name);
    break;
  case REC_INVAL:
    print_error(INVALID_DIRECTIVE_PARAM,
                "record to be registered was invalid");
    log(L_LOG_NOTICE, CLIENT, "%s: record was invalid", function_name);
    break;
  case REC_FATAL:
    print_error(UNIDENT_ERROR, "fatal error reading spool");
    log(L_LOG_NOTICE, CLIENT, "%s: fatal error reading spool", function_name);
    break;
  default:
    break;
  }
}

/* finds the class attribute in an anonymous record, and extracts the name. */
static char *
get_classname_from_anon_rec(anon_rec)
  anon_record_struct *anon_rec;
{
  anon_av_pair_struct *av;
  
  av = find_anon_class_in_rec(anon_rec);

  if (!av) return NULL;

  return(av->value);
}


/* finds the auth-area attribute in the anon record and returns the value. */
static char *
get_aaname_from_anon_rec(anon_rec)
  anon_record_struct *anon_rec;
{
  anon_av_pair_struct *av;

  av = find_anon_auth_area_in_rec(anon_rec);

  if (!av) return NULL;

  return(av->value);
}

/* --------------------- Public Functions ------------------- */

register_action_type
translate_action_str(action)
  char *action;
{
  if (STR_EQ(action, "ADD"))
  {
    return(ADD);
  }
  if (STR_EQ(action, "MOD"))
  {
    return(MOD);
  }
  if (STR_EQ(action, "DEL"))
  {
    return(DEL);
  }
  
  return(UNKNOWN_ACTION);
}

char *
action_to_string(action)
  register_action_type action;
{
  switch (action)
  {
  case ADD:
    return("ADD");
  case MOD:
    return("MOD");
  case DEL:
    return("DEL");
  default:
    return("UNKNOWN");
  }
}
           
/* given the authority area name, generate a random ID string. */
char *
generate_id(auth_area_name)
  char *auth_area_name;
{
  char      buffer[16];
  char      id_str[MAX_LINE];
  struct tm *tm;
  time_t    t;

  /* create time stamp */
  t   = time((time_t *) NULL);
  tm  = localtime(&t);

  strftime(buffer, 16, "%Y%m%d%H%M%S", tm);
  
  sprintf(id_str, "%s%d.%s", buffer, (int) getpid(), auth_area_name);
  
  return(xstrdup(id_str));
}

char *
generate_updated()
{
  return(xstrdup(make_timestamp()));
}


/* a convenience function to pull the class and authority area from a
   register spool file.  Basically, this is just an encapsulation of
   some error checking. */
int
get_class_and_aa_from_anon_rec(anon_rec, class_p, auth_area_p)
  anon_record_struct *anon_rec;
  class_struct       **class_p;
  auth_area_struct   **auth_area_p;
{
  char             *class_str;
  char             *aa_str;
  class_struct     *class;
  auth_area_struct *aa;

  aa_str = get_aaname_from_anon_rec(anon_rec);
  if (NOT_STR_EXISTS(aa_str))
  {
    print_error(MISSING_REQ_ATTRIB, "Auth-Area");
    return FALSE;
  }
  class_str = get_classname_from_anon_rec(anon_rec);
  if (NOT_STR_EXISTS(class_str))
  {
    print_error(MISSING_REQ_ATTRIB, "Class-Name");
    return FALSE;
  }

  aa = find_auth_area_by_name(aa_str);
  if (!aa)
  {
    print_error(INVALID_AUTH_AREA, aa_str);
    return FALSE;
  }
  
  class = find_class_by_name(aa->schema, class_str);
  if (!class)
  {
    print_error(INVALID_CLASS, class_str);
    return FALSE;
  }
    
  *class_p     = class;
  *auth_area_p = aa;

  return TRUE;
}

/* returns TRUE if a there is a record separator in the file. */
int
has_record_separator(fp)
  FILE  *fp;
{
  char          line[MAX_LINE];
  unsigned long orig_pos;
  int           status = FALSE;
  
  if (!fp)
  {
    log(L_LOG_ERR, DIRECTIVES,
        "has_record_separator: null data detected");
    return FALSE;
  }

  orig_pos = ftell(fp);
  
  /* rewind to the beginning of the file */
  if (fseek(fp, 0L, SEEK_SET) < 0)
  {
    log(L_LOG_ERR, DIRECTIVES,
        "has_record_separator: fseek failed: %s",
        strerror(errno));
    return FALSE;
  }

  while (readline(fp, line, MAX_LINE) != NULL)
  {
    if (*line && new_record(line))
    {
      status = TRUE;
      break;
    }
  }

  /* set fp back to original position */
  if (fseek(fp, orig_pos, SEEK_SET) < 0)
  {
    log(L_LOG_ERR, DIRECTIVES,
        "has_record_separator: fseek failed: %s",
        strerror(errno));
    return FALSE;
  }

  return(status);
}

/* updates the soa record. Returns TRUE if ok, FALSE if not. */
int
update_soa_record(auth_area, updated_str)
  auth_area_struct *auth_area;
  char             *updated_str;
{  
  free(auth_area->serial_no);
  auth_area->serial_no = xstrdup(updated_str);
  
  return(write_soa_file(auth_area));
}

/* either adds or modifies the record's 'Updated' attribute, setting
   it to 'updated_str' */
void
set_updated_attr(record, updated_str)
  record_struct *record;
  char          *updated_str;
{
  av_pair_struct   *av;

  av = find_attr_in_record_by_name(record, "Updated");
  if (!av)
  {
    append_attribute_to_record(record, record->class, "Updated", updated_str);
  }
  else
  {
    free(av->value);
    av->value = xstrdup(updated_str);
  }
}



int
compare_record_attr_by_name(rec1, rec2, attr_name)
  record_struct *rec1;
  record_struct *rec2;
  char          *attr_name;
{
  av_pair_struct *av1;
  av_pair_struct *av2;

  if (!rec1 || !rec2 || NOT_STR_EXISTS(attr_name))
  {
    return FALSE;
  }

  av1 = find_attr_in_record_by_name(rec1, attr_name);
  av2 = find_attr_in_record_by_name(rec2, attr_name);

  /* attributes are not equal if one doesn't exist */
  if (!av1 || !av2)
  {
    return FALSE;
  }

  if (NOT_STR_EXISTS((char *)av1->value) ||
      NOT_STR_EXISTS((char *)av2->value))
  {
    return FALSE;
  }

  return(STR_EQ((char *)av1->value, (char *)av2->value));
}

int
get_id_and_updated_from_anon(anon_rec, id, updated)
  anon_record_struct *anon_rec;
  char **id;
  char **updated;
{
  anon_av_pair_struct *anon_av;

  *id = NULL; *updated = NULL;
  
  /* find the ID part of the record */
  anon_av = find_anon_attr_in_rec(anon_rec, "ID");
  if (!anon_av)
  {
    return FALSE;
  }
  *id = anon_av->value;
 
  /* find the updated field */
  anon_av = find_anon_updated_in_rec(anon_rec);
  if (!anon_av)
  {
    return FALSE;
  }
  *updated = anon_av->value;

  return TRUE;
}

/* builds the query struture used to get the to-be-deleted object */
int
build_object_query(query, id, updated)
  query_struct *query;
  char         *id;
  char         *updated;
{
  char                query_str[MAX_LINE];

  if (!query || NOT_STR_EXISTS(id))
  {
    log(L_LOG_ERR, DIRECTIVES, "build_object_query: null data detected");
    return FALSE;
  }

  if (STR_EXISTS(updated))
  {
    sprintf(query_str, "ID=%s and Updated=%s*", id, updated);
  }
  else
  {
    sprintf(query_str, "ID=%s", id);
  }
  
  if (!parse_query(query_str, query))
  {
    log(L_LOG_ERR, DIRECTIVES, "find object query failed to parse: %s",
        query_str);
    return FALSE;
  }

  return TRUE;
}

/* build a query looking for other objects with the same primary keys
   as the given record */
int
build_primary_key_query(query, record)
  query_struct  *query;
  record_struct *record;
{
  dl_list_type     *attr_list;
  attribute_struct *attr;
  av_pair_struct   *av;
  char             query_str[MAX_LINE];
  char             tmp_str[MAX_LINE];
  int              count = 0;
  int              found = FALSE;
  int              not_done;

  attr_list = &(record->class->attribute_list);
  *query_str = '\0';
  
  not_done = dl_list_first(attr_list);

  while (not_done)
  {
    attr = dl_list_value(attr_list);
    if (attr->is_primary_key && !STR_EQ(attr->name, "ID"))
    {
      if ((av = find_attr_in_record_by_id(record, attr->local_id)) != NULL )
      {
        sprintf(tmp_str, "%s=\"%s\"", attr->name, (char *)av->value);
        if (count)
        {
          strcat(query_str, " AND ");
        }
        strcat(query_str, tmp_str);
        count++;
      }

      found++;
    }

    not_done = dl_list_next(attr_list);
  }

  /* handle no primary key case */
  if (!found) return TRUE;
  
  if (!parse_query(query_str, query))
  {
    return FALSE;
  }

  if (record->auth_area && record->auth_area->name)
  {
    query->auth_area_name = xstrdup(record->auth_area->name);
  }
  if (record->class && record->class->name)
  {
    query->class_name = xstrdup(record->class->name);
  }
  
  return TRUE;
}

/* reads the contents of the register spool file on an add operation
   (one fully specified record only) */
int
read_add_spool(spool_fp, new_record_p)
  FILE          *spool_fp;
  record_struct **new_record_p;
{
  auth_area_struct   *aa;
  class_struct       *class;
  anon_record_struct *anon_rec;
  record_struct      *rec;
  int                val_flag;
  rec_parse_result   status;

  if (!spool_fp || !new_record_p)
  {
    log(L_LOG_ERR, DIRECTIVES, "read_add_spool: null data detected");
    return FALSE;
  }

  val_flag = encode_validate_flag(FALSE, TRUE, FALSE);
  
  if (has_record_separator(spool_fp))
  {
    log(L_LOG_INFO, DIRECTIVES, "register add contains a record sep");
    print_error(INVALID_DIRECTIVE_PARAM, "too many records");
    return FALSE;
  }

  anon_rec = mkdb_read_anon_record(0, val_flag, &status, spool_fp);
  if (!anon_rec)
  {
    report_rec_parse_error("read_add_spool", status);
    return FALSE;
  }

  if (!get_class_and_aa_from_anon_rec(anon_rec, &class, &aa))
  {
    /* error reporting is handled in the get routine itself */
    log(L_LOG_NOTICE, CLIENT,
        "read_add_spool: add record missing or invalid auth-area or class");
    destroy_anon_record_data(anon_rec);
    return FALSE;
  }
  
  rec = mkdb_translate_anon_record(anon_rec, class, aa, val_flag);
  destroy_anon_record_data(anon_rec);
  
  if (!rec)
  {
    /* logging and error reporting taken care of internally */
    return FALSE;
  }
  
  *new_record_p = rec;

  return TRUE;
}

/* read the contents of the register spool file for a mod operation
   (id & updated, _NEW_, and the replacement record) */
int
read_mod_spool(spool_fp, new_record_p, old_record_p)
  FILE               *spool_fp;
  record_struct      **new_record_p;
  anon_record_struct **old_record_p;
{
  auth_area_struct   *aa;
  class_struct       *class;
  anon_record_struct *old_anon_rec;
  anon_record_struct *new_anon_rec;
  record_struct      *new_rec;
  int                val_flag;
  rec_parse_result   status;

  if (!spool_fp || !new_record_p || !old_record_p)
  {
    log(L_LOG_ERR, DIRECTIVES, "read_mod_spool: null data detected");
    return FALSE;
  }

  val_flag = encode_validate_flag(FALSE, TRUE, FALSE);

  if (!has_record_separator(spool_fp))
  {
    log(L_LOG_INFO, DIRECTIVES, "mod operation missing multiple objects");
    print_error(NO_OBJECT_FOUND, "");
    return FALSE;
  }

  old_anon_rec = mkdb_read_anon_record(0, val_flag, &status, spool_fp);

  if (!old_anon_rec)
  {
    report_rec_parse_error("read_mod_spool (old rec)", status);
    return FALSE;
  }

  new_anon_rec = mkdb_read_anon_record(0, val_flag, &status, spool_fp);

  if (!new_anon_rec)
  {
    report_rec_parse_error("read_mod_spool (new rec)", status);
    return FALSE;
  }

  if (!get_class_and_aa_from_anon_rec(new_anon_rec, &class, &aa))
  {
    /* FIXME: should probably take care of logging here */
    return FALSE;
  }

  new_rec = mkdb_translate_anon_record(new_anon_rec, class, aa, val_flag);
  destroy_anon_record_data(new_anon_rec);
  
  if (!new_rec)
  {
    return FALSE;
  }
  
  *new_record_p = new_rec;
  *old_record_p = old_anon_rec;
  
  return TRUE;
}

/* read the contents of the register spool file for a del operation
   (at least an ID and Updated, other stuff is ok but ignored) */
int
read_del_spool(spool_fp, old_record_p)
  FILE *spool_fp;
  anon_record_struct **old_record_p;
{
  anon_record_struct *old_rec;
  rec_parse_result   status;

  if (!spool_fp || !old_record_p)
  {
    log(L_LOG_ERR, DIRECTIVES, "read_del_spool: null data detected");
    return FALSE;
  }

  /* rewind */
  if (fseek(spool_fp, 0L, SEEK_SET) < 0)
  {
    log(L_LOG_ERR, DIRECTIVES, "read_del_spool: fseek failed: %s",
        strerror(errno));
    return FALSE;
  }

  old_rec = mkdb_read_anon_record(0, 0, &status, spool_fp);

  if (!old_rec)
  {
    report_rec_parse_error("read_del_spool", status);
    return FALSE;
  }

  *old_record_p = old_rec;

  return TRUE;
}
