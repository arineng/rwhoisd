/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "dump.h"

#include "client_msgs.h"
#include "defines.h"
#include "guardian.h"
#include "misc.h"
#include "records.h"

#define USE_NEW_DUMP 1


/* display_dump_format: this procedure displays the results using the
     "dump" command */
int
display_dump_format(record)
  record_struct *record;
{
  class_struct   *class;
  dl_list_type   *field_list;
  av_pair_struct *av_pair;
  char           *class_name;
  char           *field_name;
  char           *field_value;
  char           *field_type;
  int            list_status;
  int            have_permission = FALSE;
  
  if (!record) return FALSE;

  class      = record->class;
  class_name = class->name;

  /* we'll do the guardian check up front so we only have to do it once */
  if (check_guardian(record))
  {
    have_permission = TRUE;
  }
  
  /* check to see if object is private */
  av_pair = find_attr_in_record_by_name(record, "Private");
  if (av_pair && true_false((char *)av_pair->value) && !have_permission)
  {
    /* record is private and guarded and we are not authenticated */
    return TRUE;
  }

  field_list = &(record->av_pair_list);
  list_status = dl_list_first(field_list);

  while (list_status != 0)
  {
    av_pair = (av_pair_struct *) dl_list_value(field_list);
    field_name = av_pair->attr->name;
    field_value = (char *) av_pair->value;

    /* skip private attributes if not authenticated */
    if (av_pair->attr->is_private)
    {
      if (!have_permission)
      {
        list_status = dl_list_next(field_list);
        continue;
      }
    }
    
#ifdef USE_NEW_DUMP
    switch (av_pair->attr->type)
    {
    case TYPE_SEE_ALSO:
      field_type = "S";
      break;
    case TYPE_ID:
      field_type = "I";
      break;
    default:
      field_type = NULL;
      break;
    }

    if (field_type != NULL)
    {
      print_response(RESP_QUERY, "%s:%s;%s:%s", class_name, field_name,
                     field_type, field_value);
    }
    else
    {
      print_response(RESP_QUERY, "%s:%s:%s", class_name, field_name,
                     field_value);
    }
#else
    print_response(RESP_QUERY, "%s:%s:%s", class_name, field_name,
                   field_value);
#endif
    list_status = dl_list_next(field_list);
  }
  print_response(RESP_QUERY, "");

  return (1);
}
