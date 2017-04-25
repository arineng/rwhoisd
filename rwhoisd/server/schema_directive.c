/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


/*  Implementation of -schema
    --------------------------
   usage: -schema <auth_area> [class=] */


#include "schema.h"

#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"


/*  Internal Data Structures. */

typedef struct schema_arg_struct  
{
  auth_area_struct *auth_area;
  dl_list_type     *class_list;
} schema_arg_struct;


/* ------------------- Local Functions -------------------- */

static int
destroy_schema_arg_struct(ss)
  schema_arg_struct *ss;
{
  if (!ss) return TRUE;
  
  dl_list_destroy(ss->class_list);
  free(ss);

  return TRUE;
}


/* schema_parse_args:  This function parses that are given in the -schema
   call.  It returns a schema_arg_struct on success. */
static schema_arg_struct * 
schema_parse_args(str)
  char *str;
{
  schema_arg_struct *ss;
  auth_area_struct  *auth_area;
  class_struct      *class;
  int               argc;
  char              **argv;
  int               i;

  split_arg_list(str, &argc, &argv);
  
  if (argc < 1) 
  {
    print_error(INVALID_DIRECTIVE_PARAM, "");

    free_arg_list(argv);
    return NULL;
  }

  ss = xcalloc(1, sizeof(*ss));

  auth_area = find_auth_area_by_name(argv[0]);
  if (!auth_area)
  {
    print_error(INVALID_AUTH_AREA, "");

    destroy_schema_arg_struct(ss);
    free_arg_list(argv);
    return NULL;
  }

  ss->auth_area = auth_area;
  
  if (argc == 1)
  {
    free_arg_list(argv);
    return(ss);
  }

  ss->class_list = xcalloc(1, sizeof(*ss->class_list));
  dl_list_default(ss->class_list, TRUE, null_destroy_data);
  
  for (i = 1; i < argc; i++) 
  {
    if (auth_area && auth_area->schema)
    {
      class = find_class_by_name(auth_area->schema, argv[i]);
      if (class)
      {
        dl_list_insert(ss->class_list, class);
      }
      else
      {
        print_error(INVALID_CLASS, "");

        destroy_schema_arg_struct(ss);
        free_arg_list(argv);
        return NULL;
      }
    }
  } /* end of for (i=1;i<argc;i++) */

  free_arg_list(argv);
  return(ss);
}  /* end of schema_parse_args */


/* schema_display_attribute:  this function displays the information about
   each attribute of a class. */
static void 
schema_display_attribute(name, attr)
  char             *name;
  attribute_struct *attr;
{
  print_response(RESP_SCHEMA, "%s:attribute:%s", name, 
                 SAFE_STR_NONE(attr->name));
  print_response(RESP_SCHEMA, "%s:format:%s", name, 
                 SAFE_STR_NONE(attr->format));
  print_response(RESP_SCHEMA, "%s:description:%s", name, 
                 SAFE_STR_NONE(attr->description));

  /* to comply with the spec, indexed is either ON or OFF, the
     actually type if indexing is lost. */
  switch (attr->index) 
  {
  case INDEX_NONE: 
    print_response(RESP_SCHEMA, "%s:indexed:OFF", name);
    break;
  default:
    print_response(RESP_SCHEMA, "%s:indexed:ON", name);
    break;
  } /* end of switch (attr->index) */
  
  print_response(RESP_SCHEMA, "%s:required:%s", name,
                 on_off(attr->is_required));
  print_response(RESP_SCHEMA, "%s:multi-line:%s", name,
                 on_off(attr->is_multi_line));
  print_response(RESP_SCHEMA, "%s:repeatable:%s", name,
                 on_off(attr->is_repeatable));
  print_response(RESP_SCHEMA, "%s:hierarchical:%s", name,
                 on_off(attr->is_hierarchical));
  print_response(RESP_SCHEMA, "%s:private:%s", name,
                 on_off(attr->is_private));
  switch (attr->type) 
  {
  case TYPE_TEXT: 
    print_response(RESP_SCHEMA, "%s:type:Text", name);
    break;
  case TYPE_ID: 
    print_response(RESP_SCHEMA, "%s:type:ID", name);
    break;
  case TYPE_SEE_ALSO: 
    print_response(RESP_SCHEMA, "%s:type:See-Also", name);
    break;
  default:
    break;
    
  }  /* end of switch (attr->type) */

  print_response(RESP_SCHEMA, "%s:primary:%s", name,
                 on_off(attr->is_primary_key));

  print_response(RESP_SCHEMA, "");
  
} /* end of schema_display_attribute */


/* schema_display_attribute_list:  This function displays all the
   attributes in a class.  */ 
static void 
schema_display_attribute_list(name, list)
  char         *name;
  dl_list_type *list;
{
  int not_done;
 
  if (dl_list_empty(list))
  {
    print_error(UNIDENT_ERROR, "No attributes in class");
    return;
  }

  not_done = dl_list_first(list);
  while (not_done)
  {
    schema_display_attribute(name, dl_list_value(list));
    not_done = dl_list_next(list);
  }
  
}  /* end of schema_display_attribute_list */


/* schema_display_class: This function is called to display the
     class in a schema. */
static void 
schema_display_class(class)
  class_struct *class;
{
    schema_display_attribute_list(class->name, &(class->attribute_list));
}


/* schema_display_all_schemas: This function is called to display all the
     classes in a schema. */
static void 
schema_display_classes(class_list)
  dl_list_type *class_list;
{   
  int          not_done;
  class_struct *class;
 
  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);
    schema_display_class(class);

    not_done = dl_list_next(class_list);
  }  /* end of while(not_done) */

}  /* end of schema_display_all_schemas */


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* schema_directive:  This function process the call to -schema
     directive.*/
int schema_directive(str)
  char * str;
{
  schema_arg_struct *in = NULL;

  in = schema_parse_args(str);

  if (!in) 
  {
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "schema directive: %s", str);
  
  if (dl_list_empty(in->class_list))
  {
    schema_display_classes(&(in->auth_area->schema->class_list));
  }
  else
  {
    schema_display_classes(in->class_list);
  }

  destroy_schema_arg_struct(in);
  
/*   print_ok(); */
  return TRUE;

}  /* end of schema_directive */
