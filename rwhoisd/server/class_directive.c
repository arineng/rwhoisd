/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */


/*  Implementation of -class
 *   --------------------------
 *  Input: -class [auth_area] [<class-name>]  
 *  Output: %class class-name:description:<description>
 *     %class class-name:version:<version-number>
 *     %class
 *     %ok
 */

#include "class_directive.h"

#include "attributes.h"
#include "auth_area.h"
#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "schema.h"
#include "schema.h"

/*  Internal Data Structures. */

typedef struct _class_arg_struct  
{
  auth_area_struct *auth_area;
  dl_list_type     *class_list;
} class_arg_struct;


/* ------------------- Local Functions -------------------- */

static int
destroy_class_arg_struct(cs)
  class_arg_struct *cs;
{
  if (!cs) return TRUE;
  
  dl_list_destroy(cs->class_list);
  free(cs);

  return TRUE;
}


/* class_parse_args:  parses argument of -class call.  
 *  It returns a class_arg_struct on success. 
 */
static class_arg_struct * 
class_parse_args(str)
  char *str;
{
  class_arg_struct  *cs;
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

  cs = xcalloc(1, sizeof(*cs));

  auth_area = find_auth_area_by_name(argv[0]);
  if (!auth_area)
  {
    print_error(INVALID_AUTH_AREA, "");

    destroy_class_arg_struct(cs);
    free_arg_list(argv);
    return NULL;
  }

  cs->auth_area = auth_area;
  
  if (argc == 1)
  {
    free_arg_list(argv);
    return(cs);
  }

  cs->class_list = xcalloc(1, sizeof(*cs->class_list));
  dl_list_default(cs->class_list, TRUE, null_destroy_data);
  
  for (i = 1; i < argc; i++) 
  {
    if (auth_area && auth_area->schema)
    {
      class = find_class_by_name(auth_area->schema, argv[i]);
      if (class)
      {
        dl_list_insert(cs->class_list, class);
      }
      else
      {
        print_error(INVALID_CLASS, "");

        destroy_class_arg_struct(cs);
        free_arg_list(argv);
        return NULL;
      }
    }
  } /* end of for (i=1;i<argc;i++) */

  free_arg_list(argv);
  return(cs);
}  /* end of class_parse_args */


/* display_one_class: display one class. 
 */
static void 
display_one_class(class)
  class_struct *class;
{

    print_response(RESP_CLASS, "%s:description:%s",class->name,
                   SAFE_STR(class->description, "0"));
    print_response(RESP_CLASS, "%s:version:%s",class->name,
                   SAFE_STR(class->version, "0"));
    print_response(RESP_CLASS, "");
}


/* display_classses: display all the classes in a class-list.  
 * Only description and version info are displayed. 
 */
static void 
display_classes(class_list)
  dl_list_type *class_list;
{   
  int          not_done;
  class_struct *class;
 
  not_done = dl_list_first(class_list);
  while (not_done)
  {
    class = dl_list_value(class_list);
    display_one_class(class);

    not_done = dl_list_next(class_list);
  }  /* end of while(not_done) */

}  /* end of display_classses */


/* ------------------- PUBLIC FUNCTIONS ------------------- */


/* class_directive:  process the call to -class directive.
 */
int 
class_directive(str)
  char * str;
{
  class_arg_struct *in = NULL;


  in = class_parse_args(str);

  if (!in) 
  {
    return FALSE;
  }

  log(L_LOG_DEBUG, CLIENT, "class directive: %s", str);

  if (dl_list_empty(in->class_list))
  {
    display_classes(&(in->auth_area->schema->class_list) );
  }
  else
  {
    display_classes(in->class_list);
  }

  destroy_class_arg_struct(in);
  
/*   print_ok(); */
  return TRUE;

}  /* end of class_directive */
