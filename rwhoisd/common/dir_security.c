/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#include "dir_security.h"

#include "defines.h"
#include "directive_conf.h"
#include "fileutils.h"
#include "log.h"
#include "main_config.h"
#include "misc.h"
#include "strutil.h"

static int create_dir_security PROTO((dl_list_type **wrap_list,
                                      char *wrap_type));
static int verify_dir_security PROTO((dir_security_struct *dir_wrap,
                                      char *wrap_type));
static int count_dir_security_entries PROTO((dl_list_type *wrap_list,
                                             char *wrapper));

/* --------------------- Local Functions -------------- */
/* counts the number of times a tcp wrapper occurs in the given allow or
   deny list. */
static int
count_dir_security_entries(wrap_list, wrapper)
  dl_list_type *wrap_list;
  char         *wrapper;
{
  int                 not_done;
  int                 count     = 0;
  dir_security_struct *wrap_item;
  dl_node_type        *orig_posn;

  if (!wrap_list || !wrapper) return( 0 );

  if (dl_list_empty(wrap_list)) return( 0 );

  /* save the current position */
  orig_posn = dl_list_get_pos(wrap_list);

  not_done = dl_list_first(wrap_list);
  while (not_done)
  {
    wrap_item = dl_list_value(wrap_list);
    if (STR_EQ(wrap_item->wrapper, wrapper)) count++;
    not_done = dl_list_next(wrap_list);
  }

  /* restore the saved position */
  dl_list_put_pos(wrap_list, orig_posn);

  return( count );
}

/* verify the contents of directive security entry. */
static int
verify_dir_security(wrap_item, wrap_type)
  dir_security_struct *wrap_item;
  char                *wrap_type;
{
  int ret;

  if (!wrap_item || !wrap_type) return FALSE;

  if ((ret = examin_tcp_wrapper(wrap_item->wrapper)))
  {
    log(L_LOG_ERR, CONFIG,
        "Directive %s security wrapper had invalid syntax: %s",
        wrap_type, wrap_item->wrapper, examin_error_string(ret));
    return FALSE;
  }

  return TRUE;
}

/* allocate/create the directive security list head */
static int
create_dir_security(wrap_list, wrap_type)
  dl_list_type **wrap_list;
  char         *wrap_type;
{
  *wrap_list = xcalloc(1, sizeof(**wrap_list));

  if (!dl_list_default(*wrap_list, TRUE, destroy_dir_security_data))
  {
    log(L_LOG_ERR, CONFIG,
        "Error in creating %s directive security list", wrap_type);
    return FALSE;
  }

  return TRUE;
}

/* --------------------- Public Functions ------------- */

/* verifies the format of allow/deny tcp wrapper. Returns non-zero value
   on failure. */
int
examin_tcp_wrapper(wrapper)
  char *wrapper;
{
  if (NOT_STR_EXISTS(wrapper)) return ERW_EMTYSTR;

  return( 0 );
}

/* reads allow/deny tcp wrapper file into the allow/deny wrapper
   list. */
int
read_dir_security_file(file, wrap_list, wrap_type)
  char         *file;
  dl_list_type **wrap_list;
  char         *wrap_type;
{
  FILE *fp;
  char line[BUFSIZ];
  int  ret;

  if (!file || !*file || !wrap_list) return FALSE;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "could not open %s directive security file '%s': %s",
        wrap_type, file, strerror(errno));
    return FALSE;
  }

  destroy_dir_security_list(wrap_list);
  if (!(*wrap_list)) {
    if (!create_dir_security(wrap_list, wrap_type))
    {
      fclose(fp);
      return FALSE;
    }
  }

  set_log_context(file, 0, -1);

  while ((readline(fp, line, BUFSIZ)) != NULL)
  {
    inc_log_context_line_num(1);

    /* first, skip if we have an empty string */
    if (!*line)
    {
      continue;
    }

    /* skip comments */
    if (*line == '#')
    {
      continue;
    }

    if ((ret = examin_tcp_wrapper(line)))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid %s directive TCP Wrapper format '%s' %s: %s",
          wrap_type, line, file_context_str(), examin_error_string(ret));
      fclose(fp);
      return FALSE;
    }
    if (!add_dir_security(wrap_list, line, wrap_type))
    {
      fclose(fp);
      return FALSE;
    }
  } /* readline */

  fclose(fp);

  return TRUE;
}

/* writes the allow/deny tcp wrapper file. Appends the file name to paths_list
   if this function was able to create the file on disk. */
int
write_dir_security_file(file, suffix, wrap_list, wrap_type, paths_list)
  char         *file;
  char         *suffix;
  dl_list_type *wrap_list;
  char         *wrap_type;
  dl_list_type *paths_list;
{
  FILE                *fp = NULL;
  int                 not_done;
  dir_security_struct *wrap_item;
  char                new_file[MAX_FILE];

  if (!file || !*file || !wrap_list || !paths_list) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);
  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "could not create %s directive security file '%s': %s",
        wrap_type, new_file, strerror(errno));
    return FALSE;
  }

  not_done = dl_list_first(wrap_list);
  while (not_done)
  {
    wrap_item = dl_list_value(wrap_list);
    fprintf(fp, "%s\n", wrap_item->wrapper);
    not_done = dl_list_next(wrap_list);
  }
  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* checks the validity of the tcp wrapper list and its entries. It verifies
   that there are no duplicates in the list. */
int
verify_dir_security_list(wrap_list, wrap_type)
  dl_list_type *wrap_list;
  char         *wrap_type;
{
  int                 not_done;
  dir_security_struct *wrap_item;

  if (!wrap_type) return FALSE;

  not_done = dl_list_first(wrap_list);
  while (not_done)
  {
    wrap_item = dl_list_value(wrap_list);
    if (!verify_dir_security(wrap_item, wrap_type))
    {
      return FALSE;
    }
    if (count_dir_security_entries(wrap_list, wrap_item->wrapper) > 1)
    {
      log(L_LOG_ERR, CONFIG,
        "duplicate directive security wrapper '%s' found in the %s list",
        wrap_item->wrapper, wrap_type);
      return FALSE;
    }

    not_done = dl_list_next(wrap_list);
  }

  return TRUE;
}

/* destroy the given wrapper list. */
void
destroy_dir_security_list(wrap_list)
  dl_list_type **wrap_list;
{
  if (!wrap_list) return;
  dl_list_destroy(*wrap_list);
  *wrap_list = NULL;
}

/* initialize the directive allow tcp wrapper list. */
int
def_dir_allow_security_list(wrap_list)
  dl_list_type **wrap_list;
{
  if (!wrap_list) return FALSE;

  destroy_dir_security_list(wrap_list);

  if (!create_dir_security(wrap_list, S_DIRECTIVE_ALLOW))
  {
    return FALSE;
  }

  return TRUE;
}

/* initialize the directive deny tcp wrapper list. */
int
def_dir_deny_security_list(wrap_list)
  dl_list_type **wrap_list;
{
  if (!wrap_list) return FALSE;

  destroy_dir_security_list(wrap_list);

  if (!create_dir_security(wrap_list, S_DIRECTIVE_DENY))
  {
    return FALSE;
  }

  return TRUE;
}

/* create and append a directive tcp wrapper to the list after checking to
   make sure it is not already in the list. */
int
add_dir_security(wrap_list, wrap_str, wrap_type)
  dl_list_type **wrap_list;
  char         *wrap_str;
  char         *wrap_type;
{
  dir_security_struct *wrap_item;

  if (!wrap_list || !wrap_str || !(*wrap_list)) return FALSE;

  if (find_dir_security((*wrap_list), wrap_str))
  {
    log(L_LOG_ERR, CONFIG,
        "cannot have duplicate %s directive TCP wrapper '%s'",
        wrap_type, wrap_str);
    return FALSE;
  }

  wrap_item = xcalloc(1, sizeof(*wrap_item));

  wrap_item->wrapper = xstrdup(wrap_str);

  /* append this to the list */
  if (!dl_list_append((*wrap_list), wrap_item))
  {
    log(L_LOG_ERR, CONFIG,
        "Error appending directive security wrapper '%s' to %s wrapper list",
        wrap_item->wrapper, wrap_type);
    destroy_dir_security_data(wrap_item);
    return FALSE;
  }

  return TRUE;
}

/* find the given tcp wrapper string in the wrapper list. Return NULL if
   not in the list. */
dir_security_struct *
find_dir_security(wrap_list, wrap_str)
  dl_list_type *wrap_list;
  char         *wrap_str;
{
  int                 not_done;
  dir_security_struct *wrap_item;

  not_done = dl_list_first(wrap_list);
  while (not_done)
  {
    wrap_item = dl_list_value(wrap_list);
    if (STR_EQ(wrap_item->wrapper, wrap_str))
    {
      return( wrap_item );
    }
    not_done = dl_list_next(wrap_list);
  }

  return( NULL );
}

/* delete the given directive security wrapper from the wrapper list. */
int
del_dir_security(wrap_list, wrap_str, wrap_type)
  dl_list_type **wrap_list;
  char         *wrap_str;
  char         *wrap_type;
{
  if (!wrap_list || !wrap_str || !*wrap_str || !wrap_type) return FALSE;

  /* find it in the list */
  if (!find_dir_security(*wrap_list, wrap_str))
  {
    log(L_LOG_ERR, CONFIG,
        "'%s' directive security item not found in the %s wrapper list",
        wrap_str, wrap_type);
    return FALSE ;
  }

  if (!dl_list_delete(*wrap_list))
  {
    log(L_LOG_ERR, CONFIG,
        "Error deleting directive security item '%s' from the %s wrapper list",
        wrap_str, wrap_type);
    return FALSE;
  }

  return TRUE;
}

/* free up the memory used by directive security wrapper item. */
int
destroy_dir_security_data(dir_wrap)
  dir_security_struct *dir_wrap;
{
  if (!dir_wrap) return TRUE;

  if (dir_wrap->wrapper)
  {
    free(dir_wrap->wrapper);
  }

  free(dir_wrap);

  return TRUE;
}
