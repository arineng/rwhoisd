/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "directive_conf.h"

#include "defines.h"
#include "misc.h"
#include "log.h"
#include "fileutils.h"
#include "main_config.h"
#include "strutil.h"

/* statics */
static dl_list_type directive_list;

/* local prototypes */
static int destroy_directive_data  PROTO((directive_struct *data));

static int verify_directive PROTO((directive_struct *dir));

static int is_extended_directive PROTO((char *name));

/* --------------------- Local Functions ---------------- */

static int
destroy_directive_data(data)
  directive_struct  *data;
{
  if (!data)
  {
    return TRUE;
  }

  if (data->name)
  {
    free(data->name);
  }

  if (data->description)
  {
    free(data->description);
  }
  if (data->program)
  {
    free(data->program);
  }

  free(data);

  return TRUE;
}

/* verify the contents of directory information structure. Examins the 
   extended directive path. Checks if the essential directives are
   enabled. */
static int
verify_directive(dir)
  directive_struct *dir;
{
  int ret;

  if ( !dir || !dir->name || !*dir->name ) return FALSE;

  /* if an extended directive */
  if (is_extended_directive(dir->name)) 
  {
    if ((ret = examin_xdirective_program(dir->program)))
    {
      log(L_LOG_ERR, CONFIG, 
          "invalid extended directive '%s' program '%s': %s",
          dir->name, dir->program, examin_error_string(ret));
      return FALSE;
    }
  }
  else
  {
    if (STR_EQ(dir->name, DIR_QUIT) && dir->disabled_flag)
    {
      log(L_LOG_ERR, CONFIG, 
                   "rwhois quit directive must be enabled");
      return FALSE;
    }
    if (STR_EQ(dir->name, DIR_RWHOIS) && dir->disabled_flag)
    {
      log(L_LOG_ERR, CONFIG, 
                   "rwhois banner directive must be enabled");
      return FALSE;
    }
  }

  return TRUE;
}

/* check if the given directive name is an extended directive */
static int
is_extended_directive(name)
  char *name;
{
  return( STR_EXISTS(name) &&
          is_no_whitespace_str(name) &&
          (strlen(name) > 2) &&
          STRN_EQ(name, "X-", 2) );
}

/* --------------------- Public Functions --------------- */

/* default_directive_list: set the default directive list according to
   protocol and implementation.  Return TRUE if success, FALSE
   otherwise */
int
default_directive_list()
{
  initialize_directive_list();

  /* rwhois is the required directives */  
  if ( !add_directive("rwhois", 6, "RWhois directive", NULL, NULL, FALSE))
  {
    return FALSE;
  }
  /* set default directive-list */ 
  if ( !add_directive("class", 0, "get meta-information for the class(es)", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("directive", 0, "get server allowable directives", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("display", 0, "sets/displays the display types", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("forward", 0, "server forward boolean", NULL, 
              NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("holdconnect", 0, "hold the connection boolean", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("limit", 0, "displays and sets record hit limit", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("security", 0, "identify the authentication method", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("notify", 0, "tell server of bad referral or data change",
              NULL, NULL, FALSE ) )
  {
    return FALSE;
  }
  if( !add_directive("quit", 4, "quit connection", NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("register", 0, "add/mod/delete record in server", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("schema", 0, "get the schema of an object", 
                  NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if( !add_directive("soa", 0, "ask server's authority area", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("status", 0, "server's status", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }
  if ( !add_directive("xfer", 0, "transfer data from the server", 
              NULL, NULL, FALSE) )
  {
    return FALSE;
  }


  /* not implemented. enable disabled_flag */

  return TRUE;
}


/*----------- PUBLIC FUNCTIONS ----------------- */


/* read_directive_file: reads the directives from rwhois.dir file,
 *              places them into directive structure 
 *  format:  <directive>:<enabled>
 */
int
read_directive_file(file)
  char *file;
{
  FILE          *fp;
  char          line[MAX_LINE];
  char          tag[MAX_TEMPLATE_DESC];
  char          datum[MAX_TEMPLATE_DESC];
  directive_struct      *dir;

  /* set the default directive-list first */
  if (!default_directive_list())
  {
    log(L_LOG_ERR, CONFIG, "could not set the default directive list");
    return FALSE;
  }

  /* directive file is optional */
  if ( !file || !*file ) return TRUE;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not open directive file '%s': %s",
        file, strerror(errno));
    return FALSE;
  }

  while ((readline(fp, line, MAX_LINE)) != NULL)
  {
    if (parse_line(line, tag, datum))
    {
      if (STR_EQ(datum, "NO") || STR_EQ(datum, "OFF"))
      {
        if (STR_EQ(tag, DIR_RWHOIS))
        {
          log(L_LOG_WARNING, CONFIG, "required directive '%s' must be on", tag);
        }
        else if ((dir = find_directive(tag))) 
        {
          dir->disabled_flag = TRUE;
        }
        else
        {
          log(L_LOG_WARNING, CONFIG, "directive '%s' not valid", tag);
        }
      }
      else if (STR_EQ(datum, "YES") || STR_EQ(datum, "ON"))
      {
        /* check not implemented directives */
        if ( 0 )
        {
          log(L_LOG_WARNING, CONFIG, "directive '%s' not implemented", tag);
        }
      }
      else
      {
        log(L_LOG_WARNING, CONFIG, "directive '%s' has invalid flag '%s' ", 
          tag, datum );
      }
    } /* parse_line */
  } /* readline */
  
  fclose(fp);
  return TRUE;
}


/* read_extended_directive_file: reads the extended directives from a
      file and places them into a data structure */
int
read_extended_directive_file(file)
  char *file;
{
  FILE  *fp;
  char  line[MAX_LINE];
  char  tag[MAX_TEMPLATE_DESC];
  char  datum[MAX_TEMPLATE_DESC];
  char  description[MAX_TEMPLATE_DESC];
  char  command[MAX_TEMPLATE_DESC];
  int   command_len;
  char  program[MAX_TEMPLATE_DESC];

  /* extended directive file are optional */
  if (!file || !*file) return TRUE;
  
  *command     = '\0';
  *program     = '\0';
  *description = '\0';
  command_len  = 0;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG, "could not open extended directive file '%s': %s",
        file, strerror(errno));
    return FALSE;
  }

  while ((readline(fp, line, MAX_LINE)) != NULL)
  {
    if (new_record (line) && *command && *program) 
    {
      if (command_len == 0)
      {
        command_len = strlen(command);
      } 

      if (!add_directive(command, command_len, description, 
                         NULL, program, FALSE))
      {
        log(L_LOG_ERR, CONFIG, "could not add extended directive '%s'",
            command);
        continue;
/*         fclose(fp); */
/*         return FALSE; */
      }

      *command    = '\0';
      *program    = '\0';
      command_len = 0;
    }
    else if (parse_line(line, tag, datum))
    {
      if (STR_EQ(tag, D_COMMAND))
      {
        sprintf(command, "X-%s", datum);
      }
      else if (STR_EQ(tag, D_COMMAND_LEN))
      {
        command_len = atoi(datum) + 2;
      }
      else if (STR_EQ(tag, D_COMMAND_DESCRIPTION))
      {
        strncpy(description, datum, MAX_TEMPLATE_DESC);
      }
      else if (STR_EQ(tag, D_COMMAND_PROGRAM))
      {
        strncpy(program, datum, MAX_TEMPLATE_DESC);
      }
    }
  }
  
  if (*command && *program)
  {
    if (!add_directive(command, command_len, description, 
                       NULL, program, FALSE))
    {
      log(L_LOG_ERR, CONFIG, "could not add extended directive '%s'",
          command);
      fclose(fp);
      return FALSE;
    }
  }

  fclose(fp);
  return TRUE;
}


void
initialize_directive_list()
{
  if (!dl_list_empty(&directive_list))
  {
    dl_list_destroy(&directive_list);
  }
  
  dl_list_default(&directive_list, FALSE, destroy_directive_data);
}


directive_struct *
find_directive(name)
  char  *name;
{
  directive_struct  *di;
  int               not_done;
  
  if (!name || !*name) return NULL;

  if ( dl_list_empty(&directive_list))
  {
    return NULL;
  }

  not_done = dl_list_first(&directive_list);
  while (not_done)
  {
    di = dl_list_value(&directive_list);
    if (STRN_EQ(di->name, name, di->len))
    {
      return di;
    }

    not_done = dl_list_next(&directive_list);
  }

  return NULL;
}


int
add_directive(name, len, description, func, program, disabled_flag)
  char  *name;
  int   len;
  char  *description;
  int   (*func)();
  char  *program;
  int   disabled_flag;      /* when "off", this flag is "TRUE" */
{
  directive_struct  *item;

  if (!name || !*name)
  {
    log(L_LOG_ERR, CONFIG, "directive name required");
    return FALSE;
  }
  
  if ((item = find_directive(name)))
  {
    log(L_LOG_WARNING, CONFIG, "duplicate directive '%s', length '%d'", name, len);
    /* FIXME: whether to replace the directive or fail should be
       controlled by an option.  With replacement on, you cannot
       override a built-in directive with an external directive */
    log(L_LOG_WARNING, CONFIG, "duplicate directive '%s' is being replaced", name);
    destroy_directive_data(item);
  }

  item = xcalloc(1, sizeof(*item));
  
  item->name = xstrdup(name);
  if (!len)
  {
    item->len = strlen(name);
  }
  else
  {
    item->len = len;
  }
  
  if (description && *description)
  {
    item->description = xstrdup(description);
  }

  if (program && *program)
  {
    item->program = xstrdup(program);
  }
  
  item->function = func;
  item->disabled_flag = disabled_flag;
  if (item->disabled_flag) 
  { 
    item->cap_bit = 0x0000000;
  }
  else
  {
    item->cap_bit = find_cap(item->name);
  }

  /* if empty, works fine too */
  dl_list_append(&directive_list, item);

  return TRUE;
}


void
destroy_directive_list()
{
  dl_list_destroy(&directive_list);
}


dl_list_type *
get_directive_list()
{
  return(&directive_list);
}




long 
find_cap(directive)
  char  *directive;
{
  if (STR_EQ(directive, "class"))
  {
    return CAP_CLASS;
  }
  if (STR_EQ(directive, "directive"))
  {
    return CAP_DIRECTIVE;
  }
  if (STR_EQ(directive, "display"))
  {
    return CAP_DISPLAY;
  }
  if (STR_EQ(directive, "forward"))
  {
    return CAP_FORWARD;
  }
  if (STR_EQ(directive, "holdconnect"))
  {
    return CAP_HOLDCONNECT;
  }
  if (STR_EQ(directive, "limit"))
  {
    return CAP_LIMIT;
  }
  if (STR_EQ(directive, "notify"))
  {
    return CAP_NOTIFY;
  }
  if (STR_EQ(directive, "quit"))
  {
    return CAP_QUIT;
  }
  if (STR_EQ(directive, "register"))
  {
    return CAP_REGISTER;
  }
  if (STR_EQ(directive, "schema"))
  {
    return CAP_SCHEMA;
  }
  if (STR_EQ(directive, "security"))
  {
    return CAP_SECURITY;
  }
  if (STR_EQ(directive, "soa"))
  {
    return CAP_SOA;
  }
  if (STR_EQ(directive, "status"))
  {
    return CAP_STATUS;
  }
  if (STR_EQ(directive, "xfer"))
  {
    return CAP_XFER;
  }
  if (STR_EQ(directive, "X"))
  {
    return CAP_X;
  }
 
  else
  {
    return 0;
  }
}

/* write the directive enable/disable information. Adds the file name to
   paths_list if successful in creating a file on disk. */
int 
write_directive_file(file, suffix, paths_list)
  char         *file;
  char         *suffix;
  dl_list_type *paths_list;
{

  FILE             *fp = NULL;
  int              not_done;
  directive_struct *dir;
  char             new_file[MAX_FILE];

  if (!file || !*file || !paths_list) return FALSE;

  /* if list empty */
  if (dl_list_empty(&directive_list))
  {
    log(L_LOG_ERR, CONFIG, 
      "Directive list must not be empty - internal error");
    return FALSE;
  }

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);
  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL) 
  {
    log(L_LOG_ERR, CONFIG, "could not create directive file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }
  
  not_done = dl_list_first(&directive_list);
  while (not_done)
  {
    dir = dl_list_value(&directive_list);
    if (!STR_EQ(dir->name, DIR_QUIT) && !STR_EQ(dir->name, DIR_RWHOIS))
    {
      /* if an extended directive - skip */
      if (!is_extended_directive(dir->name)) 
      {
        /* check is enabled or disabled */
        if (dir->disabled_flag) 
        {
          fprintf(fp, "%s: %s\n", dir->name, "no");
        }
        else
        {
          fprintf(fp, "%s: %s\n", dir->name, "yes");
        }
      }
    }
    not_done = dl_list_next(&directive_list);
  }
  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* write extended directive information file. Add the file name to
   paths_list if it was created on disk. Strips the 'X-' prefix of 
   extended directives before writing. */
int 
write_extended_directive_file(file, suffix, paths_list)
  char         *file;
  char         *suffix;
  dl_list_type *paths_list;
{
  FILE             *fp = NULL;
  int              not_done;
  directive_struct *dir;
  char             new_file[MAX_FILE];
  int              xdir_count = 0;

  if (!file || !*file || !paths_list) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL) 
  {
    log(L_LOG_ERR, CONFIG, "could not create x-directive file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  /* go through the directive list */
  xdir_count = 0;
  not_done = dl_list_first(&directive_list);
  while (not_done)
  {
    dir = dl_list_value(&directive_list);
    /* if an extended directive */
    if (is_extended_directive(dir->name)) 
    {
      if (xdir_count > 0) 
      {
        fprintf(fp, "-----\n");
      }
      /* remove the 'X-' prefix from the command before writing */
      fprintf(fp, "command:     %s\n", &(dir->name[2]));
      fprintf(fp, "command-len: %u\n", strlen(&(dir->name[2])));
      fprintf(fp, "description: %s\n", dir->description);
      fprintf(fp, "program:     %s\n", dir->program);
      xdir_count += 1;
    }
    not_done = dl_list_next(&directive_list);
  }
  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* examine the validity of extended directive program path. If not found
   in the path specified, looks in bin-path of rwhois server. Also
   checks for if the program is on disk and executable. Returns
   non-zero value on failure. */
int
examin_xdirective_program(path)
  char *path;
{
  int  ret = 0;
  char new_path[MAX_FILE];

  if (!path)  return ERW_NDEF;
  if (!*path) return ERW_EMTYSTR;

  if (is_rel_path(path)) 
  {
    ret = examin_executable_name(path);
    if (ret)
    {
      bzero(new_path, sizeof(new_path));
      strncpy(new_path, get_bin_path(), sizeof(new_path)-1);
      strncat(new_path, "/", sizeof(new_path)-1);
      strncat(new_path, path, sizeof(new_path)-1);
      ret = examin_executable_name(new_path);
    }
  } 
  else
  {
    ret = examin_executable_name(path);
  }
  return( ret );
}

/* verifies all the directives in the directives list. Makes sure
   at least one normal directive is defined in the list. */
int 
verify_all_directives()
{
  int              not_done;
  int              n_dir;
  int              x_dir;
  directive_struct *dir;

  /* go through the directive list */
  n_dir = 0;
  x_dir = 0;
  not_done = dl_list_first(&directive_list);

  while (not_done)
  {
    dir = dl_list_value(&directive_list);
    if (!verify_directive(dir))
    {
      return FALSE;
    }
    if (is_extended_directive(dir->name)) 
    {
      x_dir += 1;
    }
    else 
    {
      n_dir += 1;
    }
    not_done = dl_list_next(&directive_list);
  }

  if (n_dir <= 0) 
  {
    log(L_LOG_ERR, CONFIG, 
    "directive list not initialized with normal directives - internal error");
    return FALSE;
  }

  return TRUE;
}

