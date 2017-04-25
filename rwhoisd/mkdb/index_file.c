/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "index_file.h"

#include "defines.h"
#include "fileinfo.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"

/* ------------------- Private Functions -------------------- */

static char * 
mkdb_ft_2_ft_templ(mkdb_type)
  mkdb_file_type mkdb_type;
{
  switch(mkdb_type)
  {
  case MKDB_EXACT_INDEX_FILE:
    return(INDEX_EXACT_FILE_TEMPL);
  case MKDB_CIDR_INDEX_FILE:
    return(INDEX_CIDR_FILE_TEMPL);
  case MKDB_SOUNDEX_INDEX_FILE:
    return(INDEX_SOUNDEX_FILE_TEMPL);
  default:
    return("");
  }
}

static char *
translate_type_to_str(mkdb_type)
  mkdb_file_type mkdb_type;
{
  switch(mkdb_type)
  {
  case MKDB_EXACT_INDEX_FILE:
    return("exact");
  case MKDB_CIDR_INDEX_FILE:
    return("cidr");
  case MKDB_SOUNDEX_INDEX_FILE:
    return("soundex");
  default:
    return("");
  }
}

static char *
generate_index_file_tmpname(type, prefix)
  mkdb_file_type type;
  char           *prefix;
{
  char           tmpname[MAX_FILE + 1];
  
  if (NOT_STR_EXISTS(prefix))
  {
    prefix = INDEX_DEFAULT_BASE_NAME;
  }

  /* This should generate a unique file name since there should only be
     one index file per type per process at any given time. */
  sprintf(tmpname, "%s-%s-tmp.XXXXXX", prefix, translate_type_to_str(type));
  mktemp(tmpname);
  strcat(tmpname, ".ndx");
  
  return xstrdup(tmpname);
} 

/* create_index_fp: creates an index_fp_struct and fills it out */
static index_fp_struct *
create_index_fp(type, class, auth_area, base_dir, base_name)
  mkdb_file_type   type;
  class_struct     *class;
  auth_area_struct *auth_area;
  char             *base_dir;
  char             *base_name;
{
  index_fp_struct *file;
  char            *name;

  file = xcalloc(1, sizeof(*file));

  file->type = type;

  if (STR_EXISTS(base_name))
  {
    strncpy(file->prefix, base_name, sizeof(file->prefix));
  }
  
  name = generate_index_file_tmpname(type, base_name);

  path_rel_to_full(file->real_filename, MAX_FILE, name, class->db_dir);

  free(name);
  
  sprintf(file->tmp_filename, "%s.tmp", file->real_filename);
  
  file->fp = NULL;

  return(file);
}

static int
does_index_type_exist(type, index_file_list)
  mkdb_file_type    type;
  dl_list_type      *index_file_list;
{
  index_fp_struct *index_file;
  int             not_done;
  
  if (!index_file_list || dl_list_empty(index_file_list))
  {
    return FALSE;
  }

  not_done = dl_list_first(index_file_list);
  while(not_done)
  {
    index_file = dl_list_value(index_file_list);
    if (index_file->type == type)
    {
      return TRUE;
    }
    not_done = dl_list_next(index_file_list);
  }
  return FALSE;
}

/* -------------------- Public Functions -------------------- */

/* given a type and prefix, and spool directory, generate the real
   filename template. */
char *
generate_index_file_basename(type, spool_directory, prefix)
  mkdb_file_type type;
  char           *spool_directory;
  char           *prefix;
{
  char           template[MAX_FILE];
  
  if (NOT_STR_EXISTS(prefix))
  {
    prefix = INDEX_DEFAULT_BASE_NAME;
  }
  sprintf(template, "%s/%s", spool_directory, prefix);
  strcat(template, mkdb_ft_2_ft_templ(type));

  return xstrdup(template);
}


/* NOTE: this function is very important. If two given indexing
   methods use the same mkdb file type you can map that meaning
   here. It is unclear whether this is the case but there needs to be
   some break between the indexing method and the mkdb file type. */
mkdb_file_type
convert_file_type(attr_index)
  attr_index_type attr_index;
{
  switch(attr_index)
  {
  case INDEX_EXACTLY:
    return(MKDB_EXACT_INDEX_FILE);
  case INDEX_SOUNDEX:
    return(MKDB_SOUNDEX_INDEX_FILE);
  case INDEX_CIDR:
    return(MKDB_CIDR_INDEX_FILE);
  default:
    return(MKDB_NO_FILE);
  }
}
 
index_fp_struct *
find_index_file_by_type(files, type)
  dl_list_type   *files;
  mkdb_file_type type;
{
  index_fp_struct *file;
  int             found = 0;
 
  dl_list_first(files);
  do
  {
    file = dl_list_value(files);
    if (file->type == type)
    {
      found = 1;
      break;
    }
  }  while (dl_list_next(files));
 
  if (found)
  {
    return(file);
  }
  else
  {
    return(NULL);
  }
}


/* build_index_list: given a class, auth-area and base directory fill out a 
     dl_list with blank index_fp_structs with only the type set. Note
     the condition when the type is INDEX_ALL. In that case we add all
     of the types and just exit because we've added 'em all and
     there's no sense in looking at any more of 'em.*/
int
build_index_list(class, auth_area, index_file_list, base_dir, base_name)
  class_struct     *class;
  auth_area_struct *auth_area;
  dl_list_type     *index_file_list;
  char             *base_dir;
  char             *base_name;
{
  dl_list_type     *attr_list;
  int              not_done;
  attribute_struct *val;
  index_fp_struct  *index_file;
  attr_index_type  x;
  mkdb_file_type   y;

  if (!class || !class->name || 
      !index_file_list)
  {
    return FALSE;
  }


  attr_list = &(class->attribute_list);
  not_done  = dl_list_first(attr_list);

  x = INDEX_NONE;
  y = MKDB_NO_FILE;

  while (not_done)
  {
    val = dl_list_value(attr_list);
    if (val->index == INDEX_NONE)
    {
      not_done = dl_list_next(attr_list);
      continue;
    }

    /* if the index type for this attribute is INDEX_ALL then we have  
       to run through all of the available index types and set them
       but once we've done that we can exit because we do this for the
       class not the attribute. */
    if (val->index == INDEX_ALL)
    {
      for (x = INDEX_NONE; x != INDEX_MAX_TYPE; x++)
      {
        if (x == INDEX_NONE || x == INDEX_ALL)
        {
          continue;
        }
        /* if this type isn't already in there then add it */
        y = convert_file_type(x);
        if (!does_index_type_exist(y, index_file_list))
        {
          index_file = create_index_fp(y, class, auth_area, base_dir,
                                       base_name);
          dl_list_append(index_file_list, index_file);
        }
      }
      /* break out of the while loop because we've added them all already */
      break;
    } /* if */
        
    /* if this type isn't already in there then add it */
    y = convert_file_type(val->index);
    
    if (!does_index_type_exist(y, index_file_list))
    {
      index_file = create_index_fp(y, class, auth_area, base_dir, base_name);
      dl_list_append(index_file_list, index_file);
    } /* if */
    not_done = dl_list_next(attr_list);
  } /* while */

  /* if we didn't create anything return FALSE */
  if (dl_list_empty(index_file_list))
  {
    return FALSE;
  }
  else
  {
    return TRUE;
  }
} /* get_index_list_by_class */

  

int
unlink_index_tmp_files(index_file_list)
   dl_list_type  *index_file_list;
{
  index_fp_struct *index_file;
  int             not_done;
  
  if (!index_file_list)
  {
    return FALSE;
  }

  not_done = dl_list_first(index_file_list);

  while (not_done)
  {
    index_file = dl_list_value(index_file_list);

    if (! unlink(index_file->tmp_filename))
    {
      log(L_LOG_WARNING, MKDB,
          "could not delete temporary index file '%s': %s",
          index_file, strerror(errno));
    }

    not_done = dl_list_next(index_file_list);
  }

  return TRUE;
}

int
destroy_index_fp_data(data)
  index_fp_struct *data;
{
  if (!data)
  {
    return TRUE;
  }

  if (data->fp)
  {
    fclose(data->fp);
  }
 
  free(data);

  return TRUE;
}
