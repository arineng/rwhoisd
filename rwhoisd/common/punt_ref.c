/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#include "punt_ref.h"

#include "auth_area.h"
#include "common_regexps.h"
#include "compat.h"
#include "defines.h"
#include "fileutils.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"

static int create_punt_ref PROTO((dl_list_type **ref_list));

static int verify_punt_ref PROTO((punt_ref_struct *referral));

static int count_punt_ref_entries PROTO((dl_list_type *ref_list, char *punt));

/* --------------------- Local Functions ------------------ */

/* create and setup punt-referral list. */
static int
create_punt_ref(ref_list)
  dl_list_type **ref_list;
{
  if (!ref_list || *ref_list) return FALSE;

  *ref_list = xcalloc(1, sizeof(**ref_list));

  if (!dl_list_default(*ref_list, TRUE, destroy_punt_ref_data))
  {
    log(L_LOG_ERR, CONFIG, "Error in creating punt/root referral list");
    return FALSE;
  }

  return TRUE;
}

/* verifies the contents of punt referral structure. */
static int
verify_punt_ref(referral)
  punt_ref_struct *referral;
{
  int ret;

  if (!referral) return FALSE;

  if ( (ret = examin_punt_ref(referral->punt)) )
  {
    log(L_LOG_ERR, CONFIG,
        "root referral server '%s' record has invalid format",
        referral->punt, examin_error_string(ret));
    return FALSE;
  }
  return TRUE;
}

/* count the number of times a punt-referral was found in the list. */
static int
count_punt_ref_entries(ref_list, punt)
  dl_list_type *ref_list;
  char *punt;
{
  int not_done, count;
  punt_ref_struct *referral;
  dl_node_type      *orig_posn;

  if (!ref_list || !punt) return( 0 );

  if (dl_list_empty(ref_list)) return( 0 );

  /* save the current position */
  orig_posn = dl_list_get_pos(ref_list);

  count = 0;
  not_done = dl_list_first(ref_list);
  while (not_done)
  {
    referral = dl_list_value(ref_list);
    if (STR_EQ(referral->punt, punt))
    {
      count++;
    }
    not_done = dl_list_next(ref_list);
  }

  /* restore the saved position */
  dl_list_put_pos(ref_list, orig_posn);

  return( count );
}

/* --------------------- Public Functions ----------------- */

/* examins punt referal string format. Looks for two formats of
   punt-referral. Returns non-zero value on failure. */
int
examin_punt_ref(punt_str)
  char *punt_str;
{
  static regexp *old_ref_exp = NULL;
  static regexp *url_exp     = NULL;

  if (NOT_STR_EXISTS(punt_str)) return ERW_EMTYSTR;

  /* initialize regular expressions */
  if (!old_ref_exp)
  {
    old_ref_exp = regcomp(ADMIN_PUNTREF_REGEXP);
  }
  if (!url_exp)
  {
    url_exp = regcomp(ADMIN_PUNTURL_REGEXP);
  }

  if (regexec(old_ref_exp, punt_str) && regexec(url_exp, punt_str))
  {
    return ERW_PUNTSTR;
  }
  return( 0 );
}


/* reads punt referral information from file. Creates the punt-referral
   list. */
int
read_punt_file (file, ref_list)
  char         *file;
  dl_list_type **ref_list;
{
  FILE         *fp              = NULL;
  char         line[BUFSIZ];

  if (!file || !ref_list) return FALSE;

  if ((fp = fopen(file, "r")) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "cannot open root_referral_file '%s': %s", file, strerror(errno));
    return FALSE;
  }

  /* def-init the list */
  destroy_punt_ref_list(ref_list);
  if (!create_punt_ref(ref_list))
  {
    fclose(fp);
    return FALSE;
  }

  set_log_context(file, 0, -1);

  bzero(line, sizeof(line));

  while (readline(fp, line, BUFSIZ))
  {
    inc_log_context_line_num(1);

    /* first, skip if we have an empty string */
    if (!*line)
    {
      continue;
    }

    /* skip commments */
    if (*line == '#')
    {
      continue;
    }

    if (!add_punt_ref(ref_list, line))
    {
      log(L_LOG_ERR, CONFIG,
          "invalid punt or root referral string '%s' %s",
          line, file_context_str());
      fclose(fp);
      return FALSE;
    }

  } /* while */

  fclose(fp);

  return TRUE;
}

/* write punt referral information to a file on disk. Uses suffix to create
   a new file name. Adds the created file name to the paths_list. */
int
write_punt_file(file, suffix, ref_list, paths_list)
  char         *file;
  char         *suffix;
  dl_list_type *ref_list;
  dl_list_type *paths_list;
{
  FILE            *fp;
  int             not_done;
  char            new_file[MAX_FILE];
  punt_ref_struct *item;

  if (!file || !*file || !ref_list) return FALSE;

  bzero(new_file, sizeof(new_file));
  strncpy(new_file, file, sizeof(new_file)-1);
  strncat(new_file, suffix, sizeof(new_file)-1);

  if ((fp = open_file_to_write(new_file, 60, paths_list)) == NULL)
  {
    log(L_LOG_ERR, CONFIG,
        "could not create punt referral file '%s': %s",
        new_file, strerror(errno));
    return FALSE;
  }

  not_done = dl_list_first(ref_list);
  while (not_done)
  {
    item = dl_list_value(ref_list);
    fprintf(fp, "%s\n", item->punt);
    not_done = dl_list_next(ref_list);
  }

  release_file_lock(new_file, fp);

  dl_list_append(paths_list, xstrdup(new_file));

  return TRUE;
}

/* verify the contents of the rwhois punt-referral list. Check for any
   duplicates in the list. */
int
verify_punt_ref_list(ref_list)
  dl_list_type *ref_list;
{
  int             not_done;
  punt_ref_struct *referral;

  if (!ref_list) return FALSE;

  if (dl_list_empty(ref_list)) {
    log(L_LOG_WARNING, CONFIG,
        "Warning: Punt referral list is empty");
    return TRUE;
  }

  not_done = dl_list_first(ref_list);
  while (not_done)
  {
    referral = dl_list_value(ref_list);
    if (!verify_punt_ref(referral))
    {
      return FALSE;
    }

    if (count_punt_ref_entries(ref_list, referral->punt) > 1)
    {
      log(L_LOG_ERR, CONFIG,
        "duplicate punt referral '%s' found in the list", referral->punt);
      return FALSE;
    }

    not_done = dl_list_next(ref_list);
  }

  return TRUE;
}

/* initialize the punt-referral list with defaults. */
int
def_init_punt_ref(ref_list)
  dl_list_type **ref_list;
{
  if (!ref_list) return FALSE;

  if (*ref_list)
  {
    destroy_punt_ref_list(ref_list);
  }
  if (!create_punt_ref(ref_list))
  {
    return FALSE;
  }

  return TRUE;
}

/* free-up punt referral information structure */
int
destroy_punt_ref_data(referral)
  punt_ref_struct *referral;
{

  if (!referral) return TRUE;

  if (referral->punt)
  {
    free(referral->punt);
  }

  free(referral);

  return TRUE;
}

/* free-up the complete punt-referral list. */
void
destroy_punt_ref_list(ref_list)
  dl_list_type **ref_list;
{
  if (!ref_list) return;

  dl_list_destroy(*ref_list);
  *ref_list = NULL;
}

/* add punt-referral (if not already in the list) to the list. */
int
add_punt_ref(ref_list, punt_str)
  dl_list_type **ref_list;
  char         *punt_str;
{
  int             ret;
  punt_ref_struct *referral;

  if (!ref_list || !punt_str || !*ref_list) return FALSE;

  if ((ret = examin_punt_ref(punt_str)))
  {
    log(L_LOG_ERR, CONFIG,
        "invalid punt or root referral string '%s': %s",
        punt_str, examin_error_string(ret));
    return FALSE;
  }

  if (find_punt_ref((*ref_list), punt_str))
  {
    log(L_LOG_ERR, CONFIG,
        "punt referral '%s' already defined in the list", punt_str);
    return FALSE;
  }

  referral = xcalloc(1, sizeof(*referral));

  referral->punt = xstrdup(punt_str);

  if (!dl_list_append((*ref_list), referral))
  {
    log(L_LOG_ERR, CONFIG, "Error in appending punt referral '%s' to list",
        referral->punt);
    destroy_punt_ref_data(referral);
    return FALSE;
  }

  return TRUE;
}

/* searches for a punt-referral in the list. Returns the punt-referral
   structure that matched else returns NULL. */
punt_ref_struct *
find_punt_ref(ref_list, punt)
  dl_list_type *ref_list;
  char         *punt;
{
  int             not_done;
  punt_ref_struct *referral = NULL;

  if (!punt) return FALSE;

  if (dl_list_empty(ref_list)) return( NULL );

  not_done = dl_list_first(ref_list);
  while (not_done)
  {
    referral = dl_list_value(ref_list);
    if (STR_EQ(referral->punt, punt))
    {
      return( referral );
    }
    not_done = dl_list_next(ref_list);
  }

  return( NULL );
}

/* delete a punt referral from the list. */
int
del_punt_ref(ref_list, punt)
  dl_list_type **ref_list;
  char         *punt;
{
  if (!ref_list || !punt || !*punt) return FALSE;

  if (!find_punt_ref((*ref_list), punt))
  {
    log(L_LOG_ERR, CONFIG,
        "Punt referral item '%s' not found in list",
        punt);
    return FALSE;
  }

  if (!dl_list_delete((*ref_list)))
  {
    log(L_LOG_ERR, CONFIG,
        "Error deleting punt referral item '%s' from list", punt);
    return FALSE;
  }

  return TRUE;
}
