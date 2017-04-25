/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "fileutils.h"

#include "compat.h"
#include "conf.h"
#include "defines.h"
#include "log.h"
#include "misc.h"
#include "strutil.h"
#include "types.h"

static dl_list_type *split_path_into_list PROTO((char *path));

static char *join_list_into_path PROTO((dl_list_type *path_list,
                                        int abs_path));

static int reduce_path_list PROTO((dl_list_type *path_list));

static char *get_reduced_path PROTO((char *path));

static int make_path_dirs PROTO((char *path, int mode,
                                         dl_list_type *paths_list));

/* ----------------------- LOCAL STATICS ----------------------- */

static char cwd[MAX_FILE + 1];

/* ----------------------- LOCAL FUNCTIONS --------------------- */

static int
get_path_status(path, mode)
  char      *path;
  mode_t    *mode;
{
  struct stat   sb;
  int           status;

  status = stat(path, &sb);

  if (status < 0) {
    /* stat itself failed (file doesn't exist) */
    return FALSE;
  }

  *mode = sb.st_mode;
  return TRUE;
}


static int
generate_dot_lock_name(filename, lockname)
  char  *filename;
  char  *lockname;
{
  char  dir[MAX_FILE];
  char  file[MAX_FILE];

  bzero(dir, sizeof(dir));
  bzero(file, sizeof(file));

  if (!split_path(filename, dir, file))
  {
    return FALSE;
  }
#ifndef USE_SYS_LOCK
  if (*dir)
  {
    sprintf(lockname, "%s/.%s.lock", dir, file);
  }
  else
  {
    sprintf(lockname, ".%s.lock", file);
  }
#else
   if (*dir)
  {
    sprintf(lockname, "%s/.%s.slock", dir, file);
  }
  else
  {
    sprintf(lockname, ".%s.slock", file);
  }
#endif
  return TRUE;
}

static int
generate_uniq_dot_lock_name(filename, lockname)
  char *filename;
  char *lockname;
{
  char  dir[MAX_FILE];
  char  file[MAX_FILE];

  bzero(dir, sizeof(dir));
  bzero(file, sizeof(file));

  if (!split_path(filename, dir, file))
  {
    return FALSE;
  }

  if (*dir)
  {
    sprintf(lockname, "%s/.%s.%d.lock", dir,  file, (int) getpid());
  }
  else
  {
    sprintf(lockname, ".%s.%d.lock", file, (int) getpid());
  }

  return TRUE;
}
/* ----------------------- PUBLIC FUNCTIONS -------------------- */

/* file_exists: tests to see if a file exists.  Note: does not test
      for access. */
int
file_exists(file)
  char  *file;
{
  mode_t    mode;

  if (get_path_status(file, &mode) && S_ISREG(mode)) {
    return TRUE;
  }
  return FALSE;
}

int
directory_exists(dir)
  char  *dir;
{
  mode_t    mode;

  if (get_path_status(dir, &mode) && S_ISDIR(mode)) {
    return TRUE;
  }
  return FALSE;
}

int
is_rel_path(path)
  char  *path;
{
  if (path && *path != '/') {
    return TRUE;
  }
  return FALSE;
}

int
store_current_wd()
{
  bzero(cwd, sizeof(cwd));
  if (getcwd(cwd, sizeof(cwd)) == NULL)
  {
    log(L_LOG_ERR, FILES,
        "store_current_wd: failed to get cwd: %s", strerror(errno));
    return FALSE;
  }

  return TRUE;
}

int
restore_current_wd()
{
  if (chdir(cwd) < 0)
  {
    log(L_LOG_ERR, FILES,
        "chdir to '%s' failed: %s", cwd, strerror(errno));
    return FALSE;
  }

  return TRUE;
}

time_t
get_path_mod_time(path)
  char  *path;
{
  struct stat   sb;
  int           status;

  status = stat(path, &sb);

  if (status < 0) {
    /* stat itself failed (file doesn't exist) */
    return FALSE;
  }

  return(sb.st_mtime);
}

/* split_path: splits path into the directory and file components; if
   there is no directory component, then it just returns the file
   component. */
int
split_path(path, dir, file)
  char  *path;
  char  *dir;
  char  *file;
{
  char  **argv;
  int   argc;
  int   len;

  if (!path || !*path)
  {
    return FALSE;
  }

  if (!split_list(path, '/', 0, &argc, &argv))
  {
    return FALSE;
  }

  strcpy(file, argv[argc - 1]);

  if (argc > 1)
  {
    len = strlen(path) - (strlen(file) + 1);
    strncpy(dir, path, len);
    dir[len] = '\0';
  }
  else
  {
    *dir = '\0';
  }

  free_arg_list(argv);

  return TRUE;
}


/* path_full_to_rel: changes a full pathname to a path relative to the
      root.  Returns NULL if the directory wasn't in the root
      directory, otherwise, return a pointer to the reduced path
      within the full path */
char *
path_full_to_rel(full_path, root_dir)
  char *full_path;
  char *root_dir;
{
  int   root_dir_len  = strlen(root_dir);
  int   full_path_len = strlen(full_path);

  /* if the full path isn't long enough, immediately reject */
  if (full_path_len < root_dir_len) {
    return NULL;
  }

  /* check for the incorrect base */
  if (strncmp(full_path, root_dir, root_dir_len) != 0) {
    return NULL;
  }

  /* check for a different extended base */
  if (full_path_len > root_dir_len && full_path[root_dir_len] != '/') {
    return NULL;
  }

  /* the full path is *exactly* the root directory */
  if (full_path_len == root_dir_len) {
    /* return a pointer to "" */
    return(full_path + root_dir_len);
  }
  return(full_path + root_dir_len + 1);
}

/* path_rel_to_full: basically just concatenates root_dir and
   rel_path; returns NULL if bad data.  It copies the original path
   into the new path if the 'rel_path' isn't actually relative. */
char *
path_rel_to_full(new_path, new_path_len, rel_path, root_dir)
  char *new_path;
  int  new_path_len;
  char *rel_path;
  char *root_dir;
{
  int   root_len;

  /* check for bad data */
  if (!new_path || !root_dir) {
    return NULL;
  }

  if (!is_rel_path(rel_path)) {
    strncpy(new_path, rel_path, new_path_len);
    return(new_path);
  }

  root_len = strlen(root_dir);

  bzero(new_path, new_path_len);

  strncat(new_path, root_dir, new_path_len);
  strncat(new_path, "/", new_path_len - root_len);
  strncat(new_path, rel_path, new_path_len - (root_len + 1));

  return(new_path);
}

/* canonicalize_path: this routine, given a path, will, if necessary,
      convert it to a relative path, and, if chrooted is TRUE, will
      return FALSE if the path isn't under the root directory. It will
      copy the new path into "new_path" */
int
canonicalize_path(new_path, new_path_len, path, root_dir, chrooted,
                  null_allowed)
  char  *new_path;
  int   new_path_len;
  char  *path;
  char  *root_dir;
  int   chrooted;
  int   null_allowed;
{
  char      *p;

  /* first, reject if we are given bad input */
  if (!root_dir)
  {
    return FALSE;
  }

  if (!path)
  {
    if (null_allowed) return TRUE;
    return FALSE;
  }

  /* strip unecessary crap from path; assume root_dir has already had
     this done. */
  trim(path);
  if (strlen(path) > 1)
  {
    strip_trailing(path, '/');
  }

  /* check for the empty string */
  if (!*path)
  {
    if (null_allowed) return TRUE;
    return FALSE;
  }

  p = path;
  if (! is_rel_path(path))
  {
    /* convert to a relative path, if it can */
    p = path_full_to_rel(path, root_dir);
    if (! p)
    {
      /* not in root heirarchy */
      if (chrooted)
      {
        /* can't have that! */
        return FALSE;
      }
      /* otherwise, we just go back to the original full path */
      p = path;
    }
  }

  strncpy(new_path, p, new_path_len);
  return TRUE;
}

/* Returns current date/time in yymmddhhmmss string  */
char *
make_timestamp()
{
  static char   buffer[18];
  struct tm     *tm;
  time_t        t;

  time(&t);
  tm = gmtime(&t);

  strftime(buffer, 18, "%Y%m%d%H%M%S000", tm);

  return(buffer);
}

/* Returns a temp filename */
char *
create_filename(fname, template, spool_directory)
  char *fname;
  char *template;
  char *spool_directory;

{
  sprintf(fname, template, spool_directory, make_timestamp());
  /* FIXME: should use mkstemp; this would require passing back a file
     descriptor and refactoring everything that uses this to use this
     function to open the file. */
  mktemp(fname);

  return(fname);
}

/* Returns a data text filename */
char *
create_db_filename(fname, template, spool_directory, postfix)
  char *fname;
  char *template;
  char *spool_directory;
  char *postfix;
{
  sprintf(fname, template, spool_directory, make_timestamp(), postfix);
  /* FIXME: should use mkstemp. see above. */
  mktemp(fname);

  return(fname);
}

/* FIXME: this routine is intended to allow for either dot-file
   locking or flock/lockf/fcntl style locking via a compilation
   option. */

FILE *
get_file_lock(filename, mode, block)
  char  *filename;
  char  *mode;
  int   block;
{
  FILE  *fp;

  if (STR_EQ(mode, "r"))
  {
    /* we don't actually support read locks */
    return NULL;
  }

#ifndef USE_SYS_LOCK
  if (get_dot_lock(filename, block))
  {
    fp = fopen(filename, mode);
    if (!fp)
    {
      log(L_LOG_ERR, FILES, "could not open file '%s': %s", filename,
          strerror(errno));
      return NULL;
    }

    return(fp);
  }

  return NULL;
#else
  fp = fopen(filename, mode);

  if (!fp)
  {
    log(L_LOG_ERR, FILES, "could not open file '%s': %s", filename,
        strerror(errno));
    return NULL;
  }

  if (sys_file_lock(fileno(fp), FILE_LOCK) < 0)
  {
    log(L_LOG_ERR, FILES, "could not establish system lock on file '%s': %s",
        filename, strerror(errno));
    fclose(fp);
    return NULL;
  }
  log(L_LOG_DEBUG, FILES, "get_file_lock: obtained sys_file_lock on '%s'",
       filename);
  return(fp);
#endif
}

int
release_file_lock(filename, fp)
  char  *filename;
  FILE  *fp;
{

#ifndef USE_SYS_LOCK
  if (fp) fclose(fp);

  if (release_dot_lock(filename))
  {
    return TRUE;
  }

  return FALSE;
#else
  log(L_LOG_DEBUG, FILES, "release_file_lock: released sys_file_lock on '%s'",
      filename);

  if (fp) fclose(fp);

  return TRUE;
#endif
}


int
get_dot_lock(filename, block)
  char  *filename;
  int   block;
{
  char  lockname[MAX_FILE + 1];
  char  tmplockname[MAX_FILE + 1];
  int   tmpfd;
  int   wait_period;
  int   i;

  if (!generate_dot_lock_name(filename, lockname))
  {
    return FALSE;
  }
  if (!generate_uniq_dot_lock_name(filename, tmplockname))
  {
    return FALSE;
  }

#ifndef HAVE_USLEEP
  wait_period = USLEEP_WAIT_PERIOD;
#else
  wait_period = 1;
#endif

  /* create a temporary file, then close it.  If the temp file already
     exists, then creat() will just trunc. it.  (taken from Stevens,
     "Unix Network Programming", p 98) */

  if ( (tmpfd = creat(tmplockname, 0644)) < 0)
  {
    log(L_LOG_ERR, FILES, "unable to create temporary lock file '%s': %s",
        tmplockname, strerror(errno));
    return FALSE;
  }
  close(tmpfd);

  i = 0;

  /* now try to rename the tmp file to the lock file.  This will fail
     if the lock file already exists (i.e., if some other process
     already has a lock. (Stevens, p. 98) */
  while (link(tmplockname, lockname) < 0)
  {
    if (errno == EINTR) continue;

    if (errno != EEXIST)
    {
      log(L_LOG_ERR, FILES,
          "dot locking link error attempting to get lock on '%s': %s",
          filename, strerror(errno));
      return FALSE;
    }

    /* a quadratic backoff: wait_period doubles, plus or minus 15% */
    if (i++ == 4)
    {
      wait_period *= 2;
      wait_period += (wait_period * 0.15) * (getpid() % 2 ? -1 : 1);
    }

    /* wait a period of time before trying again */
#ifdef HAVE_USLEEP
    usleep(wait_period);
#else
    sleep(wait_period);
#endif
  }

  /* clean up after ourselves */
  unlink(tmplockname);

  log(L_LOG_DEBUG, FILES, "established dot lock on '%s'", filename);
  return TRUE;
}

int
release_dot_lock(filename)
  char  *filename;
{
  char  lockname[MAX_FILE + 1];

  generate_dot_lock_name(filename, lockname);

  if (unlink(lockname) < 0)
  {
    log(L_LOG_ERR, FILES, "could not remove lockfile '%s': %s", lockname,
        strerror(errno));
    return FALSE;

  }

  log(L_LOG_DEBUG, FILES, "released dot lock on '%s'", filename);
  return TRUE;
}

int
dot_lock_exists(filename)
  char  *filename;
{
  char  lockname[MAX_FILE + 1];

  generate_dot_lock_name(filename, lockname);

  if (file_exists(lockname))
  {
    return TRUE;
  }

  return FALSE;
}

int
get_placeholder_lock(filename, block, lock_fd)
  char *filename;
  int  block;
  int  *lock_fd;
{
#ifndef USE_SYS_LOCK
  return get_dot_lock(filename, block);
#else
  char lockname[MAX_FILE + 1];
  int  fd;
  int  status;

  if (!generate_dot_lock_name(filename, lockname))
  {
    return FALSE;
  }
  /* FIXME: this routine should value the "block" parameter */

  fd  =  -1;
  while (fd < 0)
  {
    if ( (fd = open(lockname,  O_WRONLY | O_CREAT, 0644)) < 0)
    {
      if (errno == EAGAIN)
      {
        /* we sleep here instead of continuously attacking the kernel */
#ifdef HAVE_USLEEP
        usleep(USLEEP_WAIT_PERIOD);
#else
        sleep(1);
#endif
        continue;
      }
      log(L_LOG_ERR, FILES, "unable to create placeholder lock file '%s': %s",
          lockname, strerror(errno));
      return FALSE;
    }

  }

  lseek(fd, 0L, 0); 
  status = sys_file_lock(fd, FILE_LOCK);

  if (status != 0)
  {
    log(L_LOG_ERR, FILES,
        "attempt to lock placeholder lock file '%s' failed: %s",
        lockname, strerror(errno));
    return FALSE;
  }

  *lock_fd = fd;
  log(L_LOG_DEBUG, FILES, "get_placeholder_lock: got lock on file '%s' (%s)",
      filename, lockname);
  return TRUE;
#endif
}

int
release_placeholder_lock(filename, lock_fd)
  char *filename;
  int  lock_fd;
{
#ifndef USE_SYS_LOCK
  return release_dot_lock(filename);
#else
  log(L_LOG_DEBUG, FILES, "release_placeholder_lock: released lock on '%s'",
      filename);

  close(lock_fd);

  return TRUE;
#endif
}

int
placeholder_lock_exists(filename)
  char *filename;
{
#ifndef USE_SYS_LOCK
  return dot_lock_exists(filename);
#else
  char lockname[MAX_FILE + 1];
  int  fd;
  int  status;

  if (!generate_dot_lock_name(filename, lockname))
  {
    return FALSE;
  }

  fd = open(lockname, O_WRONLY);

  /* if we couldn't open the file, presume that it doesn't exist */
  if (fd < 0)
  {
    return FALSE;
  }

  status = sys_file_lock(fd, FILE_TEST);
  if (status < 0)
  {
    return FALSE;
  }

  return TRUE;
#endif
}

time_t
get_path_mtime(path)
  char      *path;
{
  struct stat   sb;
  int           status;

  status = stat(path, &sb);

  if (status < 0) {
    /* stat itself failed (file doesn't exist) */
    return (time_t) 0;
  }

  return(sb.st_mtime);
}

/* compares two files line-by-line, returns true if same and false if
   different. */
int
file_cmpr(file1, file2)
  char *file1;
  char *file2;
{
  FILE        *fptr1;
  FILE        *fptr2;
  struct stat buf1;
  struct stat buf2;
  char        *lp1;
  char        *lp2;
  char        line1[MAX_LINE];
  char        line2[MAX_LINE];

  if (!file1 || !*file1 || !file2 || !*file2)
  {
    return FALSE;
  }

  if (stat(file1, &buf1))
  {
    return FALSE;
  }

  if (stat(file2, &buf2))
  {
    return FALSE;
  }

  /* initial size check */
  if (buf1.st_size != buf2.st_size)
  {
    return FALSE;
  }

  if ((fptr1 = fopen(file1, "r")) == NULL)
  {
    return FALSE;
  }
  if ((fptr2 = fopen(file2, "r")) == NULL)
  {
    fclose(fptr1);
    return FALSE;
  }

  do {
    lp1 = fgets(line1, MAX_LINE, fptr1);
    lp2 = fgets(line2, MAX_LINE, fptr2);
    if (lp1 && lp2)
    {
      if (strcmp(line1, line2) != 0)
      {
        fclose(fptr1);
        fclose(fptr2);
        return FALSE;
      }
    }
    else if ( (!lp1 && lp2) || (lp1 && !lp2) )
    {
      fclose(fptr1);
      fclose(fptr2);
      return FALSE;
    }
  } while (lp1 && lp2);

  fclose(fptr1);
  fclose(fptr2);
  return TRUE;
}

/* compare two timestamps, currently just uses strcmp(). Returns
   1 if stamp1 is newer than stamp2, 0 if equal, and -1 if older. */
int
timestamp_cmpr(stamp1, stamp2)
  char *stamp1;
  char *stamp2;
{
  return( strcmp(stamp1, stamp2) );
}

/* increments a given timestamp to a larger value, but does not care about
   the month, year, seconds, minutes etc.. ranges while incrementing.
   - this should not go beyond all 99999..99s */
static void
increment_timestamp(stamp)
  char *stamp;
{
  int i;

  for (i=strlen(stamp)-1; i>=0; i--)
  {
    if ((stamp[i] - '0') < 9)
    {
      stamp[i] += 1;
      return;
    }
    else
    {
      stamp[i] = '0';
    }
  }
  return;
}

/* increments a given timestamp if equal or greater than current time stamp,
   else returns the current time stamp. */
char *
get_updated_timestamp(orig_stamp)
  char *orig_stamp;
{
  static char new_stamp[18];
  int         ret;

  /* returns a statically allocated time stamp */
  bzero(new_stamp, sizeof(new_stamp));
  strncpy(new_stamp, make_timestamp(), sizeof(new_stamp)-1);

  ret = timestamp_cmpr(orig_stamp, new_stamp);
  if (ret == 0)
  {
    increment_timestamp(new_stamp);
  }
  else if (ret > 0)
  {
    memset(new_stamp, 0, sizeof(new_stamp));
    strncpy(new_stamp, orig_stamp, sizeof(new_stamp)-1);
    increment_timestamp(new_stamp);
  }

  return( new_stamp );
}

/* examine the path if it is writable, if not split the paths, and again
   check if the directory section is writable. Returns a non-zero
   value on failure. */
int
examin_directory_writable(path)
  char  *path;
{
  char dir[MAX_FILE];
  char file[MAX_FILE];

  if (!path) return ERW_NDEF;

  /* is this directory writable or creatable */
  if (access(path, 2) == -1)
  {
    if (split_path(path, dir, file))
    {
      if (*dir && access(dir, 2) == 0)
      {
        return 0;
      }
      else if (!*dir && is_rel_path(path) && access(".", 2) == 0)
      {
        return 0;
      }
      else if (!*dir && !is_rel_path(path) && access("/", 2) == 0)
      {
        return 0;
      }
    }
    return ERW_WTRDIR;
  }

  return 0;
}

/* checks for the validity of timestamp string. Returns non-zero value
   on failure. */
int
examin_timestamp(stamp)
  char *stamp;
{
  if (NOT_STR_EXISTS(stamp)) return ERW_EMTYSTR;
  if (!is_number_str(stamp)) return ERW_NUMSTR;
  if (!(strlen(stamp) == 17)) return ERW_LENSTR;

  return( 0 );
}

/* examine file name string format, make sure there is no directory by
   that name. Returns non-zero on failure. */
int
examin_file_name(value)
  char *value;
{
  if (NOT_STR_EXISTS(value)) return ERW_EMTYSTR;
  if (!is_no_whitespace_str(value)) return ERW_SPACESTR;
  if (directory_exists(value)) return ERW_DIRWSN;

  return( 0 );
}

/* examine directory name string format, make sure there is no file by
   that name. Returns non-zero on failure. */
int
examin_directory_name(value)
  char *value;
{
  if (NOT_STR_EXISTS(value)) return ERW_EMTYSTR;
  if (!is_no_whitespace_str(value)) return ERW_SPACESTR;
  if (file_exists(value)) return ERW_FILEWSN;

  return( 0 );
}

/* examin if the given file name is a file on disk with executable
   file mode. */
int
examin_executable_name(value)
  char *value;
{
  mode_t mode;

  if (!value) return ERW_NDEF;

  if (!get_path_status(value, &mode)) return ERW_NOFILE;
  if (!S_ISREG(mode) || !(S_IEXEC & mode)) return ERW_EXEPROG;

  return( 0 );
}

/* returns true if the given path is already in the paths_list. Otherwise
   it adds the path to the paths_list and returns false. */
int
dup_config_path_name(paths_list, path, var_name)
  dl_list_type *paths_list;
  char         *path;
  char         *var_name;
{
  int  not_done;
  char *item;
  char *newitem;

  if (!path || !*path) return FALSE;

  if (!dl_list_empty(paths_list))
  {
    not_done = dl_list_first(paths_list);
    while (not_done)
    {
      item = dl_list_value(paths_list);
      if (strcmp(item, path) == 0)
      {
        log(L_LOG_ERR, CONFIG,
            "'%s' path defined for '%s' is already used in the configuration",
            path, var_name);
        return TRUE;
      }
      not_done = dl_list_next(paths_list);
    }
  }

  newitem = xstrdup(path);
  dl_list_append(paths_list, newitem);

  return FALSE;
}

static dl_list_type *
split_path_into_list(path)
  char *path;
{
  char         *token;
  dl_list_type *path_list;

  /* create linked list head */
  path_list = xcalloc(1, sizeof(*path_list));

  dl_list_default(path_list, TRUE, simple_destroy_data);

  token = strtok(path, "/");
  while(token)
  {
    dl_list_append(path_list, xstrdup(token));
    token = strtok(NULL, "/");
  }

  return( path_list );
}

static char *
join_list_into_path(path_list, abs_path)
  dl_list_type *path_list;
  int          abs_path;
{
  static char path[MAX_FILE];
  char        *str;
  int         not_done;

  bzero(path, sizeof(path));
  if (dl_list_empty(path_list))
  {
    if (abs_path)
    {
      strncat(path, "/", sizeof(path)-1);
    }
    return( path );
  }
  not_done = dl_list_first(path_list);
  while (not_done)
  {
    str = dl_list_value(path_list);

    if (*path || abs_path)
    {
      strncat(path, "/", sizeof(path)-1);
    }
    strncat(path, str, sizeof(path)-1);
    not_done = dl_list_next(path_list);
  }

  return( path );
}

static int
reduce_path_list(path_list)
  dl_list_type *path_list;
{
  char *token;
  int  not_done;

  not_done = dl_list_first(path_list);
  while (not_done)
  {
    token = dl_list_value(path_list);

    if (token[0] == '.' && token[1] == '.' && strlen(token) == 2)
    {
      /* delete the current element */
      if (!dl_list_delete(path_list)) return FALSE;
      /* go to the previous element */
      if (!dl_list_prev(path_list)) return FALSE;
      /* delete the element */
      if (!dl_list_delete(path_list)) return FALSE;
    }
    else
    {
      not_done = dl_list_next(path_list);
    }
  }

  return TRUE;
}

/* removes any '..' in the given path */
static char *
get_reduced_path(path)
  char *path;
{
  char         *newpath;
  dl_list_type *path_list;

  if (!path || !*path) return NULL;

  /* get out quickly if conditions are right */
  if (!strstr(path, ".."))
  {
    return( path );
  }

  if ( !(path_list = split_path_into_list(path)) )
  {
    return NULL;
  }
  if ( !reduce_path_list(path_list) )
  {
    dl_list_destroy(path_list);
    return NULL;
  }

  newpath = join_list_into_path(path_list, (!is_rel_path(path)));
  dl_list_destroy(path_list);

  return( newpath );
}

/* converts the given path into an absolute path, while removing any
   '..' references. Then compares the resultant absolute path with
   root dir to check if the path is under root directory of the
   server. */

int
path_under_root_dir(path, rootdir)
  char *path;
  char *rootdir;
{
  char *newpath, fullpath[MAX_FILE];

  if (!rootdir || !path) return FALSE;

  path_rel_to_full(fullpath, sizeof(fullpath), path, rootdir);

  trim(fullpath);
  if (strlen(fullpath) > 1)
  {
    strip_trailing(fullpath, '/');
  }

  if ((newpath = get_reduced_path(fullpath)) == NULL)
  {
    return FALSE;
  }

  if (strncmp(rootdir, newpath, strlen(rootdir)) != 0)
  {
    return FALSE;
  }

  return TRUE;
}

/* returns true if it found the given path in the paths_list. */
int
in_config_path_list(paths_list, path, var_name)
  dl_list_type *paths_list;
  char         *path;
  char         *var_name;
{
  int  not_done;
  char *item;

  if (!paths_list || !path || !*path) return FALSE;

  if (!dl_list_empty(paths_list))
  {
    not_done = dl_list_first(paths_list);
    while (not_done)
    {
      item = dl_list_value(paths_list);
      if (strcmp(item, path) == 0)
      {
        log(L_LOG_ERR, CONFIG,
          "'%s' path defined for '%s' is already used in the configuration",
          path, var_name);
        return TRUE;
      }
      not_done = dl_list_next(paths_list);
    }
  }

  return FALSE;
}

/* Works on paths without '..' in them. */
static int
make_path_dirs(path, mode, paths_list)
  char         *path;
  int          mode;
  dl_list_type *paths_list;
{
  int          not_done;
  char         *dirname;
  char         dirpath[MAX_FILE];
  dl_list_type *dir_list;

  if (!path || !*path || !paths_list) return FALSE;

  /* check for quick exit - try creating first */
  if (directory_exists(path)) return TRUE;
  if (!mkdir(path, mode))
  {
    dl_list_append(paths_list, xstrdup(path));
    return TRUE;
  }

  if ( !(dir_list = split_path_into_list(path)) )
  {
    return FALSE;
  }
  bzero(dirpath, sizeof(dirpath));
  not_done = dl_list_first(dir_list);
  while( not_done )
  {
    dirname = dl_list_value(dir_list);

    if (*dirpath || !is_rel_path(path))
    {
      strncat(dirpath, "/", sizeof(dirpath)-1);
    }
    strncat(dirpath, dirname, sizeof(dirpath)-1);
    if (!directory_exists(dirpath))
    {
      if (mkdir(dirpath, mode))
      {
        dl_list_destroy(dir_list);
        return FALSE;
      }
      /* append path created to the paths_list */
      dl_list_append(paths_list, xstrdup(dirpath));
    }
    not_done = dl_list_next(dir_list);
  }
  dl_list_destroy(dir_list);

  return TRUE;
}

/* open given filename for writing */
FILE *
open_file_to_write(filename, blk_time, paths_list)
  char         *filename;
  int          blk_time;
  dl_list_type *paths_list;
{
  char dir[MAX_FILE];
  char file[MAX_FILE];
  char *newdir;

  /* bad parameters */
  if (!filename || !*filename || !paths_list) return NULL;

  bzero(dir, sizeof(dir));
  bzero(file, sizeof(file));

  split_path(filename, dir, file);

  if (STR_EXISTS(dir))
  {
    if (!(newdir = get_reduced_path(dir))) return NULL;

    if (!make_path_dirs(newdir, 0755, paths_list)) return NULL;
  }

  return( get_file_lock(filename, "w", blk_time) );
}

int
make_config_dir(dirname, mode, paths_list)
  char         *dirname;
  int          mode;
  dl_list_type *paths_list;
{
  char *newdir;

  /* bad parameters */
  if (!dirname || !*dirname || !paths_list) return FALSE;

  if (!(newdir = get_reduced_path(dirname))) return FALSE;

  if (!make_path_dirs(newdir, mode, paths_list)) return FALSE;

  return TRUE;
}
