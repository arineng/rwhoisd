/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "misc.h"

#include "client_msgs.h"
#include "defines.h"
#include "log.h"
#include "strutil.h"
#include "types.h"

/* readline: reads a line from a file descriptor and Strips the
      trailing terminating characters from the line. Returns a pointer
      to the buffer itself */
char *
readline(fp, buffer, size)
  FILE *fp;
  char *buffer;
  int  size;
{
  if (! fgets(buffer, size, fp))
  {
    *buffer = '\0';
    return NULL;
  }

  /* remove all nasty control characters */
  strip_control(buffer);

  /* and remove trailing/leading whitespace */
  trim(buffer);
  
  return(buffer);
}

  

/* new_record: tests to see if 'line' is a record separator.  Returns
      TRUE if it is, FALSE if not */
int
new_record(line)
  char *line;
{
  if (!line || !*line)
  {
    return FALSE;
  }
  
  stripchar(line, '\n');

  if (STRN_EQ(line, "---", 3) || STR_EQ(line, "_NEW_"))
  {
    return(TRUE);
  }

  return(FALSE);
}

/* parse_line: splits a <tag>: <datum> line into its respective
      components. */
int
parse_line(line, tag, datum)
  char *line;
  char *tag;
  char *datum;
{
  char *colon = NULL;
  char *d_ptr = NULL;
  
  /* first, bail out if we have an empty string */
  if (!line || !*line)
  {
    return FALSE;
  }

  /* scan for pound */
  d_ptr = skip_whitespace(line);
  if (*d_ptr == '#')
  {
    return FALSE;
  }
  
  /* now, find the separator character */
  if ( !(colon = strchr(line, ':')) )
  {
    /* it wasn't there so this is an invalid or commented line */
    return FALSE;
  }

  *colon = '\0';
  d_ptr = colon + 1;
  
  strcpy(tag, line);
  rtrim(tag);

  d_ptr = skip_whitespace(d_ptr);
  strcpy(datum, d_ptr);

  /* put the colon back */
  *colon = ':';
  
  return TRUE;
}

/* delimstr: retrieves 'cnt' delimiters from mainbuf into
      cpbuf. Returns TRUE if successful, FALSE if not. */
int
delimstr(mainbuf, delim, cpbuf, cnt)
  char *mainbuf;
  char *delim;
  char *cpbuf;
  int  cnt;
{
  int           i           = 0;
  char          *token;
  static char   *cpbuff     = NULL;
  static int    cpbuff_size = 0;

  /* handle the occasional NULL ptr */
  if (!mainbuf)
  {
    return FALSE;
  }
  
  if (strlen(mainbuf) + 1 > cpbuff_size)
  {

    cpbuff_size = strlen(mainbuf) + 1;

    cpbuff = (char *)xrealloc(cpbuff, cpbuff_size * sizeof(char));
  }

  strcpy(cpbuff, mainbuf);

  token = strtok(cpbuff, delim);

  while ((token != NULL) && (i < cnt))
  {
    i++;
    token = strtok(NULL, delim);
  }
  if (token != NULL)
  {
    strcpy(cpbuf, token);
    return(TRUE);
  }
  else
  {
    return(FALSE);
  }
}

/* get_word: given a cp to a string, write a copy of the next "word"
    to the given buffer, skipping leading whitespace.  a "word" is
    some positive number of contiguous non-whitespace characters.
    next_cp is set to point to after the word, and the function
    returns the word if found, else NULL (with the dest buffer
    unchanged). */
char *
get_word(cp, buf)
  char *cp;
  char *buf;
{
  char *original_buf = buf;

  /* skip leading whitespace */
  while (*cp && isspace(*cp)) cp++;

  /* copy to buf upto next whitespace */
  while (*cp && !isspace(*cp))
  {
    *buf++ = *cp++;
  }

  /* if we accomplished something, terminate the 'buf' string, and
     advance 'cp' (the original text) beyond any trailing whitespace */
  if (buf != original_buf)
  {
    *buf = '\0';
    while (isspace(*cp)) cp++;
    return cp;
  }
  else
  {
    return NULL;
  }
}


/* paste: pastes the new info into the query string */
void
paste(line, cut_start, cut_end, rpl)
  char *line;
  char *cut_start;
  char *cut_end;
  char *rpl;

{
  char  *cp             = line;
  int   i               = 0;
  char  buf[MAX_LINE];

  while (cp <= cut_start)
  {
    buf[i++] = *cp;
    cp++;
  }
  buf[i] = '\0';
  strcat(buf, rpl);
  strcat(buf, cut_end);
  strcpy(line, buf);
}

/* on_off: return the ascii equivalents to the boolean argument */
char *
on_off(b)
  int b;
{
  static char *on  = "ON";
  static char *off = "OFF";

  if (b)
  {
    return (on);
  }
  else
  {
    return (off);
  }
}

/* true_false: returns TRUE if the string is set to an acceptable true
      value: "true", "yes", 'on".  FALSE otherwise. */
int
true_false(b)
  char *b;
{
  trim(b);
  
  if (STR_EQ(b, "TRUE") || STR_EQ(b, "YES") || STR_EQ(b, "ON"))
  {
    return (TRUE);
  }
  else
  {
    return (FALSE);
  }
}

char *
true_false_str(b)
  int   b;
{
  if (b)
    return "TRUE";
  return "FALSE";
}
      

/* get_tuple: parses a <tag1>:<tag2>:<datum> line. Returns TRUE if it
      succeeded, FALSE if not */
int
get_tuple(tag1, tag2, data, line)
  char *tag1;
  char *tag2;
  char *data;
  char *line;
{
  char str[MAX_LINE];

  if (line && *line && parse_line(line, tag1, str))
  {
    if (*str && parse_line(str, tag2 , data))
    {
      return TRUE;
    }
  }
  return FALSE;
}


int
split_arg_list(list, argcptr, argvptr)
  char *list;
  int  *argcptr;
  char ***argvptr;
{
    char            **argv;
    register char   *p;
    register char   *q;
    char            *list_copy;
    int             size            = 0;
    int             mode            = 0;
    char            preserve_char   = 0;
    int             i;

    if (!list || !*list)
    {
      *argcptr = 0;
      *argvptr = NULL;
      return FALSE;
    }
    
    /* get an estimate for the size of the list by counting spaces */
    size = count_spaces(list);
    size += 2; /* fudge factor */

    list_copy = xstrdup(list);

    /* allocate space for the string array */
    argv = (char **) xcalloc(1, (size * sizeof(char *)));
    
    /* p is the trailing pointer, q is the lead */
    p = q = list_copy;
    i = 0;
    
    while (*q)
    {
      /* skip leading whitespace */
      while (isspace(*q))
      {
        q++;
      }

      /* deal with quotes and braces */
      if (*q == '\"' || *q == '\'' || *q == '{')
      {
        preserve_char = *(q++); /* advance beyond quote */
        mode = 1;
      }

      p = q;
      
      if (mode)
      {
        /* scan for the preserve char or \0 */
        while (*q && *q != preserve_char)
        {   
          q++;
        }
      }
      else
      {
        /* scan for whitespace or \0 */
        while (*q && !isspace(*q))
        {
          q++;
        }
      }

      if (*q)
      {
        *(q++) = '\0';
      }

      if (i == 0)
      {
        argv[i++] = list_copy;
      }
      else
      {
        argv[i++] = p;
      }
    }

    /* shrink the argv size to fit reality (argc + 1) */
    argv = (char **) xrealloc(argv, sizeof(char *) * (i + 1));
    argv[i] = NULL;
    
    *argvptr = argv;
    *argcptr = i;

    return TRUE;
}

/* split_list: splits 'list' into components separated by 'sep'.  It
     will avoid adding NULL elements to the middle of the list and
     terminate the list with a NULL array element.  free argv[0] and
     argv when done (free_arg_list). */
int
split_list(list, sep, max_fields, argcptr, argvptr)
  char  *list;
  char  sep;
  int   max_fields;
  int   *argcptr;
  char  ***argvptr;
{
  char          **argv;
  register char *p;
  char          *list_copy;
  int           size        = 0;
  int           i;
  int           num_char;
  
  /* estimate the size of the list */
  num_char = count_char(list, sep);
  if (max_fields > 0)
  {
    size = ((num_char < max_fields) ?  num_char : max_fields) + 2;
  }
  else
  {
    size = num_char + 2;
  }
  
  list_copy = xstrdup(list);

  /* allocate the list */
  argv = (char **)xcalloc(1, (size *sizeof(char *)));

  p       = list_copy;
  argv[0] = list_copy;
  i       = 1;
  while (*p)
  {
    /* if we've already reached max fields, then *p cannot be a
       separator (this allows the separator character to be the first
       char in the last field) */
    if (*p == sep)
    {
      *p = '\0';
      p++;

      /* a trailing separator char is ignored */
      if (*p != '\0')
      {
        argv[i++] = p;
        if (max_fields && (i == max_fields)) break;
      }
    }
    else
    {
      p++;
    }
  }
  
  if (size != i + 1)
  {
    argv = (char **) xrealloc(argv, sizeof(char *) * (i + 1));
  }
  argv[i] = NULL;

  *argvptr = argv;
  *argcptr = i;

  return TRUE;
}

void
free_arg_list(argv)
  char **argv;
{
  /* first, if possible, free argv[0], which should be the start of
     the copied list string */
  if (argv && argv[0])
  {
    free(argv[0]);
  }

  /* now free the string array itself */
  if (argv)
  {
    free(argv);
  }
}


/* The "safe" memory routines */

void *
xmalloc(bytes)
  size_t bytes;
{
  char *cp;
 
  if (bytes == 0)
  {
    bytes = 1;
  }
 
  cp = malloc(bytes);
  if (cp == NULL)
  {
    log(L_LOG_ALERT, UNKNOWN,
        "can not allocate %lu bytes", (unsigned long) bytes);
    exit(1);
  }
  return (cp);
}

void *
xcalloc(nelem, size)
  size_t nelem;
  size_t size;
{
  char  *cp;

  if (nelem == 0)
  {
    nelem = 1;
  }
  if (size == 0)
  {
    size = 1;
  }
  
  cp = calloc(nelem, size);
  if (cp == NULL)
  {
    log(L_LOG_ALERT, UNKNOWN,
        "can not allocate %lu bytes", (unsigned long) (nelem * size));
    exit(1);
  }
  return (cp);
}

void *
xrealloc(ptr, bytes)
  void      *ptr;
  size_t    bytes;
{
  char *cp;
 
  if (!ptr)
  {
    cp = malloc(bytes);
  }
  else
  {
    cp = realloc(ptr, bytes);
  }

  if (cp == NULL)
  {
    log(L_LOG_ALERT, UNKNOWN, "can not reallocate %lu bytes",
        (unsigned long) bytes);
    exit(1);
  }

  return(cp);
}

char *
xstrdup (str)
  const char *str;
{
  char *s;
 
  if (str == NULL)
  {
    return (char *) NULL;
  }

  s = xmalloc(strlen(str) + 1);
  (void) strcpy(s, str);

  return(s);
}

void *
xmemdup(buf, bytes)
  const void    *buf;
  size_t        bytes;
{
  void  *b;
  
  if (buf == NULL)
  {
    return (void *)NULL;
  }

  b = xmalloc(bytes);
  bcopy(buf, b, bytes);

  return(b);
}


char *
regncpy(result, prog, item, len)
  char   *result;
  regexp *prog;
  int    item;
  int    len;
{
  int   slice_length;
  
  slice_length = prog->endp[item] - prog->startp[item];

  if (slice_length < len) len = slice_length;

  strncpy(result, prog->startp[item], len);

  return(result);
}

void
randomize()
{
  int seed;

  seed = time(NULL) ^ getpid();
  srand(seed);
}

char *
generate_salt()
{
  int         r[2]; 
  static char s[3];
  int         i;

  for (i = 0; i < 2; i++)
  {
    r[i] = rand() % 64;
    if (r[i] < 12)
    {
      s[i] = 46 + r[i]; /* ./0-9 */
    }
    else if (r[i] < 38)
    {
      s[i] = 53 + r[i];
    }
    else /* r[i] < 64 */
    {
      s[i] = 59 + r[i]; /* a-z */
    }

  }

  s[2] = '\0';

  return(s);
}
