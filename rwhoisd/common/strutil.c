/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "strutil.h"

#include "defines.h"


static int is_id_char PROTO((char value));

/* strutil.c: a collection of string manipulation tools. */
/* History: originally located in misc.c */


/* stripchar: Strips out all occurences of a specific character (in
   place) */
char *
stripchar(str, ch)
  char *str;
  char ch;
{
  int i;
  int j;
  int len;

  if (!str)
  {
    return NULL;
  }
  
  len = strlen(str);
  
  for (i = 0, j = 0; i < len; i++)
  {
    if (str[i] != ch)
    {
      str[j++] = str[i];
    }
  }
  str[j] = '\0';

  return(str);
}

/* strip_trailing: strips any characters matching ch off of the end of
   a string. */
char *
strip_trailing(str, ch)
  char *str;
  char ch;
{
  int i;
  int len;

  if (NOT_STR_EXISTS(str))
  {
    return NULL;
  }
  
  len = strlen(str);
  
  for (i = len - 1; str[i] == ch && i >= 0; i--)
  {
    str[i] = '\0';
  }

  return(str);
}

/* strip_leading: strips any characters matching ch off the front of a
   string. */
char *
strip_leading(str, ch)
  char *str;
  char ch;
{
  char *p1;
  char *p2;

  if (!str)
  {
    return NULL;
  }
  
  p1 = p2 = str;
  while (*p1 == ch)
  {
    p1++;
  }

  /* copy to front only if necessary */
  if (p1 != p2)
  {
    while (*p2)
    {
      *p2++ = *p1++;
    }
  }
  return(str);
}

char *
strip_control(str)
  char *str;
{
  int i;
  int j;
  int len;

  if (!str)
  {
    return NULL;
  }

  len = strlen(str);
  
  for (i = 0, j = 0; i < len; i++)
  {
    if (!iscntrl(str[i]) || str[i] == '\t')
    {
      str[j++] = str[i];
    }
  }
  str[j] = '\0';

  return(str);
}

/* rtrim: strips whitespace off of the end of a string. */
char *
rtrim(str)
  char *str;
{
  int i;

  if (!str)
  {
    return NULL;
  }

  for (i = strlen(str) - 1; i >= 0 && isspace(str[i]); i--)
  {
    str[i] = '\0';
  }

  return(str);
}

/* ltrim: strips the whitespace off the the front of a string */
char *
ltrim(str)
  char *str;
{
  char *p1;
  char *p2;

  if (!str)
  {
    return NULL;
  }
  
  p1 = p2 = str;
  while (isspace(*p1))
  {
    p1++;
  }

  /* copy to front only if necessary */
  if (p1 != p2)
  {
    while (*p1)
    {
      *p2++ = *p1++;
    }
    *p2 = '\0';
  }
  return(str);
}

/* trim: trim whitespace off of both ends of a string (in place) */
char *
trim(str)
  char *str;
{
  if (!str)
  {
    return NULL;
  }
  
  rtrim(str);
  ltrim(str);

  return(str);
}


/* reverses the string */
char *
strrev(str)
  char *str;
{
  char *head;
  char *tail;
  char c;

  if (!str)
  {
    return NULL;
  }
  
  for (head = str, tail = str + strlen(str) - 1; head < tail; 
       head++, tail--)
  {
    c     = *head;
    *head = *tail;
    *tail = c;
  }
  return(str);
}

char *
skip_whitespace(str)
  char  *str;
{
  char  *p = str;

  if (!str)
  {
    return NULL;
  }
  
  while (isspace(*p)) p++;
  return(p);
}

int
count_char(str, c)
  char  *str;
  char  c;
{
  char  *s;
  int   count;

  if (!str)
  {
    return -1;
  }
  
  for (count = 0, s = str; *s; s++)
  {
    if (*s == c) count++;
  }

  return(count);
}

int
count_spaces(str)
  char  *str;
{
  char  *s;
  int   count;

  if (!str)
  {
    return -1;
  }
  
  for (count = 0, s = str; *s; s++)
  {
    if (isspace(*s)) count++;
  }

  return(count);
}


/* strSTR: does a case-insensitve sub-string search */
char *
strSTR(str1, str2)       /*  by Jeff Odum  09/91  */
  char *str1;
  char *str2;
{
  int i;
  int j;
  int x;

  /* return immediately if NULL data */
  if (NOT_STR_EXISTS(str1) || NOT_STR_EXISTS(str2))
  {
    return NULL;
  }

  for (x = 0; str1[x]; x++)
  {
    if (toupper(str1[x]) == toupper(str2[0]))
    {
      /*  Matched first letter */
      for (i=x, j=0;
           (str1[i] && str2[j]) &&
           (toupper(str1[i]) == toupper(str2[j]));
           i++, j++ );

      if (!str2[j])
      {
        /*  Matched whole string  */
        return (&str1[x]);
      }
    }
  }

  return NULL;
}

/* strupr: Upcases a string. */
char *
strupr(a)
  char *a;
{
  char *b;

  if (!a)
  {
    return NULL;
  }
  
  for (b = a; *a; a++)
  {
    *a = toupper(*a);
  }
  return (b);
}

char *
compact_whitespace(str)
  char *str;
{
  int i;
  int j;
  int len;
  int flag;

  if (!str)
  {
    return NULL;
  }
  
  len = strlen(str);
  
  for (i = 0, j = 0, flag = FALSE; i < len; i++)
  {
    if (isspace(str[i]))
    {
      if (!flag)
      {
        str[j] = ' ';
        j++;
        flag = TRUE;
      }
    }
    else
    {
      str[j] = str[i];
      j++;
      flag = FALSE;
    }
  }
  str[j] = '\0';
    
  return(str);
}

/* check if the string has any whitespaces (space, tab ..) */
int
is_no_whitespace_str( str )
  char *str;
{
  if (!str) return FALSE;

  for ( ; *str; str++ )
  {
    if ( isspace(*str) )
    {
      return FALSE;
    }
  }
  return TRUE;
}

/* check if the given character string is just made of digits. */
int
is_number_str( str )
  char *str;
{
  if (!str) return FALSE;

  for ( ; *str; str++ )
  {
    if ( !isdigit(*str) )
    {
      return FALSE;
    }
  }
  return TRUE;
}

/* check if the given character is an id character */
static int
is_id_char( value )
  char value;
{
  return( isalnum(value) || 
          (value == '-') || 
          (value == '_') );
}

/* check if the given string is made of only id characters */
int
is_id_str( value )
  char *value;
{
  int i;

  if (!value) return FALSE;

  for (i = 0; i < strlen(value); i++) 
  {
    if (!is_id_char(value[i])) return FALSE;
  }
  return TRUE;
}
