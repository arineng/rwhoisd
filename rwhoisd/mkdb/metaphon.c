/* +++Date last modified: 09-Jun-1996 */

/*
**  METAPHON.C - Phonetic string matching
**
**  The Metaphone algorithm was developed by Lawrence Phillips. Like the
**  Soundex algorithm, it compares words that sound alike but are spelled
**  differently. Metaphone was designed to overcome difficulties encountered
**  with Soundex.
**
**  This implementation was written by Gary A. Parker and originally published
**  in the June/July, 1991 (vol. 5 nr. 4) issue of C Gazette. As published,
**  this code was explicitly placed in the public domain by the author.
*/

#include <ctype.h>
#include "phonetic.h"
#define MAX_LINE	512

/*
**  Character coding array
*/

static char vsvfn[26] = {
      1,16,4,16,9,2,4,16,9,2,0,2,2,2,1,4,0,2,4,4,1,0,0,0,8,0};
/*    A  B C  D E F G  H I J K L M N O P Q R S T U V W X Y Z      */

/*
**  Macros to access the character coding array
*/

#define vowel(x)  (vsvfn[(x) - 'A'] & 1)  /* AEIOU    */
#define same(x)   (vsvfn[(x) - 'A'] & 2)  /* FJLMNR   */
#define varson(x) (vsvfn[(x) - 'A'] & 4)  /* CGPST    */
#define frontv(x) (vsvfn[(x) - 'A'] & 8)  /* EIY      */
#define noghf(x)  (vsvfn[(x) - 'A'] & 16) /* BDH      */

/*
**  metaphone()
**
**  Arguments: 1 - The word to be converted to a metaphone code.
**             2 - A MAXMETAPH+1 char field for the result.
**             3 - Function flag:
**                 If 0: Compute the Metaphone code for the first argument,
**                       then compare it to the Metaphone code passed in
**                       the second argument.
**                 If 1: Compute the Metaphone code for the first argument,
**                       then store the result in the area pointed to by the
**                       second argument.
**
**  Returns: If function code is 0, returns Success_ for a match, else Error_.
**           If function code is 1, returns Success_.
*/

Boolean_T metaphone(const char *Word, char *Metaph, metaphlag Flag)
{
      char *n, *n_start, *n_end;    /* Pointers to string               */
      char *metaph, *metaph_end;    /* Pointers to metaph               */
      char ntrans[512];             /* Word with uppercase letters      */
      char newm[MAXMETAPH + 4];     /* New metaph for comparison        */
      int KSflag;                   /* State flag for X translation     */

      /*
      ** Copy word to internal buffer, dropping non-alphabetic characters
      ** and converting to upper case.
      */

      for (n = ntrans + 1, n_end = ntrans + sizeof(ntrans) - 2;
            *Word && n < n_end; ++Word)
      {
            if (isalpha(*Word))
                  *n++ = toupper(*Word);
      }

      if (n == ntrans + 1)
            return Error_;           /* Return if zero characters        */
      else  n_end = n;              /* Set end of string pointer        */

      /*
      ** Pad with NULs, front and rear
      */

      *n++ = NUL;
      *n   = NUL;
      n    = ntrans;
      *n++ = NUL;

      /*
      ** If doing comparison, redirect pointers
      */

      if (COMPARE == Flag)
      {
            metaph = Metaph;
            Metaph = newm;
      }

      /*
      ** Check for PN, KN, GN, WR, WH, and X at start
      */

      switch (*n)
      {
      case 'P':
      case 'K':
      case 'G':
            if ('N' == *(n + 1))
                  *n++ = NUL;
            break;

      case 'A':
            if ('E' == *(n + 1))
                  *n++ = NUL;
            break;

      case 'W':
            if ('R' == *(n + 1))
                  *n++ = NUL;
            else if ('H' == *(n + 1))
            {
                  *(n + 1) = *n;
                  *n++ = NUL;
            }
            break;

      case 'X':
            *n = 'S';
            break;
      }

      /*
      ** Now loop through the string, stopping at the end of the string
      ** or when the computed Metaphone code is MAXMETAPH characters long.
      */

      KSflag = False_;              /* State flag for KStranslation     */
      for (metaph_end = Metaph + MAXMETAPH, n_start = n;
            n <= n_end && Metaph < metaph_end; ++n)
      {
            if (KSflag)
            {
                  KSflag = False_;
                  *Metaph++ = *n;
            }
            else
            {
                  /* Drop duplicates except for CC    */

                  if (*(n - 1) == *n && *n != 'C')
                        continue;

                  /* Check for F J L M N R  or first letter vowel */

                  if (same(*n) || (n == n_start && vowel(*n)))
                        *Metaph++ = *n;
                  else switch (*n)
                  {
                  case 'B':
                        if (n < n_end || *(n - 1) != 'M')
                              *Metaph++ = *n;
                        break;

                  case 'C':
                        if (*(n - 1) != 'S' || !frontv(*(n + 1)))
                        {
                              if ('I' == *(n + 1) && 'A' == *(n + 2))
                                    *Metaph++ = 'X';
                              else if (frontv(*(n + 1)))
                                    *Metaph++ = 'S';
                              else if ('H' == *(n + 1))
                                    *Metaph++ = ((n == n_start &&
                                          !vowel(*(n + 2))) ||
                                          'S' == *(n - 1)) ? 'K' : 'X';
                              else  *Metaph++ = 'K';
                        }
                        break;

                  case 'D':
                        *Metaph++ = ('G' == *(n + 1) && frontv(*(n + 2))) ?
                              'J' : 'T';
                        break;

                  case 'G':
                        if ((*(n + 1) != 'H' || vowel(*(n + 2))) &&
                              (*(n + 1) != 'N' || ((n + 1) < n_end &&
                              (*(n + 2) != 'E' || *(n + 3) != 'D'))) &&
                              (*(n - 1) != 'D' || !frontv(*(n + 1))))
                        {
                              *Metaph++ = (frontv(*(n + 1)) &&
                                    *(n + 2) != 'G') ? 'J' : 'K';
                        }
                        else if ('H' == *(n + 1) && !noghf(*(n - 3)) &&
                              *(n - 4) != 'H')
                        {
                              *Metaph++ = 'F';
                        }
                        break;

                  case 'H':
                        if (!varson(*(n - 1)) && (!vowel(*(n - 1)) ||
                              vowel(*(n + 1))))
                        {
                              *Metaph++ = 'H';
                        }
                        break;

                  case 'K':
                        if (*(n - 1) != 'C')
                              *Metaph++ = 'K';
                        break;

                  case 'P':
                        *Metaph++ = ('H' == *(n + 1)) ? 'F' : 'P';
                        break;

                  case 'Q':
                        *Metaph++ = 'K';
                        break;

                  case 'S':
                        *Metaph++ = ('H' == *(n + 1) || ('I' == *(n + 1) &&
                              ('O' == *(n + 2) || 'A' == *(n + 2)))) ?
                              'X' : 'S';
                        break;

                  case 'T':
                        if ('I' == *(n + 1) && ('O' == *(n + 2) ||
                              'A' == *(n + 2)))
                        {
                              *Metaph++ = 'X';
                        }
                        else if ('H' == *(n + 1))
                              *Metaph++ = 'O';
                        else if (*(n + 1) != 'C' || *(n + 2) != 'H')
                              *Metaph++ = 'T';
                        break;

                  case 'V':
                        *Metaph++ = 'F';
                        break;

                  case 'W':
                  case 'Y':
                        if (vowel(*(n + 1)))
                              *Metaph++ = *n;
                        break;

                  case 'X':
                        if (n == n_start)
                              *Metaph++ = 'S';
                        else
                        {
                              *Metaph++ = 'K';
                              KSflag = True_;
                        }
                        break;

                  case 'Z':
                        *Metaph++ = 'S';
                        break;
                  }
            }

            /*
            ** Compare new Metaphone code with old
            */

            if (COMPARE == Flag &&
                  *(Metaph - 1) != metaph[(Metaph - newm) - 1])
            {
                  return Error_;
            }
      }

      /*
      ** If comparing, check if Metaphone codes were equal in length
      */

      if (COMPARE == Flag && metaph[Metaph - newm])
            return Error_;

      *Metaph = NUL;
      return Success_;
}

#if 0
/* strupr: Upcases a string. */
char *
strupr(a)
  char *a;
{
  char *b;
 
  for (b = a; *a; a++)
  {
    *a = toupper(*a);
  }
  return (b);
}
#endif


#ifdef TEST
 
#include <stdio.h>
#include <stdlib.h>
 
main(int argc, char *argv[])
{
  char          *a;
  char          *b;
  char          *c;
  char          input_buffer[MAX_LINE];
  char          output_buffer[MAX_LINE];
  char          tmp_buffer[MAX_LINE];
  int           is_word;
  int           done;

 
  input_buffer[0] = '\0';
  output_buffer[0] = '\0';
  tmp_buffer[0] = '\0';

  if (argc != 2)
  {
    puts("Usage: SOUNDEX string");
    return EXIT_FAILURE;
  }

  strcpy(input_buffer,strupr(argv[1]));
  b = input_buffer;
  c = b;
  is_word = 1;
  done = 0;
  while (!done) {
        if(isspace((int) *b) || !(*b)) {
		if (!(*b))
		   done = 1;
                *b = '\0';
                if(!is_word) {
			is_word = 1;
			c = b + 1;
			tmp_buffer[0] = '\0';
			b++;
                        continue;
		}
                metaphone(c,tmp_buffer,1);
                strcat(output_buffer," ");
                strcat(output_buffer,tmp_buffer);
                c = b + 1;
                tmp_buffer[0] = '\0';
		b++;
		continue;
        } else if(!isalpha((int) *b))  {
                is_word = 0;
		b++;
	} else
		b++;
  }
 


 
      printf("metaphone(\"%s\") returned %s\n",
            argv[1], output_buffer);
 
      return EXIT_SUCCESS;
}
 
#endif /* TEST */

