/* +++Date last modified: 02-Nov-1995 */

/*
**  PHONETIC.H - Snippets header file for functions to perform
**             phonetic string matching.
*/

#ifndef PHONETIC__H
#define PHONETIC__H


/* +++Date last modified: 17-Oct-1996 */

/*
** This stuff was cut from:
**  SNIPTYPE.H - Include file for SNIPPETS data types and commonly used macros
*/


#include <stdlib.h>                             /* For free()           */
#include <string.h>                             /* For NULL & strlen()  */

typedef enum {Error_ = -1, Success_, False_ = 0, True_} Boolean_T;

#define NUL '\0'
#define LAST_CHAR(s) (((char *)s)[strlen(s) - 1])
#define TOBOOL(x) (!(!(x)))
#define FREE(p) (free(p),(p)=NULL)

/*
**  File METAPHON.C
*/

/*
**  MAXMETAPH is the length of the Metaphone code.
**
**  Four is a good compromise value for English names. For comparing words
**  which are not names or for some non-English names, use a longer code
**  length for more precise matches.
**
**  The default here is 5.
*/

#define MAXMETAPH 5

typedef enum {COMPARE, GENERATE} metaphlag;

Boolean_T metaphone(const char *Word, char *Metaph, metaphlag Flag);

#endif /* PHONETIC__H */
