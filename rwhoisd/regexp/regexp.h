/*
 * Definitions etc. for regexp(3) routines.
 *
 * Caveat:  this is V8 regexp(3) [actually, a reimplementation thereof],
 * not the System V one.
 */
#ifndef _REGEXP_H_
#define _REGEXP_H_

#define NSUBEXP  10
typedef struct regexp {
        char *startp[NSUBEXP];
        char *endp[NSUBEXP];
        char regstart;          /* Internal use only. */
        char reganch;           /* Internal use only. */
        char *regmust;          /* Internal use only. */
        int regmlen;            /* Internal use only. */
        char program[1];        /* Unwarranted chumminess with compiler. */
} regexp;

extern regexp *regcomp(char *exp);
extern int regexec(regexp *prog, char *string);
extern void regsub(regexp *prog, char *source, char *dest);
extern void regerror(char *);

#endif /* _REGEXP_H_ */
