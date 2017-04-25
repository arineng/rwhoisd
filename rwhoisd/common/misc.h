/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _MISC_H_
#define _MISC_H_

/* includes */

#include "common.h"
#include "regexp.h"

/* prototypes */

char *readline PROTO((FILE *fp, char *buffer, int size));

int new_record PROTO((char *line));

int parse_line PROTO((char *line, char *tag, char *datum));

int delimstr PROTO((char *mainbuf, char *delim, char *cpbuf, int cnt));

char *get_word PROTO((char *cp, char *buf));

void paste PROTO((char *line, char *cut_start, char *cut_end, char *rpl));

char *on_off PROTO((int bool));

int true_false PROTO((char *bool));

int get_tuple PROTO((char *tag1, char *tag2, char *data, char *line));

int split_arg_list PROTO((char *list, int *argcptr, char ***argvptr));

int split_list PROTO((char *list, char sep, int max_fields,
                      int *argcptr, char ***argvptr));

void free_arg_list PROTO((char **argv));

void *xmalloc PROTO((size_t bytes));

void *xcalloc PROTO((size_t nelem, size_t size));

void *xrealloc PROTO((void *ptr, size_t bytes));

char *xstrdup PROTO((const char *str));

void *xmemdup PROTO((const void *buf, size_t bytes));

char *regncpy PROTO((char *result, regexp *prog, int item, int len));

char *true_false_str PROTO((int bool));

void randomize PROTO((void));

char *generate_salt PROTO((void));

#endif /* _MISC_H_ */
