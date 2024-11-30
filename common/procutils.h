/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _PROCUTILS_H_
#define _PROCUTILS_H_

/* includes */

#include "common.h"

/* prototypes */
int initialize_environment_list PROTO((char ***envptr, int env_size));

int add_env_value PROTO((char **env, int env_size, char *var, char *value));

void free_environment_list PROTO((char **env));

int run_program PROTO((char *program, char *param));

int run_env_program PROTO((char **argv, char **envargv));

#endif /* _PROCUTILS_H_ */
