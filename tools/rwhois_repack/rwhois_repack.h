#ifndef _RWHOIS_REPACK_H_
#define _RWHOIS_REPACK_H_

#include "common.h"

/* types */

typedef struct
{
  long size_threshold;
  int  dry_run_flag;
  int  validate_flag;
  int  verbose_flag;
  int  delete_flag;
  char *config_file;
  char *aa_name;
  char *class_name;
  char *substring;
} repack_options_struct;


#endif /* _RWHOIS_REPACK_H_ */
