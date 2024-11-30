/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _READ_CONFIG_H_
#define _READ_CONFIG_H_

/* includes */

#include "common.h"
#include "config_types.h"

/* prototypes */

int read_all_config_files PROTO((char *config_file, int chrooted));

int read_rwhois_config_files PROTO((char                  *config_file,
                                    rwhois_configs_struct *rwconf,
                                    int                   chrooted));

int write_all_config_files PROTO((char                  *config_file,
                                  char                  *suffix,
                                  rwhois_configs_struct *rwconf));

int verify_all_config PROTO((rwhois_configs_struct *rwconf));

int def_init_all_config PROTO((rwhois_configs_struct *rwconf));

void destroy_all_config PROTO((rwhois_configs_struct *rwconf));

#endif /* _READ_CONFIG_H_ */

