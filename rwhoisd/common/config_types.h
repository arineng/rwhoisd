/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */
#ifndef _CONFIG_TYPES_H_
#define _CONFIG_TYPES_H_

#include "dl_list.h"

#define S_DIRECTIVE_ALLOW             "allow"
#define S_DIRECTIVE_DENY              "deny"

/* hold punt referral information */
typedef struct _punt_ref_struct
{
  char *punt;
} punt_ref_struct;

/* holds directive security information */
typedef struct _dir_security_struct
{
  char *wrapper;
} dir_security_struct;

/* holds all the rwhois server configuration structures */
typedef struct _rwhois_configs_struct
{
  dl_list_type    *ref_list;  /* list of punt_ref_structs */
  dl_list_type    *dir_allow; /* list of dir_security_structs */
  dl_list_type    *dir_deny;  /* list of dir_security_structs */
} rwhois_configs_struct;


#endif /* _CONFIG_TYPES_H_ */
