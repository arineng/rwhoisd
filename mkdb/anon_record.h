/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _ANON_RECORD_H_
#define _ANON_RECORD_H_

/* includes */

#include "common.h"
#include "types.h"


/* prototypes */

anon_av_pair_struct *get_anon_av_pair PROTO((char            *line,
                                             int             validate_flag,
                                             av_parse_result *status));

anon_record_struct *
mkdb_read_anon_record PROTO((int              data_file_no,
                             int              validate_flag,
                             rec_parse_result *status,
                             FILE             *fp));

anon_av_pair_struct *
find_anon_attr_in_rec PROTO((anon_record_struct *anon_rec,
                             char               *attr_name));

anon_av_pair_struct *
find_anon_auth_area_in_rec PROTO((anon_record_struct *anon_rec));

anon_av_pair_struct *
find_anon_class_in_rec PROTO((anon_record_struct *anon_rec));

anon_av_pair_struct *
find_anon_updated_in_rec PROTO((anon_record_struct *anon_rec));

int destroy_anon_record_data PROTO((anon_record_struct *rec));

int destroy_anon_av_pair_data PROTO((anon_av_pair_struct *av));

#endif /* _ANON_RECORD_H_ */
