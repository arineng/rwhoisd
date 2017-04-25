/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _RECORDS_H_
#define _RECORDS_H_

/* includes */

#include "common.h"
#include "dl_list.h"
#include "types.h"

/* prototypes */

record_struct *
mkdb_translate_anon_record PROTO((anon_record_struct *anon,
                                  class_struct       *class,
                                  auth_area_struct   *auth_area,
                                  int                validate_flag));

record_struct *
mkdb_read_record PROTO((class_struct     *class,
                        auth_area_struct *auth_area,
                        int              data_file_no,
                        int              validate_flag,
                        rec_parse_result *status,
                        FILE             *fp));

record_struct *
mkdb_read_next_record PROTO((class_struct     *class,
                             auth_area_struct *auth_area,
                             int              data_file_no,
                             int              validate_flag,
                             rec_parse_result *status,
                             FILE             *fp));


int mkdb_write_record PROTO((record_struct  *record,
                             FILE           *fp));

av_pair_struct *find_attr_in_record_by_name PROTO((record_struct *record,
                                                   char          *attr_name));

av_pair_struct *find_attr_in_record_by_id PROTO((record_struct *record,
                                                 int           id));

int append_attribute_to_record PROTO((record_struct *record,
                                      class_struct  *class,
                                      char          *attrib_name,
                                      char          *value));

int delete_attribute_from_record PROTO((record_struct *record,
                                        char          *attrib_name));

av_pair_struct *copy_av_pair PROTO((av_pair_struct *av));

record_struct *copy_record PROTO((record_struct *rec));

int destroy_record_data PROTO((record_struct *rec));

int destroy_av_pair_data PROTO((av_pair_struct *av));

#endif /* _RECORDS_H_ */
