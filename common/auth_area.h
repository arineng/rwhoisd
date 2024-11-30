/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _AUTH_AREA_CONF_H_
#define _AUTH_AREA_CONF_H_

/* includes */

#include "common.h"
#include "types.h"

/* defines */

#define AA_TYPE                 "type"
#define AA_NAME                 "name"
#define AA_DATA_DIR             "data-dir"
#define AA_SCHEMA_FILE          "schema-file"
#define AA_SOA_FILE             "soa-file"
#define AA_MASTER               "master"
#define AA_SLAVE                "slave"
#define AA_XFER_ARG             "xfer-arg"
#define AA_GUARDIAN_ARG         "guardian"

#define AA_PRIMARY              "primary"
#define AA_SECONDARY            "secondary"

#define SOA_SERIAL_NUMBER       "Serial-Number"
#define SOA_REFRESH_INTERVAL    "Refresh-Interval"
#define SOA_INCREMENT_INTERVAL  "Increment-Interval"
#define SOA_RETRY_INTERVAL      "Retry-Interval"
#define SOA_TIME_TO_LIVE        "Time-To-Live"
#define SOA_PRIMARY_SERVER      "Primary-Server"
#define SOA_HOSTMASTER          "Hostmaster"

/* prototypes */

int read_auth_areas PROTO((char *file));

int add_auth_area PROTO((auth_area_struct *aa));

int read_soa_file PROTO((auth_area_struct *aa));

int write_soa_file PROTO((auth_area_struct *aa));

int destroy_soa_in_auth_area PROTO((auth_area_struct *aa));

int add_server PROTO((dl_list_type **srv_list_ptr, char *val));

void display_auth_area PROTO((auth_area_struct *aa));

void display_all_auth_areas PROTO((void));

int destroy_server_data PROTO((server_struct *server));

void destroy_auth_area_list PROTO((void));

int destroy_auth_area_data PROTO((auth_area_struct *aa));

int check_aa_syntax PROTO(( char *name, char *directory));

dl_list_type *get_auth_area_list PROTO((void));

auth_area_struct *find_auth_area_by_name PROTO((char *name));

attribute_ref_struct *find_truly_global_attr_by_name PROTO((char *name));

int check_root_referral PROTO((char *file));

int is_duplicate_aa PROTO( (auth_area_struct *aa, dl_list_type *aa_list) );

int is_country_code PROTO( ( char *str) );

char *get_default_aa_directory PROTO((auth_area_struct *aa));

char *get_aa_schema_directory PROTO((auth_area_struct *aa));

auth_area_type translate_auth_area_type PROTO(( char *val ));

char *translate_auth_area_type_str PROTO (( auth_area_type val ));

int add_auth_area_guardian PROTO((auth_area_struct *aa, char *id_str));

int is_valid_hostname PROTO((char *name));

int is_valid_port PROTO((char *port));

int write_all_auth_areas PROTO((char *file, char *suffix, 
                                dl_list_type *paths_list));

int create_auth_area PROTO((auth_area_struct *aa));

int delete_auth_area PROTO((char *name));

int examin_aa_xfer_arg PROTO((char *path));

int examin_aa_data_dir PROTO((char *path));

int examin_aa_schema_file PROTO((char *path));

int examin_aa_soa_file PROTO((char *path));

int examin_server_str PROTO((char *server));

int examin_email_address PROTO((char *email));

int examin_aa_hostmaster_str PROTO((char *contact));

int examin_serial_num PROTO((char *num));

int examin_guardian_item PROTO((char *guard_str));

int examin_hostname PROTO((char *hostname));

int examin_port_str PROTO((char *portstr));

int examin_primary_server_str PROTO((char *server));

int verify_all_auth_areas PROTO((void));

int verify_all_auth_area_paths PROTO((dl_list_type *paths_list));

int verify_aa_parse_progs PROTO((dl_list_type *paths_list));

#endif /* _AUTH_AREA_CONF_H_ */
