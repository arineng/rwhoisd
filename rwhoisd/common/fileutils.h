/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _FILEUTILS_H_
#define _FILEUTILS_H_

/* includes */

#include "common.h"
#include "dl_list.h"

/* prototypes */

int file_exists PROTO((char *file));

int directory_exists PROTO((char *dir));

int is_rel_path PROTO((char *path));

int store_current_wd PROTO((void));

int restore_current_wd PROTO((void));

time_t get_path_mod_time PROTO((char *path));

int split_path PROTO((char *path, char *dir, char *file));

char *path_full_to_rel PROTO((char *full_path, char *root_dir));

char *path_rel_to_full PROTO((char *new_path, int new_path_len,
                              char *rel_path, char *root_dir));

int canonicalize_path PROTO((char *new_path, int new_path_len,
                             char *path, char *root_dir, int chrooted,
                             int null_allowed));

char *make_timestamp PROTO((void));

char *create_filename PROTO((char *fname, char *template,
                             char *spool_directory));

char *create_db_filename PROTO((char *fname, char *template,
                                char *spool_directory, char *postfix));

FILE *get_file_lock PROTO((char *filename, char *mode, int block));

int release_file_lock PROTO((char *filename, FILE *fp));

int get_dot_lock PROTO((char *filename, int block));

int release_dot_lock PROTO((char *filename));

int dot_lock_exists PROTO((char *filename));

int get_placeholder_lock PROTO((char *filename, int block, int *lock_fd));

int release_placeholder_lock PROTO((char *filename, int lock_fd));

int placeholder_lock_exists PROTO((char *filename));

time_t get_path_mtime PROTO((char *path));

int file_cmpr PROTO((char *file1, char *file2));

int timestamp_cmpr PROTO((char *stamp1, char *stamp2));

char *get_updated_timestamp PROTO((char *orig_stamp));

int examin_directory_writable PROTO((char *dir));

int examin_timestamp PROTO((char *stamp));

int examin_file_name PROTO((char *value));

int examin_directory_name PROTO((char *value));

int examin_executable_name PROTO((char *value));

int dup_config_path_name PROTO((dl_list_type *paths_list, char *path, 
                                char *var_name));

int path_under_root_dir PROTO((char *path, char *rootdir));

int in_config_path_list PROTO((dl_list_type *paths_list, char *path, 
                               char *var_name));

FILE *open_file_to_write PROTO((char *filename, int blk_time, 
                                dl_list_type *paths_list));

int make_config_dir PROTO((char *dirname, int mode, dl_list_type *paths_list));

#endif /* _FILEUTILS_H_ */
