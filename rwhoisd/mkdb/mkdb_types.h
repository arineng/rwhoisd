/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _MKDB_TYPES_H_
#define _MKDB_TYPES_H_

/* includes */

#include "common.h"
#include "types.h"
#include "defines.h"

/* types */

typedef enum
{
  MKDB_NO_FILE,
  MKDB_ALL_FILES,
  MKDB_DATA_FILE,
  MKDB_ALL_INDEX_FILES,

  /* this index type must be first since represents the 'first' index type */
  MKDB_EXACT_INDEX_FILE,
  MKDB_SOUNDEX_INDEX_FILE,
  MKDB_CIDR_INDEX_FILE,
  /* new mkdb file types go here */
  MKDB_MAX_FILE_TYPE    /* this type MUST be last */
} mkdb_file_type;

typedef enum
{
  MKDB_BINARY_SEARCH,
  MKDB_FULL_SCAN,
  MKDB_CIDR_SEARCH
} mkdb_search_type;

typedef enum
{
  MKDB_FULL_COMPARE,
  MKDB_PARTIAL_COMPARE,
  MKDB_SUBSTR_COMPARE,
  MKDB_NOT_FULL_COMPARE,
  MKDB_NOT_PARTIAL_COMPARE,
  MKDB_NOT_SUBSTR_COMPARE,
  MKDB_NOT_CIDR_COMPARE,
  MKDB_NOT_SOUNDEX_COMPARE
} mkdb_compare_type;

#define MKDB_NEGATION_OFFSET MKDB_NOT_FULL_COMPARE

typedef enum
{
  MKDB_LOCK_OFF,
  MKDB_LOCK_ON
} mkdb_lock_type;

typedef enum
{
  MKDB_EQ_OP,
  MKDB_NOT_EQ_OP
} mkdb_operator_type;

typedef struct _file_struct
{
  mkdb_file_type   type;
  char             *filename;
  int              file_no;
  off_t            size;
  long             num_recs;
  int              lock;
  char             *tmp_filename;
  char             *base_filename;
  FILE             *fp;
} file_struct;

typedef struct _index_struct
{
  off_t  offset;
  int    data_file_no;
  int    deleted_flag;
  int    attribute_id;
  char   *value;
} index_struct;

typedef struct _query_term_struct
{
  char                      *attribute_name;
  int                       attribute_id;   /* global id */
  mkdb_search_type          search_type;
  mkdb_compare_type         comp_type;
  char                      *search_value;
  struct _query_term_struct *and_list;
  struct _query_term_struct *or_list;
} query_term_struct;


typedef struct _query_struct
{
  char              *class_name;
  char              *auth_area_name;
  query_term_struct *query_tree;
} query_struct;


/* This takes the place of a simple file pointer for an index file in
   index.c. This is so that a type is bound to the file pointer and
   its filename */
typedef struct _index_fp_struct
{
  mkdb_file_type type;
  FILE           *fp;
  char           real_filename[MAX_FILE];
  char           tmp_filename[MAX_FILE];
  char           prefix[MAX_FILE];
} index_fp_struct;

#if SIZEOF_OFF_T == 8
#define OFF_T64 1
#endif

/* Largefile support: this consists mostly of compiling with specific
   flags, changeing all variable representing offsets into files with
   off_t, changing printf format strings from %ld to %lld, changing
   fseek and ftell to fseeko and ftello.*/
#if _FILE_OFFSET_BITS > 32
#define LFS_SUPPORT_ENABLED 1
#define OFF_T64 1
#define fseek fseeko
#define ftell ftello
#endif

#endif /* _MKDB_TYPES_H_ */
