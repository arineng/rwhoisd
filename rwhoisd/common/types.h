/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _TYPES_H_
#define _TYPES_H_

/* includes */

#include "dl_list.h"

/* attribute types */

/* attr_index_type: a list of all the different indexing schemes    */
/* FIXME: this needs to be done better than I'm doing it. In the    */
/* future you should be able to add a new index type fairly easily. */
/* This isn't the easy way.                                         */

#define NUM_INDEX_TYPES 6

typedef enum
{
  INDEX_NONE,       /* don't index at all */
  INDEX_ALL,
  INDEX_EXACTLY,    /* this must alwasy be the first index type after ALL */
  INDEX_CIDR,
  INDEX_SOUNDEX,
  INDEX_MAX_TYPE    /* this must alwasy be last so that the for(;;) works */
} attr_index_type;

/* attr_type: the different base types for attributes */
typedef enum
{
  TYPE_TEXT,        /* the default: basic untyped text strings */
  TYPE_ID,          /* a ref to another RWhois obj (for db normalization) */
  TYPE_SEE_ALSO     /* a reference to other related data */
} attr_type;

/* av_parse_result: response codes resulting from parsing an av_pair */
typedef enum
{
  AV_OK,        /* av pair parsed ok */
  AV_IGNORE,    /* av pair bad, but keep going */
  AV_STOP,      /* av pair bad, need to stop */
  AV_MAX
} av_parse_result;

/* rec_parse_result: response codes resulting from parsing a record */
typedef enum
{
  REC_OK,       /* record parsed ok */
  REC_FATAL,    /* record didn't parse because of a fatal error */
  REC_INVAL,    /* record didn't parse because it was invalid */
  REC_EOF,      /* record didn't parse because at end-of-file */
  REC_NULL,     /* record didn't parse because it didn't contain any lines */
  REC_MAX
} rec_parse_result;

/* attribute_struct: all the data pertaining to an attribute.  Some
     basic rules for the flags: is_key is mutually exclusive with
     is_unique (all attributes in a class marked is key will form a
     unique, joined value).  is_multi_line is mutually exclusive with
     is_repeatable. */
typedef struct _attribute_struct
{
  int               global_id;      /* unique index assoc. with attr. name */
  int               local_id;       /* unique per class index */
  int               is_required;    /* TRUE if attr. is required */
  int               is_primary_key; /* TRUE if forms part of key */
  int               is_repeatable;  /* TRUE if attr. may be repeated */
  int               is_multi_line;  /* TRUE if 1 entry takes mult lines */
  int               is_hierarchical;/* TRUE for domain/IP-Network */
  int               is_private;     /* TRUE if attr. is private */
  int               num_aliases;    /* number of aliases for the attribute */
  char              **aliases;      /* array of aliases */
  char              *short_alias;   /* the shortest alias */
  char              *name;          /* the real name of the attribute */
  char              *description;   /* text description of attribute */
  char              *format;        /* format of the object */
  attr_index_type   index;          /* how, and if, the attr is indexed*/
  attr_type         type;           /* the type of the attribute */
} attribute_struct;

/* attribute_ref_struct: a data type meant to cross-reference global
      attribute names with the objects that contain them */
typedef struct _attribute_ref_struct
{
  int           global_id;
  char          *name;
  int           num_aliases;
  char          **aliases;
  dl_list_type  class_list;
} attribute_ref_struct;


/* object class types */

typedef struct _class_struct
{
  int          id;
  int          num_aliases;
  char         *name;
  char         **aliases;
  char         *description;
  char         *db_dir;
  char         *attr_file;
  char         *parse_program;
  char         *version;
  dl_list_type attribute_list;
} class_struct;

typedef struct _class_ref_struct
{
  char          *name;
  int           num_aliases;
  char          **aliases;
  dl_list_type  auth_area_list;
} class_ref_struct;

typedef struct _schema_struct
{
  dl_list_type      class_list;
  dl_list_type      attribute_ref_list;
} schema_struct;

/* server structure */
typedef struct _server_struct
{
  char      *name;
  char      *addr;
  int       port;
} server_struct;

typedef enum
{
  AUTH_AREA_PRIMARY,
  AUTH_AREA_SECONDARY
} auth_area_type;


/* authority area structure */
typedef struct _auth_area_struct
{
  auth_area_type            type;
  char                      *name;
  char                      *data_dir;
  char                      *schema_file;
  char                      *soa_file;
  char                      *primary_server;
  char                      *hostmaster;
  char                      *serial_no;
  char                      *xfer_arg;
  long                      refresh_interval;
  long                      increment_interval;
  long                      retry_interval;
  long                      time_to_live;
  long                      xfer_time;
  schema_struct             *schema;
  dl_list_type              *master; /* server_list */
  dl_list_type              *slave;  /* server_list */
  dl_list_type              *guardian_list;
} auth_area_struct;

/* record types -- records are actual schema class instances */
typedef struct _record_struct
{
  class_struct      *class;
  auth_area_struct  *auth_area;
  int               data_file_no;
  int               index_file_no;
  long              offset;
  dl_list_type      av_pair_list;
} record_struct;

typedef struct _av_pair_struct
{
  attribute_struct  *attr;
  void              *value;
} av_pair_struct;

/* anonymous records; sometimes we want to get a record into memory
   *before* we know what class and auth-area it belongs to */
typedef struct _anon_record_struct
{
  int          data_file_no;
  long         offset;
  dl_list_type anon_av_pair_list;
} anon_record_struct;

typedef struct _anon_av_pair_struct
{
  char  *attr_name;
  char  *value;
} anon_av_pair_struct;

/* authorization structure (guardian) */
typedef struct _auth_struct
{
  char    *mode;
  char    *scheme;
  char    *info;
  char    *type;
} auth_struct;

typedef struct _directive_struct
{  
  int   len;
  int   disabled_flag;
  long  cap_bit;
  int   (*function)();
  char  *name;
  char  *description;
  char  *program;
} directive_struct;


#endif /* _TYPES_H_ */

