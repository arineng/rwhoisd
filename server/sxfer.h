#ifndef _SXFER_H_
#define _SXFER_H_

/* includes */

#include "common.h"
#include "types.h"
#include "mkdb_types.h"

/* prototypes */

int create_data_files PROTO((auth_area_struct *aa,
                             server_struct    *server,
                             int              initial));

int index_data_files_by_suffix PROTO((auth_area_struct *aa,
                                      char             *suffix));

#endif /* _SXFER_H_ */
