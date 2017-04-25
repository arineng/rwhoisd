/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#ifndef _DL_LIST_H_
#define _DL_LIST_H_

/* includes */
#include "common.h"

/* definitions */

/* types */
typedef struct _dl_node_type
{
  struct _dl_node_type *next;
  struct _dl_node_type *prev;
  void                 *data;
} dl_node_type;

typedef struct _dl_list_type
{
  dl_node_type        *head;
  dl_node_type        *tail;
  dl_node_type        *current;
  int                 destroy_head_flag;
  int                 (*destroy_data) PROTO((void *data));
} dl_list_type;

/* prototypes */


/* sets the defaults for a dl_list control block.  It initializes the
   list to empty, sets the 'destroy_head_flag', which determines if
   the control block itself is free()d on a destroy, and supplies the
   function pointer to the data free()ing routine. */
int dl_list_default PROTO((dl_list_type *list,
                           int destroy_head_flag,
                           int (*destroy_data)()));

/* returns the value (a pointer to the data element) at the current
   position */ 
void *dl_list_value PROTO((dl_list_type *list));

/* returns the value at the current position plus n. */
void *dl_list_next_value PROTO((dl_list_type *list, int n));

/* returns the value at the current position minus n. */
void *dl_list_prev_value PROTO((dl_list_type *list, int n));

/* returns TRUE if the list is empty, false otherwise. */
int dl_list_empty PROTO((dl_list_type *list));

/* sets the position to the head of the list */
int dl_list_first PROTO((dl_list_type *list));

/* sets the position to the tail of the list */
int dl_list_last PROTO((dl_list_type *list));

/* advances the position forward one node. */
int dl_list_next PROTO((dl_list_type *list));

/* moves the position backwards one node */
int dl_list_prev PROTO((dl_list_type *list));

/* inserts a node containing 'data' right after the current position */
int dl_list_insert PROTO((dl_list_type *list, void *data));

/* inserts a node containing 'data' right before the current position */
int dl_list_insert_before PROTO((dl_list_type *list, void *data));

/* adds a node containing 'data' to the end of the list */
int dl_list_append PROTO((dl_list_type *list, void *data));

/* inserts a node containing 'data' to the beginning of the list */
int dl_list_prepend PROTO((dl_list_type *list, void *data));

/* appends list2 to the end of list1 */
int dl_list_append_list PROTO((dl_list_type *list1, dl_list_type *list2));

/* returns a pointer to the node at the current position.  This is
   meant to be used as a way of "saving" the current position */
dl_node_type *dl_list_get_pos PROTO((dl_list_type *list));

/* sets the current position to the node pointed to by 'pos', which
   was probably obtained by dl_list_get_pos(). */
int dl_list_put_pos PROTO((dl_list_type *list, dl_node_type *pos));

/* sets the current position to 'pos' while returning the old
   position. */
dl_node_type *dl_list_exchange_pos PROTO((dl_list_type *list,
                                          dl_node_type *pos));

/* free()s the node at the current position.  Note, it only executes a
   free() on the datum block and node itself, not anything pointed to
   by the datum block.  That must be freed by the user */
int dl_list_delete PROTO((dl_list_type *list));

/* deletes the whole list.  It is up to the user to free any indirect
   memory. */
int dl_list_destroy PROTO((dl_list_type *list));

/* a basic data destruction routine.  It simply free()s the data, if
   non-null. */
int simple_destroy_data PROTO((void *data));

/* a do-nothing destruction routine. */
int null_destroy_data PROTO((void *data));

#endif /* _DL_LIST_H_ */

