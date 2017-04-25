/* *************************************************************
   RWhois Software

   Copyright (c) 1994 Scott Williamson and Mark Kosters
   Copyright (c) 1996-2000 Network Solutions, Inc.

   See the file LICENSE for conditions of use and distribution.
**************************************************************** */

#include "dl_list.h"

#include "defines.h"

/* create_new_node:
   malloc()s a new node into existance, and defaults the member
   variables. */
static dl_node_type *
create_new_node(data)
  void  *data;
{
  dl_node_type  *node;
  
  node = (dl_node_type *) malloc(sizeof(dl_node_type));
  if (!node) return NULL;
    
  node->next = NULL;
  node->prev = NULL;
  node->data = data;

  return node;
}
int
dl_list_default(list, destroy_head_flag, destroy_data)
  dl_list_type  *list;
  int           destroy_head_flag;
  int           (*destroy_data)();
{
  if (list) {
    list->head              = NULL;
    list->tail              = NULL;
    list->current           = NULL;
    list->destroy_head_flag = destroy_head_flag;
    list->destroy_data      = destroy_data;

    return TRUE;
  }
  return FALSE;
}

void *
dl_list_value(list)
  dl_list_type  *list;
{
  if (!list) return NULL;
  if (!(list->current)) return NULL;
  
  return list->current->data;
}   

void *
dl_list_next_value(list, n)
  dl_list_type  *list;
  int           n;
{
  dl_node_type  *p;
  int               i;
    
  if (!list) return NULL;
  if (!(list->current)) return NULL;
    
  p = list->current;

  for (i = 0; i < n; i++)
  {
    p = p->next;
    if (!p) return NULL;
  }
  return(p->data);
}

void *
dl_list_prev_value(list, n)
  dl_list_type  *list;
  int           n;
{
  dl_node_type  *p;
  int               i;
    
  if (!list) return NULL;
  if (!(list->current)) return NULL;
    
  p = list->current;

  for (i = 0; i < n; i++)
  {
    p = p->prev;
    if (!p) return NULL;
  }
  return(p->data);
}

int
dl_list_empty(list)
  dl_list_type  *list;
{
  /* if any of the standard position fields are NULL, then the list is
     empty, or it has been generated incorrectly, in which case, we
     will assume that it is actually empty, and has garbage in the
     other fields. */
  if (!list) return TRUE;
  if (!(list->head)) return TRUE;
  if (!(list->tail)) return TRUE;
  if (!(list->current)) return TRUE;

  return FALSE;
}


int
dl_list_first(list)
  dl_list_type  *list;
{
  if (!list) return FALSE;
  if (!(list->head)) return FALSE;

  list->current = list->head;

  return TRUE;
}

int
dl_list_last(list)
  dl_list_type  *list;
{
  if (!list) return FALSE;

  if (!(list->tail)) return FALSE;

  list->current = list->tail;

  return TRUE;
    
}

int
dl_list_next(list)
  dl_list_type  *list;
{
  if (!list) return FALSE;

  if (!(list->current)) return FALSE;

  if (!(list->current->next)) return FALSE;

  list->current = list->current->next;

  return TRUE;
}

int
dl_list_prev(list)
  dl_list_type  *list;
{
  if (!list) return FALSE;

  if (!(list->current)) return FALSE;

  if (!(list->current->prev)) return FALSE;

  list->current = list->current->prev;

  return TRUE;
}
    
int
dl_list_insert(list, data)
  dl_list_type  *list;
  void          *data;
{
  dl_node_type  *node;
    
  node = create_new_node(data);
  if (!node) return FALSE;

  if (dl_list_empty(list))
  {
    list->head    = node;
    list->tail    = node;
    list->current = node;

    return TRUE;
  }
    
  node->next          = list->current->next;
  node->prev          = list->current;
  list->current->next = node;
    
  if (node->next)
  {
    node->next->prev = node;
  }
  else
  {
    list->tail = node;
  }

  return TRUE;
}

int
dl_list_insert_before(list, data)
  dl_list_type  *list;
  void          *data;
{
  dl_node_type  *node;

  node = create_new_node(data);
  if (!node) return FALSE;

  if (dl_list_empty(list))
  {
    list->head    = node;
    list->tail    = node;
    list->current = node;
        
    return TRUE;
  }

  node->next          = list->current;
  node->prev          = list->current->prev;
  list->current->prev = node;
    
  if (node->prev)
  {
    node->prev->next = node;
  }
  else
  {
    list->head = node;
  }

  return TRUE;
}


int
dl_list_append(list, data)
  dl_list_type  *list;
  void          *data;
{
  dl_node_type  *old_pos;

  if (!list) return FALSE;

  if (dl_list_empty(list))
  {
    dl_list_insert(list, data);
  }
  else
  {
    old_pos = list->current;
    dl_list_last(list);
    dl_list_insert(list, data);
    list->current = old_pos;
  }
  return TRUE;
}


int
dl_list_prepend(list, data)
  dl_list_type  *list;
  void          *data;
{
  dl_node_type  *old_pos;

  if (!list) return FALSE;

  if (dl_list_empty(list))
  {
    dl_list_insert(list, data);
  }
  else
  {
    old_pos = list->current;
    dl_list_first(list);
    dl_list_insert_before(list, data);
    list->current = old_pos;
  }
  return TRUE;
}

int
dl_list_append_list(list1, list2)
  dl_list_type  *list1;
  dl_list_type  *list2;
{
  dl_node_type  *pos1;
  dl_node_type  *pos2;
  
  if (!list1 || !list2) return FALSE;

  if (dl_list_empty(list2)) return TRUE;

  if (dl_list_empty(list1))
  {
    bcopy(list2, list1, sizeof(*list1));
    return TRUE;
  }

  pos1 = list1->tail;
  pos2 = list2->head;

  pos1->next = pos2;
  pos2->prev = pos1;
  list1->tail = list2->tail;

  return TRUE;
}

dl_node_type *
dl_list_get_pos(list)
  dl_list_type *list;
{
  if (!list) return NULL;
  return(list->current);
}

int
dl_list_put_pos(list, pos)
  dl_list_type  *list;
  dl_node_type  *pos; 
{
  if (!pos) return FALSE;

  list->current = pos;
  return TRUE;
}

dl_node_type *
dl_list_exchange_pos(list, pos)
  dl_list_type  *list;
  dl_node_type  *pos; 
{
  dl_node_type  *p;

  if (!pos) return NULL;

  p = list->current;
  list->current = pos;
  return(p);
}
    
int
dl_list_delete(list)
  dl_list_type  *list;
{
  dl_node_type  *current;
    
  if (!list) return FALSE;
  if (!(list->current)) return FALSE;

  current = list->current;
    
  if (current->data)
  {
    (list->destroy_data)(list->current->data);
  }

  if (current->next)
  {
    current->next->prev = current->prev;
    list->current = current->next;
  }
  else
  {
    /* we're at the tail */
    list->tail = current->prev;
    list->current = current->prev;
  } 
    

  if (current->prev)
  {
    current->prev->next = current->next;
  }
  else
  {
    /* we're at the head */
    list->head = current->next;
  } 
    
  free(current);
  return TRUE;
}

int
dl_list_destroy(list)
  dl_list_type  *list;
{
  int   status;

  if (!list) return TRUE;
  
  if (dl_list_empty(list))
  {
    if (list->destroy_head_flag)
    {
      free(list);
    }
    return TRUE;
  }

  dl_list_first(list);

  do
  {
    status = dl_list_delete(list);
        
  } while(status == TRUE);

  if (list->destroy_head_flag)
  {
    free(list);
  }
  
  return TRUE;
}

int
simple_destroy_data(data)
  void  *data;
{
  if (data) {
    free(data);
  }
  return TRUE;
}   

int
null_destroy_data(data)
  void  *data;
{
  return TRUE;
}

