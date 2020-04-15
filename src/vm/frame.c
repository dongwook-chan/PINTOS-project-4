#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <debug.h>
#include "userprog/pagedir.h"
#include<stdio.h>
#include "vm/frame.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/swap.h"

struct fte* init_fte (const void* upage, const void* kpage);
struct fte* find_fte (const void* upage);
struct fte* find_victim_fte (void);
void releaes_victim (struct fte* victim, size_t index);

struct list frame_table;
struct lock frame_lock;

void frame_init (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

struct fte* add_fte (const void* upage, enum palloc_flags flag)
{
  lock_acquire (&frame_lock);
  void* kpage = palloc_get_page (flag);

  if(!kpage) {
    struct fte *victim = find_victim_fte ();
    kpage = victim->kpage;

    size_t index = swap_out (kpage);
    release_victim (victim, index);
    remove_victim (victim->upage, victim->kpage, victim->thread);
  }

  struct fte *fte = init_fte (upage, kpage);
  lock_release (&frame_lock);
  return fte;
}

void
release_victim (struct fte* victim, size_t index)
{
  struct supple_pte s;
  s.upage = victim->upage;
  struct hash_elem* e = hash_find (&victim->thread->supple_pt, &s.elem);
  if (!e)
    return;

  struct supple_pte* supple_pte = hash_entry (e, struct supple_pte, elem);

  pagedir_clear_page (supple_pte->fte->thread->pagedir, supple_pte->upage);

  supple_pte->type = SWAP;
  supple_pte->index = index;
  supple_pte->fte = 0;
  supple_pte->loaded = 0;
  supple_pte->kpage = 0;
}

void remove_fte (const void* upage)
{
  lock_acquire (&frame_lock);  

  struct fte* fte = find_fte (upage);
  palloc_free_page (fte->kpage);
  list_remove (&fte->elem);
  free (fte);

  lock_release (&frame_lock);
}

struct fte* clock(bool (*is_victim)(void *, void *), bool set_condition){
  struct list_elem* e;
  struct fte* fte;
  uint32_t* pd;
  void* upage;
  for (e=list_begin (&frame_table); e!=list_end (&frame_table); e=list_next (e))
  {
    fte = list_entry (e, struct fte, elem);
    pd = fte->thread->pagedir;
    upage = fte->upage;
    if ((*is_victim)(pd, upage))
      return fte;
    if (set_condition && pagedir_is_accessed (pd, upage))
      pagedir_set_accessed (pd, upage, false);
  }
  return NULL;
}

bool no_access_no_dirt(void *pd, void *upage){
  return !pagedir_is_accessed ((uint32_t *)pd, upage) && !pagedir_is_dirty ((uint32_t *)pd, upage);
}

bool no_access_dirt(uint32_t *pd, void *upage){
  return !pagedir_is_accessed ((uint32_t *)pd, upage) && pagedir_is_dirty ((uint32_t *)pd, upage);
}

bool access_no_dirt(uint32_t *pd, void *upage){
  return pagedir_is_accessed ((uint32_t *)pd, upage) && !pagedir_is_dirty ((uint32_t *)pd, upage);
}

bool access_dirt(uint32_t *pd, void *upage){
  return pagedir_is_accessed ((uint32_t *)pd, upage) && pagedir_is_dirty ((uint32_t *)pd, upage);
}

struct fte* find_victim_fte (void)
{
  struct fte* fte;

  if(fte = clock(no_access_no_dirt, true))
    return fte;

  if(fte = clock(no_access_dirt, false))
    return fte;

  if(fte = clock(access_no_dirt, false))
    return fte;

  if(fte = clock(access_dirt, false))
    return fte;

  return NULL;
}

struct fte* init_fte (const void* upage, const void* kpage)
{
  struct fte* fte = malloc (sizeof(struct fte));

  fte->thread = thread_current ();
  fte->upage = upage;
  fte->kpage = kpage;
  list_push_back (&frame_table, &fte->elem);

  return fte;
}

struct fte* find_fte (const void* upage)
{
  struct thread* cur = thread_current ();
  struct list_elem* e;
  struct fte* fte;

  for (e=list_begin (&frame_table); e!=list_end (&frame_table); e=list_next (e))
  {
    fte = list_entry (e, struct fte, elem);
    if (fte->thread == cur && fte->upage == upage)
      return fte;
  }

  return NULL;
}

void remove_victim (void* upage, void* kpage, struct thread* t)
{
  struct list_elem* e;
  struct fte* fte;

  lock_acquire (&frame_lock);
  for (e=list_begin (&frame_table); e!=list_end (&frame_table); e=list_next (e))
  {
    fte = list_entry (e, struct fte, elem);
    if (fte->thread == t && fte->upage == upage && fte->kpage == kpage) {
      palloc_free_page (fte->kpage);
      list_remove (&fte->elem);
      free (fte);
      break;
    }
  }

  lock_release (&frame_lock);
}
