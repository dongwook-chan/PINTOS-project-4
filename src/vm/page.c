#include "vm/page.h"
#include <debug.h>
#include "userprog/process.h"
#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

void spage_init (struct hash* h)
{
  hash_init (h, spage_hash_func, spage_less_func, NULL);
}

void spage_destroy (struct hash* h)
{
  hash_destroy (h, spage_action_func);
}

bool load_page (struct supple_pte* supple_pte)
{
  bool success = false;

  switch (supple_pte->type)
  {
    case EXEC:
      success = load_exec (supple_pte);
      break;
    case SWAP:
      success = load_swap (supple_pte);
      break;
    default:
      return success;
  }

  if (!success) return 0;
  supple_pte->loaded = 0;
  return success;
}

bool load_exec (struct supple_pte* supple_pte)
{
  bool success = 0;
  struct fte* fte = add_fte (supple_pte->upage, PAL_USER);
  if (!fte)
    return success;
  else
  {
    supple_pte->kpage = fte->kpage;
    supple_pte->fte = fte;
    if (file_read_at (supple_pte->file, supple_pte->kpage, supple_pte->read_bytes, 
                      supple_pte->ofs) != (int) supple_pte->read_bytes)
    {
      remove_fte (supple_pte->upage);
      supple_pte->kpage = 0;
      supple_pte->fte = 0;
      return success;
    }
    memset (supple_pte->kpage+supple_pte->read_bytes, 0, PGSIZE-supple_pte->read_bytes);

    if (!install_page (supple_pte->upage, supple_pte->kpage, supple_pte->writable))
    {
      palloc_free_page (supple_pte->fte->kpage);
      list_remove (&supple_pte->fte->elem);
      free (supple_pte->fte);

      supple_pte->fte = 0;
      supple_pte->kpage = 0;

      hash_delete (&thread_current ()->supple_pt, &supple_pte->elem);
      free (supple_pte);
      return success;
    }
    success = 1;
    return success;
  }
}

bool load_swap (struct supple_pte* supple_pte)
{
  bool success = false;
  struct fte* fte = add_fte (supple_pte->upage, PAL_USER);
  supple_pte->kpage = fte->kpage;
  supple_pte->fte = fte;

  if (!install_page (supple_pte->upage, supple_pte->kpage, supple_pte->writable))
  {
    remove_fte (supple_pte->upage);
    supple_pte->fte = 0;
    supple_pte->kpage = 0;
    return success;
  }

  success = swap_in (supple_pte->kpage, supple_pte->index);
  return success;
}

struct supple_pte* get_supple_pte (void* upage)
{
  struct supple_pte s;
  s.upage = upage;
  struct hash_elem* e = hash_find (&thread_current ()->supple_pt, &s.elem);
  if (!e) return NULL;
  return hash_entry (e, struct supple_pte, elem);
}

struct supple_pte* init_exec_supple_pte (struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes, bool writable)
{
  struct supple_pte* supple_pte = malloc (sizeof (struct supple_pte));
  if (!supple_pte) return NULL;
  supple_pte->writable = writable;
  supple_pte->loaded = 0;
  supple_pte->upage = (void*) upage;
  supple_pte->file = file;
  supple_pte->read_bytes = read_bytes;
  supple_pte->kpage = 0;
  supple_pte->type = EXEC;
  supple_pte->index = -1;
  supple_pte->ofs = ofs;

  struct hash_elem* e = hash_insert (&thread_current ()->supple_pt, &supple_pte->elem);
  return supple_pte;
}

void release_supple_pte (void* upage, size_t index)
{
  struct supple_pte* supple_pte = get_supple_pte (upage);

  pagedir_clear_page (supple_pte->fte->thread->pagedir, supple_pte->upage);
  supple_pte->type = SWAP;
  supple_pte->fte = 0;
  supple_pte->loaded = 0;
  supple_pte->kpage = 0;

  if (supple_pte->type == SWAP)
    supple_pte->index = index;
}

bool stack_growth (void* upage)
{
  bool success = false;
  struct supple_pte* supple_pte = malloc (sizeof (struct supple_pte));
  if (!supple_pte) return false;
  struct fte* fte = add_fte (upage, PAL_USER | PAL_ZERO);
  if (!fte) return success;

  supple_pte->fte = fte;
  supple_pte->ofs = -1;
  supple_pte->type = SWAP;
  supple_pte->file = 0;
  supple_pte->read_bytes = -1;
  supple_pte->writable = 1;
  supple_pte->loaded = 1;
  supple_pte->index = -1;
  supple_pte->upage = upage;
  supple_pte->kpage = fte->kpage;

  struct hash_elem* e = hash_insert (&thread_current ()->supple_pt, &supple_pte->elem);

  if (!install_page (supple_pte->upage, supple_pte->kpage, supple_pte->writable))
  {
    remove_fte (supple_pte->upage);
    hash_delete (&thread_current ()->supple_pt, e);
    free (supple_pte);
    return success;
  }
  success = true;
  return success; 
}

unsigned spage_hash_func (const struct hash_elem* e, void* aux UNUSED)
{
  struct supple_pte* supple_pte = hash_entry (e, struct supple_pte, elem);
  return hash_int ((int) supple_pte->upage);
}

bool spage_less_func (const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED)
{
  struct supple_pte* s_a = hash_entry (a, struct supple_pte, elem);
  struct supple_pte* s_b = hash_entry (b, struct supple_pte, elem);
  if (s_a->upage < s_b->upage) return true;
  return false;
}

void spage_action_func (struct hash_elem* e, void* aux UNUSED)
{
  struct supple_pte* supple_pte = hash_entry (e, struct supple_pte, elem);

  if (supple_pte->loaded) {
    pagedir_clear_page (supple_pte->fte->thread->pagedir, supple_pte->upage);
    remove_victim (supple_pte->upage, supple_pte->kpage, supple_pte->fte->thread);
  }
  list_remove (&supple_pte->elem);
  free (supple_pte);
}

