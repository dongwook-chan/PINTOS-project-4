#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdio.h>
#include <stdbool.h>
#include <hash.h>
#include "filesys/file.h"
#include "userprog/syscall.h"

enum supple_pte_type {EXEC = 0 ,SWAP};

struct supple_pte
{
  void* upage;
  void* kpage;
  bool loaded;
  enum supple_pte_type type;
  struct hash_elem elem;
  struct fte* fte;  

  struct file* file;
  off_t ofs;
  uint32_t read_bytes;
  bool writable;
  
  size_t index;
};

void spage_init (struct hash* h);
bool load_page (struct supple_pte* supple_pte);
struct supple_pte* get_supple_pte (void* upage);
bool stack_growth (void* upage);
void release_supple_pte (void* upage, size_t index);
unsigned spage_hash_func (const struct hash_elem* e, void* aux UNUSED);
bool spage_less_func (const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED);
void spage_action_func (struct hash_elem* e, void* aux UNUSED);
bool load_exec (struct supple_pte* supple_pte);
struct supple_pte* init_exec_supple_pte (struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes, bool writable);
bool load_swap (struct supple_pte* supple_pte);
#endif /* vm/page.h */
