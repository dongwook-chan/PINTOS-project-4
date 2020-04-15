#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include "threads/thread.h"
#include <list.h>
#include "threads/palloc.h"
#include "vm/swap.h"

struct fte
  {
    void* upage;
    void* kpage;
    struct thread* thread;
    struct list_elem elem;
  };

void frame_init (void);
struct fte* add_fte (const void* upage, enum palloc_flags flag);
void remove_fte (const void* upage);
void remove_victim (void* upage, void* kpage, struct thread* t);

#endif /* vm/frame.h */