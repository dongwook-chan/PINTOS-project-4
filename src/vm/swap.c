#include "vm/swap.h"

#define SWAP_FREE 0
#define SWAP_IN_USE 1

struct bitmap* swap_map;
struct block* swap_block;
struct lock swap_lock;

void
swap_init (void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_map = bitmap_create (block_size (swap_block) * BLOCK_SECTOR_SIZE / PGSIZE);
  bitmap_set_all (swap_map, SWAP_FREE);
  lock_init (&swap_lock);
}

bool
swap_in (void* kpage, size_t index)
{
  lock_acquire (&swap_lock);
  bitmap_flip (swap_map, index);

  int upper = PGSIZE/BLOCK_SECTOR_SIZE;
  block_sector_t base = index * PGSIZE / BLOCK_SECTOR_SIZE;

  int i;
  for (i = 0; i< upper; i++)
  {
    block_read (swap_block, base +i, kpage+(i*BLOCK_SECTOR_SIZE));
  }
  lock_release (&swap_lock);
  return true;
}

size_t
swap_out (void* kpage)
{
  lock_acquire (&swap_lock);
  size_t index = bitmap_scan_and_flip (swap_map, 0, 1, SWAP_FREE);

  int upper = PGSIZE/BLOCK_SECTOR_SIZE;
  block_sector_t base = index * PGSIZE / BLOCK_SECTOR_SIZE;

  int i;
  for (i=0; i< upper; i++)
  {
    block_write (swap_block, base+i, kpage+(i*BLOCK_SECTOR_SIZE));
  }

  lock_release (&swap_lock);
  return index;
}
