#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

// added header file
#include "filesys/file.h"
#include "vm/page.h"
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void file_name_to_argv (char *s, char **argv, int *argc, size_t *arg_len);
bool install_page (void* upage, void* kpage, bool writable);

#endif /* userprog/process.h */
