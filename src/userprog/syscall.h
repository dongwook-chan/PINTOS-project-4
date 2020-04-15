#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include <stdbool.h>
#include <list.h>

void syscall_init (void);

/*mod_func********************************************************/
struct lock file_lock;

bool valid(void *vaddr);
//struct file *fd_to_file(struct list list, int fd);

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int pibonacci (int n);
int sum_of_four_integers(int a, int b, int c, int d);
/*****************************************************************/

#endif /* userprog/syscall.h */
