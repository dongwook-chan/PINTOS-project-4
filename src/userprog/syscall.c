#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// 추가한 헤더 파일
#include "devices/shutdown.h"	// for halt(); shut_donwn_power_off()
#include "threads/vaddr.h"	// for valid(); is_user_vaddr()
#include "userprog/pagedir.h"	// for valid(); pagedir_get_page()
#include "filesys/file.h"	// for file system call; struct file, functions for file
#include "threads/synch.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

typedef uint32_t (*func_of_1arg) (uint32_t arg1);
typedef uint32_t (*func_of_2arg) (uint32_t arg1, uint32_t arg2);
typedef uint32_t (*func_of_3arg) (uint32_t arg1, uint32_t arg2, uint32_t arg3);
typedef uint32_t (*func_of_4arg) (uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);

struct list file_list;

typedef struct{
  int fd;
  struct file *file;
  struct list_elem elem;
}file_elem;


// array of function addresses indexed unsing syscall enumeratior
func_of_4arg syscall_arr[SYS_INUMBER + 1] =	// SYS_INMUBER is the last element in the enum
{ 
  // project 2
  (func_of_4arg)halt,
  (func_of_4arg)exit,
  (func_of_4arg)exec,
  (func_of_4arg)wait,
  (func_of_4arg)create,
  (func_of_4arg)remove,
  (func_of_4arg)open,
  (func_of_4arg)filesize,
  (func_of_4arg)read,
  (func_of_4arg)write,
  (func_of_4arg)seek,
  (func_of_4arg)tell,
  (func_of_4arg)close,

  // Additional Implementation
  (func_of_4arg)pibonacci,
  (func_of_4arg)sum_of_four_integers//,
  

  // project 3
  /*
  (func_of_3arg)mmap,
  (func_of_3arg)munmap,
  */
  // project 4
  /*
  (func_of_3arg)chdir,
  (func_of_3arg)mkdir,
  (func_of_3arg)readdir,
  (func_of_3arg)isdir,
  (func_of_3arg)inumber,*/
  //(func_of_3arg),
};

// array of number of arguments indexed using syscal enumerator
char syscall_argc[SYS_INUMBER + 1] =
{
  0, // halt
  1, // exit
  1, // exec
  1, // wait
  2, // create
  1, // remove
  1, // open
  1, // filesize
  3, // read
  3, // write
  2, // seek
  1, // tell
  1, // close

  1, // pibonacci
  4  // sum of four integers
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  list_init(&file_list);
}

// the name of stack pointer variable
#define STK_PTR		esp		// the name of stack pointer

// stack pointers for argments
#define ARG1 (STK_PTR + 1)
#define ARG2 (STK_PTR + 2)
#define ARG3 (STK_PTR + 3)
#define ARG4 (STK_PTR + 4)

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *esp = f->esp;
  uint32_t *eax = &(f->eax);

  // check the validity of stack pointer to syscall number
  if(!valid(esp)){
    //printf("syscall handler:invalid esp:%s, %d\n", thread_current()->name, thread_current()->tid);
    exit(-1);
  }

  int syscall_enum = *esp;    

  switch(syscall_argc[syscall_enum]){
  // 0 arguments
  case 0:
    halt();
    break;

  // 1 argument
  case 1:
    // validate 1 argument
    if(!valid(ARG1)){
      //printf("syscall handler:invalid arg:%s, %d\n", thread_current()->name, thread_current()->tid);
      exit(-1);   
    } 

    *eax = ((func_of_1arg)syscall_arr[syscall_enum])(*ARG1);
    break;
  // 2 arguments
  case 2:
    // validate 2 arguments
    if(!(valid(ARG1) || !valid(ARG2))){
      //printf("syscall handler:invalid arg:%s, %d\n", thread_current()->name, thread_current()->tid);
      exit(-1);   
    }

    *eax = ((func_of_2arg)syscall_arr[syscall_enum])(*ARG1, *ARG2);
    break;
  // 3 arguments
  case 3:
    // validate 3 arguments
    if(!(valid(ARG1) || !valid(ARG2) || !valid(ARG3))){
      //printf("syscall handler:invalid arg:%s, %d\n", thread_current()->name, thread_current()->tid);
      exit(-1);   
    }

    *eax = ((func_of_3arg)syscall_arr[syscall_enum])(*ARG1, *ARG2, *ARG3);
    break;
  case 4:
    if(!(valid(ARG1) || !valid(ARG2) || !valid(ARG3) || !valid(ARG4))){
      //printf("syscall handler:invalid arg:%s, %d\n", thread_current()->name, thread_current()->tid);
      exit(-1);   
    }

    *eax = /*(func_of_4arg)*/syscall_arr[syscall_enum](*ARG1, *ARG2, *ARG3, *ARG4);
    
    break; 
  // error
  default:
    //printf("syscall handler:defulat:%s, %d\n", thread_current()->name, thread_current()->tid);
    exit(-1);
  }
}

bool valid(void *vaddr){
  struct thread *t = thread_current();

  // not null, below PHYS_BASE, mapped
  if(vaddr != NULL && is_user_vaddr(vaddr) && pagedir_get_page(t->pagedir, vaddr) != NULL)
    return true;  
  return false;
}

/*
struct file *fd_to_file(struct list list, int fd){
  struct list_elem *e;
  file_elem *f;

  for (e = list_begin (&list); e != list_end(&list); e = list_next(e)){
    f = list_entry(e, file_elem, elem);
    if(f->fd == fd)
      return f->file;
  }
}
*/

/* Terminates Pintos by calling shutdown_Power_off(). */
void halt (void){
  shutdown_power_off();
}
 
/* Terminates the current user program, returning status to the kernel. */
void exit (int status){
  struct thread *cur = thread_current();
  int i;
  printf ("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  for(i=0; i<cur->fd_upper;i++){
    close(i);
  }
  //printf("exit:before semaup(statuslock):current thread:%s, tid:%d\n", cur->name, cur->tid);
  sema_up(&thread_current()->status_lock);
  //printf("exit:after semaup(statuslock) before semadown(exitlock):current thread:%s, tid:%d\n", cur->name, cur->tid);
  sema_down(&thread_current()->exit_lock);  
  //printf("exit:before semadown(exitlock):current thread:%s, tid:%d\n", cur->name, cur->tid);
//  dying_thread.exit_status = status;
  thread_exit();
}

pid_t exec (const char *cmd_line){
  pid_t pid;
  struct thread *child;

  if(!valid(cmd_line)){
    //printf("exec:NULLcmdline:%s, %d\n", thread_current()->name, thread_current()->tid);
    exit(-1);
  }

  pid = process_execute(cmd_line);
 
  return pid;
}

int wait (pid_t pid){
  if(pid <=0 || pid > pid_upper)
    return 0;

  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  if(file == NULL){
    //printf("create:NULLfile:%s, %d\n", thread_current()->name, thread_current()->tid);
    exit(-1);
  }

  lock_acquire(&file_lock);

  bool ret = filesys_create(file, initial_size);

  lock_release(&file_lock);
  return ret;
}

bool remove (const char *file){
  lock_acquire(&file_lock);

  bool ret = filesys_remove(file);

  lock_release(&file_lock);
  return ret;
}

int open (const char *file){
  //printf("userprog/syscall:open:after being called\n");
  //printf("syscall.c:open:after_being_called:file_name:%s, thread_current:%s, tid:%d\n", file, thread_current()->name, thread_current()->tid);
 
  if(file == NULL){
    //printf("file name NULL\n");
    exit(-1);
  }

  // file이라는 파일명 지닌 file 구조체를 initial_thread->file_list에서 탐색

  lock_acquire(&file_lock);
  // create new file structure
  struct file *new_file = filesys_open(file);

  //printf("syscall.c:open:before_NULL_test:file_name:%s\n", file);

  if(new_file == NULL){
    lock_release(&file_lock); 
    //printf("file does not exist\n");
    return -1;
  }

  //printf("syscall.c:open:after_NULL_test:file_name:%s\n", file);

  // update related fileds(fd_upper, file_list) in the current thread
  struct thread *cur = thread_current();

  //printf("syscall.c:open:before_thread_field_adjustment:thread_name:%s\n", cur->name);
  
  int new_fd = ++(cur->fd_upper);
  file_mod_fd(new_file, new_fd);
  strlcpy(file_get_name(new_file), file, strlen(file) + 1);

  list_push_back(&cur->file_list, file_get_fileelem(new_file));	//여기서 죽네

  //printf("syscall.c:open:before_return:file_name:%s\n", file);

  lock_release(&file_lock);
  return new_fd;
}

int filesize (int fd){
  struct file *file = fd_to_file(fd);

  if(file == NULL)
    return 0;

  lock_acquire(&file_lock);

  int size = file_length(file);

  lock_release(&file_lock);
  return size;
}

int read (int fd, void *buffer, unsigned size){
  unsigned i;
  char c;
  uint8_t *cast_buffer = (uint8_t *)buffer;

  if(!valid(buffer)){
    exit(-1);
  }

  struct file *file = fd_to_file(fd);

  if(file == NULL)
    return 0;

  lock_acquire(&file_lock);

  int ret;

  switch(fd){
  case STDIN_FILENO:
    for(i = 0; i < size && (c = input_getc()) != NULL ; ++i)
      cast_buffer[i] = (uint8_t)c;
    ret = i; break;
  case STDOUT_FILENO:
    ret = 0; break;
  default:
    ret = file_read(file, buffer, size); break;
  }

  lock_release(&file_lock);
  return ret;
}

int write (int fd, const void *buffer, unsigned size){
//  printf("write beg\n");
  if(!valid(buffer)){
    //printf("write:inval buff:%s, %d\n", thread_current()->name, thread_current()->tid);
    exit(-1);
  }

  lock_acquire(&file_lock);

  int ret = 0;
  struct file *file;

  //print_all_list();

  switch(fd){
  case STDIN_FILENO:
    ret = 0; break;
  case STDOUT_FILENO:
    putbuf(buffer, size);
    ret = size;	break;
  default:
    file = fd_to_file(fd);
    if(name_to_thread(file_get_name(file)) != NULL){
      //printf("write denied\n");
      file_deny_write(file); 
    }
    ret = file_write(file, buffer, size); 
    file_allow_write(file); break;
  } 

  lock_release(&file_lock);
//  printf("write end\n");
  return ret;
}

void seek (int fd, unsigned position){
  struct file *file = fd_to_file(fd);

  if(file == NULL)
    return 0;

  lock_acquire(&file_lock);

  file_seek(file, position);

  lock_release(&file_lock);
  return;
}

unsigned tell (int fd){
  struct file *file = fd_to_file(fd);

  if(file == NULL)
    return 0;

  lock_acquire(&file_lock);

  int ret;
  ret = file_tell(file);

  lock_release(&file_lock);
  return ret;
}

void close (int fd){

  struct file *file = fd_to_file(fd);

  if(file == NULL)
    return;

  lock_acquire(&file_lock);

  list_remove(file_get_fileelem(file));

  file_close(file);

  lock_release(&file_lock);
  return;
}

int pibonacci (int n){
  int f[n + 1];
  int i;

  f[0] = 0;
  f[1] = 1;

  for(i = 2; i <= n; ++i)
    f[i] = f[i - 1] + f[i - 2];

  return f[n];
}

int sum_of_four_integers(int a, int b, int c, int d){
  return a + b + c + d;
}

