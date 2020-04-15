#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

//added header file
#include "userprog/syscall.h" 
#include "vm/page.h"

// specify delimiter string
#define DELIMITERS " \t\n\r"

// whether to use ' ' or DELIMITERS as delimiter
//#define DEFAULT_DELIMITER
//#define SPECIFY_DELIMITER

// set delimiter
//#ifdef SPECIFY_DELIMITER
  #define IS_BLANK (strchr(DELIMITERS, *s) != NULL)
//#elif DEFAULT_DELIMITER
//  #define IS_BLANK (*s == ' ')


#define MAX_ARG 128				// MAXimum number of ARGuments
#define MAX_ARG_ADDR MAX_ARG * sizeof(char *)	// MAXimum length of ADDResses of ARGuments

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char tmp_file_name[MAX_FILENAME];

  char *fn_copy;
  tid_t tid;
  char *save_ptr;		// for strtok
  struct file *file = NULL;	// for filesys_open
  struct list_elem* e;
  struct thread* t;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL) 
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // strcpy to avoid error(multi args)
  strlcpy (tmp_file_name, file_name, strlen(file_name) + 1);

 // for exec-missing("no-such-file")
  lock_acquire(&file_lock);
  file = filesys_open(strtok_r(tmp_file_name, DELIMITERS, &save_ptr));
  lock_release(&file_lock);
  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);
  if(file == NULL)
    return -1; 

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (strtok_r(tmp_file_name, DELIMITERS, &save_ptr),  PRI_DEFAULT, start_process, fn_copy);
  sema_down(&thread_current()->fail_lock);
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy); 
  }
  t=tid_to_thread(tid);
  if(t->load)
    return process_wait(tid);
  return tid;
 }
 
/* A thread function that loads a user process and starts it
   running. */
// file_name_ differs from file_name above
//	test by modifying one above
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread* t=thread_current();
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  sema_up(&thread_current()->parent->fail_lock);
  if (!success) {
    t->load=true;
    exit(-1);}

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

// 개선해야할 사항들
// 1. child->wait = true; -> algo2와 같은 문제
// 2. list operation -> 원자성 없으므로 lock 필요
// (해결)3. list 연산은 overhead 크기 때문에 하나로 -> parent 필드 추가하고 current_thread == child->parent로 판단
// 4. wait의 모든 연산이 child에 의존하는데 child가 도중에 죽어버리면 child 참조 불가능 
// 5. 한꺼번에 여러 thread가 죽어 dying_thread의 exit_status collect 되기 전에 덮어씌워짐
// 6. wait하기 전에 죽으면 exit_status 어떻게 collect해야?


int
process_wait (tid_t child_tid UNUSED) 
{
  static int cnt = 0;
// child 상태:
// 1. 아직 안 thread_create 안 됨
// 2. 1, 3 사이
// 3. 이미 thread_exit 됨

  // (잠금 필요)tid_to_thread는 원자성 없음
  // child가 all_list에서 remove되는 중에 호출되면 error 발생
  struct thread *child = tid_to_thread(child_tid); 
//  printf("%d\n", cnt);
  // NULL값 참조 방지
  // 기다릴 thread가 이미 죽음
  // exit_status collect 어떻게?
  if(child == NULL){
    //printf("wait:child NULL:current_thread:%s tid:%d tried to wait tid:%d\n", thread_current()->name, thread_current()->tid, child_tid);
    return -1;
  }
  // (잠금 필요)is_child_to_thread는 원자성 없음
  // child가 child_list에서 remove되는 중에 호출되면 error 발생
  // 3번 경우, 부모 자식 아닌 경우 예외처리
  if(child->parent != thread_current()){
    //printf("wait:not related:current_thread:%s tid:%d tried to wait child_thread:%s tid:%d\n", thread_current()->name, thread_current()->tid, child->name, child_tid);
    return -1;
  }

  // 이미 부모가 기다려 줬음
  if(child->wait == true)
     return -1;
/*
  // 부모가 자식을 기다려 주기 시작
  child->wait = true;
  
  // wait
  while(1){
    printf("", dying_thread.tid);	// 가장 최근 죽은 쓰레드의 tid값 불러오기
    if(dying_thread.tid == child_tid){	// 그 값이 기다리는 tid면
      return dying_thread.exit_status;	// 그만 기다리기
    }
  }
*/


  //printf("wait:before sema down(statuslock):current_thread:%s tid:%d tried to wait child_thread:%s tid:%d\n", thread_current()->name, thread_current()->tid, child->name, child_tid);
  child->wait = 1;
  sema_down(&child->status_lock);
  
  int exit_status = child->exit_status;

  //printf("wait:after sema down(statuslock) before sema up(exitlock):current_thread:%s tid:%d tried to wait child_thread:%s tid:%d\n", thread_current()->name, thread_current()->tid, child->name, child_tid);
  sema_up(&child->exit_lock);
  //printf("wait:after sema up(exitlock):current_thread:%s tid:%d tried to wait child_thread:%s tid:%d\n", thread_current()->name, thread_current()->tid, child->name, child_tid);
  sema_down(&child->remove_lock);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  if (!hash_empty (&cur->supple_pt)) {
    spage_destroy (&cur->supple_pt);
  }
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    } 

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };


/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

// S(file_name)의 내용을 argv에 예쁘게 정리
// argc는 arg 개수, arg_len은 arg 총 길이 합
  void file_name_to_argv (char *s, char *argv[MAX_ARG], int *argc, size_t *arg_len){
    *argc = 0;
    *arg_len = 0;
    int i = 1;

	while (*s != '\0')
	{
		// 공백 제거
		while (IS_BLANK)
			++s;

		// 공백 다음이 NULL이면 break
		if(*s == '\0')
			return;

		// NULL이 아니면 단어이므로 argv에 저장
		argv[(*argc)++] = s;

		// 단어 skip
		while (!IS_BLANK && *s != '\0')
			++s;

    
                if(*s == '\0'){
		// arglen 갱신
			(*arg_len) += strlen(argv[(*argc) - 1]);
               		 ++i;
               		 return;
		}

		// 단어의 마지막에 NULL 추가
		*(s++) = '\0';

		// arglen 갱신
		(*arg_len) += strlen(argv[(*argc) - 1]);
                ++i;
	}
	return;
  }

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

// temp variable to avoid duplicate operation
//must be declared in the block before use
#define SIZE tmp_size

// push ITEM of SIZE to stack
#define MEM_PUSH(item, size)	SIZE = size;	\
				*esp -= SIZE; 	\
				memcpy(*esp, item, SIZE);

// set SIZE of stack to VALUE
#define MEM_SET(value,size)	SIZE = size;		\
				*esp -= SIZE;		\
				memset(*esp, value, SIZE);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofset;
  bool success = false;
  int i;

  // arguments for function file_name_to_argv 
  char *argv[MAX_ARG];	// arguments
  int argc = 0;		// # of arguments
  size_t arg_len = 0;	// sum of arguments length including NULL ptr
  char tmp_file_name[MAX_FILENAME];
  size_t tmp_size;	// used in macroe PUSH, MEM_PUSH, MEM_SET
  char *addr_list[MAX_ARG_ADDR + 1];	// list of address of arguments
  char excess;		// excess bytes
  int esp_offset_addr;	// bytes occupied by address of arguments
  uint8_t *tmp_esp;	// temporary esp

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  strlcpy(tmp_file_name, file_name, strlen(file_name) + 1);	// strcp to avoid error
  ((char *)file_name)[strlen(file_name)] = '\0';                // mark the end to avoid error	
  file_name_to_argv(tmp_file_name,  argv, &argc, &arg_len);  	// aprse file_name

  /* Open executable file. */
  lock_acquire(&file_lock);
  file = filesys_open (argv[0]); 
  lock_release(&file_lock);

if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofset = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofset < 0 || file_ofset > file_length (file))
        goto done;
      file_seek (file, file_ofset);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofset += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

/*
  // load 함수의 모든 검사를 통과했으면 main thread의 file구조체의 field를 초기화한 후  file_list field에 추가하기
  struct thread *main_thread = get_initial_thread();
  int new_fd = main_thread->fd_upper - 1;
  main_thread->fd_upper = new_fd;
  file_mod_fd(file, new_fd);
  strlcpy(file_get_name(file), argv[0], strlen(argv[0]) + 1);
  file_deny_write(file);

  list_push_back(&main_thread->file_list, file_get_fileelem(file));
*/

// push argv[i]
   for(i = argc - 1; i >= 0 ; --i){
           MEM_PUSH(argv[i], strlen(argv[i]) + 1);
	   addr_list[i] = (char *)(*esp);
   }

// word allign
   excess = (argc + arg_len) % 4;
   if (excess){           // stack에 push된 길이가 4바이트로 나눠 떨어지지 않으면
           MEM_SET(0, 4 - excess);
  }

// push argv[-1]
   MEM_SET(0, sizeof(char *));

// push &(argv[i])
   esp_offset_addr = argc * sizeof(char *);
   MEM_PUSH(addr_list, esp_offset_addr);

// push argv
   tmp_esp = *esp;
   MEM_PUSH(&tmp_esp, sizeof(char **));

// push argc
   MEM_PUSH(&argc, sizeof(int));

// push ret addr
   MEM_SET(0, sizeof(void *));

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
 done:
  lock_acquire(&file_lock);
  file_close (file);
  lock_release(&file_lock);
  if(success == false){
    //printf("load not successfull:%s, %d\n", thread_current()->name, thread_current()->tid);
    //exit(-1);
  }
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
//  if (phdr->p_offset < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *knpage = palloc_get_page (PAL_USER);
      if (knpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, knpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (knpage);
          return false; 
        }
      memset (knpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, knpage, writable)) 
        {
          palloc_free_page (knpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    success = stack_growth (((uint8_t *) PHYS_BASE) - PGSIZE);
    if (success){
      *esp = PHYS_BASE;
    }
    else
      palloc_free_page (kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *th = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (th->pagedir, upage) == NULL
          && pagedir_set_page (th->pagedir, upage, kpage, writable));
}
