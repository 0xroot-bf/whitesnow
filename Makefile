VERSION = 2
PATCHLEVEL = 6
SUBLEVEL = 29
EXTRAVERSION = -00054-g5f01537

obj-m += whitesnow.o

KDIR = /Users/sebas/Investigacion/goldfish
CROSS_COMPILE= /Users/sebas/Investigacion/android-ndk-r8b/toolchains/arm-linux-androideabi-4.4.3/prebuilt/darwin-x86/bin/arm-linux-androideabi-
PWD := $(shell pwd)

all:
	make -C $(KDIR) ARCH=arm CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=-fno-pic  SUBDIRS=$(PWD) modules
	rm -rf *.c~
	rm -rf *.mod*
	rm -rf *.o

clean:
	make -C $(KDIR) ARCH=arm CROSS_COMPILE={CROSS_COMPILE} EXTRA_CFLAGS=-fno-pic SUBDIRS=$(PWD) clean
