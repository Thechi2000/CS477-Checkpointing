obj-m += get-tasks.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: all
	sudo rmmod get-tasks.ko
	sudo insmod get-tasks.ko
