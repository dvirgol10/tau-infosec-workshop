obj-m += firewall.o
firewall-objs := hw3secws.o fw_log.o fw_rules.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
