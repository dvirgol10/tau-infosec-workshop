obj-m += firewall.o
firewall-objs := hw4secws.o fw_log.o fw_rules.o fw_conntab.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
