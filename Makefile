
obj-m:=http_whitelist.o
http_whitelist-objs := main.o common/file.o common/host.o common/misc.o common/network.o
KDIR:=/lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
