
obj-m:=http_whitelist.o
http_whitelist-objs := main.o common/common.o common/file.o
KDIR:=/lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
