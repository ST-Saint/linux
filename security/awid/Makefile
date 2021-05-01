##
# ARM Watchpoint Isolation Domain
#
# @wid.c
# @version 0.1



# end

obj-$(CONFIG_AWID) += awid.o
awid-objs := awid_core.o loader.o
PWD := ${CURDIR}
KDIR := $(CURDIR)/../../
SOURCES=$(wildcard *.c^)
HEADERS=$(wildcard *.h^)
all: $(SOURCES) $(HEADERS) awid_user
	make -C $(KDIR) M=$(PWD)
awid_user: awid_user.c
	aarch64-linux-gnu-gcc -g awid_user.c -o awid_user -lpthread
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order awid_user
