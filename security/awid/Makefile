##
# ARM Watchpoint Isolation Domain
#
# @wid.c
# @version 0.1



# end

obj-$(CONFIG_AWID) += awid.o
awid-objs := awid_core.o
PWD := ${CURDIR}
KDIR := $(CURDIR)/../../
SOURCES=$(wildcard *.c^)
HEADERS=$(wildcard *.h^)
all: $(SOURCES) $(HEADERS)
	make -C $(KDIR) M=$(PWD)
awid_user: awid_user.c
	aarch64-linux-gnu-gcc awid_user.c -o awid_user
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order awid_user
