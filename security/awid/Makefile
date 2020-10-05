##
# ARM Watchpoint Isolation Domain
#
# @wid.c
# @version 0.1



# end

obj-$(CONFIG_AWID) += awid.o
awid-objs := awid_core.o awid_nlkern.o
KDIR := ../../
PWD := ${CURDIR}
SOURCES=$(wildcard *.c^)
HEADERS=$(wildcard *.h^)
all: $(SOURCES) $(HEADERS) awid_nluser
	make -C $(KDIR) M=$(PWD)
awid_nluser: awid_nluser.c
	aarch64-linux-gnu-gcc awid_nluser.c -o awid_nluser
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order awid_nluser
