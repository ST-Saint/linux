##
# ARM Watchpoint Isolation Domain
#
# @wid.c
# @version 0.1



# end

obj-$(CONFIG_AWID) += awid.o
awid-objs := awid_core.o awid_nlkern.o
KDIR := ../../
all: awid_nluser
	make -C $(KDIR) M=$(PWD) modules
awid_nluser:
	aarch64-linux-gnu-gcc awid_nluser.c -o awid_nluser
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order awid_nluser
