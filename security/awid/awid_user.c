/* #include "awid_nluser.h" */
#include "awid_core.h"
#include <errno.h>
#include <linux/netlink.h>
#include <linux/hw_breakpoint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>

#define gettid() syscall(SYS_gettid)

static int test_value = 0;

void test_ntid()
{
	int ret;
	int real = getuid();
	int euid = geteuid();
	pid_t pid = getpid();
	pid_t tid = gettid();
	printf("The REAL UID =: %d\n", real);
	printf("The EFFECTIVE UID =: %d\n", euid);
	printf("The PID = %d\n", pid);
	printf("The tid = %d\n\n", tid);
	/* printf("syscall id %d\n", __NR_register_watchpoint); */
	// printf("test value addr: %x\n\n", (unsigned long)(&test_value));
	ret = syscall(__NR_register_watchpoint, (unsigned long)(&test_value),
		      HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_W, HW_BREAKPOINT_SELF);
	printf("syscall return %d\n\n", ret);
	printf("------------------\n\n");
	int i, n;
	char c;
	while (1) {
		scanf("%c", &c);
		switch (c) {
		default: {
			printf("%c\n\n", c);
			break;
		}
		case 'r': {
			printf("read wp value %d\n", test_value);
			break;
		}
		case 'w': {
			printf("write wp value before %d\n", test_value);
			c = 1;
			printf("write wp value after %d\n", test_value);
			break;
		}
		case 'q': {
			return;
		}
		}
	}
}

int main(int argc, char **argv)
{
	/* fork(); */
	pthread_t ntid;
	// int err = pthread_create(&ntid, NULL, test_ntid, NULL);
	// if (err != 0)
	// printf("can't create thread: %s\n", strerror(err));
	// pthread_join(ntid,NULL);
	test_ntid();
	return 0;
}
