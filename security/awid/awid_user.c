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

static int test_value[1024] = {};

void test_func()
{
	printf("test func");
}

void test_func_sup()
{
	printf("test addr offset");
}

void test_ntid(void)
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
	int i, cnt = 0;
	char c;
	while (1) {
		scanf("%c", &c);
		switch (c) {
		default: {
			printf("%c\n\n", c);
			break;
		}
		case 'r': {
			ret = syscall(__NR_register_watchpoint,
				      (unsigned long)(&test_value[cnt]),
				      HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_R);
			cnt += 1;
			printf("syscall return %d\n\n", ret);
			printf("------------------\n\n");
			break;
		}
		case 'w': {
			ret = syscall(__NR_register_watchpoint,
				      (unsigned long)(&test_value[cnt]),
				      HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_W);
			cnt += 1;
			printf("syscall return %d\n\n", ret);
			printf("------------------\n\n");
			break;
		}
		case 'x': {
			ret = syscall(__NR_register_watchpoint,
				      (unsigned long)(&test_func),
				      HW_BREAKPOINT_LEN_8, HW_BREAKPOINT_X);
			cnt += 1;
			printf("addr are %lx %lx\n",
			       (unsigned long)(&test_func),
			       (unsigned long)(&test_func_sup));
			printf("syscall return %d\n\n", ret);
			printf("------------------\n\n");
			test_func_sup();
			/* test_func(); */
			break;
		}
		case 't': {
			printf("trigger wp value before %d\n");
			for (i = 0; i < cnt; ++i) {
				printf("%d ", test_value[i]);
			}
			puts("");
			for (i = 0; i < cnt; ++i) {
				printf("%d ", test_value[i]);
			}
			for (i = 0; i < cnt; ++i) {
				test_value[i] ^= 1;
			}
			printf("trigger wp value after\n");
			for (i = 0; i < cnt; ++i) {
				printf("%d ", test_value[i]);
			}
			puts("");
		}
		case 'q': {
			return;
		}
		}
	}
}

int main(int argc, char **argv)
{
	pthread_t ntid;
	/* fork(); */
	// int err = pthread_create(&ntid, NULL, test_ntid, NULL);
	// if (err != 0)
	// printf("can't create thread: %s\n", strerror(err));
	// pthread_join(ntid,NULL);
	test_ntid();
	return 0;
}
