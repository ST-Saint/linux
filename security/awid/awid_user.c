/* #include "awid_nluser.h" */
#include <time.h>
#include "awid_core.h"
#include "loader.h"
#include <dlfcn.h>
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

extern int add_so(int a, int b);
extern int sub_so(int a, int b);
extern void maliciosu_read_so(char *c);

void test_func(void)
{
}

void loadso(void)
{
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
				      HW_BREAKPOINT_LEN_5, HW_BREAKPOINT_R);
			cnt += 1;
			printf("syscall return %d\n\n", ret);
			printf("------------------\n\n");
			break;
		}
		case 'w': {
			ret = syscall(__NR_register_watchpoint,
				      (unsigned long)(&test_value[cnt]),
				      HW_BREAKPOINT_LEN_5, HW_BREAKPOINT_W);
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
			       (unsigned long)(&test_func));
			printf("syscall return %d\n\n", ret);
			printf("------------------\n\n");
			/* test_func(); */
			break;
		}
		case 't': {
			printf("trigger wp value before %d\n");
			for (i = cnt << 1; i >= 0; --i) {
				printf("(%d, %d) ", i, test_value[i]);
			}
			puts("");
			for (i = cnt << 1; i >= 0; --i) {
				printf("(%d, %d) ", i, test_value[i]);
			}
			for (i = cnt << 1; i >= 0; --i) {
				test_value[i] ^= 1;
			}
			printf("trigger wp value after\n");
			for (i = cnt << 1; i >= 0; --i) {
				printf("(%d, %d) ", i, test_value[i]);
			}
			puts("");
		}
		case 'q': {
			return;
		}
		}
	}
}

void benchmark(void)
{
	// one hwp len = 1 read
	int ret, rd, wt;
	long long i, loop = (long long)(1e5);
	struct timespec start, end;
	double delta_us;
	int *arr, *ptr, offset = 0x200;

	arr = (int *)malloc(0x20000000ul);
	ptr = arr;

	printf("get address %llx\n", &arr);
	ret = syscall(__NR_register_watchpoint, (unsigned long long)(ptr),
		      HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_R);

	if (ret) {
		printf("register hwp error: %d\n", ret);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	printf("Get start clock %ld %ld\n", start.tv_sec, start.tv_nsec);
	for (i = offset; i < loop; ++i) {
		rd = (int)(*(int *)(ptr + (i & 0x1fffffffl)));
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("Get end clock %ld %ld\n", end.tv_sec, end.tv_nsec);
	delta_us = (end.tv_sec - start.tv_sec) +
		   (double)(end.tv_nsec - start.tv_nsec) / 1000000000;
	printf("delta time: %.8lf s\n", delta_us);
}

extern int awid_load_so(const char *path, int index);

int main(int argc, char **argv)
{
	/* pthread_t ntid; */
	/* test_ntid(); */
	benchmark();
	/* awid_load_so("./libsample.so", 1); */
	/* void (*a)(void) = 0x4000738; */
	/* printf("exec %llx %llx\n", a, *a); */
	/* a(); */
	/* printf("exec init_done\n"); */
	return 0;
}
