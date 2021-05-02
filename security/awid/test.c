#include <stdio.h>
#include <linux/kernel.h>
#include <unistd.h>
#include <sys/syscall.h>

extern int add_so(int a, int b);
extern int sub_so(int a, int b);
extern void maliciosu_read_so(char *c);

#define __NR_identity 440

long identity_syscall(void)
{
	return syscall(__NR_identity);
}

int main()
{
	int a, b;
	a = 10;
	b = 3;
	printf("add: %d\nsub: %d\n", add_so(a, b), sub_so(a, b));
	return 0;
}
