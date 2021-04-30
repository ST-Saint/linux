#include <stdio.h>
#include "sample.h"

int add_so(int a, int b)
{
	return a + b;
}

int sub_so(int a, int b)
{
	return a - b;
}

void malicious_read_so(char *c)
{
	unsigned long long i;
	for (i = 0;; i += (1 << 30)) {
		printf("offset: %llu %08x, char: %c\n", i, c[i]);
	}
}
