#include <stdio.h>

extern int add_so(int a, int b);
extern int sub_so(int a, int b);
extern void maliciosu_read_so(char *c);

int main()
{
	int a, b;
	a = 10;
	b = 3;
	printf("add: %d\nsub: %d\n", add_so(a, b), sub_so(a, b));
	return 0;
}
