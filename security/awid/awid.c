#include "awid.h"
#include <stdio.h>
#include <unistd.h>

/* int awid_setup_slots(unsigned long, enum HW_BREAKPOINT_LEN, */
/* 		     enum HW_BREAKPOINT_TYPE) */
/* { */
/* 	return 0; */
/* } */

int awid_load_so(const char *path, int index)
{
	int ret;
	ret = syscall(__NR_awid_load_so, path, index);
	printf("awid load so return: %d\n", ret);
	return ret;
}
