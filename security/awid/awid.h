#ifndef __AWID_H_
#define __AWID_H_

#include "loader.h"
#include "loader_config.h"
#include <uapi/linux/hw_breakpoint.h>

static const sysent_t sysentries = {
	do_sys_open, /* */
	ksys_close, /* */
	ksys_write, /* */
	ksys_read, /* */
	printk, /* */
	/* scanf /\* *\/ */
};

static const ELFSymbol_t exports[] = { { "syscalls", (void *)&sysentries } };
static const ELFEnv_t env = { exports, sizeof(exports) / sizeof(*exports) };
extern int awid_setup_slots(unsigned long, enum HW_BREAKPOINT_LEN,
			    enum HW_BREAKPOINT_TYPE);
extern int awid_laod_so(const char, int);

#endif // __AWID_H_
