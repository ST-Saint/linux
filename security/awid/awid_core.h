#ifndef __AWID_CORE_H_
#define __AWID_CORE_H_

#include <linux/init.h> /* Needed for the macros */
#include <linux/perf_event.h>

/* extern struct perf_event *__percpu *sample_hbp; */

extern int register_test_watchpoint(unsigned long);

#endif // __AWID_CORE_H_
