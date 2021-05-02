#ifndef __AWID_H_
#define __AWID_H_

typedef unsigned short umode_t;

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "loader.h"
#include "loader_config.h"
/* #include <uapi/linux/hw_breakpoint.h> */

/* extern int awid_setup_slots(unsigned long, enum HW_BREAKPOINT_LEN, */
/* 			    enum HW_BREAKPOINT_TYPE); */
extern int awid_laod_so(const char, int);

#endif // __AWID_H_
