#ifndef LOADER_USER_DATA_H
#define LOADER_USER_DATA_H

#include "linux/types.h"
#include <linux/unistd.h>

typedef struct loader_env {
	struct file *fd;
	off_t offset;
	const struct ELFEnv *env;
} loader_env_t;

#define LOADER_USERDATA_T loader_env_t

#endif
