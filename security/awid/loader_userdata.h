#ifndef LOADER_USER_DATA_H
#define LOADER_USER_DATA_H

#include "linux/types.h"
#include "loader_config.h"
#include <linux/unistd.h>
#include <linux/syscalls.h>

typedef struct {
	long (*open)(int, const char *path, int mode, umode_t);
	int (*close)(unsigned int fd);
	long (*write)(unsigned int fd, const char *data, size_t size);
	long (*read)(unsigned int fd, char *buf, size_t size);
	int (*printf)(const char *fmt, ...);
	/* int (*scanf)(const char *fmt, ...); */
} sysent_t;

extern sysent_t syscalls;
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

typedef struct loader_env {
	int fd;
	const struct ELFEnv *env;
} loader_env_t;

#define LOADER_USERDATA_T loader_env_t

#endif
