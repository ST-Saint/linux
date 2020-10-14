/* #include "awid_nluser.h" */
#include "awid_core.h"
#include <errno.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define gettid() syscall(SYS_gettid)

int main(int argc, char **argv) {
  int ret;

  int real = getuid();
  int euid = geteuid();
  pid_t pid = getpid();
  pid_t tid = gettid();
  printf("The REAL UID =: %d\n", real);
  printf("The EFFECTIVE UID =: %d\n", euid);
  printf("The PID = %d\n", pid);
  printf("The tid = %d\n", tid);

  syscall(__NR_register_watchpoint, 0xffff00001234);
  return 0;
}
