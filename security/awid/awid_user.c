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

static int test_value=0;

int main(int argc, char **argv) {
  int ret;

  /* fork(); */
  int real = getuid();
  int euid = geteuid();
  pid_t pid = getpid();
  pid_t tid = gettid();
  printf("The REAL UID =: %d\n", real);
  printf("The EFFECTIVE UID =: %d\n", euid);
  printf("The PID = %d\n", pid);
  printf("The tid = %d\n\n", tid);
  /* printf("syscall id %d\n", __NR_register_watchpoint); */
  printf("test value addr: %x\n\n", (unsigned long)(&test_value));
  ret = syscall(__NR_register_watchpoint, (unsigned long)(&test_value));
  printf("syscall return %d\n\n", ret);
  printf("------------------\n\n");
  printf("test trigger ori value: %d\n", test_value);
  /* printf("test_value++ : %d\n", test_value++); */
  /* printf("++test_value : %d\n", ++test_value); */
  return 0;
}
