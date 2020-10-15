#include "awid_core.h"

#include <linux/init.h> /* Needed for the macros */
#include <linux/kallsyms.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/module.h> /* Needed by all modules */

#include <asm/string.h>
#include "awid_core.h"
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <net/sock.h>

struct perf_event *__percpu *sample_hbp;

static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs) {
  printk("--------------------------------------\n");
  printk(KERN_INFO
         "trigger hook_func. My pid: %d, tgid: %d, comm: %s, uid: %d, euid: %d\n",
         current->pid, current->tgid, current->comm, current->cred->uid, current->cred->euid);
  /* dump_stack(); */
  do_exit(SIGKILL);
}

int test_value = 0;

asmlinkage long __arm64_sys_register_watchpoint(unsigned long addr) {
  printk("--------------------------------------\n");
  printk(KERN_INFO
         "syscall func. My pid: %d, tgid: %d, comm: %s, uid: %d, euid: %d\n",
         current->pid, current->tgid, current->comm, current->cred->uid, current->cred->euid);
  int ret;
  struct perf_event_attr attr;

  /* void *addr = __symbol_get(ksym_name); */

  /* if (!addr) */
  /*   RETURN -ENXIO; */


  hw_breakpoint_init(&attr);
  /* attr.bp_addr = (unsigned long)(&test_value); */
  attr.bp_addr = addr;
  attr.bp_len = HW_BREAKPOINT_LEN_4;
  attr.bp_type = HW_BREAKPOINT_W;

  test_value+=1;
  printk("watchpoint at %08lx value: %d\n", addr, test_value);
  printk(KERN_INFO "Watchpoint registration start\n");
  /* rcu_read_lock(); */
  /* printk(KERN_INFO "Watchpoint registration rcu read lock\n"); */
  preempt_disable();
  printk(KERN_INFO "Watchpoint registration preempt disable\n");
  sample_hbp = register_wide_hw_breakpoint(&attr, sample_hbp_handler, NULL);
  /* rcu_read_unlock(); */
  /* printk(KERN_INFO "Watchpoint registration rcu read unlock\n"); */
  preempt_enable();
  printk(KERN_INFO "Watchpoint registration preempt enable\n");
  if (IS_ERR((void __force *)sample_hbp)) {
    ret = PTR_ERR((void __force *)sample_hbp);
    printk(KERN_INFO "Watchpoint registration done %d\n", ret);
    goto fail;
  }

  /* printk(KERN_INFO "HW Breakpoint for %s write installed\n", ksym_name); */
  printk(KERN_INFO "Watchpoint registration succeed\n");

  return 0;

fail:
  printk(KERN_INFO "Breakpoint registration failed\n");

  return ret;
}

static int __init awid_module_init(void) {
  /* __arm64_sys_register_watchpoint((unsigned long)(&test_value)); */
  printk(KERN_INFO
         "Code Called in hook_func. My pid: %d, tgid: %d, comm: %s, uid: %d, euid: %d\n",
         current->pid, current->tgid, current->comm, current->cred->uid, current->cred->euid);
  return 0;
}

static void __exit awid_module_exit(void) {
  printk("awid_netlink_unregister!\n");
  if (!IS_ERR((void __force *)sample_hbp)) {
    unregister_wide_hw_breakpoint(sample_hbp);
  }
}

module_init(awid_module_init);
module_exit(awid_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YayuWang");
MODULE_DESCRIPTION("ARM Watchpoint Isolation Domain");
