#include "awid_core.h"
#include "loader.h"
#include "loader_config.h"
#include "loader_userdata.h"

#include "asm/syscall_wrapper.h"
#include "linux/err.h"
#include "linux/gfp.h"
#include "linux/preempt.h"
#include "linux/smp.h"
#include <linux/cpu.h>
#include <linux/init.h> /* Needed for the macros */
#include <linux/hw_breakpoint.h>
#include <asm-generic/errno-base.h>
#include <asm/current.h>
#include <asm/hw_breakpoint.h>
#include <linux/kern_levels.h>
#include <linux/linkage.h>
#include <linux/pid.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/module.h> /* Needed by all modules */

#include <asm/string.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <net/sock.h>
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

struct perf_event *hbp;
struct perf_event **awid_hwps[ARM_MAX_WRP];

static void awid_simple_handler(struct perf_event *bp,
				struct perf_sample_data *data,
				struct pt_regs *regs)
{
	printk("--------------------------------------\n");
	printk(KERN_INFO
	       "syscall func. My pid: %d, tgid: %d, comm: %s, uid: %d, euid: %d\n",
	       current->pid, current->tgid, current->comm,
	       current->cred->uid.val, current->cred->euid.val);
	printk("--------------------------------------\n");
	printk("\ndump trigger trace\n\n");
	printk("-------------------------------------\n");
	dump_stack();
	do_exit(SIGKILL);
}

asmlinkage __attribute__((optimize("O0"))) long
__arm64_sys_watchpoint_trigger(struct perf_event *wp)
{
	switch (wp->attr.bp_type) {
	default: {
		return -EINVAL;
	}
	case HW_BREAKPOINT_R: {
		int *addr = (int *)(wp->hw.info.address);
		int value = *addr;
		printk(KERN_INFO "trigger read watchpoint at %n\n", addr);
		printk(KERN_INFO "trigger read watchpoint addr value: %d\n",
		       value);
		break;
	}
	case HW_BREAKPOINT_W: {
		int *addr = (int *)(wp->hw.info.address);
		int value = *addr;
		printk(KERN_INFO "trigger read watchpoint at %n\n", addr);
		*addr = 0;
		*addr = value;
		break;
	}
	}
	return 0;
}

void awid_clear(void)
{
}

asmlinkage long __arm64_sys_watchpoint_clear(void)
{
	awid_clear();
	return 0;
}

int awid_find_wp_slot(void)
{
	int i;
	for (i = 0; i < ARM_MAX_WRP; ++i) {
		// if (awid_hwps[i] == NULL) {
		if (current->thread.debug.awid_hbp[i] == NULL) {
			return i;
		}
	}
	return -1;
}

SYSCALL_DEFINE3(awid_setup_slots, unsigned long, start_addr,
		enum HW_BREAKPOINT_LEN, slot_length, enum HW_BREAKPOINT_TYPE,
		wp_type)
{
	struct ELFExec *exec;
	loader_env_t loader_env;
	loader_env.env = &env;
	load_elf("./lsample.so", loader_env, &exec);
	return 0;
}

SYSCALL_DEFINE1(awid_switch_to, int, slot_index)
{
	/* TODO entry gate */
	return 0;
}

SYSCALL_DEFINE0(awid_exit)
{
	/* TODO exit gate */
	return 0;
}

SYSCALL_DEFINE3(register_watchpoint,
		// asmlinkage long __arm64_sys_register_watchpoint(
		unsigned long, addr, enum HW_BREAKPOINT_LEN, wp_length,
		enum HW_BREAKPOINT_TYPE, wp_type)
{
	int ret, slot, cpu;
	/* unsigned long size; */
	struct perf_event **bp;
	struct perf_event_attr attr;
	printk("--------------------------------------\n");
	printk(KERN_INFO
	       "syscall func. cpu: %d, My pid: %d, tgid: %d, comm: %s, uid: %d, euid: %d\n",
	       smp_processor_id(), current->pid, current->tgid, current->comm,
	       current->cred->uid.val, current->cred->euid.val);
	printk("\n");

	printk("addr: %lx length: %d type: %d\n", addr, wp_length, wp_type);
	hw_breakpoint_init(&attr);
	attr.bp_addr = addr;
	if (wp_length == HW_BREAKPOINT_LEN_1 ||
	    wp_length == HW_BREAKPOINT_LEN_2 ||
	    wp_length == HW_BREAKPOINT_LEN_3 ||
	    wp_length == HW_BREAKPOINT_LEN_4 ||
	    wp_length == HW_BREAKPOINT_LEN_5 ||
	    wp_length == HW_BREAKPOINT_LEN_6 ||
	    wp_length == HW_BREAKPOINT_LEN_7 ||
	    wp_length == HW_BREAKPOINT_LEN_8) {
		attr.bp_len = wp_length;
	} else {
		return -EINVAL;
	}
	if (wp_type == HW_BREAKPOINT_R || wp_type == HW_BREAKPOINT_W ||
	    wp_type == HW_BREAKPOINT_RW) {
		attr.bp_type = wp_type;
	} else {
		return -EINVAL;
	}
	attr.disabled = 0;

	/* get_online_cpus(); */
	cpu = smp_processor_id();
	hbp = perf_event_create_kernel_counter(&attr, cpu, current,
					       awid_simple_handler, NULL);
	/* put_online_cpus(); */
	printk(KERN_INFO "watchpoint hbp addr %lx\n", (unsigned long)(hbp));

	if (IS_ERR(hbp)) {
		ret = PTR_ERR(hbp);
		goto fail;
	}

	/* slot = awid_find_wp_slot(); */
	/* if (slot == -1) { */
	/* 	return -EPERM; */
	/* } */
	/* /\* printk(KERN_INFO "register watchpoint on slot %d\n", slot); *\/ */

	/* current->thread.debug.awid_hbp[slot] = */
	/* 	kzalloc(sizeof(struct perf_event *) * nr_cpu_ids, GFP_ATOMIC); */
	/* /\* bp = kmalloc(sizeof(struct perf_event *) * nr_cpu_ids, GFP_KERNEL); *\/ */
	/* get_online_cpus(); */
	/* cpu = get_cpu(); */
	/* bp = &current->thread.debug.awid_hbp[slot][cpu]; */
	/* *bp = perf_event_create_kernel_counter(&attr, cpu, current, */
	/* 				       awid_simple_handler, NULL); */
	/* for_each_online_cpu (cpu) { */
	/* 	bp = &current->thread.debug.awid_hbp[slot][cpu]; */
	/* 	/\* printk(KERN_INFO "watchpoint bp pointer adddr %lx\n", *\/ */
	/* 	/\*        (unsigned long)(&bp)); *\/ */
	/* 	printk(KERN_INFO "watchpoint bp adddr %lx\n", */
	/* 	       (unsigned long)(bp)); */
	/* 	printk(KERN_INFO "watchpoint bp value %lx\n", */
	/* 	       (unsigned long)(*bp)); */
	/* } */
	/* if (IS_ERR(*bp)) { */
	/* 	ret = PTR_ERR(*bp); */
	/* 	goto fail; */
	/* } */
	/* get_online_cpus(); */
	/* for_each_online_cpu (cpu) { */
	/* 	bp = current->thread.debug.awid_hbp[slot] + cpu; */
	/* 	*bp = perf_event_create_kernel_counter( */
	/* 		&attr, cpu, current, awid_simple_handler, NULL); */
	/* 	if (IS_ERR(*bp)) { */
	/* 		ret = PTR_ERR(*bp); */
	/* 		goto fail; */
	/* 	} */
	/* } */
	/* for_each_online_cpu (cpu) { */
	/* 	printk(KERN_INFO "user bp address %lx\n", */
	/* 	       (unsigned long)(current->thread.debug */
	/* 				       .awid_hbp[slot][cpu])); */
	/* } */

	/* if (IS_ERR((void __force *)hbp)) { */
	/* 	ret = PTR_ERR((void __force *)hbp); */
	/* 	*hbp = NULL; */
	/* 	printk(KERN_INFO "Watchpoint registration done %d\n", ret); */
	/* 	goto fail; */
	/* } */
	/* size = copy_from_user(&awid_hwps[0], &hbp, sizeof(hbp)); */
	/* printk(KERN_INFO "copy remain size %lu\n", size); */
	/* printk(KERN_INFO "copy addr %lx value %lx\n", */
	/*        (unsigned long)&awid_hwps[0], (unsigned long)awid_hwps[0]); */
	/* current->thread.debug.awid_hbp[slot] = */
	/* 	kmalloc(sizeof(struct perf_event **), GFP_KERNEL); */
	/* unsigned long remain = */
	/* 	copy_from_user(current->thread.debug.awid_hbp + slot, hbp, */
	/* 		       sizeof(struct perf_event **)); */
	/* printk(KERN_INFO "copy remain %lu\n", remain); */
	/* printk(KERN_INFO "hbp %lx\ntarget slot %lx %lx\n", (unsigned long)hbp, */
	/*        (unsigned long)(current->thread.debug.awid_hbp + slot), */
	/*        (unsigned long)current->thread.debug.awid_hbp[slot]); */
	/* hbp = NULL; */

	/* printk(KERN_INFO "HW Breakpoint for %s write installed\n", ksym_name); */
	printk(KERN_INFO "Watchpoint registration succeed\n");

	return 0;

fail:
	printk(KERN_INFO "Breakpoint registration failed\n");

	return ret;
}

static int __init awid_module_init(void)
{
	/* __arm64_sys_register_watchpoint((unsigned long)(&test_value)); */
	return 0;
}

static void __exit awid_module_exit(void)
{
	/* awid_clear(); */
}

module_init(awid_module_init);
module_exit(awid_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YayuWang");
MODULE_DESCRIPTION("ARM Watchpoint Isolation Domain");
