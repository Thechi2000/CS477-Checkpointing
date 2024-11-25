#include "linux/pid.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/thread_info.h>

MODULE_LICENSE("GPL");

static int hello_init(void) {
  printk(KERN_ALERT "Hello, world\n");

  struct task_struct *task = pid_task(find_vpid(88296), PIDTYPE_PID);;
  printk(KERN_INFO "Process: %ld [PID = %d]\n", task->thread.sp, task->pid);
  struct pt_regs *regs = task_pt_regs(task);

  printk(KERN_INFO "AX %lu\n", regs->ax);
  printk(KERN_INFO "BX %lu\n", regs->bx);
  printk(KERN_INFO "CX %lu\n", regs->cx);
  printk(KERN_INFO "DX %lu\n", regs->dx);
  printk(KERN_INFO "SI %lu\n", regs->si);
  printk(KERN_INFO "DI %lu\n", regs->di);
  printk(KERN_INFO "BP %lu\n", regs->bp);
  printk(KERN_INFO "CS %lu\n", regs->cs);
  printk(KERN_INFO "ORIG_AX %lu\n", regs->orig_ax);
  printk(KERN_INFO "IP %lu\n", regs->ip);
  printk(KERN_INFO "FLAGS %lu\n", regs->flags);
  printk(KERN_INFO "SP %lu\n", regs->sp);
  printk(KERN_INFO "SS %lu\n", regs->ss);
  printk(KERN_INFO "8 %lu\n", regs->r8);
  printk(KERN_INFO "9 %lu\n", regs->r9);
  printk(KERN_INFO "10 %lu\n", regs->r10);
  printk(KERN_INFO "11 %lu\n", regs->r11);
  printk(KERN_INFO "12 %lu\n", regs->r12);
  printk(KERN_INFO "13 %lu\n", regs->r13);
  printk(KERN_INFO "14 %lu\n", regs->r14);
  printk(KERN_INFO "15 %lu\n", regs->r15);

  return 0;
}
static void hello_exit(void) { printk(KERN_ALERT "Goodbye, cruel world\n"); }

module_init(hello_init);
module_exit(hello_exit);