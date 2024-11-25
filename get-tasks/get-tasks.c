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

  struct task_struct *task = pid_task(find_vpid(64736), PIDTYPE_PID);;
  printk(KERN_INFO "Process: %ld [PID = %d]\n", task->thread.sp, task->pid);
  struct pt_regs *regs = task_pt_regs(task);

  printk(KERN_INFO "RIP %p\n", (void *)regs->ax);

  return 0;
}
static void hello_exit(void) { printk(KERN_ALERT "Goodbye, cruel world\n"); }

module_init(hello_init);
module_exit(hello_exit);