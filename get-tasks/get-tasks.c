#include "uapi/linux/limits.h"
#include <asm/ptrace.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/thread_info.h>

#define DEVICE_NAME "get_task"
#define CLASS_NAME "get_task_class"

#define READ_REGS _IOWR('a', 1, regs_t)

MODULE_LICENSE("GPL");

typedef struct {
  uint64_t pid;
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rsp;
  uint64_t rbp;
  uint64_t ss;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t cs;
  uint64_t ds;
  uint64_t es;
  uint64_t fs;
  uint64_t gs;
  char exe[PATH_MAX];
} regs_t;

static int major;
static struct class *device_class;
static struct device *device;

// Prototypes
static int my_init(void);
static void my_exit(void);
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// File operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = etx_ioctl,
};

module_init(my_init);
module_exit(my_exit);

static int my_init(void) {
  major = register_chrdev(0, DEVICE_NAME, &fops);
  if (major < 0) {
    printk(KERN_ERR "get_task: Failed to register a major number\n");
    return major;
  }

  device_class = class_create(CLASS_NAME);
  if (IS_ERR(device_class)) {
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_ERR "simple_device: Failed to register device class\n");
    return PTR_ERR(device_class);
  }

  device =
      device_create(device_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
  if (IS_ERR(device)) {
    class_destroy(device_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_ERR "simple_device: Failed to create the device\n");
    return PTR_ERR(device);
  }

  printk(KERN_INFO "simple_device: Device initialized successfully\n");
  return 0;

  printk(KERN_DEBUG "driver succesly loaded\n");
  return 0;
}

static void my_exit() {
  device_destroy(device_class, MKDEV(major, 0));
  class_unregister(device_class);
  class_destroy(device_class);
  unregister_chrdev(major, DEVICE_NAME);

  printk(KERN_DEBUG "driver unloaded with success\n");
}

static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  switch (cmd) {
  case READ_REGS: {
    regs_t probe;
    if (copy_from_user(&probe, (regs_t *)arg, sizeof(regs_t))) {
      pr_err("Failed to read input of task %d\n", 2);
    }

    pr_info("Read regs\n");
    struct task_struct *task = pid_task(find_vpid(probe.pid), PIDTYPE_PID);
    struct pt_regs *regs = task_pt_regs(task);

    char *pathname, *p;
    struct mm_struct *mm = task->mm;
    if (mm) {
      mmap_read_lock(mm);
      if (mm->exe_file) {
        pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (pathname) {
          p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
          strcpy(probe.exe, p);
        }
      }
      mmap_read_unlock(mm);
    }

    printk(KERN_INFO "PATH: %s\n", p);

    probe.rax = regs->ax;
    probe.rbx = regs->bx;
    probe.rcx = regs->cx;
    probe.rdx = regs->dx;
    probe.r8 = regs->r8;
    probe.r9 = regs->r9;
    probe.r10 = regs->r10;
    probe.r11 = regs->r11;
    probe.r12 = regs->r12;
    probe.r13 = regs->r13;
    probe.r14 = regs->r14;
    probe.r15 = regs->r15;
    probe.rip = regs->ip;
    probe.rsp = regs->sp;
    probe.rbp = regs->bp;
    probe.ss = regs->ss;
    probe.rsi = regs->si;
    probe.rdi = regs->di;
    probe.cs = regs->cs;

    //probe.ds = regs->ds;
    probe.ds = 0;
    //probe.es = regs->es;
    probe.es = 0;
    //probe.fs = regs->fs;
    probe.fs = 0;
    //probe.gs = regs->gs;
    probe.gs = 0;

    if (copy_to_user((regs_t *)arg, &probe, sizeof(regs_t))) {
      pr_err("Failed to write results for task %d\n", 1);
    }
    break;
  }
  default:
    pr_info("Got %u, expected one of:\n", cmd);
    pr_info("READ_REGS: %lu\n", READ_REGS);
    break;
  }
  return 0;
}
