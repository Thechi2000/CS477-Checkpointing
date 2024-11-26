#include <linux/fs.h>
#include <asm/ptrace.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/thread_info.h>
#include <linux/cdev.h>
#include <linux/device.h>


#define DEVICE_NAME "get_task"
#define CLASS_NAME "get_task_class"

#define READ_REGS _IOR('a', 1, my_regs_t)


MODULE_LICENSE("GPL");

typedef struct {
  uint64_t rax;
  uint64_t rbx;
} my_regs_t;


static int major; 
static struct class *device_class;
static struct device *device;


// Prototypes
static int my_init(void);
static void my_exit(void);
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);


// File operations
static struct file_operations fops =
{
  .owner          = THIS_MODULE,
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

  device = device_create(device_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
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


static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  switch(cmd) {
    case READ_REGS:
      pr_info("Read regs\n");
      struct task_struct *task = pid_task(find_vpid(1), PIDTYPE_PID);
      struct pt_regs *regs = task_pt_regs(task);


      my_regs_t my_regs = { 
        regs->ax, 
        regs->bx 
      };

      if( copy_to_user((my_regs_t*) arg, &my_regs, sizeof(my_regs_t)) ) {
        pr_err("Failed to read regs of task %d\n", 1);
      }
      break;
    default:
      pr_info("Got %u, expected one of:\n", cmd);
      pr_info("READ_REGS: %lu\n", READ_REGS);
      break;
  }
  return 0;
}
