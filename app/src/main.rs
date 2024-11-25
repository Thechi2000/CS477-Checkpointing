use std::{fs::OpenOptions, os::fd::AsRawFd};
use nix::ioctl_read;

#[repr(C)]
struct MyRegs {
    rax: u64,
    rbx: u64,
}

ioctl_read!(get_regs, b'a', 1, MyRegs);

fn main() {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/get_task")
        .expect("Failed to open device");

    let mut data = MyRegs {
        rax: 0,
        rbx: 0,
    };

    unsafe {
        get_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");

        println!("ioctl succeeded");
        println!("{:x}", data.rax);
        println!("{:x}", data.rbx);
    }
}
