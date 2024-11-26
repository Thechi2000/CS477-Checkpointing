use clap::{Parser, Subcommand};
use nix::ioctl_read;
use std::{fs::OpenOptions, os::fd::AsRawFd};

#[repr(C)]
struct MyRegs {
    rax: u64,
    rbx: u64,
}

ioctl_read!(get_regs, b'a', 1, MyRegs);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Get the registers of a process")]
    Probe { pid: u64 },
}

fn main() {
    let cli = Cli::parse();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/get_task")
        .expect("Failed to open device");

    let mut data = MyRegs { rax: 0, rbx: 0 };

    unsafe {
        get_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");

        println!("ioctl succeeded");
        println!("{:x}", data.rax);
        println!("{:x}", data.rbx);
    }
}
