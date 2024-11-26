use clap::{Parser, Subcommand};
use nix::ioctl_readwrite;
use std::{fs::OpenOptions, os::fd::AsRawFd};

#[repr(C)]
struct MyRegs {
    rax: u64,
    rbx: u64,
}

#[repr(C)]
struct Probe {
    pid: u64,
    rax: u64,
    rbx: u64,
}

ioctl_readwrite!(read_regs, b'a', 1, Probe);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Get the registers of a process")]
    Read { pid: u64 },
}

fn main() {
    let cli = Cli::parse();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/get_task")
        .expect("Failed to open device");

    match cli.command {
        Command::Read { pid } => {
            let mut data = Probe {
                pid,
                rax: 0,
                rbx: 0,
            };

            unsafe {
                read_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");
            }

            println!("ioctl succeeded");
            println!("{:x}", data.rax);
            println!("{:x}", data.rbx);
        }
    }
}
