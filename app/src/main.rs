use clap::{Parser, Subcommand};
use nix::ioctl_readwrite;
use std::{fs::OpenOptions, os::fd::AsRawFd};

#[repr(C)]
struct MyRegs {
    rax: u64,
    rbx: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct Probe {
    pid: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
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
                ..Default::default()
            };

            unsafe {
                read_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");
            }

            println!("ioctl succeeded");
            println!("{:#x?}", data);
        }
    }
}
