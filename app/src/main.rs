use clap::{Parser, Subcommand};
use nix::ioctl_readwrite;
use std::{ffi::CStr, fs::OpenOptions, os::fd::AsRawFd};

#[repr(C)]
struct MyRegs {
    rax: u64,
    rbx: u64,
}

#[repr(C)]
#[derive(Debug)]
struct ProbeRaw {
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
    exe: [u8; 4096],
}
#[derive(Debug)]
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
    exe: String,
}

ioctl_readwrite!(read_regs, b'a', 1, ProbeRaw);

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
            let mut data = ProbeRaw {
                pid,
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                exe: [0; 4096],
            };

            let exe;

            unsafe {
                read_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");

                exe = CStr::from_ptr(data.exe.as_ptr() as *const _)
                    .to_str()
                    .unwrap()
                    .to_owned();
            }

            let data = Probe {
                pid: data.pid,
                rax: data.rax,
                rbx: data.rbx,
                rcx: data.rcx,
                rdx: data.rdx,
                r8: data.r8,
                r9: data.r9,
                r10: data.r10,
                r11: data.r11,
                r12: data.r12,
                r13: data.r13,
                r14: data.r14,
                r15: data.r15,
                rip: data.rip,
                exe,
            };

            println!("ioctl succeeded");
            println!("{:#x?}", data);
        }
    }
}
