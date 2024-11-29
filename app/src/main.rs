use clap::{Parser, Subcommand};
use nix::{
    ioctl_readwrite,
    sys::{ptrace, signal::Signal, wait::waitpid},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CStr,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
};

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
#[derive(Debug, Serialize, Deserialize)]
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
    Read {
        pid: u64,
    },
    Dump {
        pid: u64,
        output: String,
    },
    Restore {
        dump: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Read { pid } => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/get_task")
                .expect("Failed to open device");

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
        Command::Dump { pid, output } => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/get_task")
                .expect("Failed to open device");

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

            std::fs::File::create(output)
                .expect("Failed to create output file")
                .write_all(
                    postcard::to_allocvec(&data)
                        .expect("Failed to serialize data")
                        .as_slice(),
                )
                .expect("Failed to write to output file");
        }
        Command::Restore { dump } => {
            /* let cmd = unsafe {
                process::Command::new(exe)
                    .pre_exec(|| {
                        println!("Pre-exec");
                        ptrace::traceme().expect("Failed to ptrace traceme");
                        thread::sleep(Duration::from_secs(5));
                        println!("Post-exec");
                        Ok(())
                    })
                    .spawn()
                    .expect("Failed to kill process")
            }; */

            let dump = {
                let mut bytes = vec![];
                std::fs::File::open(dump)
                    .expect("Failed to open dump file")
                    .read_to_end(&mut bytes)
                    .expect("Failed to read from dump file");

                postcard::from_bytes::<Probe>(&bytes).expect("Invalid dump file")
            };

            let pid;
            unsafe {
                use libc::*;

                pid = fork();
                if pid == 0 {
                    ptrace::traceme().expect("Failed to ptrace traceme");
                    raise(SIGSTOP);

                    execv(dump.exe.as_ptr() as *const i8, std::ptr::null_mut());
                }
            }
            let pid = Pid::from_raw(pid);

            waitpid(pid, None).unwrap();

            ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACEEXEC).unwrap();
            ptrace::cont(pid, None).unwrap();

            waitpid(pid, None).unwrap();

            ptrace::write(pid, 0x401042 as *mut libc::c_void, 0xCC).unwrap();
            ptrace::cont(pid, None).unwrap();

            waitpid(pid, None).unwrap();

            let mut regs = ptrace::getregs(pid).unwrap();

            println!("{:x} -> {:x}", regs.rip, dump.rip);

            regs.rax = dump.rax;
            regs.rbx = dump.rbx;
            regs.rcx = dump.rcx;
            regs.rdx = dump.rdx;
            regs.r8 = dump.r8;
            regs.r9 = dump.r9;
            regs.r10 = dump.r10;
            regs.r11 = dump.r11;
            regs.r12 = dump.r12;
            regs.r13 = dump.r13;
            regs.r14 = dump.r14;
            regs.r15 = dump.r15;

            // TODO: needs an offset ?
            // https://stackoverflow.com/questions/38006277/weird-behavior-setting-rip-with-ptrace
            // dmesg (when restoring rip to 00007ffff7e203f4):
            // [45434.139862] test[316473]: segfault at 7ffff7e203f4 ip 00007ffff7e203f4 sp 00007ffc7128d7b0 error 14 likely on CPU 4 (core 0, socket 0)
            // [45434.139874] Code: Unable to access opcode bytes at 0x7ffff7e203ca.
            regs.rip = dump.rip;

            ptrace::setregs(pid, regs).unwrap();
            ptrace::cont(pid, None).unwrap();

            let status = waitpid(pid, None).unwrap();

            println!("{:#?}", status);
        }
    }
}
