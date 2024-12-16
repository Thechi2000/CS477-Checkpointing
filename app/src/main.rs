use clap::{Parser, Subcommand};
use nix::{
    ioctl_readwrite,
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use object::{Object, ObjectSymbol};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::fd::AsRawFd,
};
use std::{ffi::c_void, io::BufRead};

const INT3: i64 = 0xcc;

#[derive(Debug, Serialize, Deserialize)]
struct Region {
    name: String,
    from: u64,
    data: Vec<u8>,
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
    rsp: u64,
    rbp: u64,
    ss: u64,
    rsi: u64,
    rdi: u64,
    cs: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    exe: [u8; 4096],
}

fn new_empty_raw_probe() -> ProbeRaw {
    ProbeRaw {
        pid: 0,
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
        rsp: 0,
        rbp: 0,
        ss: 0,
        rsi: 0,
        rdi: 0,
        cs: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
        exe: [0; 4096],
    }
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
    rsp: u64,
    rbp: u64,
    ss: u64,
    rsi: u64,
    rdi: u64,
    cs: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    exe: String,
    regions: Vec<Region>,
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
    ReadRegs {
        pid: u64,
    },
    ReadMem {
        pid: u64,
    },
    Dump {
        pid: u64,
        output: String,
    },
    Restore {
        dump: String,
    },
    PtraceRestore {
        pid: u64,
        dump: String,
    },
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let cli = Cli::parse();

    match cli.command {
        Command::ReadRegs { pid } => {
            let data = read_regs_with_get_tasks(pid);

            println!("ioctl succeeded");
            println!("{:#x?}", data);
        }
        Command::ReadMem { pid } => {
            let (stack_from, stack_to) = get_mem_region_limits(Pid::from_raw(pid as i32), "stack");

            println!("Stack:");
            println!("{:x} {:x}", stack_from, stack_to);

            let (heap_from, heap_to) = get_mem_region_limits(Pid::from_raw(pid as i32), "heap");

            println!("Heap:");
            println!("{:x} {:x}", heap_from, heap_to);
        }
        Command::Dump { pid, output } => {
            dump_pid(pid, output);
        }
        Command::Restore { dump } => {
            restore_from_dump(dump);
        }
        Command::PtraceRestore { pid, dump } => {
            let pid = Pid::from_raw(pid as i32);

            let stop_addr = 0x401504 as *mut libc::c_void; // stops in main loop for hello-world
                                                           // let stop_addr = 0x401650 as *mut libc::c_void; // stops in function body for hello-world-func.c
                                                           // let stop_addr = 0x40150b as *mut libc::c_void; // stops in main loop for hello-world-func.c

            let call_instr = stop_with_ptrace(pid, stop_addr);

            dump_with_ptrace(pid, dump.clone());
            restore_from_dump(dump);

            ptrace::write(pid, stop_addr, call_instr)
                .expect("failed to write back call instruction");
            ptrace::cont(pid, None).expect("failed to continue process");
        }
    }
}

fn stop_with_ptrace(pid: Pid, stop_addr: *mut c_void) -> i64 {
    // ptrace attache to the process
    ptrace::attach(pid).expect("failed to seize process");
    waitpid(pid, None).unwrap();

    println!("process attached !");

    // replace the call instruction with an interrupt
    let call_instr = ptrace::read(pid, stop_addr).expect("failed to read process");

    println!("instruction read !");

    ptrace::write(pid, stop_addr, INT3).expect("failed to write interrupt instruction");

    // restart process and wait for interrupt
    ptrace::cont(pid, None).expect("failed to continue process");
    waitpid(pid, None).unwrap();

    call_instr as i64
}

fn dump_with_ptrace(pid: Pid, to: String) {
    let exe = fs::read_link(format!("/proc/{}/exe", pid))
        .expect("failed to read exe name")
        .into_os_string()
        .into_string()
        .expect("failed to convert exe name to string");

    println!("exe: {}", exe);

    let regs = ptrace::getregs(pid).expect("Error when retrieving child process registers");

    let data = Probe {
        pid: pid.as_raw() as u64,
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        rip: regs.rip,
        rsp: regs.rsp,
        rbp: regs.rbp,
        ss: regs.ss,
        rsi: regs.rsi,
        rdi: regs.rdi,
        cs: regs.cs,
        ds: regs.ds,
        es: regs.es,
        fs: regs.fs,
        gs: regs.gs,
        exe,
        regions: vec![],
    };

    File::create(to)
        .expect("Failed to create output file")
        .write_all(
            postcard::to_allocvec(&data)
                .expect("Failed to serialize data")
                .as_slice(),
        )
        .expect("Failed to write to output file");
}

fn dump_pid(pid: u64, to: String) {
    let mut data = read_regs_with_get_tasks(pid);

    data.regions = dump_regions(pid);

    File::create(to)
        .expect("Failed to create output file")
        .write_all(
            postcard::to_allocvec(&data)
                .expect("Failed to serialize data")
                .as_slice(),
        )
        .expect("Failed to write to output file");
}

fn restore_from_dump(dump: String) {
    let dump = {
        let mut bytes = vec![];
        File::open(dump)
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

            println!("child process setup");
            println!("exe: {:#?}", dump.exe);

            // Stop itself for first setup phase
            raise(SIGSTOP);

            // Execute binary
            execv(dump.exe.as_ptr() as *const i8, std::ptr::null_mut());

            println!("child process error");
        }
    }
    let pid = Pid::from_raw(pid);

    // First setup phase

    // Sync on stop of the child process
    waitpid(pid, None).unwrap();

    // Set option to stop execution at exec
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACEEXEC)
        .expect("Error when setting ptrace option");

    // Continue the execution of the child until it reaches main
    ptrace::cont(pid, None).unwrap();

    waitpid(pid, None).unwrap();

    ptrace::write(pid, find_main_address(&dump.exe) as *mut libc::c_void, INT3).unwrap();
    ptrace::cont(pid, None).unwrap();

    let status = waitpid(pid, None).unwrap();
    println!("status after child reached main: {:#?}", status);

    // Restores registers of the child
    let mut regs = ptrace::getregs(pid).expect("Error when retrieving child process registers");

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

    regs.rip = dump.rip;
    regs.rsp = dump.rsp;
    regs.rbp = dump.rbp;
    regs.ss = dump.ss;
    regs.rsi = dump.rsi;
    regs.rdi = dump.rdi;

    regs.cs = dump.cs;
    // TODO: find a way to get the real values in get-tasks.c or in another way
    //regs.ds = dump.ds; regs.es = dump.es; regs.fs = dump.fs; regs.gs = dump.gs; regs.eflags = 0x202;

    println!("registers restored: {:x} -> {:#?}", regs.rip, regs);

    ptrace::setregs(pid, regs).expect("Error when setting registers of child process.");

    // Restores stack of the child
    for region in dump.regions {
        println!("Write {} bytes at 0x{:x}", region.data.len(), region.from);
        write_mem_region(pid, region.from, &region.data);
    }

    ptrace::cont(pid, None).unwrap();

    let status = waitpid(pid, None).unwrap();
    println!("{:#?}", status);
}

fn find_main_address(exe: &str) -> i32 {
    // Read the binary file
    let binary = fs::read(exe).expect("Failed to read the binary file");

    // Parse the binary object
    let main_address = object::File::parse(&*binary)
        .expect("Failed to parse the executable")
        .symbols()
        .find(|s| s.name() == Ok("main"))
        .expect("Failed to find main address")
        .address();

    main_address as i32
}

fn get_mem_region_limits(pid: Pid, region_name: &str) -> (usize, usize) {
    let mut map = File::open(format!("/proc/{}/maps", pid)).expect("Failed to open maps file");

    let mut str = String::new();
    map.read_to_string(&mut str)
        .expect("Failed to read maps file");

    let mut region_from = usize::MAX;
    let mut region_to = 0;

    let region_re =
        Regex::new(format!(r"([0-9a-f]+)-([0-9a-f]+).*\[{}\]\n", region_name).as_str()).unwrap();

    for c in region_re.captures_iter(&str) {
        let from = usize::from_str_radix(c.get(1).unwrap().as_str(), 16).unwrap();
        let to = usize::from_str_radix(c.get(2).unwrap().as_str(), 16).unwrap();

        region_from = region_from.min(from);
        region_to = region_to.max(to);
    }
    (region_from, region_to)
}

fn write_mem_region(pid: Pid, mut from: u64, data: &[u8]) {
    println!(
        "Write {} bytes in region 0x{:x} to 0x{:x}",
        data.len(),
        from,
        from + data.len() as u64
    );

    let data_i64: Vec<i64> = data
        .chunks(8) // Create chunks of 8 elements
        .map(|chunk| {
            // Merge up to 8 u8 into a single i64
            let mut value: i64 = 0;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as i64) << (8 * (7 - i)); // Shift bytes to their correct position
            }
            value
        })
        .collect();

    for word in data_i64 {
        ptrace::write(pid, from as *mut libc::c_void, word).expect("Failed to write in memory");
        from += 8;
    }
    println!("Writing to stack succeeded !");
}

fn read_regs_with_get_tasks(pid: u64) -> Probe {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/get_task")
        .expect("Failed to open device");

    let mut data = new_empty_raw_probe();
    data.pid = pid;

    let exe;

    unsafe {
        read_regs(file.as_raw_fd(), &mut data).expect("ioctl failed");

        exe = CStr::from_ptr(data.exe.as_ptr() as *const _)
            .to_str()
            .unwrap()
            .to_owned();
    }

    Probe {
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
        rsp: data.rsp,
        rbp: data.rbp,
        ss: data.ss,
        rsi: data.rsi,
        rdi: data.rdi,
        cs: data.cs,
        ds: data.ds,
        es: data.es,
        fs: data.fs,
        gs: data.gs,
        exe,
        regions: vec![],
    }
}

fn dump_regions(pid: u64) -> Vec<Region> {
    let map = File::open(format!("/proc/{}/maps", pid)).expect("Failed to open maps file");

    let mut regions = vec![];

    for line in std::io::BufReader::new(map).lines() {
        let line = line.expect("Failed to read line");
        if let Some(region) = dump_region(&line, pid) {
            regions.push(region);
        }
    }

    regions
}

fn dump_region(line: &str, pid: u64) -> Option<Region> {
    let regex = Regex::new(r"^([0-9a-f]+)-([0-9a-f]+) [r-]([w-])[x-][p-].*\s(.*)").unwrap();
    let captures = regex.captures(line).unwrap();

    let is_writable = captures.get(3).unwrap().as_str() == "w";
    let name = captures.get(4).unwrap().as_str().to_owned();
    if ["[vvar]", "[vdso]", "[vsyscall]"].contains(&name.as_str()) || !is_writable {
        return None;
    }

    let from = u64::from_str_radix(captures.get(1).unwrap().as_str(), 16).unwrap();
    let to = u64::from_str_radix(captures.get(2).unwrap().as_str(), 16).unwrap();

    println!("Saving region {} (0x{:x}-0x{:x})", name, from, to);

    let mut file = File::open(format!("/proc/{}/mem", pid)).expect("Failed to open mem file");
    file.seek(std::io::SeekFrom::Start(from))
        .expect("Failed to seek in mem file");

    let mut data = vec![0; (to - from) as usize];
    file.read_exact(data.as_mut_slice())
        .expect("Failed to read from mem file");

    Some(Region { name, from, data })
}
