use clap::{Parser, Subcommand};
use nix::{
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use object::{Object, ObjectSymbol};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::{
    env,
    fs::{self, File},
    io::{Read, Seek, Write},
};

const INT3: i64 = 0xcc;

#[derive(Debug, Serialize, Deserialize)]
struct Region {
    name: String,
    from: u64,
    data: Vec<u8>,
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
    eflags: u64,
    exe: String,
    regions: Vec<Region>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Get the registers of a process")]
    Dump {
        pid: u64,
        dump: String,
    },
    Restore {
        dump: String,
    },
    DumpRestore {
        pid: u64,
        dump: String,
    },
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let cli = Cli::parse();

    match cli.command {
        Command::Dump { pid, dump } => {
            let pid = Pid::from_raw(pid as i32);
            stop_with_ptrace(pid);
            dump_with_ptrace(pid, dump.clone());
            ptrace::kill(pid).expect("failed to kill processed");
        }
        Command::Restore { dump } => {
            restore_from_dump(dump);
            println!("process restored !");
        }
        Command::DumpRestore { pid, dump } => {
            let pid = Pid::from_raw(pid as i32);
            stop_with_ptrace(pid);
            dump_with_ptrace(pid, dump.clone());

            ptrace::kill(pid).expect("failed to kill processed");
            restore_from_dump(dump);
        }
    }
}

fn stop_with_ptrace(pid: Pid) {
    // ptrace attrache to the process
    ptrace::attach(pid).expect("failed to seize process");
    waitpid(pid, None).unwrap();
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
        eflags: regs.eflags,
        exe,
        regions: dump_regions(pid.as_raw() as u64, 0),
    };

    println!("registers: {:#?}", regs);

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

    // Sync on stop of the child process
    waitpid(pid, None).unwrap();

    // Set option to stop execution at exec
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACEEXEC)
        .expect("Error when setting ptrace option");

    // Continue the execution of the child until it reaches main
    ptrace::cont(pid, None).unwrap();

    waitpid(pid, None).unwrap();

    let main_start = find_main_address(&dump.exe) as *mut libc::c_void;
    let old_instr = ptrace::read(pid, main_start).expect("Failed to read at main");
    ptrace::write(pid, main_start, INT3).unwrap();
    ptrace::cont(pid, None).unwrap();

    waitpid(pid, None).unwrap();
    ptrace::write(pid, main_start, old_instr).unwrap(); // restore back old instruction

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
    regs.ds = dump.ds;
    regs.es = dump.es;
    regs.fs = dump.fs;
    regs.gs = dump.gs;
    regs.eflags = dump.eflags;

    ptrace::setregs(pid, regs).expect("Error when setting registers of child process.");

    println!("registers after restore: {:#?}", regs);

    // Restores stack of the child
    for region in dump.regions {
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
            value = reverse_bytes(value);
            value
        })
        .collect();

    for word in data_i64 {
        ptrace::write(pid, from as *mut libc::c_void, word).expect("Failed to write in memory");
        from += 8;
    }
}

fn dump_regions(pid: u64, sp: u64) -> Vec<Region> {
    let map = File::open(format!("/proc/{}/maps", pid)).expect("Failed to open maps file");

    let mut regions = vec![];

    for line in std::io::BufReader::new(map).lines() {
        let line = line.expect("Failed to read line");
        if let Some(region) = dump_region(&line, pid, sp) {
            regions.push(region);
        }
    }

    regions
}

fn dump_region(line: &str, pid: u64, lower_limit: u64) -> Option<Region> {
    let regex = Regex::new(r"^([0-9a-f]+)-([0-9a-f]+) [r-]([w-])[x-][p-].*\s(.*)").unwrap();
    let captures = regex.captures(line).unwrap();

    let is_writable = captures.get(3).unwrap().as_str() == "w";
    let name = captures.get(4).unwrap().as_str().to_owned();
    if ["[vvar]", "[vdso]", "[vsyscall]"].contains(&name.as_str()) || !is_writable {
        return None;
    }

    let mut from = u64::from_str_radix(captures.get(1).unwrap().as_str(), 16).unwrap();
    if lower_limit > 0 {
        from = lower_limit
    }
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

fn print_mem(pid: Pid, at: u64, n: u64) {
    println!(
        "memory of proc {} from 0x{:08x} to 0x{:08x}",
        pid.as_raw(),
        at,
        at + 8 * n
    );
    for i in 0..n {
        let addr = at + i * 8;
        if i % 2 == 0 {
            print!("0x{:08x}: ", addr);
        }
        let mut word = ptrace::read(pid, addr as *mut libc::c_void).expect("mem failed") as i64;
        word = reverse_bytes(word);
        print!(
            " {:08x} {:08x}",
            word & (0xffffffff << 32),
            word & 0xffffffff
        );
        if i % 2 == 1 {
            println!();
        }
    }
}

fn reverse_bytes(n: i64) -> i64 {
    let mut n_rev = 0;
    for i in 0..4 {
        let offset_low: i64 = 8 * i;
        let offset_high: i64 = 8 * (7 - i);
        let bit_low = (n >> offset_low) & 0xff;
        let bit_high = (n >> offset_high) & 0xff;
        n_rev |= (bit_low << offset_high) | (bit_high << offset_low);
    }
    n_rev
}
