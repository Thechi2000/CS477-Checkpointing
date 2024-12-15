# Checkpointing
## Requirements
This system was tested on linux with kernel version >= 6.11.5. 

## Setup

in `/get-tasks`:

```
make
make install 
```
(use `make reinstall` to reinstall the kernel extension)

in `/app`:

```
cargo b
```

in `/`:

```
gcc hello-world.c -O3 -no-pie -fno-pic -static
```

Anywhere:
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_spac # disables ASLR
```

## Run
### GDP & kernel extension
in `/`:

```
gdb a.out

start
info inferior # Get the PID
ni # A few times, to get some prints
```

in `/app`

```
sudo ./target/debug/app read <PID>
sudo ./target/debug/app dump <PID> hello.proc
sudo ./target/debug/app restore hello.proc
```

### ptrace only
in `/app`
```
sudo ./run.sh
```