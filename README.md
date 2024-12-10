# Checkpointing

## Setup

in `/get-tasks`:

```
make
make install
```

in `/app`:

```
cargo b
```

in `/`:

```
gcc hello-world.c -O3 -no-pie -fno-pic -static
```

## Run

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
