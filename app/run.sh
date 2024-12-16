#!/bin/bash

SESSION_NAME="runner"

# Setup tmux session
tmux new-session -d -s $SESSION_NAME
tmux split-window -h -t $SESSION_NAME

# Starts a.out in the second pane and retrieves the pid of the process
tmux send-keys -t $SESSION_NAME:0.1 "cd .." C-m
tmux send-keys -t $SESSION_NAME:0.1 "./a.out & echo \$! > /tmp/a_out_pid" C-m
sleep 2

A_OUT_PID=$(cat /tmp/a_out_pid)
rm -f /tmp/a_out_pid

echo "PID of a.out: $A_OUT_PID"

# starts the restore process using the pid found
tmux send-keys -t $SESSION_NAME:0.0  "./target/debug/app dump-restore $A_OUT_PID hello.proc" C-m

# Attach to tmux and setup kill-session on exit
tmux set-option -t $SESSION_NAME destroy-unattached off
tmux set-option -t $SESSION_NAME remain-on-exit off
tmux set-hook -t $SESSION_NAME pane-exited "kill-session"

tmux attach-session -t $SESSION_NAME