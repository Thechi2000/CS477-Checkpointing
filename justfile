insert-module:
    cd get-tasks && make
    - sudo rmmod get-tasks/get-tasks.ko
    sudo insmod get-tasks/get-tasks.ko


run-app:
    cd app && sudo cargo run