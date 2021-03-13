#!/bin/bash

#PIDFILE=$(mktemp -p .)
#trap "kill -9 $(cat $PIDFILE)" HUP

    #-kernel bzImage \
qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -serial stdio \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=8 oops=panic panic=10' \
    -monitor /dev/null \
    -initrd rootfs.img


