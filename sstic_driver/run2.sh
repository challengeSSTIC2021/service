#!/bin/bash

#PIDFILE=$(mktemp -p .)
#trap "kill -9 $(cat $PIDFILE)" HUP

    #-kernel bzImage \
./qemu/build/qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -serial stdio \
    -kernel linux/arch/x86/boot/bzImage \
    -append 'console=ttyS0 loglevel=8 oops=panic panic=10 ip=:::::eth0:dhcp' \
    -monitor /dev/null \
    -initrd rootfs.img \
    -net user,hostfwd=tcp::4242-:1337 -net nic \
    -device pci-sstic 


