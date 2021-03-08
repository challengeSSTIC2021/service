#!/bin/bash


qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -serial stdio \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=0 oops=panic panic=10 ip=:::::eth0:dhcp' \
    -monitor /dev/null \
    -initrd rootfs.img \
    -net user,hostfwd=tcp::4242-:1337 -net nic \
    -device pci-sstic \
    -net user,hostfwd=tcp::1337-:1337 \
    -net nic 


