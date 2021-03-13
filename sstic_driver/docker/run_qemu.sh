#!/bin/bash


qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -monitor /dev/null \
    -serial stdio \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=8 oops=panic panic=10 ip=:::::eth0:dhcp' \
    -initrd rootfs.img \
    -device pci-sstic \
    -net user,hostfwd=tcp::1337-:1337 \
    -net nic

