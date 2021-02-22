import signal
import sys
import os
from subprocess import *
import random
import time
import socket
import select

p = None


def forward(port):
    print("fu")
    time.sleep(2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", port))
    #wfile = sock.makefile("wb")
    #rfile = sock.makefile("rb")
    while True:        
        r, _, _ = select.select([sys.stdin,sock], [], [])
        #if sys.stdin in r:
        #    buf = os.read(sys.stdin.fileno(),1000)
        #    wfile.write(buf)
        if sock in r:
            #print("fufu")
            buf = sock.recv(100)
            #print(buf)
            sys.stdout.buffer.write(buf)
        if sys.stdin in r:
            buf = os.read(sys.stdin.fileno(),100)
            #print(buf)
            sock.send(buf)




def handler(sig,frame):
    sys.stderr.write("will kill {}\n".format(sig))
    try:
        p.kill()
        exit()
    except:
        exit()

signal.signal(13, handler)
signal.signal(15, handler)
signal.signal(17, handler)
signal.signal(28, handler)








port = random.randint(1025,65535)
print("port: ",port)
qemu_command=["qemu/build/qemu-system-x86_64",
    "-m", "128M",
    "-cpu", "qemu64,+smep,+smap",
    "-nographic" ,
    "-serial", "stdio" ,
    "-kernel", "linux/arch/x86/boot/bzImage" ,
    "-append", "console=ttyS0 loglevel=0 oops=panic panic=10 ip=:::::eth0:dhcp",
    "-monitor", "/dev/null" ,
    "-initrd", "rootfs.img" ,
    "-device", "pci-sstic",
    "-net", "user,hostfwd=tcp::{}-:1337".format(port),
    "-net", "nic"]
out = b""
err = b""
p = Popen(qemu_command,bufsize=0,stdin=PIPE, stdout=PIPE, stderr=PIPE)
#print("started!")
while True:
    r, _, _ = select.select([p.stdout, p.stderr], [], [])
    if p.stdout in r:
        out += os.read(p.stdout.fileno(),100)
    if p.stderr in r:
        err += os.read(p.stderr.fileno(),100)

    if b"Could not set up host forwarding rule" in err:
        #bad port
        #print("bad port, trying another one")
        port = random.randint(2000,65535)
        qemu_command=["qemu/build/qemu-system-x86_64",
            "-m", "128M",
            "-cpu", "qemu64,+smep,+smap",
            "-nographic" ,
            "-serial", "stdio" ,
            "-kernel", "bzImage" ,
            "-append", "console=ttyS0 loglevel=0 oops=panic panic=10 ip=:::::eth0:dhcp",
            "-monitor", "/dev/null" ,
            "-initrd", "rootfs.img" ,
            "-device", "pci-sstic",
            "-net", "user,hostfwd=tcp::{}-:1337".format(port),
            "-net", "nic"]
        out = b""
        err = b""
        p.kill()
        p = Popen(qemu_command,bufsize=0,stdin=PIPE, stdout=PIPE, stderr=PIPE)
        continue
    if b"service started!" in out:
        #print("service started, forwarding")
        #we're good, forward connexion to service
        forward(port)


try:
    p.wait()
except:
    pass
