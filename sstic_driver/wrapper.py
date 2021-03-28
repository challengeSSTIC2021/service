#!/usr/bin/env python3

import signal
import sys
import os
from subprocess import *
import random
import time
import socket
import select
import traceback
from datetime import datetime

p = None
def log(msg):
    peer = "{}:{}".format(os.environ.get('SOCAT_PEERADDR', '??'), os.environ.get('SOCAT_PEERPORT', '??'))
    sys.stderr.write("{} | [{}]: {}\n".format(datetime.now(), peer, msg))


def forward(port):
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
    global p

    log("will kill {}".format(sig))
    try:
        #out = os.read(p.stdout.fileno(),1000)
        #log("out : " + out.decode("utf-8"))
        p.kill()
        p = None
    finally:
        exit()

def spawn_vm():
    port = random.randint(1025,65535)
    log("assign port: {}".format(port))
    qemu_command=["qemu-system-x86_64",
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
    ret = Popen(qemu_command,bufsize=0,stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return ret,port

def run():
    global p

    signal.signal(13, handler)
    signal.signal(15, handler)
    signal.signal(17, handler)
    signal.signal(28, handler)
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(3600)

    out = b""
    err = b""
    try:
        p,port = spawn_vm()
        #print("started!")
        while True:
            r, _, _ = select.select([p.stdout, p.stderr], [], [])
            if p.stdout in r:
                out += os.read(p.stdout.fileno(),100)
            if p.stderr in r:
                err += os.read(p.stderr.fileno(),100)

            if b"Could not set up host forwarding rule" in err:
                log("fail: {}\n".format(err))
                out = b""
                err = b""
                p.kill()
                p,port = spawn_vm()
                continue
            if b"service started!" in out:
                break

        #print("service started, forwarding")
        #we're good, forward connexion to service

        forward(port)
    except SystemExit:
        pass
    except:
        log("exception")
        traceback.print_exc()
    finally:
        log("exit")
        if p != None:
            p.kill()
            p = None
        exit()

if __name__ == "__main__":
    run()
