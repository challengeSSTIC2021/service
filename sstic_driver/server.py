#!/usr/bin/python

import camellia
import datetime
from enum import IntEnum, unique
from hashlib import sha256
import json
import os
import multiprocessing as mp
import socket
import struct
import time
import traceback
import ctypes
import sys

@unique
class ReqType(IntEnum):
    CHECK = 0
    GETKEY = 1

@unique
class RespType(IntEnum):
    ACK = 0
    CHECK_OK = 1
    CHECK_EXPIRED = 2
    GETKEY_OK = 3
    GETKEY_EXPIRED = 4
    GETKEY_INVALID_PERMS = 5
    GETKEY_UNKNOW = 6
    REQUEST_ERROR = 0xfe
    UNEXPECTED_ERROR = 0xff

sstic_lib = None
SSTIC_LIB_PATH = "/usr/lib/sstic_lib.so"

def send(b):
  sys.stdout.write(b)

def recv(size):
  ret = b""
  while len(ret) < size:
    ret += sys.stdin.read(size - len(ret))
  return ret


def VM_decode(payload):
    if type(payload) != bytes or len(payload) != 20:
      return None

    cipher = payload[:16]
    id = struct.unpack("<I",payload[16:])[0]
    c_ct=ctypes.create_string_buffer(cipher,16)
    c_ct=ctypes.create_string_buffer(16)
    ret = sstic_lib.decrypt_wb(c_ct, ctypes.c_uint(id),c_pt)
    if ret:
      return None
    return c_ct.raw

def get_drm_key():
  key = ctypes.create_string_buffer(16)
  ret = sstic_lib.getkey(key)
  if(ret)
    return None
  return key


def reqCheck(m, ctx):
    if len(m) < 21:
        print("reqCheck REQUEST_ERROR")
        send(bytes([RespType.REQUEST_ERROR.value]))
        return

    payload = m[1:21]
    ts = struct.unpack('<I', payload[16:])[0]
    current_ts = int(datetime.datetime.now().timestamp())

    plain = VM_decode(payload, ctx["master-key"])

    if plain == None:
        print("reqCheck UNEXPECTED_ERROR")
        send(bytes([RespType.UNEXPECTED_ERROR.value]))
    elif ts + ctx["timeout"] > current_ts:
        print("reqCheck CHECK_OK")
        send(bytes([RespType.CHECK_OK.value]) + plain)
    else:
        print("reqCheck CHECK_EXPIRED")
        send(bytes([RespType.CHECK_EXPIRED.value]) + plain)
    return

def reqGetKey(m, ctx):
    if len(m) < 21:
        print("reqGetKey REQUEST_ERROR")
        send(bytes([RespType.REQUEST_ERROR.value]))
        return

    payload = m[1:21]
    ts = struct.unpack('<I', payload[16:])[0]
    current_ts = int(datetime.datetime.now().timestamp())

    # whitebox expired
    if ts + ctx["timeout"] <= current_ts:
        print("reqGetKey GETKEY_EXPIRED")
        send(bytes([RespType.GETKEY_EXPIRED.value]))
        return

    plain = VM_decode(payload)
    if plain == None or len(plain) != 16:
        print("reqGetKey UNEXPECTED_ERROR")
        send(bytes([RespType.UNEXPECTED_ERROR.value]))
        return

    ident, perm = struct.unpack('<QQ', plain)

    if ident not in ctx["keys"]:
        print("reqGetKey GETKEY_UNKNOW")
        send(bytes([RespType.GETKEY_UNKNOW.value]))
        return

    if ctx["keys"][ident]["perms"] < perm:
        print("reqGetKey GETKEY_INVALID_PERMS")
        send(bytes([RespType.GETKEY_INVALID_PERMS.value]))
        return

    print("reqGetKey GETKEY_OK {} with perm {}".format(ident, perm))
    key = ctypes.create_string_buffer(16)
    ret = sstic_lib.getkey(key)
    if(ret)
      send(bytes([RespType.UNEXPEXTED_ERROR.value]))
    send(bytes([RespType.GETKEY_OK.value]) +   + bytes.fromhex(ctx["keys"][ident]["counter"]))

    return

def process_main(ctx):
    m = recv(512)
    if len(m) < 1:
        send(bytes([RespType.REQUEST_ERROR.value]))
        return

    req = int(m[0])
    try:
        reqType = ReqType(req)
    except ValueError:
        print("process_main REQUEST_ERROR unknown reqType")
        send(bytes([RespType.REQUEST_ERROR.value]))
        return

    if reqType == ReqType.CHECK:
        reqCheck(m, ctx)
    elif reqType == ReqType.GETKEY:
        reqGetKey(m, ctx)
    else:
        print("process_main REQUEST_ERROR no handler for reqType {}".format(reqType))
        send(bytes([RespType.REQUEST_ERROR.value]))

def main():
  global sstic_lib
  import argparse
  sstic_lib = ctypes.CDLL(SSTIC_LIB_PATH)
  parser = argparse.ArgumentParser()

  class hexArg:

      def __call__(self, raw):
          try:
              b = bytes.fromhex(raw)
          except ValueError:
              raise argparse.ArgumentTypeError('Not an hexa value')

          return b

  parser.add_argument("-t", "--timeout", type=int, help="whitebox expired", required=True)
  parser.add_argument("-k", "--key-file", type=str, help="key files", default="keys.json")
  

    args = parser.parse_args()
  

def _main():
    import argparse
    parser = argparse.ArgumentParser()

    class hexArg:

        def __call__(self, raw):
            try:
                b = bytes.fromhex(raw)
            except ValueError:
                raise argparse.ArgumentTypeError('Not an hexa value')

            return b

    parser.add_argument("-K", "--master-key", type=hexArg(), help="whitebox master key", required=True)
    parser.add_argument("-t", "--timeout", type=int, help="whitebox expired", required=True)
    parser.add_argument("-k", "--key-file", type=str, help="key files", default="keys.json")
    parser.add_argument("-w", "--workers", type=int, help="worker", default=16)
    parser.add_argument("-l", "--listen-port", type=int, help="listening port", default=65430)

    args = parser.parse_args()

    if not os.path.isfile(args.key_file):
        parser.error('Cannot found {}'.format(args.key_file))

    with open(args.key_file, 'r') as f:
        jkeys = json.loads(f.read())
    keys = {}
    for j in jkeys:
        keys[j['ident']] = j

    context = {
        "keys": keys,
        "master-key": args.master_key,
        "timeout": args.timeout
    }

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.listen_port))
    sock.listen(8 * args.workers)

    workers = [mp.Process(target=worker, args=(sock, context), daemon=True) for i in range(args.workers)]

    for w in workers:
        w.start()

    while True:
        for i in range(len(workers)):
            workers[i].join(0.001)
            if workers[i].exitcode != None:
                workers[i] = mp.Process(target=worker, args=(sock, context), daemon=True)
                workers[i].start()
        time.sleep(1)

if __name__ == '__main__':
    #main()
    payload = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    id = 0
    pt = VM_decode(payload,id)
    #no hexdump in my static python
    print("pt: {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ", 
      ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15])

    key = get_get()
    ct = key
    print("key: {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ", 
      ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15])
