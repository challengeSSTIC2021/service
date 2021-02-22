from pwn import *
import camellia
import struct
import hashlib
import hexdump
import time
from enum import IntEnum, unique

context.log_level="DEBUG"
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

master_key = b"\xdd\x2d\xbe\x18\x99\x1c\xd1\xc3\x82\x16\xc4\xc0\x53\xa1\xdf\x0b"
"""
>>> import camellia
>>> plain = b"This is a text. "
>>> c1 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
>>> encrypted = c1.encrypt(plain)
>>> c2 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
>>> c2.decrypt(encrypted)


struct file_info file_perms[NB_FILES] = { { 0x4307121376ebbe45, 0xffffffffffffffff},
                                        {0x0906271dff3e20b4, 0x10000},
                                        {0x7e0a6dea7841ef77, 0},
                                        {0x9c92b27651376bfb, 2}}; //this last one needs prod key

"""
def _recv(size):
    ret = b""
    while len(ret) != size:
        ret += r.recv(size - len(ret))
    return ret

def get_camellia_key(ts):
    return hashlib.sha256(master_key + struct.pack("<I",ts)).digest()[:16]

def get_payload(id, perm, ts):
    pt = struct.pack("<QQ",id, perm)
    print("pt:")
    hexdump.hexdump(pt)

    key = get_camellia_key(ts)
    print("key = ")
    hexdump.hexdump(key)
    c1 = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    encrypted = c1.encrypt(pt)
    print("encrypted:")
    hexdump.hexdump(encrypted)
    return pt,encrypted


def req_check(id, perm, ts):
    print("req check")
    pt,payload = get_payload(id,perm,ts)
    req = b"\x00" + payload + struct.pack("<I",ts)
    r.send(req)
    resp = _recv(1)
    if resp != b"\xff":
        resp += _recv(16)
    return (pt, resp)

def req_key(id, perm, ts):
    print("req key")
    pt,payload = get_payload(id,perm,ts)
    req = b"\x01" + payload + struct.pack("<I",ts)
    r.send(req)
    #r.send(b"a"*0x11)
    resp = _recv(1)
    if resp != b"\x03":
        return (pt, resp)
        print("fail")
        return
    print("OK")
    return (pt,b"\x03" + _recv(16))

#get ts of the last hour.
def get_ts():
    ts = int(time.time())
    ts -= (ts % 3600)
    return ts


if 0:
    hexdump.hexdump(get_payload(0x1234567812345678,0x1111111,0x60313d9f))
    raise

#r = remote("localhost",4242)
r = remote("localhost",1337)
r.recvuntil("STIC")
ts = get_ts()
old_ts = ts - 5000
futur_ts = ts + 5000
print("test ts")
print("test good ts")
print(f"ts :{ts:x}, {ts % 3600:x}")
pt, resp = req_check(0x4307121376ebbe45,0xfffff,ts)
hexdump.hexdump(resp)
hexdump.hexdump(bytes([RespType.CHECK_OK.value]) + pt)
assert(resp == bytes([RespType.CHECK_OK.value]) + pt)
pt, resp = req_key(0x4307121376ebbe45,0xfffff,ts)
assert(resp == bytes([RespType.GETKEY_OK.value]) + b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
print("test futur ts")
pt, resp = req_check(0x4307121376ebbe45,0xfffff,futur_ts)
assert(resp == bytes([RespType.UNEXPECTED_ERROR.value]))
pt, resp = req_key(0x4307121376ebbe45,0xfffff,futur_ts)
assert(resp == bytes([RespType.UNEXPECTED_ERROR.value]))
print("test old ts")
pt, resp = req_check(0x4307121376ebbe45,0xfffff,old_ts)
assert(resp == bytes([RespType.CHECK_EXPIRED.value]) + pt)
pt, resp = req_key(0x4307121376ebbe45,0xfffff,old_ts)
assert(resp == bytes([RespType.GETKEY_EXPIRED.value]))
print("tests OK!!")
#todo tests wrong id, wrong  perms, wrong key
while True:
    print (hexdump.hexdump(r.recv()))
