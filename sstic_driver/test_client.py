from pwn import *
import camellia
import struct
import hashlib
import hexdump
import time
from enum import IntEnum, unique

code_decrypt = b"\x45\x06\x01\x00\x49\x07\x40\x00\x4c\xe3\x2c\x10\x42\x1f\x00\x20\x42\x1b\x00\x30\x40\x1e\x01\x00\x40\x1a\x01\x00\x4e\x00\x07\x00\x4f\x00\x06\x00\x40\x07\x10\x00\x4c\x03\x04\x10\x45\x1e\x07\x00\x49\x1f\x14\x00\x4c\xe3\x38\x11\x42\x1b\x00\x30\x4e\x00\x06\x00\x40\x1b\x10\x00\x4e\x04\x06\x00\x40\x1b\x10\x00\x4e\x08\x06\x00\x40\x1b\x10\x00\x4e\x0c\x06\x00\x45\x1a\x06\x00\x40\x1b\x01\x00\x43\x1a\x07\x00\x45\x16\x05\x00\x49\x1a\x05\x00\x4c\xa3\x98\x10\x7d\x03\xd0\x10\x42\x1b\x00\x30\x4f\x00\x06\x00\x40\x1b\x10\x00\x4f\x04\x06\x00\x40\x1b\x10\x00\x4f\x08\x06\x00\x40\x1b\x10\x00\x4f\x0c\x06\x00\x4c\x03\x30\x10\x2a\x04\x00\x00\x2a\x08\x00\x00\x2a\x08\x00\x00\x2a\x0c\x00\x00\x2a\x0c\x00\x00\x2a\x0c\x00\x00\x7d\x03\xd0\x10\x2a\x0c\x00\x00\x2a\x08\x00\x00\x2a\x08\x00\x00\x2a\x04\x00\x00\x2a\x04\x00\x00\x2a\x04\x00\x00\x4c\x03\x74\x10\x20\x02\x01\x00\x25\x0e\x00\x00\x42\x16\x03\x00\x27\x17\x10\x00\x26\x0f\x10\x00\x24\x0e\x05\x00\x20\x0a\x03\x00\x25\x06\x02\x00\x42\x16\x01\x00\x27\x17\x0c\x00\x26\x07\x14\x00\x24\x06\x05\x00\x20\x02\x01\x00\x25\x0e\x00\x00\x42\x16\x03\x00\x27\x17\x08\x00\x26\x0f\x18\x00\x24\x0e\x05\x00\x20\x0a\x03\x00\x25\x06\x02\x00\x42\x16\x01\x00\x27\x17\x07\x00\x26\x07\x19\x00\x24\x06\x05\x00\x40\x1f\x01\x00\x0b\x00\x00\x00\x42\x03\x00\x20\x42\x0b\x00\x01\x4e\x05\x00\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x00\x30\x40\x03\x10\x00\x40\x0b\x10\x00\x4e\x05\x10\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x10\x30\x40\x03\x10\x00\x40\x0b\x10\x00\x4e\x05\x20\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x20\x30\x40\x03\x10\x00\x40\x0b\x10\x00\x4e\x05\x30\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x30\x30\x0b\x00\x00\x00"
key = bytes([249, 252, 192,
 83,
 135,
 67,
 166,
 149,
 253,
 236,
 156,
 217,
 211,
 21,
 141,
 58,
 98,
 204,
 39,
 61,
 232,
 144,
 85,
 129,
 196,
 250,
 201,
 28,
 190,
 69,
 16,
 52,
 26,
 9,
 22,
 202,
 250,
 5,
 20,
 246,
 128,
 228,
 96,
 74,
 168,
 151,
 186,
 212,
 173,
 98,
 160,
 45,
 205,
 155,
 53,
 116,
 135,
 246,
 122,
 180,
 113,
 52,
 182,
 151])


context.log_level="DEBUG"
class RespType(IntEnum):
    ACK = 0
    CHECK_OK = 1
    CHECK_EXPIRED = 2
    GETKEY_OK = 3
    GETKEY_EXPIRED = 4
    GETKEY_INVALID_PERMS = 5
    GETKEY_UNKNOW = 6
    GETKEY_DEBUG_DEVICE = 7,
    EXEC_CODE_ERROR = 8,
    EXEC_FILE_KEY_OK = 9,
    EXEC_FILE_BAD_KEY = 10,
    EXEC_FILE_ERROR = 11,
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

def req_exec_code(inp, code, ts):
    code_size = struct.pack("<Q", len(code))
    input_size = struct.pack("<Q", len(inp))
    output_size = struct.pack("<Q", 0x40)
    pt, payload = get_payload(0,1,ts)
    req = b"\x02" + payload + struct.pack("<I",ts) + code_size + code + input_size + inp + output_size
    r.send(req)
    output = _recv(0x40)
    err = r.recvuntil("---DEBUG LOG END---\n")
    return output, err

def req_exec_file(inp, f, ts):
    file_size = struct.pack("<Q", len(f))
    pt, payload = get_payload(0,1,ts)
    req = b"\x03" + payload + struct.pack("<I",ts) + inp
    r.send(req)
    resp = _recv(1)
    if resp == bytes([RespType.EXEC_FILE_BAD_KEY]):
        print ("fail")
        raise
    req = file_size + f
    r.send(req)
    err = r.recvuntil("---EXEC OUTPUT END---\n")
    return  err




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

print("test execute code")




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
pt, resp = req_check(0x4307121376ebbe45,0xfffff, futur_ts)
assert(resp == bytes([RespType.UNEXPECTED_ERROR.value]))
pt, resp = req_key(0x4307121376ebbe45,0xfffff, futur_ts)
assert(resp == bytes([RespType.UNEXPECTED_ERROR.value]))
print("test old ts")
pt, resp = req_check(0x4307121376ebbe45,0xfffff, old_ts)
assert(resp == bytes([RespType.CHECK_EXPIRED.value]) + pt)
pt, resp = req_key(0x4307121376ebbe45,0xfffff, old_ts)
assert(resp == bytes([RespType.GETKEY_EXPIRED.value]))




inp = bytes([i for i in range(0x40)])
"""
0000000: 7E D2 B8 C6 C8 DA B0 CF  47 F3 F1 5A CD 68 A2 97  ~.......G..Z.h..
00000010: 4A E5 D2 5A E0 80 C7 5A  00 82 F8 8D 3A 74 37 71  J..Z...Z....:t7q
00000020: 30 92 2E 68 AC BD 07 F3  F5 1A F6 D6 0D BE F8 4F  0..h...........O
00000030: F0 26 F2 CE B0 AC 99 E8  DD AE A7 43 83 7B 64 BE  .&.........C.{d.

00000000: 7E 32 B8 C6 C8 DA B0 CF  47 F3 F1 5A CD 68 A2 97  ~2......G..Z.h..
00000010: 7A 85 D2 5A E0 80 C7 5A  00 82 F8 8D 3A 74 37 71  z..Z...Z....:t7q
00000020: 10 B2 2E 68 AC BD 07 F3  F5 1A F6 D6 0D BE F8 4F  ...h...........O
00000030: 20 C6 F1 CE B0 AC 99 E8  DD AE A7 43 83 7B 64 BE   ..........C.{d.
"""
out,err = req_exec_code(inp, code_decrypt,ts)
hexdump.hexdump(out)
print(err.decode("utf-8"))
assert(out == b"\x7E\x32\xB8\xC6\xC8\xDA\xB0\xCF\x47\xF3\xF1\x5A\xCD\x68\xA2\x97\x7A\x85\xD2\x5A\xE0\x80\xC7\x5A\x00\x82\xF8\x8D\x3A\x74\x37\x71\x10\xB2\x2E\x68\xAC\xBD\x07\xF3\xF5\x1A\xF6\xD6\x0D\xBE\xF8\x4F\x20\xC6\xF1\xCE\xB0\xAC\x99\xE8\xDD\xAE\xA7\x43\x83\x7B\x64\xBE")

with open("hw","rb") as f:
    file_content = f.read()
err = req_exec_file(key,file_content,ts)
print(str(err))
assert(err == b'---EXEC OUTPUT START---\nHello World!\n---EXEC OUTPUT END---\n')





print("tests OK!!")
#todo tests wrong id, wrong  perms, wrong key
while True:
    print (hexdump.hexdump(r.recv()))
