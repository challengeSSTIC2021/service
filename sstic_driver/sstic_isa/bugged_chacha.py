from asm import Emulator, assemble_code
import struct
from hexdump import hexdump

#we can put a troll or something random here
decrypted_content = bytes([0xff for _ in range(0x30)]) + b"EXECUTE FILE OK!"

start_key = b"expand 32-byte k"
key = start_key + bytes([
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

def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)


#bugged chacha so key can be retrived (final add is missing)
def encrypt(pt, key):
    mat = []
    for i in range(16):
        mat.append(struct.unpack("<I",key[i*4:(i+1)*4])[0])
    x = mat
    for i in range(10):
        quarter_round(x, 0, 4,  8, 12)
        quarter_round(x, 1, 5,  9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)

        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7,  8, 13)
        quarter_round(x, 3, 4,  9, 14)

    #here is the bugged part
    xx = 0x2000
    for i in range(0x10):
        if not i%4:
            x[i] += xx
            xx += 0x10

    skey = b""
    for i in range(16):
        skey += struct.pack("<I",x[i])
    hexdump(skey)
    ct = bytes([skey[i] ^ pt[i] for i in range(0x40)])
    return ct




packer ="""
LD.VI R0 0x2040

MOV.VDI R6 0
_LLL:
CMPEQ.BDI R6 10
JC.BTAC _TEST2


CMPEQ.BD R0 R6
JC.BTC _III
JC.V _END
_III:
ADD.BID R6 1
JC.V _LLL 

_TEST2:
#test xorkey
LD.VI R1 0x200
CMPLE.HD R0 R1
JC.HFC _END


CMPGT.DI R0 0x210
JC.DTAC _GOOD
JC.V _END

_GOOD:
CMPLT.QI R0 0x220
JC.QFC _END

XOR.VD R5 R5
ADD.DID R5 0x70d
SHL.DID R5 10
ADD.DID R5 c00
#CMPEQ.DID R0 0x70d0c00
CMPEQ.DD R0 R5
JC.DTC _AAA
JC.V _END

_AAA:
XOR.VD R5 R5
ADD.DID R5 0x106
SHL.DID R5 10
ADD.DID R5 20f
#CMPEQ.DID R0 0x106020f
CMPEQ.DD R0 R5
JC.DTC _BBB
JC.V _END

_BBB:
CMPEQ.HID R0 0x408
JC.HTC _GOGO
JC.V _END

_GOGO:
MOV.VID R7 0x1100
_LOOP:
CMPEQ.VDI R7 0x1300
JC.VTAC _CODE
LD.V R1 R7
XOR.VD R1 R0
ST.V R1 R7
ADD.VID R7 0x10
JC.V _LOOP

_CODE:
CALL 0x1100

_END:
RET
"""

chacha20_routine = """
#matrix is at 0x100
_CODE:
    XOR.VD R1 R1
_COPY_LOOP:
    CMPEQ.VID R1 0x40
    JC.VTAC _START_SALSA
    MOV.VDI R7 0x2000
    MOV.VDI R6 0x3000
    ADD.VD R7 R1
    ADD.VD R6 R1
    LD.V R0 R7
    ST.V R0 R6
    ADD.VID R1 0x10
    JC.V _COPY_LOOP

_START_SALSA:
    XOR.VD R7 R7
_ROUND_LOOP:
    CMPEQ.VDI R7 0x14
    JC.VTAC _END

#load mat into register
    MOV.VDI R6 0x3000
    LD.V R0 R6
    ADD.VID R6 0x10
    LD.V R1 R6
    ADD.VID R6 0x10
    LD.V R2 R6
    ADD.VID R6 0x10
    LD.V R3 R6
    ### if round is ODD

    XOR.VD R6 R6
    ADD.VID R6 0x1
    AND.VD R6 R7
    XOR.VD R5 R5
    CMPEQ.VD R6 R5
    JC.VAC _SHIFT_REG

    CALL _DO_ROUND
_WRITE_MEM:
    MOV.VDI R6 0x3000
    ST.V R0 R6
    ADD.VID R6 0x10
    ST.V R1 R6
    ADD.VID R6 0x10
    ST.V R2 R6
    ADD.VID R6 0x10
    ST.V R3 R6
    JC.V _ROUND_LOOP

_SHIFT_REG:
    MROTL.D R1
    MROTL.D R2
    MROTL.D R2
    MROTL.D R3
    MROTL.D R3
    MROTL.D R3

    CALL _DO_ROUND

    MROTL.D R3
    MROTL.D R2
    MROTL.D R2
    MROTL.D R1
    MROTL.D R1
    MROTL.D R1
    JC.V _WRITE_MEM

_DO_ROUND:
    ADD.DD R0 R1
    XOR.DD R3 R0
    MOV.VD R5 R3
    SHL.DID R5 10
    SHR.DID R3 10
    OR.DD R3 R5

    ADD.DD R2 R3
    XOR.DD R1 R2
    MOV.VD R5 R1
    SHL.DID R5 c
    SHR.DID R1 14
    OR.DD R1 R5

    ADD.DD R0 R1
    XOR.DD R3 R0
    MOV.VD R5 R3
    SHL.DID R5 8
    SHR.DID R3 18
    OR.DD R3 R5

    ADD.DD R2 R3
    XOR.DD R1 R2
    MOV.VD R5 R1
    SHL.DID R5 7
    SHR.DID R1 19
    OR.DD R1 R5

    ADD.VID R7 1
    RET

_END:
#here we should add the original matrix at 0x2000 before xor but a
#missing flag in the ADD make it add 0x2000 instead of the
#content at 0x2000, so the key can be retrieved easily

#we don't use a loop to have LD/ST immediate somewhere in the code
    MOV.VDI R0 0x2000
    MOV.VDI R2 0x100
    LD.VI R1 0x3000
    LD.V R3 R2
    ADD.DD R1 R0
    XOR.VD R1 R3
    ST.VI R1 0x3000
    ADD.VID R0 0x10
    ADD.VID R2 0x10

    LD.VI R1 0x3010
    LD.V R3 R2
    ADD.DD R1 R0
    XOR.VD R1 R3
    ST.VI R1 0x3010
    ADD.VID R0 0x10
    ADD.VID R2 0x10

    LD.VI R1 0x3020
    LD.V R3 R2
    ADD.DD R1 R0
    XOR.VD R1 R3
    ST.VI R1 0x3020
    ADD.VID R0 0x10
    ADD.VID R2 0x10

    LD.VI R1 0x3030
    LD.V R3 R2
    ADD.DD R1 R0
    XOR.VD R1 R3
    ST.VI R1 0x3030

    RET
"""
#from asm import *

code_chacha = assemble_code(chacha20_routine, 0x1100)
code_packer = assemble_code(packer,0x1000)
print(len(code_packer))
code_packer += b"\x00" * (0x100 - len(code_packer))
code_chacha += b"\x00" * (0x200 - len(code_chacha))
code_chacha_p = bytearray(0x200)


key_packer = bytes([0xe, 3, 5, 0xa, 8, 4, 9, 0xb, 0, 0xc, 0xd, 7, 0xf, 2, 6, 1])
for i in range(0x200):
    code_chacha_p[i] = code_chacha[i] ^ key_packer[i % 0x10]

ct = encrypt(decrypted_content,key)
pt = encrypt(ct,key)
assert(pt == decrypted_content)
print("rom 0x100:")
print("{ ",end='')
for i in ct:
    print(f"0x{i:x}, ",end='')
print("}")

buf = b""
buf += struct.pack("<H",0x30e)
buf += struct.pack("<H",0xa05 + 2)
buf += struct.pack("<H",0x408 + 150)
buf += struct.pack("<H",0xb09 + 3)
buf += struct.pack("<H",0xc00 + 300)
buf += struct.pack("<H",0x70d + 198)
buf += struct.pack("<H",0x20f + 101)
buf += struct.pack("<H",0x106 + 98)

buf += struct.pack("<I",0xa05030e - 0x10000)
buf += struct.pack("<I",0xb090408 - 0x25080)
buf += struct.pack("<I",0x70d0c00 - 0x100)
buf += struct.pack("<I",0x106020f - 0x700000)

buf += struct.pack("<Q",0xb0904080a05030e + 0x1480068400)
buf += struct.pack("<Q",0x106020f070d0c00 + 0x1000)

print("rom 0x200:")
print("{ ",end='')
for i in buf:
    print(f"0x{i:x}, ",end='')
print("}")

print("code")
code = code_packer + code_chacha_p
assert(len(code) == 0x300)
for i in range(len(code)//32):
    print('"',end="")
    for j in range(32):
        print(f"\\x{code[i*32+j]:02x}",end='')
    print('"')
    


test= False
if test:
    stdin = key + key_packer

    #test packer
    e = Emulator()
    e.mem[0x100:0x100+len(ct)] = ct
    e.mem[0x200:0x200+len(buf)] = buf
    e.mem[0x2000:0x2000+len(stdin)] = stdin
    e.mem[0x1000:0x1000+len(code_packer)] = code_packer
    e.mem[0x1100:0x1100+len(code_chacha_p)] = code_chacha_p
    e.execute(True)
    assert(e.mem[0x1100:0x1300] == code_chacha)
    assert(e.mem[0x3000:0x3040] == decrypted_content)





def test():
    import hexdump
    mat_raw = bytes([i for i in range(0x40)])
    mat = []
    for i in range(16):
        mat.append(struct.unpack("<I",mat_raw[i*4:(i+1)*4])[0])
    x = mat
    for i in range(10):
        quarter_round(x, 0, 4,  8, 12)
        quarter_round(x, 1, 5,  9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)

        print("round 0 :")
        print(list(map(hex,x)))

        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7,  8, 13)
        quarter_round(x, 3, 4,  9, 14)

        print("round 1 :")
        print(list(map(hex,x)))
    xx = 0x2000
    for i in range(0x10):
        if not i%4:
            x[i] += xx
            xx += 0x10

    code = assemble_code(chacha20_routine, 0x1000)
    rom = bytes([0]*0x100 + [i for i in range(0x40)])
    stdin = bytes([i for i in range(0x40)])
    em = Emulator()
    #em.mem[0:0+len(rom)] = rom
    em.mem[0x2000:0x2000+len(stdin)] = stdin
    em.mem[0x1000:0x1000+len(code)] = code
    em.execute(True)
    mat2 = []
    for i in range(16):
        mat2.append(struct.unpack("<I",em.mem[0x3000+i*4:0x3000+(i+1)*4])[0])
    hexdump.hexdump(em.mem[0x3000:0x3040])
    assert(mat2 == x)

def test2():
    import hexdump

    code = assemble_code(chacha20_routine, 0x1000)
    rom = bytes([ 0x24, 0x72, 0x98, 0x45, 0x33, 0xe3, 0xf6, 0xe7, 0x72, 0xb, 0xda, 0xef, 0x39, 0x3e, 0x4, 0x96, 0xd8, 0x2f, 0xc7, 0x26, 0x45, 0x3e, 0x19, 0x5, 0x15, 0x2e, 0xbd, 0x8c, 0xf3, 0xdc, 0xca, 0x45, 0x9f, 0xdf, 0xea, 0x53, 0xef, 0xf6, 0xef, 0x35, 0xcf, 0x5b, 0x63, 0xf1, 0xf4, 0x3c, 0x57, 0x4e, 0xc9, 0x4e, 0x7b, 0xf, 0x2c, 0x15, 0x89, 0x9d, 0x14, 0x72, 0xf4, 0x2e, 0x72, 0x34, 0x4, 0xd2])
    stdin = key
    em = Emulator()
    em.mem[0x100:0x100+len(rom)] = rom
    em.mem[0x2000:0x2000+len(stdin)] = stdin
    em.mem[0x1000:0x1000+len(code)] = code
    em.execute(False)
    hexdump.hexdump(em.mem[0x3000:0x3040])

#0 ROM
#0x1000 CODE
#0x2000 STDIN
#0x3000 STDOUT
#0x4000 DATA

def test3():
    import hexdump
    code = assemble_code(chacha20_routine, 0x1000)
    rom = bytes([ 0x24, 0x72, 0x98, 0x45, 0x33, 0xe3, 0xf6, 0xe7, 0x72, 0xb, 0xda, 0xef, 0x39, 0x3e, 0x4, 0x96, 0xd8, 0x2f, 0xc7, 0x26, 0x45, 0x3e, 0x19, 0x5, 0x15, 0x2e, 0xbd, 0x8c, 0xf3, 0xdc, 0xca, 0x45, 0x9f, 0xdf, 0xea, 0x53, 0xef, 0xf6, 0xef, 0x35, 0xcf, 0x5b, 0x63, 0xf1, 0xf4, 0x3c, 0x57, 0x4e, 0xc9, 0x4e, 0x7b, 0xf, 0x2c, 0x15, 0x89, 0x9d, 0x14, 0x72, 0xf4, 0x2e, 0x72, 0x34, 0x4, 0xd2])
    stdin = key
    em = Emulator()
    em.mem[0x100:0x100+len(rom)] = rom
    em.mem[0x2000:0x2000+len(stdin)] = stdin
    em.mem[0x1000:0x1000+len(code)] = code
    em.execute(False)
    hexdump.hexdump(em.mem[0x3000:0x3040])