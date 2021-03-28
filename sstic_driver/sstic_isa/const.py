from z3 import *
import struct

l = [0xe, 3, 5, 0xa, 8, 4, 9, 0xb, 0, 0xc, 0xd, 7, 0xf, 2, 6, 1]
l16 = []
l32 = []
l64 = []

for i in range(8):
    l16.append(l[i*2] | l[i*2+1] << 8)

for i in range(4):
    l32.append(l16[i*2] | l16[i*2+1] << 16)

for i in range(2):
    l64.append(l32[i*2] | l32[i*2+1] << 32)

print(list(map(hex,l16)))
print(list(map(hex,l32)))
print(list(map(hex,l64)))

"""['0x30e', '0xa05', '0x408', '0xb09', '0xc00', '0x70d', '0x20f', '0x106']
['0xa05030e', '0xb090408', '0x70d0c00', '0x106020f']
['0xb0904080a05030e', '0x106020f070d0c00']"""

syms = [BitVec(f"x{i:02x}", 8) for i in range(16)]

s = Solver()
if 0:
    
    s.add(Concat(BitVecVal(0x44,8),BitVec("x",8)) == 0x4455)
    print(s.check())
    print(s.model())
    raise

for i in range(16):
    for j in range(i+1,16):
        s.add(syms[i] != syms[j])

for i in range(16):
    s.add(syms[i] < 16)
    s.add(syms[i] >= 0)

syms16 = []
for i in range(8):
    syms16.append(Concat(syms[i*2+1], syms[i*2]))

syms32 = []
for i in range(4):
    syms32.append(Concat(syms16[i*2+1], syms16[i*2]))

syms64 = []
for i in range(2):
    syms64.append(Concat(syms32[i*2+1], syms32[i*2]))


s.add(syms16[0] <= 0x30e)
s.add(syms16[1] <= 0xa05 + 2)
s.add(syms16[2] <= 0x408 + 150)
s.add(syms16[3] <= 0xb09 + 3)
s.add(syms16[4] <= 0xc00 + 300)
s.add(syms16[5] <= 0x70d + 198)
s.add(syms16[6] <= 0x20f + 101)
s.add(syms16[7] <= 0x106 + 98)

s.add(syms32[0] > 0xa05030e - 0x10000)
s.add(syms32[1] > 0xb090408 - 0x25080)
s.add(syms32[2] > 0x70d0c00 - 0x100)
s.add(syms32[3] > 0x106020f - 0x700000)

s.add(syms64[0] < 0xb0904080a05030e + 0x1480068400)
s.add(syms64[1] < 0x106020f070d0c00 + 0x1000)

s.add(Or(syms32[0] == 0x70d0c00, syms32[1] == 0x70d0c00, syms32[2] == 0x70d0c00, syms32[3] == 0x70d0c00))
s.add(Or(syms32[0] == 0x106020f, syms32[1] == 0x106020f, syms32[2] == 0x106020f, syms32[3] == 0x106020f))
s.add(Or(syms16[0] == 0x408, syms16[1] == 0x408, syms16[2] == 0x408, syms16[3] == 0x408, syms16[4] == 0x408, syms16[5] == 0x408, syms16[6] == 0x408, syms16[7] == 0x408))
#s.add(Or(syms16[0] == 0xc00, syms16[1] == 0xc00, syms16[2] == 0xc00, syms16[3] == 0xc00, syms16[4] == 0xc00, syms16[5] == 0xc00, syms16[6] == 0xc00, syms16[7] == 0xc00))

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

print (buf)



if 0:
    for i in range(8):
        s.add(syms16[i] >= 0x106)
        s.add(syms16[i] < 0xd00)
    s.add(Or(syms16[0] == 0x408, syms16[1] == 0x408, syms16[2] == 0x408, syms16[3] == 0x408, syms16[4] == 0x408, syms16[5] == 0x408, syms16[6] == 0x408, syms16[7] == 0x408))
    s.add(Or(syms16[0] == 0xa05, syms16[1] == 0xa05, syms16[2] == 0xa05, syms16[3] == 0xa05, syms16[4] == 0xa05, syms16[5] == 0xa05, syms16[6] == 0xa05, syms16[7] == 0xa05))

    for i in range(4):
        s.add(syms32[i] > 0x1050100)
        s.add(syms32[i] <= 0xb090408)
    s.add(Or(syms32[0] == 0x70d0c00, syms32[1] == 0x70d0c00, syms32[2] == 0x70d0c00, syms32[3] == 0x70d0c00))


    for i in range(2):
        s.add(syms64[i] < 0xc0904080a05030e)
        s.add(syms64[i] > 0x1000200070d0c00)


    s.add(syms[0] != 13)
    s.add(syms[0] != 11)
    s.add(syms[0] != 10)
    s.add(syms[0] != 6)
    s.add(syms[0] != 3)
#s.add(syms[0] != 9)
#s.add(syms[0] != 14)
#s.add(syms[2] != 5)
s.add(Or(syms[0] != l[0], syms[1] != l[1], syms[2] != l[2], syms[3] != l[3], 
    syms[4] != l[4], syms[5] != l[5], syms[6] != l[6], syms[7] != l[7], 
    syms[8] != l[8], syms[9] != l[9], syms[10] != l[10], syms[11] != l[11], 
    syms[12] != l[12], syms[13] != l[13], syms[14] != l[14], syms[15] != l[15],))
print(s.check())
#print(s.model())
