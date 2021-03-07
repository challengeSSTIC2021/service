import struct

#we can put a troll or something random here
decrypted_content = bytes([0xff for _ in range(0x30)]) + b"EXECUTE FILE OK!"

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

    skey = b""
    for i in range(16):
        skey += struct.pack("<I",x[i])
    ct = bytes([skey[i] ^ pt[i] for i in range(0x40)])
    return ct


ct = encrypt(decrypted_content,key)
print("{ ",end='')
for i in ct:
    print(f"0x{i:x}, ",end='')
print("}")

