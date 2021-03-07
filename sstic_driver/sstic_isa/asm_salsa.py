import operator
import struct
import binascii
import salsa20



#instr 32bits
# 31 ..     20 19  15   8    4    0
#           I      op1   mode  opcode
#if not immediate:
#21: direct indirect
#22: mem/reg
#





#opcodes
#0 ADD
#1 SUB
#2 MOV
#3 AND
#4 OR
#5 XOR
#6 SHR
#7 SHL
#8 NOT
#9 CMP
#10 MROTL
#
#12 JT/F
#13 J
#14 LD
#15 ST
#
# 
# 
# memory layout
# 0x0
# reserved memory RO
# 0x1000 
# code RO
# 0x2000
# data RW
# 0x3000
# stdin RO
# 0x4000
# stdout RW
# 
# 

"""
#include <stdint.h>
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))
#define ROUNDS 20
 
void salsa20_block(uint32_t out[16], uint32_t const in[16])
{
	int i;
	uint32_t x[16];

	for (i = 0; i < 16; ++i)
		x[i] = in[i];
	// 10 loops × 2 rounds/loop = 20 rounds
	for (i = 0; i < ROUNDS; i += 2) {
		// Odd round
		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
	}
	for (i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];
}
"""

"""dexor routine
"""



#normal
#0..3: opcode
#4..7: mode
#8: imm/reg
#9: direct 
#10..12:op1 (reg)
#if cmp:
#   13..15: 0:eq 1:lt 2:gt 3:lte 4:gte
# if imm value
#     16..31: imm
#   if reg:
#       16..17 : reg

#if jmp
#   13: is conditional
#   14: true/false
#   15: all/at least one
#   16..31

#if call:
#   13: call/ret

#mode =


#opcodes
#0 ADD
#1 SUB
#2 MUL
#3 AND
#4 OR
#5 XOR
#6 SHR
#7 SHL
#8 NOT
#9 CMP
#10 MROTL
#
#12 JT/F
#13 J
#14 LD
#15 ST

class BadInstrException(Exception):
    pass

class SegfaultException(Exception):
    pass

class sstic_instr:
    opnames = {
        0 : "ADD",
        1 : "SUB",
        2 : "MOV",
        3 : "AND",
        4 : "OR",
        5 : "XOR",
        6 : "SHR",
        7 : "SHL",
        8 : "NOT",
        9 : "CMP",
        10: "MROTL",
        11: "RET",
        12: "JC",
        13: "CALL",
        14: "LD",
        15: "ST"
    }

    ropnames = dict([reversed(i) for i in opnames.items()])

    cmp_opnames = {
        0 : "EQ",
        1 : "LT",
        2 : "GT",
        3 : "LTE",
        4 : "GTE"
    }

    cmp_ropnames = dict([reversed(i) for i in cmp_opnames.items()])

    modenames = {
        0 : "B",
        1 : "H",
        2 : "D",
        3 : "Q",
        4 : "V",
        7 : "None"
    }
    rmodenames = dict([reversed(i) for i in modenames.items()])

    def __init__(self):
        self.opcode = None
        self.mode = None
        self.is_imm = None
        self.is_direct = None
        self.op1 = None
        self.op1_regno = None
        self.is_cmp = None
        self.cmp_op = None
        self.op2 = None
        self.imm = None
        self.is_jmp = None
        self.jump_true = None
        self.jump_all = None
        self.jump_cond = None
        self.is_call = None
        self.is_ret = None

    def disasm(self, instr):
        opcode = instr & 0xf
        self.opcode = sstic_instr.opnames[opcode]
        mode = (instr >> 4) & 0xf
        try:
            self.mode = sstic_instr.modenames[mode]
        except:
            raise BadInstrException
        self.is_imm = (instr >> 8) & 1
        self.is_direct = (instr >> 9) & 1
        self.is_jmp = self.opcode  == "JC"
        self.is_call = self.opcode == "CALL"
        self.is_ret = self.opcode == "RET"
       

        if not self.is_jmp:
            self.op1 = (instr >> 10) & 7
        if self.is_imm:
            self.imm = (instr >> 16) & 0xffff
        else:
            self.op2 = (instr >> 16) & 7
        self.is_cmp = self.opcode == "CMP"
        if self.is_cmp:
            cmp_op = (instr >> 13) & 3
            self.cmp_op = sstic_instr.cmp_opnames[cmp_op]
        
        if self.is_jmp:
            self.jump_cond = (instr >> 13) & 1
            self.jump_true = (instr >> 14) & 1
            self.jump_all = (instr >> 15) & 1
        
        





    def asm(self, line):
        line = line.lstrip().rstrip()
        toks = line.split(" ")
        if toks[0] in ["CALL", "RET"]:
            opcode = toks[0]
            flags = ""
        else:
            opcode,flags = toks[0].split(".")
        self.opcode = opcode
        if self.opcode == "CALL":
            self.is_imm = True
            self.is_direct =  True
            self.imm = int(toks[1],16)
            self.mode = "None"
            self.jump_true = True
            self.jump_all = True
            self.is_call = True
            return
        if self.opcode == "RET":
            self.is_imm = False
            self.is_direct = False
            self.imm = 0
            self.mode = "B"
            self.op2 = 0
            self.op1 = 0
            self.is_ret = True
            return
        if len(flags):
            self.mode = flags[0]
            if "I" in flags:
                self.is_imm = True
            else:
                self.is_imm = False
            if "D" in flags[1:]:
                self.is_direct = True
            else:
                self.is_direct = False
        if self.opcode == "JC":
            self.is_imm = True
            self.is_direct =  True
            self.imm = int(toks[1],16)
            self.jump_true = "T" in flags
            self.jump_all = "A" in flags
            self.jump_cond = "C" in flags
            return
        
        if self.opcode.startswith("CMP"):
            self.cmp_op = self.opcode[3:]
            self.opcode = "CMP"
        if self.opcode not in ["J", "JC"]:
            self.op1 = int(toks[1][1])
            if self.opcode not in ["MROTL"]:
                if self.is_imm:
                    self.imm = int(toks[2],16)
                else:
                    self.op2 = int(toks[2][1])
        

    def encode(self):
        instr = 0
        instr |= sstic_instr.ropnames[self.opcode]
        instr |= sstic_instr.rmodenames[self.mode] << 4
        instr |= int(self.is_imm) << 8
        instr |= int(self.is_direct) << 9
        if self.opcode == "JC":
            instr |= int(self.jump_cond) << 13
            instr |= int(self.jump_true) << 14
            instr |= int(self.jump_all) << 15
        elif self.opcode in ["CALL", "RET"]:
            pass
        else:
            instr |= self.op1 << 10
        if self.opcode == "CMP":
            instr |= sstic_instr.cmp_ropnames[self.cmp_op] << 13
        if self.is_imm:
            instr |= self.imm << 16
        else:
            if not self.opcode == "MROTL":
                instr |= self.op2 << 16
        instr &= 0xffffffff
        return struct.pack("<I",instr)




            
            





class register:

    masks = {
        "B" : [0xff]*8,
        "H" : [0xffff] * 16,
        "D" : [0xffffffff] * 4,
        "Q" : [0xffffffffffffffff] * 2,
        "V" : [0xffffffffffffffffffffffffffffffff]
    }

    def __init__(self):
        self.raw = bytearray(16)

    def assign_B(self, b):
        for i in range(16):
            self.raw[i] = b[i]
    
    def get_B(self):
        ret = []
        for i in range(16):
            ret.append(self.raw[i])
    
    def get_H(self):
        return struct.unpack("<HHHHHHHH", self.raw)

    def assign_H(self, h):
        self.raw = bytearray(struct.pack("<HHHHHHHH", h))

    def get_D(self):
        return list(struct.unpack("<IIII", self.raw))

    def assign_D(self, d):
        self.raw = bytearray(struct.pack("<IIII", *d))

    def get_Q(self):
        return list(struct.unpack("<QQ", self.raw))

    def assign_Q(self, q):
        self.raw = bytearray(struct.pack("<QQ", *q))

    def get_V(self):
        a,b =  struct.unpack("<QQ", self.raw)
        return [a | (b <<64)]

    def assign_V(self, v):
        v = v[0]
        a,b = v & 0xffffffffffffffff, v >> 64
        self.raw = bytearray(struct.pack("<QQ", a,b))

    def from_bytes(self, bytes):
        self.raw = bytearray(bytes)

    def get_with_mode(self,mode):
        f = getattr(self,f"get_{mode}")
        return f()

    def assign_with_mode(self,mode,l):
        f = getattr(self,f"assign_{mode}")
        f(l)


class Emulator:

    opers = {
        "ADD" : operator.add,
        "SUB" : operator.sub,
        "MUL" : operator.mul,
        "AND" : operator.and_,
        "OR" : operator.or_,
        "XOR" : operator.xor,
        "NOT" : operator.invert,
        "EQ" : operator.eq,
        "LT" : operator.lt,
        "GT" : operator.gt,
        "LE" : operator.le,
        "GE" : operator.ge
    }

    mode_bits = {
        "B" : 8,
        "H" : 16,
        "D" : 32,
        "Q" : 64,
        "V" : 128
    }

    mode_nb = {
        "B" : 16,
        "H" : 8,
        "D" : 4,
        "Q" : 2,
        "V" : 1
    }

    def __init__(self, code, stdin,ROM):
        self.mem = bytearray(0x10000)
        #TODO init memory with static values and stdin and code
        self.mem[0x1000:0x1000 + len(code)] = code
        self.mem[0x2000:0x2000 + len(stdin)] = stdin
        self.mem[0x0000:0x0000 + len(ROM)] = ROM
        self.PC = 0x1000
        self.regs = [register() for i in range(8)]
        self.test_reg = register()
        self.stack = []

    def get_reg_mem(self,addr):
        if addr > 0x10000 - 16:
            raise SegfaultException
        r = register()
        r.from_bytes(self.mem[addr: addr+16])
        return r

    def do_operation(self, instr : sstic_instr):
        if instr.is_direct:
            if instr.is_imm:
                op2 = instr.imm
            else:
                op2 = self.regs[instr.op2]
        else:
            if instr.is_imm:
                op2 = self.get_reg_mem(instr.imm)
            else:
                if instr.mode != "V":
                    raise BadInstrException
                op2 = self.get_reg_mem(self.regs[instr.op2].get_V()[0])
        
        op1_l = self.regs[instr.op1].get_with_mode(instr.mode)
        if instr.is_direct and instr.is_imm:
            op2_l = [instr.imm] * Emulator.mode_nb[instr.mode]
        else: 
            op2_l = op2.get_with_mode(instr.mode)
        oper = Emulator.opers[instr.opcode if instr.opcode != "CMP" else instr.cmp_op]
        for i in range(len(op1_l)):
            op1_l[i] = oper(op1_l[i],op2_l[i])
        mask = register.masks[instr.mode]
        op1_l = [x & y for x,y in zip(op1_l,mask)]
        if instr.opcode != "CMP":
            self.regs[instr.op1].assign_with_mode(instr.mode,op1_l)
        else:
            self.test_reg.assign_with_mode(instr.mode,op1_l)
            

            
    def do_shift(self, instr : sstic_instr):
        if not instr.is_direct or not instr.is_imm:
            raise BadInstrException
        if instr.imm >= Emulator.mode_bits[instr.mode]:
            raise BadInstrException
        op1_l = self.regs[instr.op1].get_with_mode(instr.mode)
        oper = operator.lshift if instr.opcode == "SHL" else operator.rshift
        for i in range(len(op1_l)):
            op1_l[i] = oper(op1_l[i],instr.imm)
        mask = register.masks[instr.mode]
        op1_l = [x & y for x,y in zip(op1_l,mask)]
        self.regs[instr.op1].assign_with_mode(instr.mode,op1_l)
            
    def do_MROTL(self,instr):
        op1_l = self.regs[instr.op1].get_with_mode(instr.mode)
        new = [0] * len(op1_l)
        for i in range(len(op1_l)):
            new[(i-1) % len(op1_l)] = op1_l[i]
        self.regs[instr.op1].assign_with_mode(instr.mode,new)

    def do_JC(self, instr):
        if not instr.is_direct or not instr.is_imm:
            raise BadInstrException
        if instr.imm % 4:
            raise BadInstrException
        
        test_reg_l = self.test_reg.get_with_mode(instr.mode)
        if instr.jump_all:
            will_jump = all(x == instr.jump_true for x in test_reg_l)
        else:
            will_jump = any(x == instr.jump_true for x in test_reg_l)
        if will_jump:
            if instr.imm >= 0x10000:
                return SegfaultException
            self.PC = instr.imm
        else:
            self.PC += 4

    def do_CALL(self, instr):
        if not instr.is_direct or not instr.is_imm:
            raise BadInstrException
        if instr.imm % 4:
            raise BadInstrException
        if instr.imm >= 0x10000:
            raise SegfaultException
        self.stack.append(self.PC+4)
        self.PC = instr.imm

    def do_RET(self, instr):
        #if not instr.is_direct or not instr.is_imm:
         #   raise BadInstrException
        if self.stack == []:
            raise SegfaultException
        self.PC = self.stack.pop()


    def do_LD(self, instr):
        if instr.is_direct:
            raise BadInstrException
        if not instr.is_direct:
            if instr.is_imm:
                addr = instr.imm
            else:
                addr = self.regs[instr.op2].get_V()[0]
        #nb_bytes = Emulator.mode_bits[instr.mode] // 8
        reg_l = self.regs[instr.op1].get_with_mode(instr.mode)
        v = self.get_reg_mem(addr)
        v_l = v.get_with_mode(instr.mode)
        #v = struct.unpack(f"<{instr.mode}",self.mem[addr:])[0]
        reg_l[0] = v_l[0]
        self.regs[instr.op1].assign_with_mode(instr.mode,reg_l)

    def do_ST(self, instr):
        if instr.is_direct:
            raise BadInstrException
        if not instr.is_direct:
            if instr.is_imm:
                addr = instr.imm
            else:
                addr = self.regs[instr.op2].get_V()[0]
        nb_bytes = Emulator.mode_bits[instr.mode] // 8
        reg_l = self.regs[instr.op1].get_with_mode(instr.mode)
        if instr.mode != "V":
            packmode = instr.mode if instr.mode != "D" else "I"
            self.mem[addr:addr+nb_bytes] = struct.pack(f"<{packmode}",reg_l[0])
        else:
            self.mem[addr:addr+nb_bytes] = self.regs[instr.op1].raw

    def do_MOV(self, instr):
        if not instr.is_direct:
            return BadInstrException
        if instr.is_direct:
            if instr.is_imm:
                op2 = instr.imm
                op1_l = self.regs[instr.op1].get_with_mode(instr.mode)
                op1_l[0] = instr.imm
                mask = register.masks[instr.mode]
                op1_l = [x & y for x,y in zip(op1_l,mask)]
                self.regs[instr.op1].assign_with_mode(instr.mode,op1_l)
            else:
                if instr.mode != "V":
                    raise BadInstrException
                op2 = self.regs[instr.op2].get_V()
                self.regs[instr.op1].assign_V(op2)
        

    def execute(self):
        #if self.PC < 0x1000 or self.PC > 0x2000:
        #    raise SegfaultException
        for i in range(10000):
            self.dump_state()
            hexdump.hexdump(em.mem[0x3000:0x3040])
            instr_raw = struct.unpack("<I", self.mem[self.PC:self.PC+4])[0]
            instr = sstic_instr()
            instr.disasm(instr_raw)
            if instr.opcode in ["ADD", "SUB",  "AND", "OR", "XOR", "NOT", "CMP"]:
                self.do_operation(instr)
            elif instr.opcode in ["SHL", "SHR"]:
                self.do_shift(instr)
            elif instr.opcode == "RET" and not self.stack:
                return
            else:
                f = getattr(self,f"do_{instr.opcode}")
                f(instr)
            if instr.opcode not in ["JC", "CALL", "RET"]:
                self.PC += 4
        raise Exception

    def dump_state(self):
        ret = ""
        ret += "regs:\n"
        ret += f"PC : {self.PC:x}\n"
        for i in range(8):
            ret += f"R{i} : {binascii.hexlify(self.regs[i].raw)}\n"
        ret += f"CREG: {binascii.hexlify(self.test_reg.raw)}\n"
        ret += "stack: " + str(list(map(hex,self.stack)))
        print(ret)


def assemble_code(code, base_addr):
    labels = {}
    lines = code.split("\n")
    #first pass
    addr = base_addr
    for line in lines:
        line = line.lstrip()
        if line == "":
            continue
        if line.startswith("#"):
            continue
        if line.startswith("_"):
            labels[line.replace(":","")] = addr
            continue
        addr +=4
    #assemble
    code = b""
    for line in lines:
        line = line.lstrip()
        if line == "":
            continue
        if line.startswith("#"):
            continue
        if line.startswith("_"):
            continue
        if "_" in line:
            for l in labels:
                if l in line:
                    line = line.replace(l,f"0x{labels[l]:x}")
                    break
        i = sstic_instr()
        i.asm(line)
        code += i.encode()
    return code




slasa20_routine = """
#matrix is at 0x100
_CODE:
    XOR.VD R1 R1
_COPY_LOOP:
    CMPEQ.VID R1 0x40
    JC.VTAC _START_SALSA
    MOV.VDI R7 0x100
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
    XOR.VD R6 R6
    ADD.VID R6 0x1
    AND.VD R6 R7
    XOR.VD R5 R5
    CMPEQ.VD R6 R5
    JC.VAC _ROUND_EVEN
_ROUND_ODD:
    MOV.VDI R6 0x3000
    LD.V R0 R6
    ADD.VID R6 0x10
    LD.V R1 R6
    ADD.VID R6 0x10
    LD.V R2 R6
    ADD.VID R6 0x10
    LD.V R3 R6
    CALL _DO_ROUND
#WRITEMEM
    MOV.VDI R6 0x3000
    ST.V R0 R6
    ADD.VID R6 0x10
    ST.V R1 R6
    ADD.VID R6 0x10
    ST.V R2 R6
    ADD.VID R6 0x10
    ST.V R3 R6
    JC.V _ROUND_LOOP

_ROUND_EVEN:
    XOR.VD R6 R6
    XOR.VD R5 R5
    XOR.VD R0 R0
    MOV.VID R4 0x3000
_NEXT_LINE:
    CMPEQ.VID R4 0x3040
    JC.VTAC _LOAD_OK                            
    LD.D R0 R4
    MROTL.D R0
    ADD.VID R4 0x4
    LD.D R1 R4
    MROTL.D R1
    ADD.VID R4 0x4
    LD.D R2 R4
    MROTL.D R2
    ADD.VID R4 0x4
    LD.D R3 R4
    MROTL.D R3
    ADD.VID R4 0x4
    JC.V _NEXT_LINE
_LOAD_OK:
    CALL _DO_ROUND
    #write MEM
    MOV.VID R4 0x3000
_STORE_N_LINE:
    CMPEQ.VID R4 0x3040
    JC.VTAC _ROUND_LOOP                            
    ST.D R0 R4
    MROTL.D R0
    MROTL.D R0
    MROTL.D R0
    ADD.VID R4 0x4
    ST.D R1 R4
    MROTL.D R1
    MROTL.D R1
    MROTL.D R1
    ADD.VID R4 0x4
    ST.D R2 R4
    MROTL.D R2
    MROTL.D R2
    MROTL.D R2
    ADD.VID R4 0x4
    ST.D R3 R4
    MROTL.D R3
    MROTL.D R3
    MROTL.D R3
    ADD.VID R4 0x4
    JC.V _STORE_N_LINE



_DO_ROUND:
    MOV.VD R4 R0
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 7
    SHR.DID R4 19
    OR.DD R4 R5
    XOR.DD R1 R4

    MOV.VD R4 R0
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 9
    SHR.DID R4 17
    OR.DD R4 R5
    XOR.DD R2 R4

    MOV.VD R4 R2
    ADD.DD R4 R1
    MOV.VD R5 R4
    SHL.DID R5 d
    SHR.DID R4 13
    OR.DD R4 R5
    XOR.DD R3 R4

    MOV.VD R4 R2
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 12
    SHR.DID R4 0xe
    OR.DD R4 R5
    XOR.DD R0 R4

    ADD.VID R7 1
    RET

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
    MOV.VDI R7 0x100
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
    XOR.VD R6 R6
    ADD.VID R6 0x1
    AND.VD R6 R7
    XOR.VD R5 R5
    CMPEQ.VD R6 R5
    JC.VAC _ROUND_EVEN
_ROUND_ODD:
    MOV.VDI R6 0x3000
    LD.V R0 R6
    ADD.VID R6 0x10
    LD.V R1 R6
    ADD.VID R6 0x10
    LD.V R2 R6
    ADD.VID R6 0x10
    LD.V R3 R6
    CALL _DO_ROUND
#WRITEMEM
    MOV.VDI R6 0x3000
    ST.V R0 R6
    ADD.VID R6 0x10
    ST.V R1 R6
    ADD.VID R6 0x10
    ST.V R2 R6
    ADD.VID R6 0x10
    ST.V R3 R6
    JC.V _ROUND_LOOP

_ROUND_EVEN:
    XOR.VD R6 R6
    XOR.VD R5 R5
    XOR.VD R0 R0
    MOV.VID R4 0x3000
_NEXT_LINE:
    CMPEQ.VID R4 0x3040
    JC.VTAC _LOAD_OK                            
    LD.D R0 R4
    MROTL.D R0
    ADD.VID R4 0x4
    LD.D R1 R4
    MROTL.D R1
    ADD.VID R4 0x4
    LD.D R2 R4
    MROTL.D R2
    ADD.VID R4 0x4
    LD.D R3 R4
    MROTL.D R3
    ADD.VID R4 0x4
    JC.V _NEXT_LINE
_LOAD_OK:
    CALL _DO_ROUND
    #write MEM
    MOV.VID R4 0x3000
_STORE_N_LINE:
    CMPEQ.VID R4 0x3040
    JC.VTAC _ROUND_LOOP                            
    ST.D R0 R4
    MROTL.D R0
    MROTL.D R0
    MROTL.D R0
    ADD.VID R4 0x4
    ST.D R1 R4
    MROTL.D R1
    MROTL.D R1
    MROTL.D R1
    ADD.VID R4 0x4
    ST.D R2 R4
    MROTL.D R2
    MROTL.D R2
    MROTL.D R2
    ADD.VID R4 0x4
    ST.D R3 R4
    MROTL.D R3
    MROTL.D R3
    MROTL.D R3
    ADD.VID R4 0x4
    JC.V _STORE_N_LINE



_DO_ROUND:
    MOV.VD R4 R0
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 7
    SHR.DID R4 19
    OR.DD R4 R5
    XOR.DD R1 R4

    MOV.VD R4 R0
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 9
    SHR.DID R4 17
    OR.DD R4 R5
    XOR.DD R2 R4

    MOV.VD R4 R2
    ADD.DD R4 R1
    MOV.VD R5 R4
    SHL.DID R5 d
    SHR.DID R4 13
    OR.DD R4 R5
    XOR.DD R3 R4

    MOV.VD R4 R2
    ADD.DD R4 R3
    MOV.VD R5 R4
    SHL.DID R5 12
    SHR.DID R4 0xe
    OR.DD R4 R5
    XOR.DD R0 R4

    ADD.VID R7 1
    RET

_END:
    RET
"""

import hexdump

def _rotl32(w,r):
    return ( ( ( w << r ) & 0xffffffff) | ( w >> ( 32 - r ) ) )

def salsa20_round(_s):
    _mask = 0xffffffff
    _s[ 4] ^= _rotl32((_s[ 0] + _s[12]) & _mask, 7)
    _s[ 8] ^= _rotl32((_s[ 0] + _s[ 4]) & _mask, 9)
    _s[12] ^= _rotl32((_s[ 4] + _s[ 8]) & _mask,13)
    _s[ 0] ^= _rotl32((_s[ 8] + _s[12]) & _mask,18)

    # quarterround 2
    _s[ 9] ^= _rotl32((_s[ 1] + _s[ 5]) & _mask, 7)
    _s[13] ^= _rotl32((_s[ 5] + _s[ 9]) & _mask, 9)
    _s[ 1] ^= _rotl32((_s[ 9] + _s[13]) & _mask,13)
    _s[ 5] ^= _rotl32((_s[ 1] + _s[13]) & _mask,18)

    # quarterround 3
    _s[14] ^= _rotl32((_s[ 6] + _s[10]) & _mask, 7)
    _s[ 2] ^= _rotl32((_s[10] + _s[14]) & _mask, 9)
    _s[ 6] ^= _rotl32((_s[ 2] + _s[14]) & _mask,13)
    _s[10] ^= _rotl32((_s[ 2] + _s[ 6]) & _mask,18)

    # quarterround 4
    _s[ 3] ^= _rotl32((_s[11] + _s[15]) & _mask, 7)
    _s[ 7] ^= _rotl32((_s[ 3] + _s[15]) & _mask, 9)
    _s[11] ^= _rotl32((_s[ 3] + _s[ 7]) & _mask,13)
    _s[15] ^= _rotl32((_s[ 7] + _s[11]) & _mask,18)

def transpose(_s):
    return [_s[ 0], _s[ 4], _s[ 8], _s[12],
               _s[ 1], _s[ 5], _s[ 9], _s[13],
               _s[ 2], _s[ 6], _s[10], _s[14],
               _s[ 3], _s[ 7], _s[11], _s[15]]
"""
round 0 :
['0x41c350c2', '0xa99dfeca', '0x818e8f80', '0x393b393b', 
'0x90b090b', '0x3eef6eb5', '0x2e096a4d', '0xedf2f3ec', 
'0x39363738', '0x292b292b', '0xcc1c9777', '0xea8ac9c9', 
'0x1b3a5978', '0xb54a4bb4', '0x191b191b', '0xc9e95cca']
round 1 :
['0xe272506e', '0x610dd92d', '0x37566313', '0x9900ab89', '0xd6d90077', '0x53b528f', '0x3653f933', '0x615aed71', '0xb92cfdb1', '0xd3328a6e', '0xbd0521de', '0x6a044650', '0x86fe2b3b', '0xae00b5c8', '0x496a98b3', '0x6ee71b6']
"""


if __name__ == "__main__":
    mat_raw = bytes([i for i in range(0x40)])
    mat = []
    for i in range(16):
        mat.append(struct.unpack("<I",mat_raw[i*4:(i+1)*4])[0])
    r0 = salsa20_round(mat)
    
    print("round 0 :")
    print(list(map(hex,mat)))

    mat = transpose(mat)
    r1 = salsa20_round(mat)

    print("round 1 :")
    print(list(map(hex,mat)))

    code = assemble_code(slasa20_routine, 0x1000)
    rom = bytes([0]*0x100 + [i for i in range(0x40)])
    em = Emulator(code,b"",rom)
    em.execute()
    hexdump.hexdump(em.mem[0x3000:0x3040])


    


        
