import keystone as ks
import capstone as cs
import unicorn as uc

ASM = """
.syntax unified
.thumb
.global _start

_start:
    mov r4, #0              
    ldr r5, =data           
    ldrsb r6, [r5, r4]
    mov r7, r6      
           
loop:
    add r0, r4, #1
    sub r1, r7, r0

    push {r7}
    push {r1}
    mov r0, #1              
    mov r1, sp             
    mov r2, #1             
    mov r7, #1
    lsl r7, r7, #2             
    svc #0

    sub sp, sp, #8        
    mov r0, #0             
    str r0, [sp, #4]      
    ldr r0, =3600         
    str r0, [sp]          
    mov r0, sp            
    mov r1, #0            
    mov r7, #162          
    svc #0                 
    add sp, sp, #8        

    pop {r1}
    pop {r7}
    add r4, r4, #1          
    ldrsb r6, [r5, r4]      
    cmp r6, #127           
    beq end
    add r7, r7, r6
    b loop

end:
    mov r0, #0
    mov r7, #1             
    svc #0

data:
    .byte 116              
    .byte -7, -8, 3, 4, 21, -12, 2, 6
    .byte -20, 9, 9, 0, 1, -12, -1, 20, -12
    .byte -3, 3, 6, -8, 15, 13, -25, 22, -14
    .byte 8, -6, 12, -7, 8, 0, -8, -67, 1, 1, 93
    .byte 127               
"""

flag = bytearray()

assembler = ks.Ks(ks.KS_ARCH_ARM, ks.KS_MODE_THUMB)
disassembler = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
emulator = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB)

code, _ = assembler.asm(ASM)
asmcode = bytes(code)
initial_address = 0
stackaddr = 2048
for addr, size, mnem, op_str in disassembler.disasm_lite(asmcode, initial_address):
    instruction = asmcode[addr:addr + size]
    print(f'{addr:04x}|\t{instruction.hex():<8}\t{mnem:<5}\t{op_str}')

def hook_intr(self, intr, _):
    mem = emulator.reg_read(uc.arm_const.UC_ARM_REG_R1)
    dat = emulator.mem_read(mem, 1)
    r7 = emulator.reg_read(uc.arm_const.UC_ARM_REG_R7)
    if r7 == 4:
        flag.extend(dat)

emulator.mem_map(initial_address, 1024) 
emulator.mem_map(stackaddr, 1024)

emulator.reg_write(uc.arm_const.UC_ARM_REG_R13, stackaddr + 1024)
emulator.mem_write(initial_address, asmcode)  

emulator.hook_add(uc.UC_HOOK_INTR, hook_intr)

emulator.emu_start(initial_address | 1, initial_address + 0x5e)
print(flag.decode())