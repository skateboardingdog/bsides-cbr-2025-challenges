#!/usr/bin/env python3

import threading
import time
import secrets
import string
from libchat import *

HOST = "127.0.0.1"
PORT = 1337
FLAG = b"skbdg{n0w_0wn_th3_wh0le_s3rv3r!}"
ROOM_NAME = b"flagroom"
ROOM_PASSWORD = b''.join(secrets.choice(string.printable).encode() for _ in range(64))

print(ROOM_PASSWORD)
def chatter():
    try:
        r = connect(HOST, PORT, b"Doug Flagson")
        log.info("Sender bot connected.")

        time.sleep(1)

        join_room(r, ROOM_NAME, ROOM_PASSWORD)
        recv_response(r)
        log.info("Sender bot joined the room.")

        time.sleep(1) 
        while True:
            time.sleep(2)
            send_message(r, FLAG)
            log.info("Sender bot sent the flag.")

        r.close()
    except Exception as e:
        log.error(f"Sender bot error: {e}")


def admin():
    try:
        r = connect(HOST, PORT, b"Admin")
        log.info("Admin bot connected.")

        create_room(r, ROOM_NAME, ROOM_PASSWORD)
        recv_response(r)         
        log.info(f"Room '{ROOM_NAME}' created by admin.")


    except Exception as e:
        log.error(f"admin bot error: {e}")

def main():
    admin_thread = threading.Thread(target=admin)
    chatter_thread = threading.Thread(target=chatter)

    num_users = secrets.randbelow(40)
    users = []
    for i in range(num_users):
        users.append(connect(HOST, PORT, b"user" + b"A" * secrets.randbelow(0x300)))

    for i in range(num_users):
        users[i].close()

    admin_thread.start()
    chatter_thread.start()

    admin_thread.join()
    chatter_thread.join()



if __name__ == "__main__":
    main()
