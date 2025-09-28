#!/usr/bin/env python3

from pwn import *
from enum import IntEnum, auto

class Command(IntEnum):
    CONNECT = 0
    SEND_MESSAGE = 1
    LIST_ROOM = 2
    JOIN_ROOM = 3
    LEAVE_ROOM = 4
    CREATE_ROOM = 5
    DELETE_ROOM = 6
    KICK = 7
    EDIT_ROOM = 8

class Response(IntEnum):
    CONNECT_SUCCESS = 0
    CONNECT_FAIL = 1
    MESSAGE = 2
    ROOM_LIST = 3
    JOIN_ROOM_SUCCESS = 4
    JOIN_ROOM_FAIL = 5
    LEAVE_ROOM_SUCCESS = 6
    LEAVE_ROOM_FAIL = 7
    CREATE_ROOM_SUCCESS = 8
    CREATE_ROOM_FAIL = 9
    DELETE_ROOM_SUCCESS = 10
    DELETE_ROOM_FAIL = 11
    KICK_SUCCESS = 12
    KICK_FAIL = 13
    EDIT_ROOM_SUCCESS = 14
    EDIT_ROOM_FAIL = 15

MSG_BODY_LEN = 1024

def connect(host, port, username):
    """Connect to the chat server and send the initial CONNECT command."""
    r = remote(host, port)
    payload = p32(int(Command.CONNECT)) + username + b'\0' * (MSG_BODY_LEN - len(username))
    r.send(payload)
    return r

def send_message(r, message):
    """Send a message to the server."""
    payload = p32(int(Command.SEND_MESSAGE)) + message + b'\0' * (MSG_BODY_LEN - len(message))
    r.send(payload)

def list_rooms(r):
    """Send the LIST_ROOM command to the server."""
    payload = p32(int(Command.LIST_ROOM)) + b'\0' * MSG_BODY_LEN
    r.send(payload)

def create_room(r, room_name, password=b""):
    """Create a new room."""
    body = room_name + b'\0' + password
    payload = p32(int(Command.CREATE_ROOM)) + body + b'\0' * (MSG_BODY_LEN - len(body))
    r.send(payload)

def join_room(r, room_name, password=""):
    """Join a room."""
    body = room_name + b'\0' + password
    payload = p32(int(Command.JOIN_ROOM)) + body + b'\0' * (MSG_BODY_LEN - len(body))
    r.send(payload)

def leave_room(r):
    """Leave the current room."""
    payload = p32(int(Command.LEAVE_ROOM)) + b'\0' * MSG_BODY_LEN
    r.send(payload)

def delete_room(r, room_name):
    """Delete a room."""
    payload = p32(int(Command.DELETE_ROOM)) + room_name + b'\0' * (MSG_BODY_LEN - len(room_name))
    r.send(payload)

def edit_room(r, old_name, new_name):
    """Edit a room's name."""
    body = old_name + b'\0' + new_name
    payload = p32(int(Command.EDIT_ROOM)) + body + b'\0' * (MSG_BODY_LEN - len(body))
    r.send(payload)

def kick_user(r, room_name, user_name):
    """Kick a user from a room."""
    body = room_name + b'\0' + user_name
    payload = p32(int(Command.KICK)) + body + b'\0' * (MSG_BODY_LEN - len(body))
    r.send(payload)

def recv_response(r):
    """Receive and parse a response from the server."""
    response = r.recv(1024)
    if not response:
        return None, None
    kind = Response(u32(response[:4]))
    body = response[4:].strip(b'\x00')

    return kind, body

if __name__ == '__main__':
    # Example usage
    host = "127.0.0.1"
    port = 1337
    username = "testuser"

    r = connect(host, port, username)

    # Create a room
    create_room(r, "my-room", "password123")
    kind, body = recv_response(r)
    print(f"Response: {kind}, {body.decode(errors='ignore')}")

    # Join the room
    join_room(r, "my-room", "password123")
    kind, body = recv_response(r)
    print(f"Response: {kind}, {body.decode(errors='ignore')}")

    # Send a message
    send_message(r, "Hello, world!")

    # List rooms
    list_rooms(r)
    kind, body = recv_response(r)
    print(f"Response: {kind}, {body.decode(errors='ignore')}")

    r.close()
