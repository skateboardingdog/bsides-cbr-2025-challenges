import socket

REMOTE = '127.0.0.1'
PORT = 1337

payload = b'\xff\x00\xfe\x01' + b'skbd' + b'AAAA' + b'dogz'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((REMOTE, PORT))
s.settimeout(1)
s.send(payload)
while(1):
    try:
        print(s.recv(1024).decode().strip("\n"))
    except socket.timeout:
        break
s.close()
