from pwn import *
import sys
from Crypto.Util.number import long_to_bytes

def rust_solver(n, e, c):
    conn = process(['./solver/target/release/solver'], stderr=sys.stderr, level='error')
    conn.sendline(f'{n} {e} {c}'.encode())
    ans = conn.recvline().decode()
    conn.close()
    if 'No solution found' in ans:
        return None
    return long_to_bytes(int(ans))

# conn = process(['python3', '../publish/supersanic2.py'])
conn = remote('0.0.0.0', 1337)
print(conn.recvline().decode())
n = int(conn.recvline().decode().split('n = ')[1])
e = int(conn.recvline().decode().split('e = ')[1])
c = int(conn.recvline().decode().split('c = ')[1])

pin = rust_solver(n, e, c)
if pin:
    conn.sendlineafter(b'PIN: ', pin)
    print(conn.recvline().decode())
else:
    print('failed... try again')
