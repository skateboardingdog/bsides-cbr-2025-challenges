from pwn import *
from string import digits as ALPHABET
import itertools
from Crypto.Util.number import bytes_to_long
from gmpy2 import mpz

# conn = process(['python3', '../publish/supersanic1.py'])
conn = remote('0.0.0.0', 1337)
print(conn.recvline().decode())
n = int(conn.recvline().decode().split('n = ')[1])
e = int(conn.recvline().decode().split('e = ')[1])
c = int(conn.recvline().decode().split('c = ')[1])

def go(pin):
    c_ = pow(mpz(bytes_to_long(pin.encode())), e, n)
    return c == c_

pins = list(''.join(p) for p in itertools.product(ALPHABET, repeat=6))
pin = iters.mbruteforce(go, pins, 1, 'fixed')
conn.sendlineafter(b'PIN: ', pin.encode())
print(conn.recvline().decode())
