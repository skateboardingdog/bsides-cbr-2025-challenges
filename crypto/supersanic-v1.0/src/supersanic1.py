#!/usr/bin/env python3

from string import digits as ALPHABET
import math, random, signal, os
from Crypto.Util.number import getPrime, bytes_to_long

print(f'Welcome to supeRSAnic-v{math.log10(len(ALPHABET))}')

n = getPrime(256) * getPrime(256)
e = 0x10001
pin = ''.join(random.choices(ALPHABET, k=6))
c = pow(bytes_to_long(pin.encode()), e, n)
print(f'{n = }')
print(f'{e = }')
print(f'{c = }')

signal.signal(signal.SIGALRM, lambda *_: print('You Gotta Go Faster!') or exit(1))
signal.alarm(30)

guess = input('PIN: ')
if guess == pin:
    print(os.getenv('FLAG', 'skbdg{fake_flag}'))
else:
    print('Incorrect!')
