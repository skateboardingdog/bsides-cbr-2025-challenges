import random
from binteger import Bin
from base64 import b64encode
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

F = GF(2)
n_dialogues = 30 # number of dialogues
n = 8 * n_dialogues
m = 4 # number of choices per dialogue
V = VectorSpace(F, n)

start_state = V([0] * n)
end_state = V([1] * n)

sol = [V.random_element() for _ in range(n_dialogues - 1)]
sol += [end_state - sum(sol) - start_state]

assert start_state + sum(sol) == end_state

choices = []
ans = []
for i in range(n_dialogues):
    C = [V.random_element() for _ in range(m)]
    idx = random.randint(0, 3)
    ans.append(idx)
    C[idx] = sol[i]
    choices.append(C)

out = b''
for c in flatten(choices):
    out += Bin(c, n=n).bytes
print(b64encode(out).decode())

k = ','.join(map(str, ans)).encode()
key = sha256(k).digest()
aes = AES.new(key, AES.MODE_GCM, nonce=b'\x00'*12)
flag = b'skbdg{the_flag_was_stuck_in_the_linear_algebranch!}'
enc_flag, tag = aes.encrypt_and_digest(flag)
print(b64encode(enc_flag + tag).decode())
