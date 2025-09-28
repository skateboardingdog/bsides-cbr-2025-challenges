from Crypto.Util.number import isPrime
import requests

# p_phrase and q_phrase contain English sentences, without punctuation
from secret import p_phrase, q_phrase, flag

WORDS = set(requests.get('https://raw.githubusercontent.com/dwyl/english-words/refs/heads/master/words_alpha.txt').text.splitlines())

pq_words = set(p_phrase.split(' ') + q_phrase.split(' '))
assert pq_words - WORDS == set()

p = int.from_bytes(p_phrase.encode())
q = int.from_bytes(q_phrase.encode())
assert isPrime(p) and isPrime(q)

n = p * q
e = 0x10001
c = pow(int.from_bytes(flag.encode()), e, n)
print(f'{n = }')
print(f'{e = }')
print(f'{c = }')
