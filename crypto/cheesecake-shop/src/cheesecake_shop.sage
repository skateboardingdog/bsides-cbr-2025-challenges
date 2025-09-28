from hashlib import sha256
from math import pi
from ast import literal_eval
from os import getenv

FLAG = getenv('FLAG', 'skbdg{????????????????????????????????????????????????????????????????}')

def cheese_assert(condition):
    # The idea is that `condition` is normally something that is true. But we've cheesed it somehow, so it must now be false.
    assert not condition, "That's no gouda. Oh well, batter luck next time."

print("Welcome to the cheesecake shop 🧀🍰🏪!")
print("We have cheesecakes ranging from mild (⭐) to sharp (⭐⭐⭐⭐⭐) and everything in between. Would you like to try them all?")

print("⭐ Factorisation Cheesecake 🧀🍰")
print("RSA was invented in 1977, under the assumption that factorisation is extremely difficult.")
N = random_prime(2^512) * random_prime(2^512)
print(f'{N = }')
factor = int(input("Enter a factor of N: "))
assert N % factor == 0, "It needs to be a factor of N"
cheese_assert(factor == 1 or factor == N)

print("⭐⭐ Collision Cheesecake 🧀🍰")
print("SHA-256 was published in 2001, and is designed so that hash collisions are practically impossible to find.")
payload1 = bytes.fromhex(input("Enter first payload (hex): "))
payload2 = bytes.fromhex(input("Enter second payload (hex): "))
assert all(a != b for a, b in zip(payload1, payload2)), "The payloads must have every single byte be different"
cheese_assert(sha256(payload1).digest() != sha256(payload2).digest())

print("⭐⭐⭐ Irrational Cheesecake 🧀🍰")
print("Lambert showed in 1768 that π is irrational, i.e. cannot be written as a/b.")
a = int(input("Enter a: "))
b = int(input("Enter b: "))
cheese_assert(pi != a/b)

print("⭐⭐⭐⭐ Balanced Ternary Cheesecake 🧀🍰")
print("An online calculator told me that 1337 is '-1,-1,-1,-1,-1,0,-1,1' in balanced ternary. Also this is unique.")
trits = literal_eval(input("Enter balanced trits: "))
assert all(trit in {-1,0,1} for trit in trits), "Balanced trits only take the values {-1, 0, 1}"
assert sum(trits[i]*3^i for i in range(len(trits))) == 1337, "Must be a balanced ternary representation of 1337"
cheese_assert(sum(trits) == -5)

print("⭐⭐⭐⭐⭐ Fermat's Little Cheesecake 🧀🍰")
print("The smaller FLT was first stated in 1640 and is quite useful in crypto: it states that a^p ≡ a (mod p).")
p = int(input("Enter p: "))
a = GF(p)(input("Enter a: "))
cheese_assert(a ^ p == a)

print("⭐⭐⭐⭐⭐⭐ Bonus star: Fermat's Last Cheesecake 🧀🍰")
print("The bigger FLT is notorious for having a proof that doesn't fit in a margin. It states that a^n + b^n = c^n has no solutions.")
a = int(input("Enter a: "))
b = int(input("Enter b: "))
c = int(input("Enter c: "))
n = int(input("Enter n: "))
assert a > 0 and b > 0 and c > 0 and n > 2, "Ensure a, b, c are positive integers, and n is greater than 2"
cheese_assert(a^n + b^n != c^n)

print("Did you enjoy our assortment of cheesecakes? Here's a flag for your troubles.")
print(FLAG)
