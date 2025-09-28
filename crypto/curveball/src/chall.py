#!/bin/env python3

from sage.all import (
    EllipticCurve,
    GF,
    is_prime,
    randint,
    Integer,
    PolynomialRing
)
import os
import secrets

HITS_TO_WIN = 40
FLAG = os.getenv("FLAG", "skbdg{test_flag}")

def get_user_parameters():
    print("Step up to the plate! Let's define the field.")
    while True:
        try:
            a = int(input("Enter parameter 'a': "))
            b = int(input("Enter parameter 'b': "))
            p = int(input("Enter prime 'p': "))

            if p.bit_length() < 384:
                print("\n[!] We need a big league field. p must be at least 384 bits.")
                continue

            if not is_prime(p):
                print("\n[!] You can't play ball without a prime field.")
                continue

            if (4 * a**3 + 27 * b**2) % p == 0:
                print("\n[!] That's a foul ball! Try again.")
                continue

            return a, b, p

        except (ValueError, TypeError):
            print("\n[!] Invalid input. Please enter valid integers for a, b, and p.")
            continue


def construct_fp2(p):
    Fp = GF(p)
    non_residue = Fp.quadratic_nonresidue()
    R, j = PolynomialRing(Fp, 'j').objgen()
    modulus = j**2 - non_residue
    Fp2 = GF(p**2, name='j', modulus=modulus)
    return Fp2, modulus


def main():
    hit_counter = 0
    print("="*60)
    print(f" Welcome to BSides Field! Can you score {HITS_TO_WIN} hits in a row to win the flag?")
    print("="*60)

    a, b, p = get_user_parameters()
    Fp2, modulus = construct_fp2(p)
    print(f"Field modulus: {modulus}")

    try:
        E = EllipticCurve(Fp2, [a, b])
    except Exception as e:
        print(f"\n[!] An error occurred while creating the curve: {e}")
        return

    E_twist = E.quadratic_twist()
    while hit_counter < HITS_TO_WIN:
        print("-" * 30)
        print(f"Pitch #{hit_counter + 1} | Hits: {hit_counter} / {HITS_TO_WIN}")
        print("-" * 30)

        use_twist = secrets.randbits(1)
        if use_twist:
            current_curve = E_twist
            print("The pitcher winds up... it's a CURVEBALL, twisting through the air!")
        else:
            current_curve = E
            print("Here comes the heat... a FASTBALL, straight down the middle!")

        try:
            P = current_curve.random_point()
            k = secrets.randbelow(int((p + 1)**2))
            Q = k * P

        except Exception as e:
            print(f"\n[!] Catcher's interference! Had trouble finding a good point on the curve: {e}")
            return

        print(f"\nCurve is y^2 = x^3 + ({current_curve.a4()})x + ({current_curve.a6()})")
        print(f"Here is the pitch:")
        print(f"  P = {P.xy()}")
        print(f"  Q = {Q.xy()}")
        try:
            user_k = int(input("Enter your value for k: "))

            if user_k * P == Q:
                hit_counter += 1
                print(f"\nSmack! That's a hit! You have {hit_counter} hit(s).\n")
            else:
                print(f"\nSwing and a miss! That's a strike! The correct answer was {k}.")
                return

        except (ValueError, TypeError):
            print("\n[!] Invalid input for k. That's an automatic strike!")
            return

    print("=" * 60)
    print(f"You've hit {HITS_TO_WIN} pitches in a row!")
    print("Here is your flag:")
    print(f"\n    {FLAG}\n")
    print("=" * 60)

if __name__ == "__main__":
    main()
