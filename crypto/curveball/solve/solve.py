from pwn import *

context.log_level = "debug"
from sage.all import EllipticCurve, GF, Integer, PolynomialRing, EllipticCurve_from_j
from Crypto.Util.number import *
from tqdm import tqdm


def solve_challenge():
    # Start the challenge script using Sage
    conn = connect("localhost", 1337)

    # https://github.com/microsoft/twin-smooth-integers
    p = 24600714170622799816088836092734294918071122448528500631523214880860080654749490140217212311032942985224695552198151
    K = GF(p)
    E = EllipticCurve_from_j(K(1728))
    a = E.a4()
    b = E.a6()

    conn.sendlineafter(b"Enter parameter 'a': ", str(a).encode())
    conn.sendlineafter(b"Enter parameter 'b': ", str(b).encode())
    conn.sendlineafter(b"Enter prime 'p': ", str(p).encode())

    # --- 2. Parse Field Information ---
    modulus = (
        conn.recvline_startswith(b"Field modulus:").decode().split(":")[-1].strip()
    )

    Fp = GF(p)
    R, j = PolynomialRing(Fp, "j").objgen()
    non_residue = int(modulus.split(" + ")[1])
    modulus_poly = j**2 + non_residue
    Fp2 = GF(p**2, name="j", modulus=modulus_poly)

    curves = {}
    for i in tqdm(range(HITS_TO_WIN)):
        conn.recvuntil(b"Curve is y^2 = x^3 + (")
        a4_str = conn.recvuntil(b")", drop=True).decode()
        conn.recvuntil(b"(")
        a6_str = conn.recvuntil(b")", drop=True).decode()
        a4 = eval(a4_str)
        a6 = eval(a6_str)
        current_curve = curves.get((a4, a6), EllipticCurve(Fp2, [a4, a6]))
        curves[(a4, a6)] = current_curve
        print("current_curve = ", current_curve)

        conn.recvuntil(b"P = (")
        px_str = conn.recvuntil(b",", drop=True).decode()
        py_str = conn.recvuntil(b")", drop=True).decode()
        P_x = eval(px_str)
        P_y = eval(py_str)
        P = current_curve((P_x, P_y))
        print("P = ", P)

        conn.recvuntil(b"Q = (")
        qx_str = conn.recvuntil(b",", drop=True).decode()
        qy_str = conn.recvuntil(b")", drop=True).decode()

        Q_x = eval(qx_str)
        Q_y = eval(qy_str)
        Q = current_curve((Q_x, Q_y))
        print("Q = ", Q)

        k = Q.log(P)
        print("Found k = ", k)
        conn.sendlineafter(b"Enter your value for k:", str(k).encode())

    print(conn.recvall())
    conn.close()


if __name__ == "__main__":
    HITS_TO_WIN = 40
    solve_challenge()
