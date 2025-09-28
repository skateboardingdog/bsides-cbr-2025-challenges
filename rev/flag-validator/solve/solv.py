"""
Inspecting the Mach-O (i.e. with `ipsw`) shows a few interesting things:

$ ipsw macho info flag_validator.dylib
Magic         = 64-bit MachO
Type          = DYLIB
CPU           = AARCH64, ARM64
Commands      = 8 (Size: 448)
Flags         = NoUndefs, DyldLink, TwoLevel, NoReexportedDylibs
000: LC_SEGMENT_64 sz=0x00004000 off=0x00000000-0x00004000 addr=0x000000000-0x000004000 r-x/r-x   __TEXT
001: LC_SEGMENT_64 sz=0x00004000 off=0x00004000-0x00008000 addr=0x000004000-0x000008000 rw-/rw-
    sz=0x00000100 off=0x00004000-0x00004100 addr=0x000004000-0x000004100                     .                   (ModInitFuncPointers)
002: LC_SEGMENT_64 sz=0x00004a60 off=0x00008000-0x0000ca60 addr=0x000008000-0x000010000 r--/r--   __LINKEDIT
003: LC_ID_DYLIB                  (0)
004: LC_DYLD_CHAINED_FIXUPS      offset=0x000008000  size=0x60
005: LC_LOAD_DYLIB               /usr/lib/libSystem.B.dylib (0)
006: LC_ROUTINES                 Address: 0x000001e0, Module: 0

LC_ROUTINES specifies an initialization function that will be called when the
library is loaded.
LC_DYLD_CHAINED_FIXUPS defines an external "flag" variable which is to be set
by the main executable - this is our "input" that gets validated and printed.
There is also a ModInitFuncPointers section at
0x4000-0x4100, which upon inspection looks like invalid pointer values.

But looking at the initialization function at 0x1e0:

0x1000781e0: adrp   x2, 4
0x1000781e4: ldr    x1, [x2, #0x108]     ; 0x4108 holds ptr to flag
0x1000781e8: ldrb   w0, [x1]             ; w0 now holds current flag char
0x1000781ec: add    x1, x1, #0x1         ; increment so we look at next flag char next
0x1000781f0: str    x1, [x2, #0x108]     ; update flag ptr to be next flag char
0x1000781f4: adr    x4, 0x1000781e0      ; get addr of this function start
0x1000781f8: mov    x3, #0x0 ; =0        ; start loop with x3 = 0
0x1000781fc: ldrb   w1, [x2, x3]         ; get the constant byte data at 0x4000 + x3
0x100078200: eor    x1, x1, x0           ; x1 = x1 ^ x0
0x100078204: eor    x1, x1, x4           ; x1 = x1 ^ x4
0x100078208: str    x1, [x2, x3]         ; store x1 into the byte data at 0x4000 + x3
0x10007820c: add    x3, x3, #0x8         ; inc x3 by 8
0x100078210: cmp    x3, #0x100           ; repeat 32 times
0x100078214: b.ne   0x1000781fc
0x100078218: ldr    x16, [x2, #0x100]
0x10007821c: br     x16

For each char in the flag, it seems to loop over the 32 pointer values at
0x4000-0x4100 (the ModInitFuncPointers) and update them.

For example, with correct first character "s"

```
0x10007c000: 0x00000001000781e0 0x000000010007816b
0x10007c010: 0x00000001000781e9 0x000000010007816d
0x10007c020: 0x00000001000781ea 0x0000000100078171
0x10007c030: 0x00000001000781e5 0x000000010007816d
0x10007c040: 0x00000001000781e4 0x0000000100078177
0x10007c050: 0x00000001000781c8 0x0000000100078141
0x10007c060: 0x00000001000781d2 0x000000010007816d
0x10007c070: 0x00000001000781ec 0x0000000100078162
0x10007c080: 0x00000001000781dd 0x0000000100078158
0x10007c090: 0x00000001000781c0 0x0000000100078141
0x10007c0a0: 0x00000001000781cc 0x000000010007815c
0x10007c0b0: 0x00000001000781d0 0x0000000100078155
0x10007c0c0: 0x00000001000781ea 0x000000010007816c
0x10007c0d0: 0x00000001000781e0 0x0000000100078161
0x10007c0e0: 0x00000001000781e6 0x0000000100078127
0x10007c0f0: 0x00000001000781ba 0x0000000100078150
```

on the next iteration, with correct second character "k"

```
(lldb) x/32gx $x2
0x10007c000: 0x000000010007816b 0x00000001000781e0
0x10007c010: 0x0000000100078162 0x00000001000781e6
0x10007c020: 0x0000000100078161 0x00000001000781fa
0x10007c030: 0x000000010007816e 0x00000001000781e6
0x10007c040: 0x000000010007816f 0x00000001000781fc
0x10007c050: 0x0000000100078143 0x00000001000781ca
0x10007c060: 0x0000000100078159 0x00000001000781e6
0x10007c070: 0x0000000100078167 0x00000001000781e9
0x10007c080: 0x0000000100078156 0x00000001000781d3
0x10007c090: 0x000000010007814b 0x00000001000781ca
0x10007c0a0: 0x0000000100078147 0x00000001000781d7
0x10007c0b0: 0x000000010007815b 0x00000001000781de
0x10007c0c0: 0x0000000100078161 0x00000001000781e7
0x10007c0d0: 0x000000010007816b 0x00000001000781ea
0x10007c0e0: 0x000000010007816d 0x00000001000781ac
0x10007c0f0: 0x0000000100078131 0x00000001000781db
```

These init functions are called sequentially, so to "succeed" (i.e. avoid a
crash) on the i-th character and print it, the LSB of this pointer must be 0xe0
to point back to the entrypoint function and print the correct character of the
flag.
"""

data = open('../publish/flag_validator.dylib', 'rb').read()
inits = [int.from_bytes(data[0x4000 + i*8 : 0x4000 + i*8 + 8], 'little') for i in range(32)]
flag = ''
for j in range(32):
    c = inits[j]
    flag += chr(c)
    for i in range(32):
        inits[i] ^= c ^ 0xe0
print(flag)
