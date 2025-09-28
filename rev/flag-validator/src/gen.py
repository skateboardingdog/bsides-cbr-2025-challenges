import os
import struct

from pathlib import Path


def seg(segname=b'', vmaddr=0, vmsize=0, fileoff=0, filesize=0, maxprot=0, initprot=0, nsects=0, flags=0):
    seg = bytearray()
    seg += struct.pack('<II', 0x19, 72 + nsects * 80)
    seg += segname.ljust(16, b'\x00')
    seg += struct.pack('<QQQQiiII', vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags)
    return seg


def sect(sectname=b'', segname=b'', addr=0, size=0, offset=0, align=0, flags=0):
    sect = bytearray()
    sect += sectname.ljust(16, b'\x00')
    sect += segname.ljust(16, b'\x00')
    sect += struct.pack('<QQIIIIIIII', addr, size, offset, align, 0, 0, flags, 0, 0, 0)
    return sect


def main():
    buffer = bytearray()

    rw_off = 0x4000
    ro_off = 0x8000

    ncmds = 7
    buffer += struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 6, ncmds, 0, 0x100085, 0)

    # segments
    buffer += seg(b'__TEXT', vmsize=0x4000, filesize=0x4000, maxprot=5, initprot=5)
    buffer += seg(vmaddr=0x4000, vmsize=0x4000, fileoff=0x4000, filesize=0x4000, maxprot=3, initprot=3, nsects=1)
    buffer += sect(addr=0x4000, size=(8 * 32), offset=0x4000, flags=0x9)

    buffer += seg(b'__LINKEDIT', vmaddr=0x8000, vmsize=0x4000, fileoff=0x8000, filesize=0x60, maxprot=1, initprot=1)


    # LC_ID_DYLIB
    buffer += struct.pack('<IIIIII', 0xd, 0x18, 0x14, 1, 0, 0)

    # LC_CHAINED_FIXUPS
    buffer += struct.pack('<IIII', 0x80000034, 0x10, 0x8000, 0x60)

    # LC_LOAD_DYLIB
    buffer += struct.pack('<IIIIII', 0xc, 0x38, 0x18, 2, 0, 0)
    buffer += b'/usr/lib/libSystem.B.dylib' + b'\x00' * 6

    # LC_ROUTINES
    buffer += struct.pack('<IIIIIIIIII', 0x11, 0x28, 0x1e0, 0, 0, 0, 0, 0, 0, 0)

    # update header size
    buffer[20:22] = struct.pack('<H', len(buffer) - 4 * 8)

    # leave space for LC_CODE_SIGNATURE
    buffer += b'\x00' * 0x10

    assert len(buffer) == 0x1e0
    text = bytes.fromhex('22000090418440f92000403921040091418400f964ffff10030080d241686338210000ca210004ca416823f8632000917f0004f141ffff54508040f900021fd6')
    buffer += text


    ### RW seg
    buffer += b'\x00' * (rw_off - len(buffer))

    # init offs
    flag = b'skbdg{got_to_be_init_to_win_it}\n'
    assert len(flag) == 32
    data = [flag[0]];
    for i in range(1, len(flag)):
        data.append(data[-1] ^ flag[i] ^ 0xe0)
    for i in range(32):
        buffer += struct.pack('<Q', data[i])

    # GOT
    assert len(buffer) == rw_off + 0x100
    buffer += struct.pack('<QQ', 0x8010000000000000, 0x8000000000000001)


    ### RO seg
    buffer += b'\x00' * (ro_off - len(buffer))

    # fixups
    buffer += struct.pack('<IIIIIII', 0, 0x20, 0x48, 0x50, 2, 1, 0)

    buffer += b'\x00' * (ro_off + 0x20 - len(buffer))
    buffer += struct.pack('<IIII', 3, 0, 0x10, 0)

    buffer += struct.pack('<IHHQIHH', 0x18, 0x4000, 6, 0x4000, 0, 1, 0x100)

    # fixup imports
    assert len(buffer) == ro_off + 0x48
    buffer += struct.pack('<II', 1 | 0 << 8 | 1 << 9, 0xff | 1 << 8 | 10 << 9)
    buffer += b'\x00_putchar\x00_flag\x00'

    Path('flag_validator.dylib').write_bytes(buffer)
    Path('flag_validator_signed.dylib').write_bytes(buffer)

    os.system('codesign -s - flag_validator_signed.dylib')


if __name__ == '__main__':
    main()
