#!/usr/bin/env python3

import os
from subprocess import check_call, check_output
from string import ascii_letters, ascii_lowercase, digits
from tempfile import NamedTemporaryFile

c_source = '''
#include <stdio.h>

int main(int argc, char** argv) {{
  printf("{fmtstr}", argv[1][0]);
}}
'''

fmtstr = input('format string: ')

if len(fmtstr) > 30:
    print('too long!')
    exit(1)

if not all(c in ascii_letters + digits + '%$*.#-+ ' for c in fmtstr):
    print('invalid chars!')
    exit(1)

with NamedTemporaryFile(suffix='.c') as f:
    f.write(c_source.format(fmtstr=fmtstr).encode())
    f.flush()
    b = f.name + '_out'
    check_call(['/usr/bin/gcc', '-B/usr/bin', f.name, '-o', b])

    for c in ascii_lowercase:
        try:
            o = check_output([b, c]).strip().decode()
            assert o == c.upper()
        except:
            print('incorrect!')
            break
    else:
        print(os.getenv('FLAG', 'skbdg{testflag}'))

    os.unlink(b)
