from functools import cache
import time
from gmpy2 import mpz

import requests
from suffix_tree import Tree
from tqdm import tqdm

n, e, c = 0, 0, 0
exec(open('../publish/output.txt', 'r').read())

start = time.time()
print('fetching words and building suffix tree...')
WORDS = requests.get('https://raw.githubusercontent.com/dwyl/english-words/refs/heads/master/words_alpha.txt').text.splitlines()
short_words = ['a', 'i', 'of', 'it', 'is', 'by', 'be', 'my', 'me', 'do', 'as', 'at', 'an', 'up', 'to', 'go', 'he', 'hi', 'if', 'in', 'no', 'on', 'ok', 'so']
WORDS = set([w for w in WORDS if len(w) > 2 or (w in short_words)])
stree = Tree({w:w for w in WORDS})
print(f'done {time.time() - start}s')

@cache
def words_from_suffix(suffix):
    out = []
    for (w, _) in stree.find_all(suffix):
        if w.endswith(suffix):
            out.append(w)
    return out

def check_phrase(phrase):
    words = phrase.split()
    return all(w in WORDS for w in words[1:]) and words_from_suffix(words[0])

def find_candidates(p_current):
    seen = set()
    cands = []
    for w in tqdm(WORDS):
        p_lower_str = w + p_current
        if p_lower_str in seen:
            continue
        p_lower = int.from_bytes(p_lower_str.encode())
        if p_lower % 2 == 0:
            continue
        l = len(p_lower_str)
        q_lower = mpz(n) * pow(mpz(p_lower), -1, (1<<(8*l))) % (1<<(8*l))
        q_lower_str = int(q_lower).to_bytes(l)
        qw = q_lower_str.replace(b'!', b'')
        if qw.replace(b' ', b'').isalpha():
            seen.add(q_lower_str.decode())
            if check_phrase(qw.decode()):
                cands.append((p_lower_str, q_lower_str.decode()))
    return sorted(cands, key=lambda a: len(a[0]) + len(a[1]))

def interactive_crib(p_current):
    print()
    print(f'cribbing with "{p_current}"')

    cands = find_candidates(p_current)

    print()

    for i, c in enumerate(cands):
        print(str(i+1).zfill(2) + ': ' + c[0] + '\n    ' + c[1])
        print()

    s1 = int(input('selection> ')) - 1

    print('01: ' + cands[s1][0])
    print('02: ' + cands[s1][1])

    s2 = int(input('which> ')) - 1
    target = cands[s1][s2]
    add = input('prefix (enter to skip)> ')

    interactive_crib(add + target)

interactive_crib('')
