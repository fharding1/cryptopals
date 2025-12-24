import math

def xor_bytes(x,y,l):
    return bytes([x[i] ^ y[i] for i in range(l)])

english_freq = [
    0.0812,  # A
    0.0149,  # B
    0.0271,  # C
    0.0432,  # D
    0.1202, # E
    0.0230,  # F
    0.0203,  # G
    0.0592,  # H
    0.0731,  # I
    0.0010,  # J
    0.0069,  # K
    0.0398,  # L
    0.0261,  # M
    0.0695,  # N
    0.0768,  # O
    0.0182,  # P
    0.0011,  # Q
    0.0602,  # R
    0.0628,  # S
    0.0910,  # T
    0.0288,  # U
    0.0111,  # V
    0.0209,  # W
    0.0017,  # X
    0.0211,  # Y
    0.0007,   # Z
]


def freq(b):
    counts = [0] * 26
    for ch in b.lower():
        if ch >= b'a'[0] and ch <= b'z'[0]:
            counts[ch - b'a'[0]] += 1
    return [(counts[i] / len(b)) for i in range(26)]

def english_score(b):
    #return math.dist(english_freq,freq(b))
    return sum([((x-y)**2)/(x+y) for (x,y) in zip(english_freq, freq(b))])


print(english_score(b'The quick brown fox jumps over the lazy dog.'))
print(english_score(b'Jhadsfbaukdy$%@#$&*GFBDSYU'))


with open('input4', 'r') as file:
    ctxts = [bytes.fromhex(line.strip()) for line in file]

    candidates = []

    for ctxt in ctxts:
        for ch in range(128):
            pad = [ch] * len(ctxt)
            dec = xor_bytes(ctxt,pad,len(ctxt))
            try:
                dec.decode('utf-8')
                score = english_score(dec)
                candidates.append((score, dec))
            except:
                continue

    candidates.sort(key=lambda x: x[0])

    for top_candidate in candidates[:10]:
        print(top_candidate[0], top_candidate[1].decode('utf-8'))
