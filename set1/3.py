import math

ctxt = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

def xor_bytes(x,y,l):
    return bytes([x[i] ^ y[i] for i in range(l)])

english_freq = [
    8.12,  # A
    1.49,  # B
    2.71,  # C
    4.32,  # D
    12.02, # E
    2.30,  # F
    2.03,  # G
    5.92,  # H
    7.31,  # I
    0.10,  # J
    0.69,  # K
    3.98,  # L
    2.61,  # M
    6.95,  # N
    7.68,  # O
    1.82,  # P
    0.11,  # Q
    6.02,  # R
    6.28,  # S
    9.10,  # T
    2.88,  # U
    1.11,  # V
    2.09,  # W
    0.17,  # X
    2.11,  # Y
    0.07   # Z
]

def freq(b):
    counts = [0] * 26
    for ch in b.lower():
        if ch >= b'a'[0] and ch <= b'z'[0]:
            counts[ch - ord('a')] += 1
    return [(counts[i] / len(b)) * 100 for i in range(26)]

# should probably use chi-squared
def english_score(b):
    return math.dist(english_freq, freq(b))

candidates = []

for ch in range(128):
    pad = [ch] * len(ctxt)
    dec = xor_bytes(ctxt,pad,len(ctxt))
    score = english_score(dec)
    candidates.append((score, dec))

candidates.sort(key=lambda x: x[0])

for top_candidate in candidates[:5]:
    print(top_candidate[0], top_candidate[1].decode('utf-8'))
