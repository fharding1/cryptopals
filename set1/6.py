import itertools
import base64
import math

def xor_bytes(x,y,l):
    return bytes([x[i] ^ y[i] for i in range(l)])

def hamming_distance(x,y):
    return sum([(a ^ b).bit_count() for (a,b) in itertools.zip_longest(x,y,fillvalue=0)])

def keysize_score(x, size):
    padded_x = x + bytes([0] * (- len(x) % size))

    distances = []
    for chunk_idx in range(int(len(padded_x)/size)-1):
        first = padded_x[chunk_idx*size:(chunk_idx+1)*size]
        second = padded_x[(chunk_idx+1)*size:(chunk_idx+2)*size]
        distances.append(hamming_distance(first,second))

    return (sum(distances)/len(distances))/size

def chunk_list(arr, size):
    chunks = []
    for i in range(0, len(arr), size):
        chunks.append(arr[i:i + size])
    return chunks

def transpose(x,size):
    padded_x = x + bytes([0] * (- len(x) % size))
    rows = chunk_list(padded_x, size)
    return [ bytes([row[i] for row in rows]) for i in range(size) ]

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
    return sum([((x-y)**2)/(x+y) for (x,y) in zip(english_freq, freq(b))])

def ceil_div(n, d):
    return int(math.ceil(float(n) / float(d)))

def enc_repeating_key_xor(ptxt, key):
    pad = key
    if len(key) < len(ptxt):
        pad = key * ceil_div(len(ptxt), len(key))

    return xor_bytes(ptxt, pad, len(ptxt))

with open("input6", "r") as file:
    contents = file.read().strip()
    ctxt = base64.b64decode(contents)

    scores = []
    for size in range(2,40):
        score = keysize_score(ctxt,size)
        scores.append((score,size))

    scores.sort(key=lambda x: x[0])

    key_sizes = [score[1] for score in scores[:3]]

    for size in key_sizes:
        key = []
        blocks = transpose(ctxt,size)
        for block in blocks:
            candidates = []

            for ch in range(128):
                pad = [ch] * len(block)
                dec = xor_bytes(block,pad,len(block))
                score = english_score(dec)
                candidates.append((score, ch))

            candidates.sort(key=lambda x: x[0])
            key.append(candidates[0][1])
        print(size)
        print(bytes(key).decode('utf-8'))
        print(enc_repeating_key_xor(bytes(ctxt), bytes(key)).decode('utf-8'))
