import math

ptxt = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

def xor_bytes(x,y,l):
    return bytes([x[i] ^ y[i] for i in range(l)])

def ceil_div(n, d):
    return int(math.ceil(float(n) / float(d)))

def enc_repeating_key_xor(ptxt, key):
    pad = key
    if len(key) < len(ptxt):
        pad = key * ceil_div(len(ptxt), len(key))

    return xor_bytes(ptxt, pad, len(ptxt))

print(enc_repeating_key_xor(ptxt, b"ICE").hex())
