x = bytes.fromhex("1c0111001f010100061a024b53535009181c")
y = bytes.fromhex("686974207468652062756c6c277320657965")

def xor_bytes(x,y,l):
    return bytes([x[i] ^ y[i] for i in range(l)])

z = xor_bytes(x,y,len(x))

print(bytes.hex(z), z.decode('utf-8'))
