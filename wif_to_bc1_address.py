#!/usr/bin/python 
"""
This script convert private key into public key
usage:
python private_to_public.py private_key
"""

import sys
import hashlib

def bech32_polymod(values):
  GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  chk = 1
  for v in values:
    b = (chk >> 25)
    chk = (chk & 0x1ffffff) << 5 ^ v
    for i in range(5):
      chk ^= GEN[i] if ((b >> i) & 1) else 0
  return chk

def bech32_hrp_expand(s):
  return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_verify_checksum(hrp, data):
  return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
  values = bech32_hrp_expand(hrp) + data
  polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
  return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

class compressed_Point(object):
    def __init__(self, _x, _y, _order = None): self.x, self.y, self.order = _x, _y, _order

    def calc(self, top, bottom, other_x):
        l = (top * inverse_mod(bottom)) % p
        x3 = (l * l - self.x - other_x) % p
        return compressed_Point(x3, (l * (self.x - x3) - self.y) % p)

    def double(self):
        if self == INFINITY: return INFINITY
        return self.calc(3 * self.x * self.x, 2 * self.y, self.x)

    def __add__(self, other):
        if other == INFINITY: return self
        if self == INFINITY: return other
        if self.x == other.x:
            if (self.y + other.y) % p == 0: return INFINITY
            return self.double()
        return self.calc(other.y - self.y, other.x - self.x, other.x)

    def __mul__(self, e):
        if self.order: e %= self.order
        if e == 0 or self == INFINITY: return INFINITY
        result, q = INFINITY, self
        while e:
            if e&1: result += q
            e, q = e >> 1, q.double()
        return result

    def __str__(self):
        if self == INFINITY: return "infinity"
        if self.y & 1:
            return "03%x" % (self.x)
        else:
            return "02%x" % (self.x)

def inverse_mod(a):
    if a < 0 or a >= p: a = a % p
    c, d, uc, vc, ud, vd = a, p, 1, 0, 0, 1
    while c:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
    if ud > 0: return ud
    return ud + p

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
INFINITY = compressed_Point(None, None) # secp256k1
g = compressed_Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L)

# for compatibility with following code...
class SHA256:
    new = hashlib.sha256

if str != bytes:
    # Python 3.x
    def ord(c):
        return c
    def chr(n):
        return bytes( (n,) )

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)
b58chars = __b58chars

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        if isinstance(c, str):
            c = ord(c)
        long_value += (256**i) * c

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0:
            nPad += 1
        else:
            break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length = None):
    """ decode v into a string of len bytes
    """
    long_value = 0
    for i, c in enumerate(v[::-1]):
        pos = __b58chars.find(c)
        assert pos != -1
        long_value += pos * (__b58base**i)

    result = bytes()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
            continue
        break

    result = bytes(nPad) + result
    if length is not None and len(result) != length:
        return None

    return result

def main():
    wif = sys.argv[1]
    res = b58decode(wif)
    decoded = str(res.encode('hex'))
    pri = decoded[4:-10]  

    #read hex string
    private_key = int(pri,16)
    lo = g * private_key

    #sha 256
    pu_sha1 = hashlib.sha256()
    if not len(str(lo)) % 2 == 0:
        return result
    pu_sha1.update(str(lo).decode('hex'))
    output = pu_sha1.digest().encode('hex')

    #rimped 160
    h = hashlib.new('ripemd160')
    h.update(output.decode('hex'))
    output = h.digest().encode('hex')
    
    #convert 8bit to 5bit
    fi = output
    hex8 = int(fi,16)

    bit8 = bin(hex8)
    no_header = bit8[2:]

    if not len(no_header) % 8 == 0:
        for i in range(0,8 - len(no_header) % 8):
            no_header = "0" + no_header

    if not len(no_header) == 160:
        print "somethig wrong"
    
    full_hex = ""
    for i in range(0,len(no_header),5):
        one = no_header[i:i+5]
        inval = int(one,2)
        one_hex = hex(inval)[2:]
        if len(one_hex) == 1:
            one_hex = "0"+one_hex
        full_hex = full_hex + one_hex

    ve = "00" + full_hex

    #now calculate checksum
    hrp = "bc"
    data = []
    for i in range(0,len(ve),2):
        data.append(int(ve[i:i+2],16))

    checksum_array = bech32_create_checksum(hrp, data)

    checksum = ""
    for x in checksum_array:
        he =  hex(x)[2:]
        if len(he) == 1:
            he = "0" + he
        checksum = checksum + he

    fin = ve + checksum

    bech32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

    address = ""
    for i in range(0,len(fin),2):
        one = int(fin[i:i+2],16)
        temp = bech32[one]
        address = address + temp

    fin_address = "bc1" + address
    print fin_address


if __name__ == '__main__':
    main()
