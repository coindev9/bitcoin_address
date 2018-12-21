#!/usr/bin/python 
"""
This script convert private key into wallet format
usage:
python private_to_wallet_format.py private_key
"""

import sys
import hashlib


class SHA256:
    new = hashlib.sha256

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
        if c == 0: nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def main():
    #private_key = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    #private_key = 11253563012059685825953619222107823549092147699031672238385790369351542642469
    
    #read hex string
    add_80 = "80"+ sys.argv[1]
    private_key = int(add_80,16)

    #sha 256
    pu_sha1 = hashlib.sha256()
    #if not len(str(lo)) % 2 == 0:
    #    return result
    pu_sha1.update(str(add_80).decode('hex'))
    output = pu_sha1.digest().encode('hex')

    #sha 256
    pu_sha2 = hashlib.sha256()
    pu_sha2.update(output.decode('hex'))
    output = pu_sha2.digest().encode('hex')

    #add checksum
    che = output[0:8]
    fi = add_80+che

    public_key_wallet_format = b58encode(fi.decode('hex'))
    print public_key_wallet_format
    #answer = 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
    #5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V


if __name__ == '__main__':
    main()
