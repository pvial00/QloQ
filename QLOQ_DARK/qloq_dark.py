from qloq import encrypt
from qloq import decrypt
from dark import crypt
import sys
from os import urandom
from Crypto.Util import number

# Made to work with keys generated from 512 bit primes
keylen = 32
noncelen = 16
Klen = 128
mode = sys.argv[1]
infile = sys.argv[2]
outfile = sys.argv[3]
key = long(sys.argv[4])
mod = long(sys.argv[5])
M = long(sys.argv[6])

if mode == "e":
    f = open(infile, "r")
    msg = f.read()
    f.close()
    keyP = urandom(keylen)
    nonce = urandom(noncelen)
    KP = number.bytes_to_long(keyP)
    K = number.long_to_bytes(encrypt(number.bytes_to_long(keyP), key, mod, M))
    print len(K)
    ctxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(K+nonce+ctxt)
    f.close()
elif mode == "d":
    f = open(infile, "r")
    data = f.read()
    f.close()
    K = data[:Klen]
    nonce = data[Klen:Klen+noncelen]
    msg = data[noncelen+Klen:len(data) - 1]
    KP = decrypt(number.bytes_to_long(K), key, mod)
    keyP = number.long_to_bytes(decrypt(number.bytes_to_long(K), key, mod, M))
    ptxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(ptxt)
    f.close()
