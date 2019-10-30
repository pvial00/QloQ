from qloq import encrypt, decrypt, oaep_encrypt, oaep_decrypt
from qapla import crypt
import sys
from os import urandom
from Crypto.Util import number

keylen = 32
noncelen = 16
Klen = 128
Ylen = 128
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
    X, Y = oaep_encrypt(KP, M)
    K = encrypt(X, key, mod, M)
    y = number.long_to_bytes(Y)
    x = number.long_to_bytes(K)
    ctxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(x+y+nonce+ctxt)
    f.close()
elif mode == "d":
    f = open(infile, "r")
    data = f.read()
    f.close()
    X = data[:Klen]
    Y = data[Klen:Ylen+Klen]
    nonce = data[Klen+Ylen:Klen+Ylen+noncelen]
    msg = data[Klen+Ylen+noncelen:len(data)]
    K = decrypt(number.bytes_to_long(X), key, mod, M)
    keyP = number.long_to_bytes(oaep_decrypt(number.long_to_bytes(K), Y))
    ptxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(ptxt)
    f.close()
