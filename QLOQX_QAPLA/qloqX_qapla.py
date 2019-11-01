from qloqX import encrypt, decrypt, oaep_encrypt, oaep_decrypt, sign, verify
from qapla import crypt
import sys
from os import urandom
from Crypto.Util import number

# usage:
# python qloqX_qaplay.py e <input file> <output file> <public key> <modulus> <mask> <secret key>
# python qloqX_qaplay.py d <input file> <output file> <secret key> <modulus> <mask> <public key>
keylen = 32
noncelen = 16
Klen = 192
Ylen = 192
Slen = 192
mode = sys.argv[1]
infile = sys.argv[2]
outfile = sys.argv[3]
key = long(sys.argv[4])
mod = long(sys.argv[5])
M = long(sys.argv[6])
key2 = long(sys.argv[7])

if mode == "e":
    f = open(infile, "r")
    msg = f.read()
    f.close()
    keyP = urandom(keylen)
    nonce = urandom(noncelen)
    KP = number.bytes_to_long(keyP)
    print KP
    X, Y = oaep_encrypt(KP, M)
    K = encrypt(X, key, mod, M)
    S = sign(K, key2, mod, M)
    y = number.long_to_bytes(Y)
    x = number.long_to_bytes(K)
    s = number.long_to_bytes(S)
    ctxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(s+x+y+nonce+ctxt)
    f.close()
elif mode == "d":
    f = open(infile, "r")
    data = f.read()
    f.close()
    S = data[:Slen]
    X = data[Slen:Slen+Klen]
    x = number.bytes_to_long(X)
    Y = data[Slen+Klen:Slen+Ylen+Klen]
    nonce = data[Slen+Klen+Ylen:Slen+Klen+Ylen+noncelen]
    msg = data[Klen+Ylen+noncelen:len(data)]
    K = decrypt(x, key, mod, M)
    KP = oaep_decrypt(number.long_to_bytes(K), Y)
    print KP
    keyP = number.long_to_bytes(KP)
    if verify(KP, x, key2, mod, M) == False:
        print "Signing verification failed.  Message is not authentic."
        exit(1)
    ptxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(ptxt)
    f.close()
