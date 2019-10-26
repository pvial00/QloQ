import random
from Crypto.Util import number
import math

# requires pycrypto

def encrypt(ptxt, pk, mod):
    return pow(ptxt, pk, mod)

def decrypt(ctxt, sk, mod):
    return pow(ctxt, sk, mod)

def sign(ctxt, sk, mod):
    return pow(ctxt, sk, mod)

def verify(ptxt, ctxt, pk, mod, s):
    x = pow(ptxt, pk, mod)
    if x == ctxt:
        return True
    else:
        return False

def testencrypt(pk, sk, mod):
    msg = "012345678901234567890"
    msg = "H"
    m = number.bytes_to_long(msg)
    ctxt = encrypt(m, pk, mod)
    if sk != None:

        ptxt = decrypt(ctxt, sk, mod)
        if ptxt == m:
            return True
        else:
            return False
    return False

#def genBasePrimes(psize):
#    p = number.getPrime(psize)
#    q = number.getPrime(psize)
#    while q == p:
#        q = number.getPrime(psize)
#    return p, q

def genBasePrimes(psize):
    p = number.getPrime(psize)
    q = number.getPrime(psize)
    while q == p:
        q = number.getPrime(psize)
    return p, q
        


def keygen():
    good = 0
    psize = 512
    while good != 1:
        p, q = genBasePrimes(psize)
        a = p * q
        C = p % q
        K = q % p
        G = (q % p) % p
        H = (p % q) % q
        J = (C+K+G+H) + 1

        t = ((p - 1) * (q - 1))
        n = (((((p + G) / (G+1)) * ((q+H) / (H+1)))) * ((p + (G+H+1))) % (G+H) *((q / 2) + 1))  / (J-p-q)
        s = (t % ((p - 1) * (q - 1) * G * H * K * C))
        pk = (number.getRandomRange(1, s))
        g = number.GCD(pk, s)
        while g != 1:
            pk = (number.getRandomRange(1, s))
            g = number.GCD(pk, s)
            if g == 1:
                break
        sk = number.inverse(pk, s)
        if pk != None:
            if testencrypt(pk, sk, n):
                good = 1
    return sk, pk, n
