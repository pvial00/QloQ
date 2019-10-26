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
    psize = 1024
    while good != 1:
        p, q = genBasePrimes(psize)
        l, m = genBasePrimes(psize)
        C = p % q
        K = q % p

        U = l % m
        V = m % l
    
        a = (((((p + K) / (K+1)) * ((q+C) / (C+1)))) * ((p + (K+C+1))) % (K+C) *((q / 2) + 1))
        b = (((((l + K) / (U+1)) * ((m+V) / (V+1)))) * ((l + (U+V+1))) % (U+V) *((m / 2) + 1))
        n = (((b + a) / (C + K + U + V + 1)) + 1) * (l * m)
        t = ((l - 1) * (m - 1))
        pk = (number.getRandomRange(1, t))
        g = number.GCD(pk, t)
        while g != 1:
            pk = (number.getRandomRange(1, t))
            g = number.GCD(pk, t)
            if g == 1:
                break
        sk = number.inverse(pk, t)
        if pk != None:
            if testencrypt(pk, sk, n):
                good = 1
    return sk, pk, n
