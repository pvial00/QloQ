import random
from Crypto.Util import number
from Crypto.Random import random as prandom
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
    return Falses

def genBasePrimes(psize):
    p = number.getPrime(psize)
    q = number.getPrime(psize)
    while q == p:
        q = number.getPrime(psize)
    return p, q

def keygen():
    good = 0
    psize = 8
    o = 2
    while good != 1:
        C = number.getPrime(psize)
        p, q = genBasePrimes(psize)
        rm1 = p % 2
        rm2 = q % 2
        n = ((p /2) * (q / 2)) + rm1 + rm2
        t = ((p - 1) * (q - 1))
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
    return sk, pk, n, p, q, t

#msg = "A"
#m = number.bytes_to_long(msg)
m = 12
print m
sk, pk, mod, p, q, t =  keygen()
print sk, pk, mod
ctxt = encrypt(m, pk, mod)
print ctxt
ptxt = decrypt(ctxt, sk, mod)
print ptxt
if ptxt != m:
    print "Key is broken"
    exit(1)

import math
crack = int(math.sqrt(math.sqrt(mod)))
print "crack", crack

primes = []
ceiling = 500000
start = 1
inc = 1
for i in range(start, ceiling, inc):
#for i in range(crack, 6500, 1):
    #print i, mod % i
    #if i == t:
    #    print mod & i
    #if i == s:
    #    print mod & i
    #if i == l:
    #    print mod & i
    try:
        if (mod % i) == 0 and i >= 1:
            primes.append(i)
    except ZeroDivisionError as zer:
        pass

print primes
print "Modulus sanity check"
sk2 = number.inverse(pk, mod)
print sk2
print decrypt(ctxt, sk2, mod)
print "Modulus - 1 sanity check"
sk2 = number.inverse(pk, (mod - 1))
print sk2
print decrypt(ctxt, sk2, mod)
print "mod mod P"
print mod % p
print "mod mod Q"
print mod % q
print "mod mod T"
print mod % t
print "Solve with P and Q but the question is how to identify P and Q"
ps = ((p - 1) * (q - 1))
sk2 = number.inverse(pk, ps)
print sk2
print decrypt(ctxt, sk2, mod)
print "p, q"
print p, q
print primes

print "Crack"
s = (p - 1)
sk2 = number.inverse(pk, s)
print decrypt(ctxt, sk2, mod)
