import random
from Crypto.Util import number
from Crypto.Random import random as prandom
import math

# requires pycrypto

def fermat(n):
    from math import sqrt
    x = long(sqrt(n)) + 1
    y = long(sqrt(x**2 - n))
    while True:
        w = x**2 - n - y**2
        if w == 0:
            break
        if w > 0:
            y += 1
        else:
            x += 1
    return x+y

def encrypt(ptxt, pk, n, M):
    phase1 = pow(ptxt, pk, n)
    return pow(phase1, pk, M)

def decrypt(ctxt, sk, n, M):
    phase1 = pow(ctxt, sk, M)
    return pow(phase1, sk, n)

def sign(ctxt, sk, n, M):
    phase1 = pow(ctxt, sk, M)
    return pow(phase1, sk, n)

def verify(ptxt, ctxt, pk, n, M):
    phase1 = pow(ptxt, pk, M)
    x = pow(phase1, pk, n)
    if x == ctxt:
        return True
    else:
        return False

def testencrypt(pk, sk, mod):
    #msg = "012345678901234567890"
    msg = "0"
    m = number.bytes_to_long(msg)
    ctxt = pow(m, pk, mod)
    if sk != None:

        ptxt = pow(ctxt, sk, mod)
        if ptxt == m:
            return True
        else:
            return False
    return False

def genBasePrimes(psize):
    p = number.getPrime(psize)
    q = number.getPrime(psize)
    while q == p:
        q = number.getPrime(psize)
    a = number.getPrime(psize)
    while a == p or a == q:
        a = number.getPrime(psize)
    b = number.getPrime(psize)
    while b == p or b == q or b == a:
        b = number.getPrime(psize)
    return p, q, a, b

def keygen():
    good = 0
    psize = 8
    while good != 1:
    #for x in range(1):
        # Generate base primes
        p, q, a, b = genBasePrimes(psize)
        C = p % q
        K = ((((p%q) + (q%p)) * p) * a)
        # Generate the mask
        M = p * q * K
        # Generate the modulus
        n = a * b * C
        # Cloak the totient
        s = ((p - 1) * (q - 1) * p)
        t = ((a - 1) * (b - 1) * s * a * q)
        # Generate the public key
        pk = (number.getRandomRange(1, t))
        g = number.GCD(pk, t)
        while g != 1:
            pk = (number.getRandomRange(1, t))
            g = number.GCD(pk, t)
            if g == 1:
                break
        # Generate the secret key
        sk = number.inverse(pk, t)
        if pk != None:
            if testencrypt(pk, sk, n):
                good = 1
    return sk, pk, n, M, t, p, q, a, b, K

message = "A"
msg = number.bytes_to_long(message)
print msg
sk, pk, mod, M, t, p, q, a, b, K =  keygen()

print sk, pk, mod, M
ctxt = encrypt(msg, pk, mod, M)
print ctxt
ptxt = decrypt(ctxt, sk, mod, M)
print ptxt
if ptxt != msg:
    print "Key is broken"
    exit(1)
#ctxt = 573793408
#pk = 118548683247652358416567
#mod = 2021998883
#M = 1903170901

import math
crack = int(math.sqrt(math.sqrt(mod)))
print "crack", crack

primes = []
masks = []
ceiling = 500000
start = 2
inc = 1
for i in range(start, ceiling, inc):
    try:
        if (mod % i) == 0 and i >= 1:
            primes.append(i)
    except ZeroDivisionError as zer:
        pass

for i in range(start, ceiling, inc):
    try:
        if (M % i) == 0 and i >= 1:
            masks.append(i)
    except ZeroDivisionError as zer:
        pass


print primes
print masks
print "Modulus sanity check"
sk2 = number.inverse(pk, mod)
print sk2
print decrypt(ctxt, sk2, mod, M)
print "Modulus - 1 sanity check"
sk2 = number.inverse(pk, (mod - 1))
print sk2
print decrypt(ctxt, sk2, mod, M)
print "mod mod P"
print M % p
print "mod mod Q"
print M % q
print "mod mod A"
print mod % a
print "mod mod B"
print mod % b
print "mod mod T"
print mod % t
print "Solve with P and Q but the question is how to identify P and Q"
ps = ((p - 1) * (q - 1))
sk2 = number.inverse(pk, ps)
print sk2
print decrypt(ctxt, sk2, mod, M)
print primes
print "This should always decrypt"
sk2 = number.inverse(pk, t)
print sk2
print decrypt(ctxt, sk2, mod, M)


#print "Crack from primes"
#if primes[len(primes)-1] == mod:
#    primes.pop()
#p2 = primes.pop()
#q2 = mod /p2
#s = ((p2 - 1) * (q2 - 1))
#sk2 = number.inverse(pk, s)
#tmp = decrypt(ctxt, sk2, mod, M)
#if tmp == msg:
#    print "Cracked", tmp
#    exit(0)
print "Solve with P,Q,A,B but the question is how to identify U"
ps = ((p - 1) * (q - 1) * p * (a - 1) * (b - 1))
sk2 = number.inverse(pk, ps)
print sk2
print decrypt(ctxt, sk2, mod, M)
print primes
print "This should always decrypt"
sk2 = number.inverse(pk, t)
print sk2
print decrypt(ctxt, sk2, mod, M)


print "Crack with P"
sk2 = number.inverse(pk, (p-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    #exit(0)
print "Crack with Q"
sk2 = number.inverse(pk, (q-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    #exit(0)
print "Reddit santiy check"
s = ((mod) * 2) 
#s = (((p - 1) * mod) * ((q - 1) * mod))
sk2 = number.inverse(pk, s)
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    #exit(0)
print "Crack with P"
sk2 = number.inverse(pk, (p-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    #exit(0)
print "Crack with Q"
sk2 = number.inverse(pk, (q-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
print "Crack with A"
sk2 = number.inverse(pk, (a-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    #exit(0)
print "Crack with B"
sk2 = number.inverse(pk, (b-1))
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp

print "Finding A in the modulus with Fermat"
a2 = fermat(mod)
b2 = mod/ a2
print a2, b2
print "Finding cloaked prime in the mask with Fermat"
p2 = fermat(M)
q2 = M/p2
print p2, q2
# this is just a check, I put the known U in there
t = ((p2 - 1) * (q2 - 1) * (a2 - 1) * (b2 - 1))
sk2 = number.inverse(pk, t)
tmp = decrypt(ctxt, sk2, mod, M)
if tmp == msg:
    print "Cracked", tmp
    exit(0)
print primes
print masks
print p, q, K, a, b
