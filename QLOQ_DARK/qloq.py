from Crypto.Util import number

# requires pycrypto

def encrypt(ptxt, pk, n, M):
    phase1 = pow(ptxt, pk, M)
    return pow(phase1, pk, n)

def decrypt(ctxt, sk, n, M):
    phase1 = pow(ctxt, sk, n)
    return pow(phase1, sk, M)

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

def testencrypt(pk, sk, n):
    msg = "H"
    m = number.bytes_to_long(msg)
    ctxt = pow(m, pk, n)
    if sk != None:

        ptxt = pow(ctxt, sk, n)
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
    psize = 1024
    while good != 1:
        # Generate base primes
        p, q, a, b = genBasePrimes(psize)
        # Generate cloaking values
        C = (p % q)
        K = (q % p)
        G = (p % q) + (q)
        H = (p % q) + (p)
        # Generate the cloaking mask
        M = ((K * G) * (C+K)/K) + (((p/q) + (q/p))/(K+C))
        # Generate the modulus
        n = a * b
        # Cloak the totient
        t = ((p - 1) * (q - 1) * p * (a - 1) * (b - 1))
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
            if testencrypt(pk, sk, M):
                good = 1
    return sk, pk, n, M
