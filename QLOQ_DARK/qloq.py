from Crypto.Util import number

# requires pycrypto

def encrypt(ptxt, pk, mod, M):
    phase1 = pow(ptxt, pk, M)
    return pow(phase1, pk, mod)

def decrypt(ctxt, sk, mod, M):
    phase1 = pow(ctxt, sk, mod)
    return pow(phase1, sk, M)

# Signing algorithm TBD

def testencrypt(pk, sk, mod):
    msg = "H"
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
    return p, q

def keygen():
    good = 0
    psize = 512
    while good != 1:
        # Generate base primes
        p, q = genBasePrimes(psize)
        # Generate cloaking values
        C = (p % q)
        K = (q % p)
        G = (p % q) + (q)
        H = (p % q) + (p)
        # Cloak the cloaking modulus
        M = ((K * G ) * (C+K)/K) + (((p/q) + (q/p))/(K+C))
        # Generate the modulus
        n = p * q
        # Cloak the totient
        t = ((p - 1) * (q - 1) * p)
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
