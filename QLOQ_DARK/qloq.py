from Crypto.Util import number

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
        C = (p % q) + p
        K = (q % p) + q
        G = (p % q) +  (p/q) 
        H = (q % p) + (((q/p)))
        # Cloak the modulus
        n = (((p * q) / (G+H)) * ((K/G) + (G/H)) + (p/q)) + (q/p)
        # Reflect the totient
        t = ((p - 1) * (q - 1)  * p * (G - 1))
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
    return sk, pk, n
