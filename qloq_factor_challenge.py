from Crypto.Util import number

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


# Crack the modulus and find the secret key
p = 191
q = 167
sk = 5605993
pk = 934177
n = 997
ctxt = 976
print "Hand selected primes for P and Q"
print p, q
print "Modulus", n
print "Factoring with Fermat..."
q =fermat(n)
print q
p = n / q
t = ((p - 1) * (q - 1) * p)
sk2 = number.inverse(pk, t)
print "Crack"
print pow(ctxt, sk2, n)
