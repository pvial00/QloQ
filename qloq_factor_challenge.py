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
p = 40237
q = 42923
sk = 295174267
pk = 477071467
n = 80474
print "Hand selected primes for P and Q"
print p, q
print "Modulus", n
print "Factoring with Fermat..."
print fermat(n)
