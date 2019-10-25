def factor(n):
    # Seach for the totient
    guesses = []
    ceiling = n * 5
    x = n
    while True:
        if (n % x) == n and x != n:
            guesses.append(x)
            x += 1
        else:
            x += 1
        if x == ceiling:
            break
        if x == 35520:
            print "Hey, we passed it! Break!"
            exit(0)
            break
    return guesses


# Crack the modulus and find the secret key
p = 157
q = 181
sk = 24533
pk = 1277
n = 8882
t = 35520
ctxt = 4816
print "Hand selected primes for P and Q"
print p, q
print "Modulus", n
print "Factoring..."
guesses = factor(n)
print "Secret key guess, should be 24533"
print guesses
