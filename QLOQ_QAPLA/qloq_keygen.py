from qloq import keygen

sk, pk, n, M = keygen()
print "Secret key:", sk
print "Public Key:", pk
print "Modulus:", n
print "Mask:", M
