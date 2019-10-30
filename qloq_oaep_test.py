from qloq import oaep_encrypt, oaep_decrypt, encrypt, decrypt, keygen
from Crypto.Util import number

m = 1234
sk, pk, n, M = keygen()

X, Y = oaep_encrypt(m, M)
ctxt = encrypt(X, pk, n, M)

X = decrypt(ctxt, sk, n, M)
#print X, Y
ptxt = oaep_decrypt(number.long_to_bytes(X), number.long_to_bytes(Y))
print ptxt
