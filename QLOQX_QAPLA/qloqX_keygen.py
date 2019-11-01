from qloqX import keygen

sk, pk, n, M = keygen()
pkfile = "qloq.pk"
skfile = "qloq.sk"
pkdata = "Public key:" + str(pk) + "\n" + "Modulus:" + str(n) + "\n" + "Mask:" + str(M)
skdata = "Secret key:" + str(sk) + "\n" + "Modulus:" + str(n) + "\n" + "Mask:" + str(M)
f = open(pkfile, "w")
f.write(pkdata)
f.close()
f = open(skfile, "w")
f.write(skdata)
f.close()
