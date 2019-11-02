# Q'loQ

*** Q'loQ - model X is the recommended cipher with a key length of 3072 bits or P size of 1536

Q'loQ, pronounced cloak is the Klingon High Command's Public Key encryption algorithm adopted from the Human algorithm ZRSA.

Q'loQ leaves P, Q, A and B open to detection but U it cloaks in shroud of darkness.  Like ZRSA It is resistant to Fermat's theorem.  It also introduces the concept of a mask which is a second modulus with which to encrypt with.  The hope is that the second modulus may close to double the encryption strength while keeping the key sizes the same.

Zay HuSh So'Ha - Ready torpedoes, decloak - Star Trek III - The Search for Spock

# Q'loQX Castle

Q'loQX Castle requires DarkCastle and DarkPass.  DarkCastle is used for symmentric file encryption and message authentication.  DarkPass is for password generation.  castle.py then uses Q'loQX to share a 128 character password between two people.  The program is meant to share small files over email.  It is meant to work with 3072 bit QX keys.  Recommended DarkCastle cipher is zanderfish3 which uses a 256 bit key.
