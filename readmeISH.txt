I used eclipse to make this


So I created 3 very important methods.

1. A method to generate two RSA public and private keys
2. A method to encrypt either of the keys
3. A method to decrypt either of the keys\


The idea is that if it is Client-Server.
The client and server have the RSA methods and each send each other their
Public keys to encrypt keys so that they'll be able to decrypt.

Obviously these methods are important for getting the client server encryption to
use public key to encrypt the shared key.