# HybridEncryption
This question is on the implementation of hybrid encryption. For convenience, the hybrid encryption technique is provided in Figure 1. Suppose Bob has 1 Megabyte (MB) of sensitive data
and wishes to send encrypted data to Alice using hybrid encryption, which is a combination of AES and RSA encryption. Securely sending the data by the hybrid encryption works as follows:

* Alice: Alice generates the public-key pk = (e, n) and private-key sk = (d, p, q) of the RSA
cryptosystem. Alice gives the public key pk to Bob.

* Bob: Bob has a plaintext message M of size 1 MB. Bob randomly samples an AES key of size 128 bits, $K ← {(0, 1)}^{128}$, and then Bob computes the following:
  * Encrypt the key using the RSA encryption algorithm as $C_{aes} ← K^e$ mod n
  * Encrypt the data M using the AES encryption algorithm, Caes ← AES.Enc(K, M).
Bob sends the RSA encrypted key K and the AES encryption of M, i.e., ($C_{rsa}$, $C_{aes}$), to Alice.

* After receiving ($C_{rsa}$, $C_{aes}$), Alice first decrypts Crsa using the private key sk and
obtains K as $K$ ← ${C_{rsa}}^d$ mod n, and then decrypts Caes using the AES key K to obtain M as M ← AES.Dec(K, $C_{aes}$).
  
  
![0005](https://github.com/srana0/HybridEncryption/assets/93364397/6e34d6dd-7bc5-4f93-ae5c-81cdaec57386)
