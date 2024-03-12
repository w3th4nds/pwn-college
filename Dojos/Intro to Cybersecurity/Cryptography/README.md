<div align="center">
    <h1> Cryptography</h1> 
</div>

### Level 1 - Decode base64-encoded data

```bash
In this challenge you will decode base64 data.
Despite base64 data appearing "mangled", it is not an encryption scheme.
It is an encoding, much like base2, base10, base16, and ascii.
It is a popular way of encoding raw bytes.


flag (b64): cHduLmNvbGxlZ2V7a242dFZaT1FoUEtOT3VfZEh2WDZubUJGNTFuLjAxTTNNek1zTUROM0l6V30K
```

```bash
$ echo cHduLmNvbGxlZ2V7a242dFZaT1FoUEtOT3VfZEh2WDZubUJGNTFuLjAxTTNNek1zTUROM0l6V30K | base64 -d
```

### Level 2 - Decrypt a secret encrypted with a one-time pad, assuming a securely transferred key

```bash
In this challenge you will decrypt a secret encrypted with a one-time pad.
Although simple, this is the most secure encryption mechanism, if you could just securely transfer the key.


key (b64): 0zagmSTbgd0QUEThAnpuQVk1TYi6Gi2biazdky4Ucu6JomlNfORhi+Ansvx7HiaBxlHI8xpotLW1
secret ciphertext (b64): o0HOt0e07bF1NyGaMlcJMRhgK+fMdGzt2sSJ1R1RRr/zkD83KIwnpdBh/M82ZGvyixWGwFMS48i/
```

```python
import base64

# Convert base64 encoded key and ciphertext to bytes
key_b64 = "F10YJvTat/1WrDIFZV5lJGSUkVHWQwC7j465WXplv6j7nj+LHPghHC1v3qTyAvh8h42Rxujrgn1F"
secret_b64 = "Zyp2CJe125Ezy1d+VXMCVCXB9z6gLUHN3ObtH0kgi/mBrGnxSJBnMh0pkJe/eLUPysnf9aGR1QBP"

key = base64.b64decode(key_b64)
secret = base64.b64decode(secret_b64)

# Perform XOR operation between key and ciphertext
plaintext = bytes([a ^ b for a, b in zip(key, secret)])

# Print the decrypted plaintext
print("Decrypted plaintext:", plaintext.decode())
```

### Level 3 - Decrypt a secret encrypted with a one-time pad, where the key is reused for arbitrary data

```bash
In this challenge you will decrypt a secret encrypted with a one-time pad.
You can encrypt arbitrary data, with the key being reused each time.


secret ciphertext (b64): 1PDFg29e8THfdGJtFnTzR0Xv+PdUMn0/B2EOGLm79ex9ZchB3b3toyMl433LI+cl+tkqRgQMJJxC
plaintext (b64):
```

```python

```
