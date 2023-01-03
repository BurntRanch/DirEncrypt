# DirEncrypt
A Small and Simple Python Encrypt/Decrypt Folder tool

# Dependecies
requires pycryptodome and pycryptodomex. install it by the command
`pip install pycryptodome pycryptodomex`

# How To Use
the usage it's very simple.

```python
python3 encrypt.py #for encrypt the folder content
python3 decrypt.py #for decrypting the file .ecd (default out.ecd)
```
just don't forget the password and you'll be alright ;)

# File format

This file is constructed by generating a ZIP file (lets call it 'zip') with the absolute path of every file (might change for security), then it gets encrypted with a password-derived key, the password-derivation algorithm is PBKDF2, the salt for the algorithm is then stored in the file, lets call it 'salt'

The file is hashed 3 times, once full hash, second time is the first 32 bytes, third time is the last 32 bytes, this is to avoid hash collisions, lets call each hash 'hashx', (e.g. hash1, hash2, hash3)

then the final file is constructed in this way:
zip + salt + hash1 + hash2 + hash3 + identifier

what is the identifier? its to identify the format of the file, its usually ECD1.x.

If you were to store the headers as a C struct:
```c
struct {
  uint8_t salt[16]; // not hex, dont treat it as a regular char array
  uint8_t hash1[32];
  uint8_t hash2[32];
  uint8_t hash3[32];
  uint8_t identifier[6]; // is a char array, feel free to print it.
} ecd_headers;
```
