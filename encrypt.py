# encryption section
# TODO: improve security by embedding a key encrypted by the password instead of directly decrypting with the password
# unlike the decryption section, there is slightly more hesitation in turning THIS to C code, its not like it will help us alot, except for speed but no other reason.

from zipfile import ZipFile
from hashlib import pbkdf2_hmac, sha256
from secrets import token_bytes
from Crypto.Cipher.AES import new, MODE_CBC
from Crypto.Util.Padding import pad
from os import remove, rmdir, path, walk

files = input("Insert directory name: ")
z = ZipFile('out.tmp', 'w')

def isfile(s):
    return not path.isdir(path.join(files, s))


def writeToZip(files):
    for r, d, f in walk(files):
        for file in f:
            z.write(path.abspath(path.join(r, file)))
        for folder in d:
            writeToZip(path.join(files, folder))

def clearDir(files):
    for r, d, f in walk(files):
        for file in f:
            remove(path.abspath(path.join(r, file)))
        for folder in d:
            clearDir(path.join(files, folder))
            rmdir(path.join(files, folder))

writeToZip(files)

z.close()

clearDir(files)

with open('out.tmp', 'rb') as src:
    with open(path.join(files, 'out.ecd'), 'wb') as f:
        salt = token_bytes(16)
        ekey = pbkdf2_hmac('SHA256', sha256(input("Insert encryption key: ").encode()).digest(), salt, 400000, 32)
        aes_obj = new(ekey, MODE_CBC)
        f.seek(0)
        content = pad(src.read(), 16)
        # FILE FORMAT (might be modified later)
        # ENCRYPTED ZIP FILE (dynamically sized) + SALT USED FOR ENCRYPTION KEY (16 bytes) + IV (16 bytes) + HASH (32 bytes) + SECOND HASH (32 bytes) + IDENTIFIER (6 bytes)
        f.write(aes_obj.encrypt(content) + salt + aes_obj.iv + sha256(content).digest() + sha256(content[:32]).digest() + b'ECD1.1')

remove('out.tmp')
