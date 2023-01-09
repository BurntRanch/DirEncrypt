# Decryption section
# TODO: design the decoding engine in C for performance, and because we can just take the headers, turn it to a struct (easier than you might think), and read it.

from zipfile import ZipFile
from hashlib import pbkdf2_hmac, sha256
from os import stat, remove, path
from Crypto.Cipher.AES import new, MODE_CBC
from Crypto.Util.Padding import unpad

ecd_file = input("Insert .ecd (EnCrypted Directory) file: ")

content = b''


# FILE FORMAT (might be modified later)
# ENCRYPTED ZIP FILE (dynamically sized) + SALT USED FOR ENCRYPTION KEY (16 bytes) + IV (16 bytes) + HASH (32 bytes) + IDENTIFIER (6 bytes)

with open(ecd_file, 'rb') as file:
    while True:
        file.seek(stat(ecd_file).st_size - 6)
        format = file.read(6)
        if format != b'ECD1.2':
            if format.startswith(b'ECD'):
                print('Loading Legacy Pack..')
                try:
                    exec(f'from {format.decode().replace(".", "_")} import process')
                    content = process(ecd_file, file)
                    if content == False:
                        continue
                except ImportError:
                    print(f'You do not have a Legacy Pack for format version {format.decode()}, Please download it from https://github.com/BurntRanch/DirEncrypt/releases/tag/{format.decode()}-LP.')
            else:
                print('Unknown format!')
        else:
            length = 134
            # read the headers at the end
            file.seek(stat(ecd_file).st_size - length)
            # get the salt (16 bytes read, we are now offsetted to the IV)
            ekey = pbkdf2_hmac('SHA256', sha256(input("Insert encryption key: ").encode()).digest(), file.read(16), 400000, 32)
            # get the IV (we are now offsetted to the hash)
            aes_obj = new(ekey, MODE_CBC, file.read(16))
            # reset the offset
            file.seek(0)
            # read the content (content len = file length - header overhead size (16 + 16 + 32 + 6 = 70))
            content = aes_obj.decrypt(file.read(stat(ecd_file).st_size - length))
            # seek to the last 32 bytes of the header (hash)
            file.seek(stat(ecd_file).st_size - (length - 32))
            # verify hash with content digest for password verification
            if sha256(content).digest() != file.read(32) or sha256(content[32:]).digest() != file.read(32) or sha256(content[:32]).digest() != file.read(32):
                print("Incorrect password!")
                continue
        break

if content:
    remove(ecd_file)
    
    with open('_out.tmp', 'wb+') as file:
        file.write(unpad(content, 16))

    with ZipFile('_out.tmp') as z:
        z.extractall(input('Where would you like to extract this file? [For security, please do not type "/" if you do not trust this archive] '))

    remove('_out.tmp')
