#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 13 07:24:34 2019

@author: root
"""

from Crypto.Cipher import DES3
import base64
import os


def encrypt_file(key, in_filename, out_filename=None, chunksize=16 * 1024):
    """ Encrypts a file using DES3 (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, or 24 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """

    if not out_filename:
        out_filename = in_filename + '.enc'

    # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = os.urandom(8)
    print("Initialization Vector-->" + str(iv))

    encryptor = DES3.new(key, DES3.MODE_CBC, iv)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:

            # we have to write the iv in the begining of the file,
            # so the receiver can extract it easily. the iv is not a secret !
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
                chunkd = encryptor.encrypt(chunk)
                chunkd = base64.b64encode(chunkd).decode()
                print("Encoded Cipher Text -->" + chunkd)


def decrypt_file(key, in_filename, out_filename, chunksize=16 * 1024):
    """ Decrypts a file using DES3 (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """

    with open(in_filename, 'rb') as infile:

        iv = infile.read(8)  # iv must be 8 bytes long. it is read from the file
        # because the trasmitter has written the iv in the front of the file. the iv is not a secret !
        decryptor = DES3.new(key, DES3.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break

                plaintext = decryptor.decrypt(chunk)
                outfile.write(plaintext)
                print("Decrypted Value-->" + str(plaintext))
                decipher_text = plaintext.decode("utf-8")
                print('Decoded Deciphered Text--' + decipher_text)


# choose a key of 16 or 24 bytes long
key = b'0123456789abcdef'
print('key-->' + str(key));

encrypt_file(key, 'temp', chunksize=16 * 1024)
print("Done")
#
#
decrypt_file(key, 'temp.enc', 'testdec.txt', chunksize=16 * 1024)
print("Done")

