import os,sys,argparse,tempfile,shutil
import secretsharing as sss
import jsonpickle 
from hashlib import sha256
from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt
from random import randrange
import base64
from Crypto.Cipher import AES
from Crypto import Random

#  Stephen's
def encryptNew(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


# Ours
def decryptNew(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

# Original's
def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decrypt(enc, password):
	private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


# "Ciphetext may have to be in UTF-8" - Overheard in postgrad lab
decrypt("./cipherText.txt", "secret")