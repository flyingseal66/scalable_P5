# notes on secretsharing module below:
# - sudo -H pip install secret-sharing is needed first
# - secretsharing uses /dev/random by default, which is slow as it
#   gathers entropy from OS events - that's not only slow, but can
#   also frequently block, to get around this edit the source and
#   change it to use /dev/urandom which won't block
#   source to edit for me was:
#   /usr/local/lib/python2.7/dist-packages/secretsharing/entropy.py
import secretsharing as sss
import argparse
import json

import base64
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt
from random import randrange
import jsonpickle
from hashlib import sha256
import base64


# for encryptingfrom crypto.Cipher import AES you need: sudo -H pip install pycrypto
def pxor(pwd,share):

    '''
      XOR a hashed password into a Shamir-share
      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result


def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
        take k passwords, indices of those, and the "public" shares and
        recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]]))

    secret=sss.SecretSharer.recover_secret(shares)
    return secret

# modified from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

unpad = lambda s: s[:-ord(s[len(s) - 1:])]
#password = input("Enter encryption password: ")


def get_private_key(password):
    salt = b"this is a salt"
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

def decrypt(enc, password):
    private_key = password#get_private_key(password)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

# getopt handling
argparser=argparse.ArgumentParser(description='See if we can decrypt the ciphertext yet.')
argparser.add_argument('-p','--passwords',     
                    dest='pwdfile',
                    help='file containing passwords, format: "<hash> <password>"')
argparser.add_argument('-i','--inferno',     
                    dest='infernofile',
                    help='file containing inferno ball as json.')
argparser.add_argument('-d','--delimiter',     
                    dest='delim',
                    help='delimiter between password and hash if not default')
args=argparser.parse_args()

# post opt checks
if args.pwdfile is None:
    print("Must pass the cracked passwords file. Format: <hash>:<password> per line")
    sys.exit(5)

if args.infernofile is None:
    print("Must pass the infernoball json file.")
    sys.exit(5)


delimiter = " "
if args.delim is None:
    delimiter = " "
else:
    demlimiter = args.delim

# read passwords in, however will read hash and password as hash needed for mapping
passwords=[]
print ("Reading in passwords.")
with open(args.pwdfile,"r") as pwdf:
    for line in pwdf:
       # print("Appending password: " + line)
        passwords.append(line.strip())
l=len(passwords)

#read in the cipher json file
with open(args.infernofile, 'r') as f:
            infernofile = json.load(f)

cipher = infernofile['ciphertext']
hashes = infernofile['hashes']
shares = infernofile['shares']
#now need to map our cracked hashes to the hashes from json
#creating a list of tuples in the form (password, index)
tuples = []

for pw in passwords:
    hin = 0
    splitIndex = 1
    for h in hashes:
        if pw != "":
            splitpw = pw.split(delimiter,1)
            splitIndex = 1
            hashstring = splitpw[0]

            if hashstring in h:
                tuples.append((splitpw[splitIndex],hin))
            hin+=1

#finally a loop to run from a to len(tuples) to check for two subsequent equal secrets
plist = []
ilist = []
slist = []
prev_secret = ""
secret = ""
enoughK = False
i=0

for t in tuples:
    plist.append(t[0])
    ilist.append(i)
    slist.append((shares[t[1]].strip()).encode('ascii', 'replace'))

    secret = pwds_shares_to_secret(plist,ilist,slist)
    print"secret = " + secret
    if secret == prev_secret:
        enoughK = True
        print("SUCCESS: K is " + str(len(plist)))
        print("SECRET: " + secret)
    prev_secret = secret
    i+=1

if enoughK:
    result = decrypt(jsonpickle.encode(enc), secret.zfill(32).decode('hex'))

    with open("nextInferno.json","w") as out:
        out.write(result)
    print ("Newest infernoball in nextInferno.json")
else:
    # not enough passwords cracked yet
    print("Keep on cracking, k not reached yet! Currently have " + str(len(plist)) + " cracked.")
