# Vulnerability Name - No encryption.  A successful
# test is one that gets a token using a hard coded password 
# found only in the environment and then decrypts the data with it.
# The server handles this likewise.  If you get a token the data was
# properly encrypted
#
#  Real World:   Should be using some sort of password manager or
#  commercial product like Hashicorp's vault
import socket
import re
import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def authenticate(p, pw, s) :
    data = b"AUTH"
    cipher_aes = AES.new(pw, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    encMsg = b''.join([cipher_aes.nonce, tag, ciphertext])
    s.sendto(encMsg, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

def decryptData(data, pw) :
    try:
        nonce, tag, ciphertext = \
            [ data[0:16],
            data[ 16:32],
            data[32:]
            ]
        AEScipher = AES.new(pw, AES.MODE_EAX, nonce)
        msg = AEScipher.decrypt_and_verify(ciphertext, tag).decode()
        return msg
    except Exception as e:
        errMsg = "WTH?: {0}".format(e).encode()
        print(errMsg)
try:
    s1 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    infPort = 23456
    incPort = 23457
    secret = os.environ['SECRET'].encode('UTF-8')
    encryptedInfToken = authenticate(infPort, secret, s1)
    encryptedIncToken = authenticate(incPort, secret, s2)

    # SampleNetworkServer sending encrypted tokens now.  Check
    # that they are valid
    infToken = decryptData(encryptedInfToken, secret)
    incToken = decryptData(encryptedIncToken, secret)
    incMatch = re.search("[a-z,A-Z,0-9]{16}",incToken)
    infMatch = re.search("[a-z,A-Z,0-9]{16}",infToken)
    assert(incMatch != None and infMatch != None)
    print("Test passes - vulnerability fixed!")

except Exception as ex:
    print (ex)
    raise
