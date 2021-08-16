# Vulnerability Name - Multiple sessions  A successful
# test is one that gets a token using a hard coded password 
# found only in the environment.   The server handles this
# likewise.  Do this twice.
#
#  Then log out with the first session and see if the
#  second one still works
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
def logOut(p, pw, s) :
    data = b"LOGOUT"
    cipher_aes = AES.new(pw, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    encMsg = b''.join([cipher_aes.nonce, tag, ciphertext])
    s.sendto(encMsg, ("127.0.0.1", p))
    #  Server send no confirmation or message on return

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

def executeCommand(p, pw, token, s) :
    data = b"%s;GET_TEMP" % token.encode()
    cipher_aes = AES.new(pw, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    encMsg = b''.join([cipher_aes.nonce, tag, ciphertext])
    s.sendto(encMsg, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

try:
    #    Authentication attempts are now tracked by IP and port....
    s1 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    infPort = 23456
    incPort = 23457
    secret = os.environ['SECRET'].encode('UTF-8')
    encryptedInfToken = authenticate(infPort, secret, s1)
    encryptedIncToken = authenticate(incPort, secret, s2)
    encryptedInfToken2 = authenticate(infPort, secret, s1)
    encryptedIncToken2= authenticate(incPort, secret, s2)
    # SampleNetworkServer sending encrypted tokens now.  Check
    # that they are valid
    infToken = decryptData(encryptedInfToken2, secret)
    incToken = decryptData(encryptedIncToken2, secret)

    logOut(infPort, secret, s1)
    logOut(incPort, secret, s2)

    infRetVal = executeCommand(infPort, secret, infToken, s1)
    incRetVal = executeCommand(incPort, secret, incToken, s2)

    # SampleNetworkServer will return "Bad Token" if not still authenticated.
    # If assertion fails (return value is not "bad token") then the test for
    # the vulnerability passes; proving the vulnerability exists
    assert(infRetVal == b'Invalid Command' and incRetVal == b'Invalid Command')
    print("Test passes - vulnerability fixed!!")
except Exception as ex:
    print (ex)
    raise
