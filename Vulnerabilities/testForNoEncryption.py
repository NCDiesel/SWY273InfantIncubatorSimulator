# Vulnerability Name - Token not encrypted and available by sniffers.
# A successful test is one that gets a token using a hard coded password 
# found in the source code and returns a clear text token.   This would
# prove that vulnerability exists
import socket
import re

def authenticate(p, pw) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

#  No good definitive way to check to see if something is encrypted but
#  should fail to decode and should not end up looking exactly like one
#  of our tokens if developers followed our security requirement to encrypt 
def testEncryption(token) :
    decodedToken = ""
    try:
        decodedToken = token.decode()
    except Exception as e:
        # Somethings amiss with the encoding and therefore probably binary encryption
        # This is not definitive but is a solid indicator
        return False
    #  Decoded.   Depending on how they did it, it might decode(MAC, etc).  So check
    #  to make sure it looks exactly like one of our tokens.
    match = re.search("[a-z,A-Z,0-9]{16}",decodedToken)
    if (match):
        return True

    #  Got here - we are reasonably sure its not a clear text token
    return False

try:
    
    infPort = 23456
    incPort = 23457
    # Expecting to be able to send commandsa unencrypted
    infToken = authenticate(infPort, b"!Q#E%T&U8i6y4r2w")
    incToken = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")


    # SampleNetworkServer isn't encrypting and therefore
    # should send a token we can recognize over the network
    assert(testEncryption(incToken) and testEncryption(infToken))
    print("Test passes - vulnerability exists!")
except Exception as ex:
    print (ex)
    raise