# Vulnerability Name - Hard coded password.  A successful
# test is one that gets a token using a hard coded password 
# found in the source code.   This would prove that password
# exists.    This test should fail once we fix the vulnerability
import socket
import re

def authenticate(p, pw) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

try:
    
    infPort = 23456
    incPort = 23457
    infToken = authenticate(infPort, b"!Q#E%T&U8i6y4r2w")
    incToken = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")

    # SampleNetworkServer has authentication so the testcase will exit at this assertion.
    incMatch = re.search("[a-z,A-Z,0-9]{16}",incToken.decode())
    infMatch = re.search("[a-z,A-Z,0-9]{16}",infToken.decode())
    assert(infToken != None and incToken != None and incMatch != None and infMatch != None)
    print("Test passes - vulnerability exists!")
except Exception as ex:
    print (ex)
    raise
