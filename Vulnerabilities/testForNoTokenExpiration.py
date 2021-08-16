# Vulnerability Name - Token never expires.
# A successful test is one that gets a tokens and then can execute commands
# after the token expiration period.  Currently 15 mins
#
# If this test passes - and a token is still good after 15 minutes - it means
# the developers did not complete our requirement to securely rotate tokens
#
import socket
import time

def authenticate(p, pw) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

def executeCommand(p, token) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"%s;GET_TEMP" % token, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

try:
    
    infPort = 23456
    incPort = 23457
    infToken = authenticate(infPort, b"!Q#E%T&U8i6y4r2w")
    incToken = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")
    # Currently testing with a short interval to speed testing
    # This interval should be part of the application config
    # and should contain a "dev" value that is short (to speed up
    # testing) and a "production" value that matches requirements
    time.sleep(1*60)
    #  After idle for "X" mins, the token should be invalid
    infRetVal = executeCommand(infPort, infToken)
    incRetVal = executeCommand(infPort, incToken)

    # SampleNetworkServer will return "Bad Token" if not still authenticated.
    # If assertion fails (return value is not "bad token") then the test for
    # the vulnerability passes; proving the vulnerability exists
    assert(infRetVal != 'Bad Token' and incRetVal != 'Bad Token')
    print("Test passes - vulnerability exists!")
except Exception as ex:
    print (ex)
    raise
