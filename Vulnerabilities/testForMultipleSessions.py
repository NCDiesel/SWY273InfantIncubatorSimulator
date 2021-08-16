# Vulnerability Name - User can create multiple sessions.
# A successful test is one that gets a token multiple times for the
# same user.
import socket

def authenticate(p, pw) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

def logOut(p, token) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"LOGOUT %s" % token, ("127.0.0.1", p))

def executeCommand(p, token) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"%s;GET_TEMP" % token, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

try:
    
    infPort = 23456
    incPort = 23457
    infToken1 = authenticate(infPort, b"!Q#E%T&U8i6y4r2w")
    incToken1 = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")
    infToken2 = authenticate(infPort, b"!Q#E%T&U8i6y4r2w")
    incToken2 = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")
    logOut(infPort, infToken1)  #  Logged out, right?   No tokens should work now
    logOut(incPort, incToken1)  #  ditto
    infRetVal = executeCommand(infPort, infToken2)
    incRetVal = executeCommand(infPort, incToken2)

    # SampleNetworkServer will return "Bad Token" if not still authenticated.
    # If assertion fails (return value is not "bad token") then the test for
    # the vulnerability passes; proving the vulnerability exists
    assert(infRetVal != 'Bad Token' and incRetVal != 'Bad Token')
    print("Test passes - vulnerability exists!")
except Exception as ex:
    print (ex)
    raise
