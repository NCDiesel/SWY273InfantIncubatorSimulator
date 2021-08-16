import threading
import datetime
import traceback
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import infinc
import time
import math
import socket
import fcntl
import os
import errno
import random
import string

class SmartNetworkThermometer (threading.Thread) :
    open_cmds = ["AUTH", "LOGOUT"]
    prot_cmds = ["SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP"]

    def __init__ (self, source, updatePeriod, port) :
        threading.Thread.__init__(self, daemon = True) 
        #set daemon to be true, so it doesn't block program from exiting
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()
        self.tokens = []
        self.sessions = {}

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"

    def setSource(self, source) :
        self.source = source

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod 

    def setDegreeUnit(self, s) :
        self.deg = s
        if self.deg not in ["F", "K", "C"] :
            self.deg = "K"

    def updateTemperature(self) :
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self) :
        if self.deg == "C" :
            return self.curTemperature - 273
        if self.deg == "F" :
            return (self.curTemperature - 273) * 9 / 5 + 32

        return self.curTemperature

    def encryptData(self, data):
        try:
            cipher_aes = AES.new(os.environ['SECRET'].encode('UTF-8'), AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("UTF-8"))
            encMsg = b''.join([cipher_aes.nonce, tag, ciphertext])
            return encMsg
        except Exception as e:
            print(traceback.print_exc())
            print(e)

    def processCommands(self, msg, addr) :
        cmds = msg.split(';')
        for c in cmds :
            cs = c.split(' ')
            if len(cs) == 1 : # Now valid for all commands
                user = ''.join(addr[0]+'-'+str(addr[1]))
                if cs[0] == "AUTH":
                    token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
                    self.sessions[user] = {
                        "timestamp": datetime.datetime.now(),
                        "token": token
                    }
                    outGoingMsg = self.encryptData(token)
                    self.serverSocket.sendto(outGoingMsg, addr)
                elif cs[0] == "LOGOUT":
                    if(self.sessions[user]):
                        del self.sessions[user]
                elif c == "SET_DEGF" :
                    self.deg = "F"
                elif c == "SET_DEGC" :
                    self.deg = "C"
                elif c == "SET_DEGK" :
                    self.deg = "K"
                elif c == "GET_TEMP" :
                    self.serverSocket.sendto(b"%f\n" % self.getTemperature(), addr)
                elif c == "UPDATE_TEMP" :
                    self.updateTemperature()
                elif c :
                    self.serverSocket.sendto(b"Invalid Command\n", addr)
            else:
                self.serverSocket.sendto(b"Invalid Command - are you using the old command syntax for AUTH or LOGOUT?\n", addr)


    def run(self) : #the running function
        while True : 
            try :
                # We should have have received a message encrypted message
                encMsg, addr = self.serverSocket.recvfrom(1024)
                try:
                    # private_key = RSA.import_key(open("./receiver").read(), passphrase="Farmall1")
                    # pkSize = private_key.size_in_bytes()
                    # enc_sessionKey, 
                    nonce, tag, ciphertext = \
                        [ encMsg[:16],
                        encMsg[ 16:32],
                        encMsg[32:]
                        ]
                    # cipher = PKCS1_OAEP.new(private_key)
                    # sessionKey = cipher.decrypt(enc_sessionKey)
                    AEScipher = AES.new(os.environ['SECRET'].encode('UTF-8'), AES.MODE_EAX, nonce)
                    msg = AEScipher.decrypt_and_verify(ciphertext, tag).decode()
                except Exception as e:
                    print(traceback.format_exc())
                    errMsg = "WTH?: {0}".format(e).encode()
                    self.serverSocket.sendto(errMsg, addr)
                cmds = msg.split(' ')
                if len(cmds) == 1 :
                    self.processCommands(msg, addr)
                else :
                    # otherwise deprecated AUTH or bad command
                    self.serverSocket.sendto(b"Bad Command or deprecated use of AUTH\n", addr)
    
            except IOError as e :
                if e.errno == errno.EWOULDBLOCK :
                    #do nothing
                    pass
                else :
                    #do nothing for now
                    pass
                msg = ""

 

            self.updateTemperature()
            time.sleep(self.updatePeriod)


class SimpleClient :
    def __init__(self, therm1, therm2) :
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))


    def updateInfTemp(self, frame) :
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature()-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature()-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

UPDATE_PERIOD = .05 #in seconds
SIMULATION_STEP = .1 #in seconds

#create a new instance of IncubatorSimulator
bob = infinc.Human(mass = 8, length = 1.68, temperature = 36 + 273)
#bobThermo = infinc.SmartThermometer(bob, UPDATE_PERIOD)
bobThermo = SmartNetworkThermometer(bob, UPDATE_PERIOD, 23456)
bobThermo.start() #start the thread

inc = infinc.Incubator(width = 1, depth=1, height = 1, temperature = 37 + 273, roomTemperature = 20 + 273)
#incThermo = infinc.SmartNetworkThermometer(inc, UPDATE_PERIOD)
incThermo = SmartNetworkThermometer(inc, UPDATE_PERIOD, 23457)
incThermo.start() #start the thread

incHeater = infinc.SmartHeater(powerOutput = 1500, setTemperature = 45 + 273, thermometer = incThermo, updatePeriod = UPDATE_PERIOD)
inc.setHeater(incHeater)
incHeater.start() #start the thread

sim = infinc.Simulator(infant = bob, incubator = inc, roomTemp = 20 + 273, timeStep = SIMULATION_STEP, sleepTime = SIMULATION_STEP / 10)

sim.start()

sc = SimpleClient(bobThermo, incThermo)

plt.grid()
plt.show()

