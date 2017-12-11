from OpenSSL import SSL
import os, socket
from shared.client import *
from shared.globle import buffersize, verify_cb
from shared.openssl import *
import threading


class Listener(threading.Thread):
    def __init__(self, socket,output,commands):
        super().__init__()
        self.output=output
        self.socket=socket
        self.commands=commands

    def process_msg(self,msg):
        commande=msg.split(':')[0]
        if(commande not in self.commands):
            return msg
        result=self.commands[commande](msg.split(':')[1])
        self.socket.send(result)
        return None

    def run(self):
        try:
            while 1:
                msg = self.socket.recv(buffersize).decode("utf-8")
                msg = self.process_msg(msg)
                if (msg != None):
                    self.output(msg)
        except Exception:
            return

class Clientf:
    def __init__(self,host='localhost',port=2025,key='keys/client.key',cert='keys/client.cert',authourity='keys/CA.cert'):
        # Initialize context
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(key))
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up client
        self.socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.socket.connect((host, port))
        self.commands={"publickey":self.set_destination}
        self.destination=None

    def authentification(self,client):
        json=client.serialise()
        try:
            self.socket.send(json)
        except Exception:
            return
        auth=self.socket.recv(buffersize).decode("utf-8")
        if(auth=="TRUE"):
            return True
        else:
            return False

    def start_listener(self,output):
        listener=Listener(self.socket,output,self.commands)
        listener.start()

    def set_destination(self,pubkey):
        self.destination=pubkey

    def send(self,text):
        try:
            if self.destination!=None:
                text=encrypt_RSA(self.destination,text)
            self.socket.send(text)
        except Exception:
            return

    def __del__(self):
        self.socket.shutdown()
        self.socket.close()


client=Clientf()
if client.authentification(Client(5555, 'cn5', 'sn5', 'uid5', 'pwd5', 'certif5')):
    client.start_listener(print)
    while(1):
        a=input()
        client.send(a)