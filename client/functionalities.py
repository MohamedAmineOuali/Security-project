from OpenSSL import SSL
import os, socket
from shared.client import *
from shared.globle import buffersize, verify_cb
from shared.openssl import *
import threading
import base64

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
        result=self.commands[commande](msg.split(commande+':')[1])
        return None

    def run(self):
        try:
             while 1:
                 msg = self.socket.recv(buffersize).decode("utf-8")
                 msg = self.process_msg(msg)
                 if (msg != None):
                     self.output(msg)
        except Exception as e:
            print(e)
            self.socket.close()

class Clientf:
    def __init__(self,host='localhost',port=2025,key='keys/client.key',cert='keys/client.cert',authourity='keys/CA.cert'):
        # Initialize context
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
        self.key=load_key_file(key)
        ctx.use_privatekey(self.key)
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up client
        self.socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.socket.connect((host, port))
        self.commands={"newUser$$":self.add_user}
        self.clients={}
        self.selected=None
        self.sign=False

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

    def add_user(self,info):
        infos=info.split("||")
        cert=infos[1].encode()
        a=bytes_to_certif(cert)
        self.clients[infos[0]]=a

    def send(self,text):
        try:
            if self.selected!=None:
                text=encrypt_with_certif(self.selected,text)
            self.socket.send(text)
        except Exception as e:
            print (e)
            return

    def active_sign(self):
        self.sign = not self.sign

    def select_destination(self,login):
        try:
            self.selected=self.clients['login']
        except Exception as e:
            print (e)

    def __del__(self):
        self.socket.shutdown()
        self.socket.close()


client=Clientf()
if(client.authentification(Client(3333, 'cn3', 'sn3', 'uid3', 'pwd3'))):
    client.start_listener(print)
    while(1):
        a=input()
        client.send(a)