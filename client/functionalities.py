from OpenSSL import SSL
import os, socket
from shared.client import *
import threading

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print ('Got certificate: %s' % cert.get_subject())
    return ok

class Listener(threading.Thread):
    def __init__(self, socket,output):
        super().__init__()
        self.output=output
        self.socket=socket

    def run(self):
        try:
            while 1:
                msg = self.socket.recv(1024).decode("utf-8")
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

    def authentification(self,client):
        json=client.serialise()
        try:
            self.socket.send(json)
        except Exception:
            return
        auth=self.socket.recv(1024).decode("utf-8")
        if(auth=="TRUE"):
            return True
        else:
            return False

    def start_listener(self,output):
        listener=Listener(self.socket,output)
        listener.start()

    def send(self,text):
        try:
            self.socket.send(text)
        except Exception:
            return

    def __del__(self):
        self.socket.shutdown()
        self.socket.close()


client=Clientf()
if(client.authentification(Client("1","nom","prenom","login","password"))):
    client.start_listener(print)
    while(1):
        a=input()
        client.send(a)