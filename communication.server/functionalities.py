from shared.client import Client
from shared.globle import *
from shared.ldap import *

from OpenSSL import SSL
import threading
import sys, os, select, socket


class ClientThread(threading.Thread):

    def __init__(self, ip, port, socket:SSL.Connection,output,addClient,removeClient,commands):
        threading.Thread.__init__(self)
        self.source = ip+":"+str(port)
        self.socket = socket
        self.output=output
        self.addClient=addClient
        self.removeClient=removeClient
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
            json = self.socket.recv(buffersize).decode("utf-8")
        except Exception:
            return
        client=Client.loadJson(json)
        self.client = Server.authentification(client)
        if (self.client!=None):
            self.socket.send("TRUE")

            self.addClient(self.source,self)
            try:
                while 1:
                    msg = self.socket.recv(buffersize).decode("utf-8")
                    msg=self.process_msg(msg)
                    if(msg!=None):
                        self.output(self.source,msg)
            except SSL.Error:
                print ('Connection died unexpectedly')
        else:
            self.socket.send("Authentification error")

        self.removeClient(self.source)




class Server:

    ldap_server = LDAP_server()

    def __init__(self, port=2025, nb=3,key='keys/server.key',cert='keys/server.cert',authourity='keys/CA.cert'):
        # Initialize context
        self.clients = {}
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(key))
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up server
        self.server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.server.bind(('', port))
        self.server.listen(nb)
        self.commands={'request':self.public_key_request}

    def __del__(self):
        self.server.close()

    def listen(self):
        connection, address=self.server.accept()
        client=ClientThread(address[0],address[1],connection,self.writeMsg,self.addClient,self.removeClient,self.commands)
        client.start()


    def writeMsg(self,source,msg,destination='ALL'):
        if(destination=='ALL'):
            for id,client in self.clients.items():
                if(id!=source):
                    client.socket.send(msg)
        return

    def addClient(self,key,object):
        self.clients[key]=object

    def removeClient(self,key):
        try:
            self.clients[key].socket.shutdown()
            self.clients[key].socket.close()
        except Exception:
            return
        try:
            del self.clients[key]
        except Exception:
            return

    def public_key_request(self,login):
        for id, client in self.clients.items():
            if (client.client.login==login):
                return "publickey:"+client.client.certification
        return "login not found"

    @staticmethod
    def authentification(client):
        cl = Server.ldap_server.findClient(client.login)
        if cl == None:
            return None
        else:
            if client.password == cl.password :
                return cl
            return None



server=Server()
while 1:
    server.listen()