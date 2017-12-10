from shared.client import Client
from shared.ldap import *

from OpenSSL import SSL
import threading
import sys, os, select, socket


class ClientThread(threading.Thread):

    def __init__(self, ip, port, socket:SSL.Connection,output,addClient,removeClient):
        threading.Thread.__init__(self)
        self.source = ip+":"+str(port)
        self.socket = socket
        self.output=output
        self.addClient=addClient
        self.removeClient=removeClient

    def run(self):
        try:
            json = self.socket.recv(1024).decode("utf-8")
        except Exception:
            return
        client=Client.loadJson(json)
        if (Server.authentification(client)):
            self.socket.send("TRUE")
            self.client = client
            self.addClient(self.source,self)
            try:
                while 1:
                    msg = self.socket.recv(1024).decode("utf-8")
                    self.output(self.source,msg)
            except SSL.Error:
                print ('Connection died unexpectedly')
        self.removeClient(self.source)




class Server:

    ldap_server = LDAP_server()

    def __init__(self, port=2025, nb=3,key='keys/server.key',cert='keys/server.cert',authourity='keys/CA.cert'):
        # Initialize context
        self.clients = {}
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, Server.verify_cb)  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(key))
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up server
        self.server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.server.bind(('', port))
        self.server.listen(nb)

    def __del__(self):
        self.server.close()

    def listen(self):
        connection, address=self.server.accept()
        client=ClientThread(address[0],address[1],connection,self.writeMsg,self.addClient,self.removeClient)
        client.start()


    def writeMsg(self,source,msg,destination='ALL'):
        if(destination=='ALL'):
            for id,client in self.clients.items():
                if(id!=source):
                    client.socket.send(msg)

    def addClient(self,key,object):
        self.clients[key]=object

    def removeClient(self,key):
        del self.clients[key]

    @staticmethod
    def authentification(client):
        cl = Server.ldap_server.findClient(client.login)
        if cl == NONE:
            return False
        else:
            if client.password == cl.password:
                return True
            return False



    @staticmethod
    def verify_cb(conn, cert, errnum, depth, ok):
        # This obviously has to be updated
        print('Got certificate: %s' % cert.get_subject())
        return ok

# # Test authentification
client = Client(2222, 'cn2', 'sn2', 'uid2', 'pwd2', 'certif2')

print(Server.authentification(client))

server=Server()
while 1:
    server.listen()