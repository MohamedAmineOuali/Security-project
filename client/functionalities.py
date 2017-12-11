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

####################
class Resgistration:
    
    def __init__(self,host='',port=2128):
        self.client = None
        self.host = host
        self.port = port
        self.my_socket = None

    def __del__(self):
        self.my_socket.shutdown()
        self.my_socket.close()

    def fill_client_info(self,num=0,nom='',prenom='',login='',password='',certification=None):
    
        #
        self.client =  Client(num, nom, prenom, login, password, certification)
        # pour le test
        self.client = Client(33373, 'cn3', 'sn3', 'uid3', 'pwd3', 'certif3')

    def generate_keypPair(self):
        self.key_pair = create_keyPair(crypto.TYPE_RSA, 1024)

    def fill_certification_request_info(self, C="CN", ST = "ST", L="L", O="O", OU="OU", CN="CN", emailAddress="E-mail address"):
        self.client.certification = create_certRequest(self.key_pair,C=C, ST=ST, L=L, O=O, OU=OU, CN=CN, emailAddress=emailAddress)

    def set_up_socket(self):
        if not self.my_socket:
            self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.my_socket.connect((self.host, self.port))

    def validate_with_pki(self):
        # send client and certif request
        serialised_client = self.client.serialise().encode('utf-8')
        self.my_socket.send(serialised_client)
        # recieve client object with his new certifcat
        client_json_object = self.my_socket.recv(buffersize).decode("utf-8")
        # recieve authority certifcat
        authority_certif = self.my_socket.recv(buffersize).decode("utf-8")
        # load client object
        client = Client.loadJson(client_json_object)
        # save client key and certif
        save_key_file("clientTest.key",self.key_pair,passphrase=self.client.password)
        # save client certif
        save_certif_file("clientTest.cert",string_to_certif(client.certification))
        # save authority certif 
        save_certif_file("serverTest.cert",string_to_certif(authority_certif))
    
    def register(self):
        self.fill_client_info(5445, 'iojio', 'klj', 'ohiu', 'hiu')
        self.generate_keypPair()
        self.fill_certification_request_info()
        self.set_up_socket()
        self.validate_with_pki()
    

reg = Resgistration()
reg.register()

####################






client=Clientf()
if(client.authentification(Client(3333, 'cn3', 'sn3', 'uid3', 'pwd3', 'certif3'))):
    client.start_listener(print)
    while(1):
        a=input()
        client.send(a)