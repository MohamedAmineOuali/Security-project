
from shared.openssl import *

# Create public/private keys for a client
def generate_KeyPair():
    return create_keyPair(crypto.TYPE_RSA, 1024)

#create client request
def create_client_certif_request(name,key):
    return create_certRequest(key, CN=name+'Certificate')
