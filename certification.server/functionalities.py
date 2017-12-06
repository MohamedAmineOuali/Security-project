from client import Client
from shared.openssl import *
import openssl
import os


def signUp(client:Client):
    return True

def make_certification(certificateRequest):
    return "certification"


class CertificationServer:
    def __init__(self,keyfile='keys/CA.pkey',certificatefile='keys/CA.cert'):
        # if os.path.isfile(keyfile):
        #     st_key = open(keyfile, 'rt').read()
        #
        # else:
        #     self.cakey = createKeyPair(TYPE_RSA, 1024)
        #     open('keys/CA.pkey', 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.cakey))
        #
        # careq = createCertRequest(self.cakey, CN='Certificate Authority')
        # self.cacert = createCertificate(careq, careq, self.cakey, 0, 0, 60 * 60 * 24 * 365 * 5)  # five years
        # open('keys/CA.cert', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.cacert))