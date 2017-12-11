from Crypto.Util import asn1

from client import Client
from shared.openssl import *
from shared.ldap import *
import os


class CertificationServer:
    def __init__(self,keyfile='keys/CA.pkey',certificatefile='keys/CA.cert'):
        if os.path.isfile(keyfile):
            self.key = load_key_file(keyfile)
        else:
            self.key = create_keyPair(crypto.TYPE_RSA, 1024)
            save_key_file(keyfile,self.key)

        if os.path.isfile(certificatefile):
            self.certif = load_certi_file(certificatefile)
            pub=self.certif.get_pubkey()
            # Only works for RSA (I think)
            if pub.type() != crypto.TYPE_RSA or self.key.type() != crypto.TYPE_RSA:
                raise Exception('Can only handle RSA keys')

            # This seems to work with public as well
            pub_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pub)
            priv_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, self.key)

            # Decode DER
            pub_der = asn1.DerSequence()
            pub_der.decode(pub_asn1)
            priv_der = asn1.DerSequence()
            priv_der.decode(priv_asn1)

            # Get the modulus
            pub_modulus = pub_der[1]
            priv_modulus = priv_der[1]

            if pub_modulus != priv_modulus:
                self.certif=None

        if(not hasattr(self, 'certif') or self.certif==None):
            careq = create_certRequest(self.key, CN='Certificate Authority')
            self.certif = create_certificate(careq, careq, self.key, 0, 0, 60 * 60 * 24 * 365 * 5)
            save_certif_file(certificatefile,self.certif)


        self.ldap_server = LDAP_server()

    def signUp(self, client:Client, client_request):
        certif = create_certificate(client.certification, self.certif, self.key, 0, 0, 60 * 60 * 24 * 365 * 5)
        client.certification = crypto.dump_certificate(crypto.FILETYPE_PEM, certif)
        return self.ldap_server.create(client)

# PKI=CertificationServer()
# l=LDAP_server()
# client = Client(3333, 'cn3', 'sn3', 'uid3', 'pwd3', 'certif3')
# created=l.create(client)
# print('Is a new entry created ? %s'%created)
# print(l.findClient('uid3'))

