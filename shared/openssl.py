from OpenSSL import crypto
from OpenSSL._util import lib as cryptolib
from Crypto.PublicKey import RSA
import hashlib

TYPE_RSA = crypto.TYPE_RSA
# TYPE_DSA = crypto.TYPE_DSA
#apt-get install libssl-dev

def create_keyPair(type=crypto.TYPE_RSA, bits=1024):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def create_certRequest(pkey, digest="sha384", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key, value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def create_certificate(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="sha384"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


def load_key_file(keyfile, passphrase=''):
    st_key = open(keyfile, 'rt').read()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, st_key, passphrase=str.encode(passphrase))
    return key


def save_key_file(filename, key, passphrase=''):
    with open(filename, 'wb') as file:
        file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=str.encode(passphrase)))
    return True


def load_certi_file(certfile):
    st_cert = open(certfile, 'rt').read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
    return cert

def certif_to_bytes(certif):
    return crypto.dump_certificate(crypto.FILETYPE_PEM, certif)

def bytes_to_certif(certif):
    return crypto.load_certificate(crypto.FILETYPE_PEM, certif)


def save_certif_file(filename, certif):
    with open(filename, 'wb') as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certif))

def Get_PublicKey_String_from_KeyPair(pkey):
    """ Format a public key as a PEM """
    bio = crypto._new_mem_buf()
    cryptolib.PEM_write_bio_PUBKEY(bio, pkey._pkey)
    return crypto._bio_to_string(bio)

def Get_PublicKey_From_KeyPair(keyPair):
    publicKeyString = Get_PublicKey_String_from_KeyPair(keyPair)
    return RSA.importKey(publicKeyString)

def encrypt_with_certif(cert,msg):
    pub_key = cert.get_pubkey()
    return pub_key.encrypt(msg.encode('utf-8'), '')


def Get_PrivateKey_From_KeyPair(keyPair):
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, keyPair)
    return RSA.importKey(private_key)



def encrypt_RSA(public_key, data):
    return public_key.encrypt(data.encode('utf-8'), '')


def decrypt_RSA(private_key, data_encrypted):
    return private_key.decrypt(data_encrypted).decode('utf-8')


def hash_SHA512(data):
    return hashlib.sha512(data.encode('utf-8')).hexdigest()


#Test Hashage SHA512
#print(hash_SHA512('Test Hash SHA512'))

## Generate key pair
# kp = create_keyPair(TYPE_RSA, 4096)
#
## Extract Public key from Key Pair
# pub = Get_PublicKey_From_KeyPair(kp)
## Extract Private key from Key Pair
# prv = Get_PrivateKey_From_KeyPair(kp)
#
# msg='hello'
## Encrypt message with the public key
# enc = encrypt_RSA(pub, msg)
## Decrypt message with the private key
# dec = decrypt_RSA(prv, enc)
#
# print(enc)
# print(dec)
