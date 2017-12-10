from OpenSSL import crypto

# TYPE_RSA = crypto.TYPE_RSA
# TYPE_DSA = crypto.TYPE_DSA


def create_keyPair(type, bits):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def create_certRequest(pkey, digest="md5", **name):
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


def create_certificate(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="md5"):
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


def save_certif_file(filename, certif):
    with open(filename, 'wb') as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certif))
