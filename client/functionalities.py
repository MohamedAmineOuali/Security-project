
from shared.openssl import *





for (fname, cname) in [('client', 'Simple Client'), ('server', 'Simple Server')]:
    pkey = createKeyPair(TYPE_RSA, 1024)
    req = createCertRequest(pkey, CN=cname)
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5)) # five years
    open('simple/%s.pkey' % (fname,), 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    open('simple/%s.cert' % (fname,), 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))