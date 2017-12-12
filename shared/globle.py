signpattern="$signatures$"
deletpattern='deleteUser$$'
newpettern='newUser$$'
buffersize=5000000

hostCS="localhost"
portCS=2025
connection_nb_CS=3

hostPKI="localhost"
portPKI=2128
connection_nb_PKI=3

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print ('Got certificate: %s' % cert.get_subject())
    return ok