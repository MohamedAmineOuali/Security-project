buffersize=50000
signpattern="$signatures$"
def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print ('Got certificate: %s' % cert.get_subject())
    return ok