from client import Client
import ldap3


class LDAP_server:
    def __init__(self,uri='ldap://localhost',login = "cn=admin,dc=suse,dc=com",password = "Admin"):
        self.server = ldap3.Server(uri)
        self.connection = ldap3.Connection(self.server, user=login, password=password)

    def create(self,client:Client):
        # create a client in LDAP server
        return client

    def findClient(self,login):

        search_base = 'dc=suse,dc=de'

        #self.connection.search(search_base, search_filter, attributes=attrs)

