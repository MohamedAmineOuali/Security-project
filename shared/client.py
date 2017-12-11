import json
class Client:

    def __init__(self,num=0,nom='',prenom='',login='',password='',certification=None):
        self.num = int(num.__str__())
        self.nom = nom.__str__()
        self.prenom = prenom.__str__()
        self.login = login.__str__()
        self.password = password
        self.certification = certification.__str__()

    def __str__(self):
        return 'login:'+str(self.login)+'-'+str('nom:'+self.nom)+'-'+str('prenom:'+self.prenom)+'-'\
               +'numTelephone:' + str(self.num) + '-'+'password:'+self.password\
               +'-'+'certification:'+self.certification+'.'


    def serialise(self):
        return json.dumps(self.__dict__)  # data serialized

    @staticmethod
    def loadJson(data):
        data_loaded = json.loads(data)  # data loaded

        client=Client()
        client.__dict__.update(data_loaded)
        return client
