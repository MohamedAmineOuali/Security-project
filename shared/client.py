class Client:

    def __init__(self,num,nom,prenom,login,password,certification=None):
        self.num = num
        self.nom = nom
        self.prenom = prenom
        self.login = login
        self.password = password
        self.certification = certification
