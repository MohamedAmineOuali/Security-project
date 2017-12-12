
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal, QObject, QCoreApplication
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QApplication

from client.AppGUI import Ui_UserWindow
from client.functionalities import Clientf, Resgistration

from shared.client import Client


class Action(QObject):
    displayFun = pyqtSignal(str)
    ajouterClient=pyqtSignal(str)
    deleteClient=pyqtSignal(str)
    def __init__(self, gui: Ui_UserWindow):
        super().__init__()
        self.gui=gui
        self.connection_tab(False)
        self.gui.keys_dir_btn.clicked.connect(self.select_key_directory)
        self.gui.login_btn.clicked.connect(self.login)
        self.gui.send_btn.clicked.connect(self.send)
        self.gui.signCheck.stateChanged.connect(self.sign_change)
        self.gui.file_selection_btn.clicked.connect(self.select_registration_directory)
        self.gui.register_btn.clicked.connect(self.register)
        self.directory=None
        self.registration_directory = None
        self.gui.clientsLists.addItem("all users")
        self.gui.clientsLists.currentTextChanged.connect(self.userSelect)

    def select_key_directory(self):
        self.directory = str(QFileDialog.getExistingDirectory(self.gui.centralwidget, "Select Directory"))
        self.gui.label_directory.setText(self.directory)

    def select_registration_directory(self):
        self.registration_directory = str(QFileDialog.getExistingDirectory(self.gui.centralwidget, "Select Directory"))
        self.gui.public_key_file_input.setText(self.registration_directory)
   
    def sign_change(self):
        self.client.sign=not self.client.sign

    def send(self):
        self.client.send(self.gui.text_input.text())
        self.gui.text_output.setText(self.gui.text_output.toPlainText()+"me: "+self.gui.text_input.text()+"\n")
        self.gui.text_input.setText("")

    def login(self):
        if(self.directory==None or self.directory==''):
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText("select keys directory ")
            msg.setDetailedText("with client.key, client.cert,CA.cert")
            msg.setWindowTitle("Error")
            msg.show()
            return
        login=self.gui.username_login_input.text()
        password=self.gui.password_login_input.text()
        if(login=="" or password==""):
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText("specifier login et password ")
            msg.setWindowTitle("Error")
            msg.show()
            return
        try:
            self.client.__del__()
            del self.client
        except Exception as e:
            print(e)
        self.client=Clientf(key=self.directory+'/client.key',cert=self.directory+'/client.cert',authourity=self.directory+'/CA.cert')
        auth=self.client.authentification(Client(login=login,password=password))
        if(auth==True):
            self.displayFun.connect(self.display_result)
            self.ajouterClient.connect(self.add_client)
            self.deleteClient.connect(self.del_client)
            self.client.start_listener(self.displayFun.emit,self.ajouterClient.emit,self.deleteClient.emit)
            self.connection_tab(True)
        else:
            del self.client
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText(auth)
            msg.setWindowTitle("Authentification error")
            msg.show()

    def register(self):
        if self.registration_directory == None or self.registration_directory == '':
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText("select a directory")
            msg.setDetailedText("to save key and certificats")
            msg.setWindowTitle("Error")
            msg.show()
            return
        firstName= self.gui.fname_input.text()
        lastName = self.gui.lname_input.text()
        login=self.gui.username_input.text()
        password=self.gui.password_input.text()
        #self.direcory
        if login=="" or password=="" or firstName == "" or lastName == "":
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText("specifier first name, last name, login et password ")
            msg.setWindowTitle("Error")
            msg.show()
            return

        print(firstName, lastName, login, password, self.registration_directory)
        reg = Resgistration()
        registred = reg.register(self.registration_directory ,lastName, firstName, login, password)
        if registred == True:
            print("registration succeded")
        else:
            msg = QMessageBox(self.gui.centralwidget)
            msg.setIcon(QMessageBox.Information)
            msg.setText(registred)
            msg.setWindowTitle("Registration error")
            msg.show()


    def del_client(self,login):
        self.gui.clientsLists.setCurrentText(login)
        index=self.gui.clientsLists.currentIndex()
        self.gui.clientsLists.setCurrentIndex(0)
        self.gui.clientsLists.removeItem(index)

    def add_client(self,text):
        self.gui.clientsLists.addItem(text)

    def get_client_info(self):
        c=Client(1,self.gui.fname_input.text(),self.gui.lname_input.text(),self.gui.username_input.text(),self.gui.password_input.text())

    def connection_tab(self,state):
        self.gui.tabWidget.setTabEnabled(2, state)
        self.gui.tabWidget.setTabEnabled(0,not state)
        self.gui.tabWidget.setTabEnabled(1 ,not state)
        if(state):
            self.gui.tabWidget.setCurrentIndex(2)

    def display_result(self,text):
        self.gui.text_output.setText(self.gui.text_output.toPlainText()+text+"\n")


    def userSelect(self,login):
        self.client.select_destination(login)

    def closeAll(self):
        try:
            self.client.__del__()
        except Exception as e:
            return
        print("app closed")