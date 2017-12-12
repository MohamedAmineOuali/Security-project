
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog

from client.AppGUI import Ui_UserWindow
from client.functionalities import Clientf

from shared.client import Client


class Action():
    def __init__(self,gui:Ui_UserWindow):
        self.gui=gui
        self.connection_tab(False)
        self.gui.keys_dir_btn.clicked.connect(self.select_key_directory)
        self.gui.login_btn.clicked.connect(self.login)
        self.gui.send_btn.clicked.connect(self.send)
        self.gui.signCheck.stateChanged.connect(self.sign_change)
        self.directory=None
        return

    def select_key_directory(self):
        self.directory = str(QFileDialog.getExistingDirectory(self.gui.centralwidget, "Select Directory"))
        self.gui.label_directory.setText(self.directory)

    def sign_change(self):
        self.client.sign=not self.client.sign

    def send(self):
        self.client.send(self.gui.text_input.text())
        self.gui.text_input.setText("")

    def login(self):
        if(self.directory==None):
            print("error")
            return
        login=self.gui.username_login_input.text()
        password=self.gui.password_login_input.text()
        self.client=Clientf(key=self.directory+'/client.key',cert=self.directory+'/client.cert',authourity=self.directory+'/CA.cert')
        if(self.client.authentification(Client(login=login,password=password))):
            self.client.start_listener(print)
            self.connection_tab(True)

    def get_client_info(self):
        c=Client(1,self.gui.fname_input.text(),self.gui.lname_input.text(),self.gui.username_input.text(),self.gui.password_input.text())

    def connection_tab(self,state):
        self.gui.tabWidget.setTabEnabled(2, state)
        if(state):
            self.gui.tabWidget.setCurrentIndex(2)

    def display_result(self,text):
        self.gui.text_output.setText(self.gui.text_output.toPlainText()+"\n"+text)
