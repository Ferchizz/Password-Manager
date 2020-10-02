import sys
import user_login
import os
import webbrowser
from cryptoHandler import db_wrapper
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QDialog, QLineEdit, QTextEdit, QPushButton, QMessageBox, QMainWindow, QComboBox, QTableWidget, QTableWidgetItem, QToolTip, QStatusBar, QMenu, QAction
from PySide2.QtCore import QFile, Qt, Signal, QTimer
from PySide2.QtGui import QIcon 

login_class = user_login.login_auth()
database = None

# Permite imprimir informacion para debugging en la terminal.
DEBUG = False

class GUI_Login(QDialog):

    switch_create = Signal()
    event_iniciarSesion = Signal(str)

    def __init__(self, parent=None):
        super(GUI_Login, self).__init__(parent)
        ui_file = QFile(self.resource_path("pass_manager\GUI_Login.ui"))
        ui_file.open(QFile.ReadOnly)

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()
        self.window.setWindowIcon(QIcon(self.resource_path("rsc\icon.png")))

        self.line_username = self.window.findChild(QLineEdit, 'username_text')
        self.line_password = self.window.findChild(QLineEdit, 'password_text')
        btn_create = self.window.findChild(QPushButton, 'new_account_button')
        btn_login = self.window.findChild(QPushButton, 'login_button')

        self.line_password.setEchoMode(QLineEdit.EchoMode.Password)

        btn_create.clicked.connect(self.create_handler)
        btn_login.clicked.connect(self.login_handler)

        self.window.setWindowTitle("Password Manager")
        self.window.setWindowFlags(
            Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.window.setFixedSize(240, 122)
        self.window.show()

    # Needed for pyinstaller
    def resource_path(self, relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    def create_handler(self):
        self.switch_create.emit()

    def login_handler(self):
        global login_class
        username = self.line_username.text()
        password = self.line_password.text()

        if len(username) == 0 or len(password) == 0:
            return

        if not login_class.tryLogin(username, password):
            alert = QMessageBox()
            alert.setIcon(QMessageBox.Warning)
            alert.setText("Error al iniciar sesión.")
            alert.setInformativeText(
                "El nombre de usuario o la contraseña son incorrectos")
            alert.setStandardButtons(QMessageBox.Ok)
            alert.exec_()
        else:
            if DEBUG:
                print("DEBUG: Inicio de sesion correcto")
            self.event_iniciarSesion.emit(username)
            self.line_username.setText("")
            self.line_password.setText("")

    def ocultar(self):
        if self.window.isVisible():
            self.window.hide()


class GUI_Create(QDialog):

    event_iniciarSesion = Signal(str)

    def __init__(self, parent=None):
        super(GUI_Create, self).__init__(parent)
        ui_file = QFile(self.resource_path("pass_manager\GUI_Create.ui"))
        ui_file.open(QFile.ReadOnly)

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()
        self.window.setWindowIcon(QIcon(self.resource_path("rsc\icon.png")))

        self.line_name = self.window.findChild(QLineEdit, 'line_name')
        self.line_username = self.window.findChild(QLineEdit, 'line_username')
        self.line_password = self.window.findChild(QLineEdit, 'line_password')
        self.box_cipher = self.window.findChild(QComboBox, 'box_cipher')
        btn_create = self.window.findChild(QPushButton, 'btn_create')

        self.line_password.setEchoMode(QLineEdit.EchoMode.Password)

        self.window.setFixedSize(312, 304)

        btn_create.clicked.connect(self.create_handler)

        self.window.setWindowTitle("Password Manager")
        self.window.setWindowFlags(
            Qt.WindowTitleHint | Qt.WindowCloseButtonHint)

        self.window.show()

    # Needed for pyinstaller
    def resource_path(self, relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    def create_handler(self):
        global login_class
        name = self.line_name.text()
        username = self.line_username.text()
        password = self.line_password.text()

        cipher = self.box_cipher.currentIndex()  # 0 = AES, 1= ChaCha20

        if len(name) == 0 or len(username) == 0 or len(password) == 0:
            return

        val, err = login_class.createUser(name, username, password, cipher)
        if not val:
            alert = QMessageBox()
            alert.setIcon(QMessageBox.Warning)
            alert.setText(err)
            alert.setInformativeText(
                "El nombre de usuario debe tener mínimo 6 caracteres.")
            alert.setStandardButtons(QMessageBox.Ok)
            alert.exec_()
        else:
            if DEBUG:
                print("DEBUG: Creando cuenta...")
            self.event_iniciarSesion.emit(username)
            self.line_username.setText("")
            self.line_password.setText("")

    def ocultar(self):
        if self.window.isVisible():
            self.window.hide()


class GUI_MainWindow(QMainWindow):
    def __init__(self, name):
        super(GUI_MainWindow, self).__init__(None)
        ui_file = QFile(self.resource_path("pass_manager\GUI_MainWindow.ui"))
        ui_file.open(QFile.ReadOnly)

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()
        self.window.setWindowIcon(QIcon(self.resource_path("rsc\icon.png")))

        self.tabla_cuentas = self.window.findChild(QTableWidget, 'tableWidget')

        btn_add = self.window.findChild(QPushButton, 'btn_add')
        btn_add.clicked.connect(self.openDialogNewAccount)

        btn_delete = self.window.findChild(QPushButton, 'btn_delete')
        btn_delete.clicked.connect(self.deleteAccount)

        #self.tabla_cuentas.doubleClicked.connect(self.copyValue)
        self.window.setWindowTitle(name+" - Password Manager")

        self.status = self.window.findChild(QStatusBar, 'statusBar')

        # Tamaño columna "Nombre de usuario"
        self.tabla_cuentas.setColumnWidth(2, 150)

        # Oculto columna con los id
        self.tabla_cuentas.hideColumn(5)

        self.window.setFixedSize(661, 303)

        self.refreshTable()

        # ContextMenu policy 
        self.tabla_cuentas.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabla_cuentas.customContextMenuRequested.connect(self.on_context_menu)

        self.tableContextMenu = QMenu()
        self.tableContextMenu.addAction("Ir a web")
        self.tableContextMenu.addSeparator()
        copymenu = self.tableContextMenu.addMenu("Copiar")
        copymenu.addAction("Web")
        copymenu.addAction("Usuario")
        copymenu.addAction("Contraseña")
        self.tableContextMenu.triggered[QAction].connect(self.do_action)
        
        self.window.show()

    # Needed for pyinstaller
    def resource_path(self, relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    def on_context_menu(self, pos):
        self.index = self.tabla_cuentas.indexAt(pos)
        self.tableContextMenu.exec_(self.tabla_cuentas.mapToGlobal(pos))   

    def do_action(self, elem):
        row_number = self.index.row()
        value = None
        if elem.text() == "Web":
            value = self.tabla_cuentas.item(row_number, 1)
            if value is not None:
                value = value.text()
        elif elem.text() == "Usuario":
            value = self.tabla_cuentas.item(row_number, 2)
            if value is not None:
                value = value.text()
        elif elem.text() == "Contraseña":
            item_id = self.tabla_cuentas.item(row_number, 5)
            if item_id is not None:
                item_id = item_id.text()
                for entry in self.cuentas:
                    if int(entry[0]) == int(item_id):
                        value = entry[4]
                        break
        elif elem.text() == "Ir a web":
            web = self.tabla_cuentas.item(row_number, 1)
            if web is not None:
                web = web.text()
                webbrowser.open(web)

        if value is not None:
            QApplication.clipboard().setText(value)
            self.status.showMessage("Copiado al portapapeles, se limpiará en 20 segundos", 5000)
            QTimer.singleShot(20000, self.clearClipboard)

    def clearClipboard(self):
        QApplication.clipboard().setText("")
        self.status.showMessage("Portapapeles limpiado", 5000)
            

    def refreshTable(self):
        global database
        self.cuentas = database.getAllAccounts()
        self.tabla_cuentas.clearContents()

        row = 0
        for entry in self.cuentas:
            self.tabla_cuentas.setRowCount(row + 1)

            item = QTableWidgetItem(entry[1])
            item.setTextAlignment(4)

            self.tabla_cuentas.setItem(row, 0, QTableWidgetItem(item))
            item.setText(entry[2])
            self.tabla_cuentas.setItem(row, 1, QTableWidgetItem(item))
            item.setText(entry[3])
            self.tabla_cuentas.setItem(row, 2, QTableWidgetItem(item))
            item.setText(len(entry[4])*str("*"))
            self.tabla_cuentas.setItem(row, 3, QTableWidgetItem(item))
            item.setText(entry[5])
            self.tabla_cuentas.setItem(row, 4, QTableWidgetItem(item))
            item.setText(str(entry[0]))
            self.tabla_cuentas.setItem(row, 5, QTableWidgetItem(item))

            row += 1

    def openDialogNewAccount(self):
        GUI_AddAccount(self)

    def deleteAccount(self):
        global database
        item_selected = self.tabla_cuentas.selectedItems()

        if item_selected:
            row_number = item_selected[0].row()
            item_id = self.tabla_cuentas.item(row_number, 5).text()
            database.removeAccount(item_id)

            self.tabla_cuentas.removeRow(row_number)
            self.tabla_cuentas.clearSelection()

        self.refreshTable()


class GUI_AddAccount(QDialog):
    def __init__(self, parent):
        super(GUI_AddAccount, self).__init__(parent)
        ui_file = QFile(self.resource_path("pass_manager\GUI_AddAccount.ui"))
        ui_file.open(QFile.ReadOnly)

        self.parent = parent

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()
        self.window.setWindowIcon(QIcon(self.resource_path("rsc\icon.png")))

        self.line_title = self.window.findChild(QLineEdit, 'line_title')
        self.line_url = self.window.findChild(QLineEdit, 'line_url')
        self.line_username = self.window.findChild(QLineEdit, 'line_username')
        self.line_password = self.window.findChild(QLineEdit, 'line_password')
        self.text_notes = self.window.findChild(QTextEdit, 'text_notes')

        self.line_password.setEchoMode(QLineEdit.EchoMode.Password)

        btn_add = self.window.findChild(QPushButton, 'btn_add')
        btn_cancel = self.window.findChild(QPushButton, 'btn_cancel')

        btn_add.clicked.connect(self.addAccount)
        btn_cancel.clicked.connect(self.cancel)

        self.window.setWindowFlags(
            Qt.WindowTitleHint | Qt.WindowCloseButtonHint)

        self.setAttribute(Qt.WA_DeleteOnClose)

        self.window.setModal(True)

        self.window.show()

    # Needed for pyinstaller
    def resource_path(self, relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    def addAccount(self):
        global database
        title = self.line_title.text()
        url = self.line_url.text()
        username = self.line_username.text()
        password = self.line_password.text()
        comment = self.text_notes.toPlainText()

        if not url:
            url = "-"

        if len(title) == 0 or len(username) == 0 or len(password) == 0:
            return

        database.addAccount(title, url, username, password, comment)

        self.parent.refreshTable()

        self.window.done(0)

    def cancel(self):
        self.window.done(0)


class Controller:
    def __init__(self):
        self.login = None
        self.create = None

    def show_login(self):
        self.login = GUI_Login()
        self.login.switch_create.connect(self.show_create)
        self.login.event_iniciarSesion.connect(self.iniciarSesion)

    def show_create(self):
        self.create = GUI_Create()
        self.create.event_iniciarSesion.connect(self.iniciarSesion)
        self.login.ocultar()

    def show_main(self, text):
        self.mainWindow = GUI_MainWindow(text)
        self.login.ocultar()
        if self.create is not None:
            self.create.ocultar()

    def iniciarSesion(self, username):
        global login_class
        global database

        database = user_login.db_instance

        if database is None:
            if DEBUG:
                print("DEBUG: Error al iniciar sesion")
            return

        self.show_main(login_class.getUserName(username))

    def cerrarSesion(self):
        global database
        if database is not None:
            database.close()
        if DEBUG:
            print(f"DEBUG: Sesion terminada")


if __name__ == "__main__":
    # Create the Qt Application
    app = QApplication(sys.argv)

    # Creo controlador de ventanas
    controller = Controller()
    controller.show_login()

    # Run the main Qt loop
    exit_code = app.exec_()
    controller.cerrarSesion()
    sys.exit(exit_code)
