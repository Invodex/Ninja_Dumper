from binaryninja import PluginCommand
import binaryninjaui
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QFileDialog, QPushButton, QLineEdit,QDialog
from ..windbg import wrapper_dump as wrapper

# glob ref to window stay on :)
global_widget_reference = None

#resul class
class ResultWindow(QWidget):
    def __init__(self, result):
        super().__init__()
        self.setWindowTitle('Result')
        self.setGeometry(100, 100, 400, 200)  # x, y, width, height
        layout = QVBoxLayout()
        # Mostra o resultado em um QLabel
        result_label = QLabel(result)
        layout.addWidget(result_label)
        self.setLayout(layout)

def showResultWindow(result):
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = ResultWindow(result)
    global_widget_reference.show()

#get path class
class CustomWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ninja-Dumper")
        self.setGeometry(100, 100, 300, 200)  # x, y, width, height
        layout = QVBoxLayout()
        self.label = QLabel("Ninja-Dumper!")
        layout.addWidget(self.label)
        self.setLayout(layout)

def show_custom_widget():
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = CustomWidget()
    global_widget_reference.show()

def get_file_path():
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    file_path, _ = QFileDialog.getOpenFileName(None, "Select a file")

    return file_path

def show_my_test(path_windb,path_dump):
    global global_widget_reference
    wrapper.cdb_path = wrapper.get_paths_bin(path_windb)
    wrapper.dump_path = path_dump
    
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = MyApp()
    global_widget_reference.show()

#input class
class InputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Input Data :)')
        self.setGeometry(300, 300, 200, 100)
        self.user_input = ''

        layout = QVBoxLayout()
        self.line_edit = QLineEdit(self)
        layout.addWidget(self.line_edit)

        ok_button = QPushButton('OK', self)
        ok_button.clicked.connect(self.accept_input)
        layout.addWidget(ok_button)

        self.setLayout(layout)

    def accept_input(self):
        self.user_input = self.line_edit.text()
        self.accept()

def get_user_input(bv):
    app = QApplication.instance() or QApplication([])
    dialog = InputDialog()
    if dialog.exec() == QDialog.Accepted:
        return dialog.user_input
    return None