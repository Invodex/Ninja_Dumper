from binaryninja import PluginCommand
import binaryninjaui
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QFileDialog, QPushButton, QLineEdit, QDialog
from ..windbg import wrapper_dump as wrapper

# Reference to keep the window persistently visible
global_widget_reference = None

class ResultWindow(QWidget):
    """
    A window that displays the result of an operation.

    This class defines a simple window with a label to show the result of some operation.
    It sets up the window title, size, and layout upon initialization.

    Attributes:
        result (str): The result text to display in the window.
    """
    def __init__(self, result):
        super().__init__()
        self.setWindowTitle('Result')
        self.setGeometry(100, 100, 400, 200)  # x, y, width, height
        layout = QVBoxLayout()
        result_label = QLabel(result)
        layout.addWidget(result_label)
        self.setLayout(layout)

def showResultWindow(result):
    """
    Displays the ResultWindow with a given result.

    This function checks for an existing QApplication instance, creates one if none exists,
    and then creates or shows the ResultWindow with the specified result.

    Parameters:
        result (str): The result text to be displayed.
    """
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = ResultWindow(result)
    global_widget_reference.show()

class CustomWidget(QWidget):
    """
    A custom widget that displays a simple message.

    This class defines a custom window that shows a fixed message, 'Ninja-Dumper!',
    and sets up the window title and size.

    Attributes:
        None
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ninja-Dumper")
        self.setGeometry(100, 100, 300, 200)  # x, y, width, height
        layout = QVBoxLayout()
        self.label = QLabel("Ninja-Dumper!")
        layout.addWidget(self.label)
        self.setLayout(layout)

def show_custom_widget():
    """
    Displays the CustomWidget.

    Ensures that an instance of QApplication exists and displays CustomWidget. It creates
    a new instance of CustomWidget if it does not already exist.
    """
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = CustomWidget()
    global_widget_reference.show()

def get_file_path():
    """
    Opens a file dialog to select a file path.

    Ensures that an instance of QApplication exists and uses a file dialog to allow the user
    to select a file. Returns the selected file path.

    Returns:
        str: The path to the selected file.
    """
    global global_widget_reference
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    file_path, _ = QFileDialog.getOpenFileName(None, "Select a file")
    return file_path

def show_my_test(path_windb, path_dump):
    """
    Prepares and shows a main application window based on specified paths.

    Updates paths for the windbg wrapper, ensures an instance of QApplication exists,
    and displays the main application window.

    Parameters:
        path_windb (str): The path to the windbg executable.
        path_dump (str): The path to the dump file.
    """
    global global_widget_reference
    wrapper.cdb_path = wrapper.get_paths_bin(path_windb)
    wrapper.dump_path = path_dump
    
    app = QApplication.instance() if QApplication.instance() else QApplication([])
    if not global_widget_reference:
        global_widget_reference = MyApp()
    global_widget_reference.show()

class InputDialog(QDialog):
    """
    A dialog that allows user input through a QLineEdit.

    This class provides a modal dialog with a line edit and an OK button. The user can
    input text, and the dialog will store and provide this input when accepted.

    Attributes:
        user_input (str): The text input by the user.
    """
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
        """
        Stores the text from the QLineEdit when the OK button is clicked and closes the dialog.
        """
        self.user_input = self.line_edit.text()
        self.accept()

def get_user_input(bv):
    """
    Displays the InputDialog and returns the user input.

    Creates and shows the InputDialog, and if the user accepts it, returns the input.
    If the dialog is cancelled, returns None.

    Parameters:
        bv: Not used in this context, can be removed for cleanliness.

    Returns:
        str or None: The text input by the user, or None if cancelled.
    """
    app = QApplication.instance() or QApplication([])
    dialog = InputDialog()
    if dialog.exec() == QDialog.Accepted:
        return dialog.user_input
    return None
