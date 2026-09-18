import sys
from PyQt6.QtWidgets import QApplication, QStackedWidget
from client.ui.windows import LoginWindow
from client.ui.theme_config import get_theme_qss


class MainWindow(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vestochka Premium Terminal")
        self.resize(850, 580)

        # Накатываем дефолтную темную тему
        self.setStyleSheet(get_theme_qss(is_light=False))

        self.login_win = LoginWindow(self.open_chat_screen)
        self.addWidget(self.login_win)

    def open_chat_screen(self, username, private_key):
        from client.ui.windows import ChatWindow
        self.chat_win = ChatWindow(username, private_key)
        self.addWidget(self.chat_win)
        self.setCurrentWidget(self.chat_win)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())
