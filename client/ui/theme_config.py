LOCALIZATION = {
    "RU": {
        "title": "ВЕСТОЧКА", "subtitle": "УЗЕЛ СВЯЗИ E2EE", "username": "Имя пользователя",
        "password": "Пароль", "signin": "Войти", "signup": "Регистрация",
        "search_node": "Поиск или добавление контакта...", "select_node": "Выберите контакт для общения",
        "write_msg": "Напишите секретное сообщение...", "send": "Отправить", "not_found": "Узел не найден!",
        "conn_error": "Ошибка сервера", "secured": "Канал зашифрован сквозным методом E2EE.",
        "empty_fields": "Заполните все поля", "reg_success": "Успешно! Нажмите Войти."
    },
    "EN": {
        "title": "VESTOCHKA", "subtitle": "E2EE SECURED NODE", "username": "Username",
        "password": "Password", "signin": "Sign In", "signup": "Sign Up",
        "search_node": "Search or add node username...", "select_node": "Select a node card to chat",
        "write_msg": "Write a secured message...", "send": "Send", "not_found": "Node missing in DB!",
        "conn_error": "Server offline", "secured": "Channel secured via E2EE protocol.",
        "empty_fields": "Fields cannot be empty", "reg_success": "Success! Click Sign In."
    }
}

def get_theme_qss(is_light=False):
    if is_light:
        return """
            QWidget { color: #0f172a; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
            QFrame#sidePanel, QFrame#chatPanel, QFrame#menuPanel { background-color: rgba(255, 255, 255, 0.45); border: 1px solid rgba(15, 23, 42, 0.08); border-radius: 24px; }
            QLineEdit { background-color: rgba(255, 255, 255, 0.75); border: 1px solid rgba(15, 23, 42, 0.1); border-radius: 16px; padding: 12px 18px; color: #0f172a; }
            QLineEdit:focus { background-color: #ffffff; border: 1px solid #6366f1; }
            QListWidget { background-color: transparent; border: none; outline: none; }
            QListWidget::item { background-color: rgba(255, 255, 255, 0.6); border: 1px solid rgba(15, 23, 42, 0.05); border-radius: 20px; margin: 6px; padding: 10px; color: #1e293b; }
            QListWidget::item:hover { background-color: rgba(255, 255, 255, 0.9); border: 1px solid rgba(15, 23, 42, 0.15); }
            QListWidget::item:selected { background-color: rgba(99, 102, 241, 0.15); border: 1px solid #6366f1; color: #0f172a; font-weight: 600; }
            QPushButton { background-color: rgba(15, 23, 42, 0.04); border: 1px solid rgba(15, 23, 42, 0.08); border-radius: 14px; color: #0f172a; font-weight: 600; padding: 12px; }
            QPushButton:hover { background-color: rgba(99, 102, 241, 0.1); border: 1px solid #6366f1; }
            QPushButton#menuButton { background-color: transparent; border: none; font-size: 18px; padding: 14px; border-radius: 12px; }
            QPushButton#menuButton:checked { background-color: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); }
            QTextBrowser { background-color: transparent; border: none; }
            QComboBox { background-color: rgba(255, 255, 255, 0.8); border: 1px solid rgba(15, 23, 42, 0.1); border-radius: 12px; padding: 6px; color: #0f172a; }
        """
    else:
        return """
            QWidget { color: #f8fafc; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
            QFrame#sidePanel, QFrame#chatPanel, QFrame#menuPanel { background-color: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 24px; }
            QLineEdit { background-color: rgba(15, 15, 25, 0.5); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 16px; padding: 12px 18px; color: #ffffff; }
            QLineEdit:focus { background-color: rgba(15, 15, 25, 0.7); border: 1px solid rgba(99, 102, 241, 0.4); }
            QListWidget { background-color: transparent; border: none; outline: none; }
            QListWidget::item { background-color: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 20px; margin: 6px; color: #e2e8f0; }
            QListWidget::item:hover { background-color: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.12); }
            QListWidget::item:selected { background-color: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.4); color: #ffffff; }
            QPushButton { background-color: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 14px; color: #ffffff; font-weight: 600; padding: 12px; }
            QPushButton:hover { background-color: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.2); }
            QPushButton#menuButton { background-color: transparent; border: none; font-size: 18px; padding: 14px; border-radius: 12px; }
            QPushButton#menuButton:checked { background-color: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); }
            QTextBrowser { background-color: transparent; border: none; }
            QComboBox { background-color: rgba(15, 15, 25, 0.5); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 6px; color: #ffffff; }
        """
