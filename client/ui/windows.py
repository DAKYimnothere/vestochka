import sys
import json
import os
import requests
import asyncio
import websockets
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
                             QPushButton, QTextBrowser, QLabel, QFrame, QListWidget, QListWidgetItem, QStackedWidget,
                             QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QPainter, QColor, QRadialGradient, QLinearGradient, QIcon, QPixmap, QFont

from client.crypto_utils import generate_and_save_keys, load_private_key, encrypt_message, decrypt_message
from client.ui.theme_config import LOCALIZATION, get_theme_qss

SERVER_URL = os.getenv("VESTOCHKA_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
WS_URL = os.getenv("VESTOCHKA_WS_URL", SERVER_URL.replace("https://", "wss://").replace("http://", "ws://") + "/ws").rstrip("/")
AUTH_TOKEN = ""

CURRENT_LANG = "RU"
IS_LIGHT_THEME = False

def auth_headers():
    return {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}


def draw_premium_background(widget, event):
    painter = QPainter(widget)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    if IS_LIGHT_THEME:
        base_grad = QLinearGradient(0, 0, widget.width(), widget.height())
        base_grad.setColorAt(0.0, QColor("#f1f5f9"))
        base_grad.setColorAt(1.0, QColor("#e2e8f0"))
        painter.fillRect(widget.rect(), base_grad)
        glow = QRadialGradient(widget.width() * 0.1, widget.height() * 0.2, widget.width() * 0.6)
        glow.setColorAt(0.0, QColor(253, 186, 116, 40))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(widget.rect(), glow)
    else:
        base_grad = QLinearGradient(0, 0, widget.width(), widget.height())
        base_grad.setColorAt(0.0, QColor("#0a0f1d"))
        base_grad.setColorAt(1.0, QColor("#07070c"))
        painter.fillRect(widget.rect(), base_grad)
        glow = QRadialGradient(widget.width() * 0.1, widget.height() * 0.2, widget.width() * 0.5)
        glow.setColorAt(0.0, QColor(99, 102, 241, 20))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(widget.rect(), glow)
    painter.end()


def create_avatar_icon(text, is_online=False, custom_color_hex=None):
    pixmap = QPixmap(110, 110)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    avatar_color = QColor(custom_color_hex) if custom_color_hex else QColor("#6366f1")
    if IS_LIGHT_THEME:
        avatar_color.setAlpha(60)
    else:
        avatar_color.setAlpha(40)

    painter.setBrush(avatar_color)
    painter.setPen(QColor(255, 255, 255, 40))
    painter.drawEllipse(30, 15, 50, 50)

    painter.setPen(QColor("#0f172a" if IS_LIGHT_THEME else "#ffffff"))
    painter.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
    painter.drawText(30, 15, 50, 50, Qt.AlignmentFlag.AlignCenter, text[:1].upper() if text else "?")

    painter.setBrush(QColor("#10b981") if is_online else QColor("#64748b"))
    painter.setPen(QColor("#ffffff" if IS_LIGHT_THEME else "#07070c"))
    painter.drawEllipse(68, 48, 12, 12)

    painter.end()
    return QIcon(pixmap)
class WebSocketReceiver(QThread):
    message_received = pyqtSignal(str, str)
    status_changed = pyqtSignal(str, bool)

    def __init__(self, username, private_key):
        super().__init__()
        self.username = username
        self.private_key = private_key

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.listen())

    async def listen(self):
        uri = f"{WS_URL}/{self.username}?token={AUTH_TOKEN}"
        try:
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                while True:
                    raw_data = await websocket.recv()
                    data = json.loads(raw_data)
                    if data.get("type") == "status_change":
                        self.status_changed.emit(data["username"], data["online"])
                    elif data.get("type") == "message":
                        try:
                            decrypted = decrypt_message(data["encrypted_msg"], self.private_key)
                            self.message_received.emit(data["from_user"], decrypted)
                        except Exception: pass
        except Exception: pass

    def send_message(self, to_user, encrypted_hex):
        if hasattr(self, 'websocket') and self.loop:
            payload = json.dumps({"to_user": to_user, "encrypted_msg": encrypted_hex})
            asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)


class LoginWindow(QWidget):
    def __init__(self, on_login_success):
        super().__init__()
        self.on_login_success = on_login_success
        self.init_ui()

    def paintEvent(self, event):
        draw_premium_background(self, event)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.glass_card = QFrame()
        self.glass_card.setFixedSize(360, 400)
        card_layout = QVBoxLayout(self.glass_card)
        card_layout.setContentsMargins(30, 40, 30, 40)
        card_layout.setSpacing(14)

        self.title = QLabel("VESTOCHKA")
        self.title.setStyleSheet("font-size: 26px; font-weight: 200; letter-spacing: 6px;")
        card_layout.addWidget(self.title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.username_input = QLineEdit()
        card_layout.addWidget(self.username_input)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        card_layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()
        self.btn_login = QPushButton("Sign In")
        self.btn_reg = QPushButton("Sign Up")
        self.btn_login.clicked.connect(self.handle_login)
        self.btn_reg.clicked.connect(self.handle_register)
        btn_layout.addWidget(self.btn_login)
        btn_layout.addWidget(self.btn_reg)
        card_layout.addLayout(btn_layout)

        self.status_label = QLabel("")
        card_layout.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.glass_card)
        self.setLayout(main_layout)
        self.update_localization()

    def update_localization(self):
        lang = LOCALIZATION[CURRENT_LANG]
        self.username_input.setPlaceholderText(lang["username"])
        self.password_input.setPlaceholderText(lang["password"])
        self.btn_login.setText(lang["signin"])
        self.btn_reg.setText(lang["signup"])
        self.glass_card.setStyleSheet(
            f"background-color: {'rgba(255,255,255,0.5)' if IS_LIGHT_THEME else 'rgba(255,255,255,0.02)'}; border-radius: 24px; border: 1px solid {'rgba(15,23,42,0.1)' if IS_LIGHT_THEME else 'rgba(255,255,255,0.05)'};")

    def handle_register(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password:
            self.status_label.setStyleSheet("color: #ef4444;")
            self.status_label.setText("Заполните все поля")
            return

        pub_hex = generate_and_save_keys(username, password)
        try:
            res = requests.post(f"{SERVER_URL}/register",
                                json={"username": username, "password": password, "public_key": pub_hex})
            if res.status_code == 200:
                self.status_label.setStyleSheet("color: #10b981;")
                self.status_label.setText(LOCALIZATION[CURRENT_LANG]["reg_success"])
            else:
                self.status_label.setStyleSheet("color: #ef4444;")
                self.status_label.setText(res.json().get("detail", "Ошибка регистрации"))
        except Exception as e:
            self.status_label.setStyleSheet("color: #ef4444;")
            self.status_label.setText(f"Нет связи с сервером")

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password: return

        private_key = load_private_key(username, password)
        if not private_key:
            self.status_label.setStyleSheet("color: #ef4444;")
            self.status_label.setText("Ключ E2EE не найден на этом ПК")
            return

        try:
            res = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
            if res.status_code == 200:
                global AUTH_TOKEN
                AUTH_TOKEN = res.json().get("token", "")
                self.on_login_success(username, private_key)
            else:
                self.status_label.setStyleSheet("color: #ef4444;")
                self.status_label.setText("Неверный логин или пароль")
        except Exception as e:
            self.status_label.setStyleSheet("color: #ef4444;")
            self.status_label.setText("Нет связи с сервером")


class ChatWindow(QWidget):
    def __init__(self, username, private_key):
        super().__init__()
        self.username = username
        self.private_key = private_key
        self.current_chat_target = None
        self.contacts_online_state = {}
        self.contacts_cached_colors = {}
        self.user_selected_color = "#6366f1"
        self.init_ui()

        self.receiver = WebSocketReceiver(self.username, self.private_key)
        self.receiver.message_received.connect(self.display_message)
        self.receiver.status_changed.connect(self.handle_global_status_change)
        self.receiver.start()

        self.load_profile_data_from_db()

    def paintEvent(self, event):
        draw_premium_background(self, event)

    def init_ui(self):
        root_layout = QHBoxLayout()
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(10)

        # Сайдбар меню
        self.sidebar_menu = QFrame()
        self.sidebar_menu.setObjectName("menuPanel")
        self.sidebar_menu.setFixedWidth(70)
        sidebar_layout = QVBoxLayout(self.sidebar_menu)
        sidebar_layout.setContentsMargins(5, 20, 5, 20)

        self.btn_menu_chats = QPushButton("💬")
        self.btn_menu_chats.setObjectName("menuButton")
        self.btn_menu_chats.setCheckable(True)
        self.btn_menu_chats.setChecked(True)
        self.btn_menu_chats.clicked.connect(lambda: self.switch_tab(0))

        self.btn_menu_profile = QPushButton("👤")
        self.btn_menu_profile.setObjectName("menuButton")
        self.btn_menu_profile.setCheckable(True)
        self.btn_menu_profile.clicked.connect(lambda: self.switch_tab(1))

        self.btn_menu_settings = QPushButton("⚙️")
        self.btn_menu_settings.setObjectName("menuButton")
        self.btn_menu_settings.setCheckable(True)
        self.btn_menu_settings.clicked.connect(lambda: self.switch_tab(2))

        sidebar_layout.addWidget(self.btn_menu_chats)
        sidebar_layout.addWidget(self.btn_menu_profile)
        sidebar_layout.addWidget(self.btn_menu_settings)
        sidebar_layout.addStretch()
        root_layout.addWidget(self.sidebar_menu)

        self.tabs_container = QStackedWidget()

        # ВКЛАДКА ЧАТОВ
        chats_tab_widget = QWidget()
        self.chats_main_layout = QHBoxLayout(chats_tab_widget)
        self.chats_main_layout.setContentsMargins(0, 0, 0, 0)
        self.chats_main_layout.setSpacing(12)

        self.side_panel = QFrame()
        self.side_panel.setObjectName("sidePanel")
        side_layout = QVBoxLayout(self.side_panel)
        side_layout.setContentsMargins(12, 16, 12, 16)

        self.contact_search = QLineEdit()
        self.contact_search.textChanged.connect(self.handle_local_search)
        self.contact_search.returnPressed.connect(self.add_new_contact)
        side_layout.addWidget(self.contact_search)

        self.chats_list = QListWidget()
        self.chats_list.setViewMode(QListWidget.ViewMode.IconMode)
        self.chats_list.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.chats_list.setMovement(QListWidget.Movement.Static)
        self.chats_list.setSpacing(12)
        self.chats_list.setIconSize(QSize(110, 75))
        self.chats_list.itemClicked.connect(self.select_chat)
        side_layout.addWidget(self.chats_list)
        self.chats_main_layout.addWidget(self.side_panel, 2)

        self.chat_panel = QFrame()
        self.chat_panel.setObjectName("chatPanel")
        self.chat_layout = QVBoxLayout(self.chat_panel)
        self.chat_layout.setContentsMargins(0, 0, 0, 15)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(15, 10, 15, 10)
        self.btn_back = QPushButton("←")
        self.btn_back.setFixedSize(45, 38)
        self.btn_back.clicked.connect(self.animate_chat_close)

        self.chat_header = QLabel()
        self.chat_header.setStyleSheet("font-weight: 600; font-size: 15px; padding-left: 10px;")
        header_layout.addWidget(self.btn_back)
        header_layout.addWidget(self.chat_header)
        header_layout.addStretch()

        header_frame = QFrame()
        header_frame.setStyleSheet("background-color: rgba(0,0,0,0.05);")
        header_frame.setLayout(header_layout)
        self.chat_layout.addWidget(header_frame)

        self.chat_display = QTextBrowser()
        self.chat_layout.addWidget(self.chat_display, 8)

        input_container = QHBoxLayout()
        input_container.setContentsMargins(15, 0, 15, 0)
        input_container.setSpacing(10)
        self.msg_input = QLineEdit()
        self.msg_input.returnPressed.connect(self.send_message)

        self.btn_send = QPushButton()
        self.btn_send.setFixedSize(85, 42)
        self.btn_send.clicked.connect(self.send_message)
        input_container.addWidget(self.msg_input)
        input_container.addWidget(self.btn_send)
        self.chat_layout.addLayout(input_container, 1)

        self.chats_main_layout.addWidget(self.chat_panel, 0)
        self.tabs_container.addWidget(chats_tab_widget)
        # ВКЛАДКА ПРОФИЛЯ
        profile_widget = QFrame()
        profile_widget.setObjectName("chatPanel")
        profile_layout = QVBoxLayout(profile_widget)
        profile_layout.setContentsMargins(40, 40, 40, 40)
        profile_layout.setSpacing(15)
        profile_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.prof_title = QLabel("ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ" if CURRENT_LANG == "RU" else "USER PROFILE")
        self.prof_title.setStyleSheet("font-size: 20px; font-weight: 300; letter-spacing: 3px; margin-bottom: 20px;")
        profile_layout.addWidget(self.prof_title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.lbl_system_username = QLabel(f"System ID (Node): {self.username}")
        self.lbl_system_username.setStyleSheet("color: #64748b; font-size: 13px; margin-bottom: 5px;")
        profile_layout.addWidget(self.lbl_system_username)

        profile_layout.addWidget(QLabel("Отображаемое имя / Display Name:"))
        self.input_display_name = QLineEdit()
        self.input_display_name.setPlaceholderText("Введите ваше имя для друзей...")
        profile_layout.addWidget(self.input_display_name)

        profile_layout.addWidget(QLabel("О себе / Bio:"))
        self.input_bio = QLineEdit()
        self.input_bio.setPlaceholderText("Расскажите что-нибудь о себе...")
        profile_layout.addWidget(self.input_bio)

        profile_layout.addWidget(QLabel("Цвет аватарки / Avatar Theme Color:"))
        color_layout = QHBoxLayout()
        color_layout.setSpacing(10)

        self.color_box = QComboBox()
        self.color_box.addItems(["Indigo (#6366f1)", "Emerald (#10b981)", "Rose (#f43f5e)", "Amber (#f59e0b)"])
        color_layout.addWidget(self.color_box)
        profile_layout.addLayout(color_layout)

        profile_layout.addSpacing(15)

        self.btn_save_profile = QPushButton("Сохранить профиль" if CURRENT_LANG == "RU" else "Save Profile")
        self.btn_save_profile.setStyleSheet(
            "background-color: rgba(99, 102, 241, 0.2); border: 1px solid #6366f1; font-weight: bold; padding: 12px;")
        self.btn_save_profile.setFixedSize(170, 42)
        self.btn_save_profile.clicked.connect(self.save_profile_data_to_db)
        profile_layout.addWidget(self.btn_save_profile)

        self.lbl_profile_status = QLabel("")
        profile_layout.addWidget(self.lbl_profile_status, alignment=Qt.AlignmentFlag.AlignCenter)
        self.tabs_container.addWidget(profile_widget)

        # ВКЛАДКА НАСТРОЕК
        settings_widget = QFrame()
        settings_widget.setObjectName("chatPanel")
        settings_layout = QVBoxLayout(settings_widget)
        settings_layout.setContentsMargins(40, 40, 40, 40)
        settings_layout.setSpacing(20)
        settings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.sett_title = QLabel("НАСТРОЙКИ СИСТЕМЫ" if CURRENT_LANG == "RU" else "SYSTEM SETTINGS")
        self.sett_title.setStyleSheet("font-size: 20px; font-weight: 300; letter-spacing: 3px; margin-bottom: 20px;")
        settings_layout.addWidget(self.sett_title, alignment=Qt.AlignmentFlag.AlignCenter)

        lang_row = QHBoxLayout()
        self.lbl_setting_lang = QLabel("Язык интерфейса / Language:")
        self.settings_lang_box = QComboBox()
        self.settings_lang_box.addItems(["RU", "EN"])
        self.settings_lang_box.currentTextChanged.connect(self.change_system_lang)
        lang_row.addWidget(self.lbl_setting_lang)
        lang_row.addWidget(self.settings_lang_box)
        settings_layout.addLayout(lang_row)

        theme_row = QHBoxLayout()
        self.lbl_setting_theme = QLabel("Тема оформления / UI Theme:")
        self.btn_theme_toggle = QPushButton("Темная / Deep Night" if not IS_LIGHT_THEME else "Светлая / Zen Light")
        self.btn_theme_toggle.clicked.connect(self.toggle_theme)
        theme_row.addWidget(self.lbl_setting_theme)
        theme_row.addWidget(self.btn_theme_toggle)
        settings_layout.addLayout(theme_row)

        self.tabs_container.addWidget(settings_widget)

        root_layout.addWidget(self.tabs_container, 4)
        self.setLayout(root_layout)
        self.change_system_lang(CURRENT_LANG)

    def switch_tab(self, index):
        self.btn_menu_chats.setChecked(index == 0)
        self.btn_menu_profile.setChecked(index == 1)
        self.btn_menu_settings.setChecked(index == 2)
        self.tabs_container.setCurrentIndex(index)
        if index == 1:
            self.lbl_profile_status.setText("")

    def change_system_lang(self, lang):
        global CURRENT_LANG
        CURRENT_LANG = lang
        l = LOCALIZATION[CURRENT_LANG]
        self.contact_search.setPlaceholderText(l["search_node"])
        self.msg_input.setPlaceholderText(l["write_msg"])
        self.btn_send.setText(l["send"])

        if CURRENT_LANG == "RU":
            self.prof_title.setText("ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ")
            self.sett_title.setText("НАСТРОЙКИ СИСТЕМЫ")
            self.btn_save_profile.setText("Сохранить профиль")
            self.input_display_name.setPlaceholderText("Введите ваше имя для друзей...")
            self.input_bio.setPlaceholderText("Расскажите что-нибудь о себе...")
        else:
            self.prof_title.setText("USER PROFILE")
            self.sett_title.setText("SYSTEM SETTINGS")
            self.btn_save_profile.setText("Save Profile")
            self.input_display_name.setPlaceholderText("Enter your display name...")
            self.input_bio.setPlaceholderText("Write something about yourself...")

        if not self.current_chat_target:
            self.chat_header.setText(l["select_node"])
    def toggle_theme(self):
        global IS_LIGHT_THEME
        IS_LIGHT_THEME = not IS_LIGHT_THEME
        if IS_LIGHT_THEME:
            self.btn_theme_toggle.setText("Светлая / Zen Light" if CURRENT_LANG == "RU" else "Light / Zen Light")
        else:
            self.btn_theme_toggle.setText("Темная / Deep Night" if CURRENT_LANG == "RU" else "Dark / Deep Night")
        self.window().setStyleSheet(get_theme_qss(IS_LIGHT_THEME))
        for i in range(self.chats_list.count()):
            item = self.chats_list.item(i)
            is_on = self.contacts_online_state.get(item.text(), False)
            color_hex = self.contacts_cached_colors.get(item.text(), "#6366f1")
            item.setIcon(create_avatar_icon(item.text(), is_on, color_hex))
        self.update()

    def load_profile_data_from_db(self):
        try:
            res = requests.get(f"{SERVER_URL}/profile/{self.username}")
            if res.status_code == 200:
                data = res.json()
                if data.get("display_name"): self.input_display_name.setText(data["display_name"])
                if data.get("bio"): self.input_bio.setText(data["bio"])
                color_hex = data.get("avatar_color", "#6366f1")
                self.user_selected_color = color_hex
                color_map = {"#6366f1": 0, "#10b981": 1, "#f43f5e": 2, "#f59e0b": 3}
                self.color_box.setCurrentIndex(color_map.get(color_hex, 0))
        except Exception: pass

    def save_profile_data_to_db(self):
        display_name = self.input_display_name.text().strip()
        bio = self.input_bio.text().strip()
        color_idx = self.color_box.currentIndex()
        color_map = {0: "#6366f1", 1: "#10b981", 2: "#f43f5e", 3: "#f59e0b"}
        self.user_selected_color = color_map.get(color_idx, "#6366f1")
        try:
            res = requests.post(f"{SERVER_URL}/profile/{self.username}/update", headers=auth_headers(), json={
                "display_name": display_name, "bio": bio, "avatar_color": self.user_selected_color
            })
            if res.status_code == 200:
                self.lbl_profile_status.setStyleSheet("color: #10b981;")
                self.lbl_profile_status.setText("Изменения сохранены!" if CURRENT_LANG == "RU" else "Changes saved!")
        except Exception:
            self.lbl_profile_status.setText(LOCALIZATION[CURRENT_LANG]["conn_error"])

    def handle_local_search(self, text):
        search_query = text.strip().lower()
        for i in range(self.chats_list.count()):
            item = self.chats_list.item(i)
            item.setHidden(search_query not in item.text().lower() if search_query else False)

    def add_new_contact(self):
        target = self.contact_search.text().strip()
        if not target or target == self.username: return
        try:
            res = requests.get(f"{SERVER_URL}/check_user/{target}")
            if res.status_code == 200:
                is_online = res.json().get("online", False)
                self.contacts_online_state[target] = is_online
                profile_res = requests.get(f"{SERVER_URL}/profile/{target}")
                color_hex = "#6366f1"
                if profile_res.status_code == 200:
                    color_hex = profile_res.json().get("avatar_color", "#6366f1")
                self.contacts_cached_colors[target] = color_hex
                items = [self.chats_list.item(i).text() for i in range(self.chats_list.count())]
                if target not in items:
                    item = QListWidgetItem(create_avatar_icon(target, is_online, color_hex), target)
                    item.setSizeHint(QSize(110, 110))
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom)
                    self.chats_list.addItem(item)
                self.contact_search.clear()
            else:
                self.contact_search.setText(LOCALIZATION[CURRENT_LANG]["not_found"])
        except Exception:
            self.contact_search.setText(LOCALIZATION[CURRENT_LANG]["conn_error"])

    def handle_global_status_change(self, target_user, is_online):
        self.contacts_online_state[target_user] = is_online
        color_hex = self.contacts_cached_colors.get(target_user, "#6366f1")
        for i in range(self.chats_list.count()):
            item = self.chats_list.item(i)
            if item.text() == target_user:
                item.setIcon(create_avatar_icon(target_user, is_online, color_hex))
                break

    def select_chat(self, item):
        self.current_chat_target = item.text()
        display_title = self.current_chat_target
        try:
            res = requests.get(f"{SERVER_URL}/profile/{self.current_chat_target}", headers=auth_headers())
            if res.status_code == 200 and res.json().get("display_name"):
                display_title = f"{res.json()['display_name']} (@{self.current_chat_target})"
        except Exception: pass
        self.chat_header.setText(display_title)
        self.chat_display.clear()
        self.chat_display.append(f"<i style='color: {'#64748b' if IS_LIGHT_THEME else '#475569'};'>{LOCALIZATION[CURRENT_LANG]['secured']}</i><br>")
        try:
            res = requests.get(f"{SERVER_URL}/history/{self.username}/{self.current_chat_target}", headers=auth_headers())
            if res.status_code == 200:
                for msg in res.json():
                    try:
                        decrypted_text = decrypt_message(msg["encrypted_text"], self.private_key)
                        if msg["sender"] == self.username:
                            bubble = f"<div align='right' style='margin-bottom: 8px;'><div style='background-color: {'rgba(99,102,241,0.8)' if IS_LIGHT_THEME else 'rgba(99,102,241,0.2)'}; border: 1px solid rgba(99,102,241,0.4); padding: 12px 16px; border-radius: 16px 16px 4px 16px; display: inline-block; text-align: left; max-width: 70%; color:#ffffff;'>{decrypted_text}</div></div>"
                        else:
                            bubble = f"<div align='left' style='margin-bottom: 8px;'><div style='background-color: {'#ffffff' if IS_LIGHT_THEME else 'rgba(255,255,255,0.04)'}; border: 1px solid rgba(255,255,255,0.08); padding: 12px 16px; border-radius: 16px 16px 16px 4px; display: inline-block; max-width: 70%; color: {'#0f172a' if IS_LIGHT_THEME else '#e2e8f0'};'>{decrypted_text}</div></div>"
                        self.chat_display.append(bubble)
                    except Exception: pass
        except Exception: pass
        self.chats_main_layout.setStretch(0, 1)
        self.chats_main_layout.setStretch(1, 2)

    def animate_chat_close(self):
        self.current_chat_target = None
        self.chat_header.setText(LOCALIZATION[CURRENT_LANG]["select_node"])
        self.chats_main_layout.setStretch(0, 1)
        self.chats_main_layout.setStretch(1, 0)

    def send_message(self):
        target = self.current_chat_target
        text = self.msg_input.text().strip()
        if not target or not text: return
        try:
            res = requests.get(f"{SERVER_URL}/get_key/{target}")
            if res.status_code != 200: return
            recipient_pub_hex = res.json()["public_key"]
            encrypted_hex = encrypt_message(text, recipient_pub_hex)
            self.receiver.send_message(target, encrypted_hex)
            bubble = f"<div align='right' style='margin-bottom: 8px;'><div style='background-color: {'rgba(99,102,241,0.8)' if IS_LIGHT_THEME else 'rgba(99,102,241,0.2)'}; border: 1px solid rgba(99,102,241,0.4); color: #ffffff; padding: 12px 16px; border-radius: 16px 16px 4px 16px; display: inline-block; max-width: 70%;'>{text}</div></div>"
            self.chat_display.append(bubble)
            self.msg_input.clear()
        except Exception as e:
            self.chat_display.append(f"SYSTEM ERROR: {e}")

    def display_message(self, sender, text):
        items = [self.chats_list.item(i).text() for i in range(self.chats_list.count())]
        is_on = self.contacts_online_state.get(sender, False)
        color_hex = self.contacts_cached_colors.get(sender, "#6366f1")
        if sender not in items:
            try:
                profile_res = requests.get(f"{SERVER_URL}/profile/{sender}")
                if profile_res.status_code == 200: color_hex = profile_res.json().get("avatar_color", "#6366f1")
            except Exception: pass
            self.contacts_cached_colors[sender] = color_hex
            item = QListWidgetItem(create_avatar_icon(sender, is_on, color_hex), sender)
            item.setSizeHint(QSize(110, 110))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom)
            self.chats_list.addItem(item)

        if self.current_chat_target == sender:
            bubble = f"<div align='left' style='margin-bottom: 8px;'><div style='background-color: {'#ffffff' if IS_LIGHT_THEME else 'rgba(255,255,255,0.04)'}; border: 1px solid rgba(255,255,255,0.08); color: {'#0f172a' if IS_LIGHT_THEME else '#e2e8f0'}; padding: 12px 16px; border-radius: 16px 16px 16px 4px; display: inline-block; max-width: 70%;'>{text}</div></div>"
            self.chat_display.append(bubble)
