import flet as ft
from abc import ABC, abstractmethod
from functools import total_ordering
from datetime import datetime
from typing import Optional
import random
import string
import os
import atexit

class BaseEntity(ABC):

    @abstractmethod
    def describe(self) -> str:
        ...

class BaseUI(ABC):

    @abstractmethod
    def build(self) -> ft.Control:
        ...


@total_ordering
class User(BaseEntity):
    # Пользователь приложения

    def __init__(self, login: str, password_hash: str = ""):
        self._login = login
        self._password_hash = password_hash
        self._time_in: Optional[datetime] = None
        self._time_out: Optional[datetime] = None

    @property
    def login(self) -> str:
        return self._login

    @login.setter
    def login(self, value: str) -> None:
        if not value:
            raise ValueError("login не может быть пустым")
        self._login = value

    @property
    def password_hash(self) -> str:
        return self._password_hash

    @password_hash.setter
    def password_hash(self, value: str) -> None:
        self._password_hash = value

    @property
    def time_in(self) -> Optional[datetime]:
        return self._time_in

    @time_in.setter
    def time_in(self, value: datetime) -> None:
        self._time_in = value

    @property
    def time_out(self) -> Optional[datetime]:
        return self._time_out

    @time_out.setter
    def time_out(self, value: datetime) -> None:
        self._time_out = value

    def describe(self) -> str:
        return f"User({self._login})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self._login == other._login

    def __lt__(self, other) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self._login < other._login

    def __hash__(self) -> int:
        return hash(self._login)

    def __repr__(self) -> str:
        return f"User(login={self._login!r})"

    def __str__(self) -> str:
        return f"Пользователь {self._login}"


@total_ordering
class PasswordEntry(BaseEntity):
    # Одна запись сгенерированного пароля

    def __init__(self, site: str, login: str, password: str,
                 created_at: Optional[datetime] = None, length: int = 0):
        self._site = site
        self._login = login
        self._password = password
        self._created_at = created_at or datetime.now()
        self._length = length or len(password)

    @property
    def site(self) -> str:
        return self._site

    @site.setter
    def site(self, value: str) -> None:
        self._site = value

    @property
    def login(self) -> str:
        return self._login

    @login.setter
    def login(self, value: str) -> None:
        self._login = value

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, value: str) -> None:
        self._password = value
        self._length = len(value)

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @created_at.setter
    def created_at(self, value: datetime) -> None:
        self._created_at = value

    @property
    def length(self) -> int:
        return self._length

    def describe(self) -> str:
        return f"{self._site}:{self._login} -> {self._password}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, PasswordEntry):
            return NotImplemented
        return (self._site, self._login) == (other._site, other._login)

    def __lt__(self, other) -> bool:
        if not isinstance(other, PasswordEntry):
            return NotImplemented
        return (self._site, self._login) < (other._site, other._login)

    def __hash__(self) -> int:
        return hash((self._site, self._login))

    def __repr__(self) -> str:
        return (f"PasswordEntry(site={self._site!r}, login={self._login!r}, "
                f"length={self._length})")

    def __str__(self) -> str:
        return f"[{self._site}] {self._login}: {self._password}"

    def __len__(self) -> int:
        return self._length

class LoginMap:

    def __init__(self):
        self._keys: list[str] = []
        self._values: list[PasswordEntry] = []

    @staticmethod
    def make_key(site: str, login: str) -> str:
        return f"{site.lower()}::{login.lower()}"

    def put(self, entry: PasswordEntry) -> None:
        key = self.make_key(entry.site, entry.login)
        if key in self._keys:
            self._values[self._keys.index(key)] = entry
        else:
            self._keys.append(key)
            self._values.append(entry)

    def get(self, site: str, login: str) -> Optional[PasswordEntry]:
        key = self.make_key(site, login)
        if key in self._keys:
            return self._values[self._keys.index(key)]
        return None

    def remove(self, site: str, login: str) -> bool:
        key = self.make_key(site, login)
        if key in self._keys:
            idx = self._keys.index(key)
            self._keys.pop(idx)
            self._values.pop(idx)
            return True
        return False

    def keys(self) -> list[str]:
        return list(self._keys)

    def values(self) -> list[PasswordEntry]:
        return list(self._values)

    def items(self) -> list[tuple[str, PasswordEntry]]:
        return list(zip(self._keys, self._values))

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key: str) -> bool:
        return key in self._keys

    def __iter__(self):
        return iter(self._values)

    def __repr__(self) -> str:
        return f"LoginMap(size={len(self)})"

    def __str__(self) -> str:
        return "\n".join(str(v) for v in self._values)

# ГЕНЕРАТОР ПАРОЛЕЙ

class PasswordGenerator(BaseEntity):
    """Генератор паролей с настраиваемыми параметрами."""

    def __init__(self):
        self._use_lower = True
        self._use_upper = True
        self._use_digits = True
        self._use_symbols = False
        self._length = 12

    @property
    def length(self) -> int:
        return self._length

    @length.setter
    def length(self, value: int) -> None:
        if value < 4:
            raise ValueError("Длина пароля должна быть >= 4")
        self._length = value

    @property
    def use_lower(self) -> bool:
        return self._use_lower

    @use_lower.setter
    def use_lower(self, value: bool) -> None:
        self._use_lower = value

    @property
    def use_upper(self) -> bool:
        return self._use_upper

    @use_upper.setter
    def use_upper(self, value: bool) -> None:
        self._use_upper = value

    @property
    def use_digits(self) -> bool:
        return self._use_digits

    @use_digits.setter
    def use_digits(self, value: bool) -> None:
        self._use_digits = value

    @property
    def use_symbols(self) -> bool:
        return self._use_symbols

    @use_symbols.setter
    def use_symbols(self, value: bool) -> None:
        self._use_symbols = value

    @staticmethod
    def estimate_strength(password: str) -> str:
        score = 0
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        if len(password) >= 12:
            score += 1
        return {1: "Очень слабый", 2: "Слабый", 3: "Средний",
                4: "Сильный", 5: "Очень сильный"}.get(score, "Очень слабый")

    def generate(self) -> str:
        alphabet = ""
        if self._use_lower:
            alphabet += string.ascii_lowercase
        if self._use_upper:
            alphabet += string.ascii_uppercase
        if self._use_digits:
            alphabet += string.digits
        if self._use_symbols:
            alphabet += "!@#$%^&*()-_=+"
        if not alphabet:
            raise ValueError("Выберите хотя бы один набор символов")

        password_chars = []
        if self._use_lower:
            password_chars.append(random.choice(string.ascii_lowercase))
        if self._use_upper:
            password_chars.append(random.choice(string.ascii_uppercase))
        if self._use_digits:
            password_chars.append(random.choice(string.digits))
        if self._use_symbols:
            password_chars.append(random.choice("!@#$%^&*()-_=+"))

        while len(password_chars) < self._length:
            password_chars.append(random.choice(alphabet))

        random.shuffle(password_chars)
        return "".join(password_chars[:self._length])

    def describe(self) -> str:
        return (f"Generator(len={self._length}, lower={self._use_lower}, "
                f"upper={self._use_upper}, digits={self._use_digits}, "
                f"symbols={self._use_symbols})")

class TitleText(BaseUI):
    def __init__(self, text: str):
        self._text = text

    def build(self) -> ft.Control:
        return ft.Text(self._text, size=24, weight=ft.FontWeight.BOLD,
                       text_align=ft.TextAlign.CENTER)


class InputField(BaseUI):
    def __init__(self, label: str, value: str = "", password: bool = False,
                 width: int = 320):
        self._label = label
        self._value = value
        self._password = password
        self._width = width

    @property
    def control(self) -> ft.TextField:
        tf = ft.TextField(label=self._label, value=self._value,
                          password=self._password, width=self._width,
                          text_align=ft.TextAlign.LEFT)
        return tf

    def build(self) -> ft.Control:
        return self.control


class PasswordLengthSlider(BaseUI):
    def __init__(self, on_change, initial: int = 12):
        self._on_change = on_change
        self._initial = initial

    def build(self) -> ft.Control:
        return ft.Slider(min=4, max=32, divisions=28, value=self._initial,
                         label="{value}", on_change=self._on_change,
                         width=320)


class OptionCheckbox(BaseUI):
    def __init__(self, label: str, value: bool, on_change):
        self._label = label
        self._value = value
        self._on_change = on_change

    def build(self) -> ft.Control:
        return ft.Checkbox(label=self._label, value=self._value,
                           on_change=self._on_change)


class ActionButton(BaseUI):
    def __init__(self, text: str, on_click, icon: str = None):
        self._text = text
        self._on_click = on_click
        self._icon = icon

    def build(self) -> ft.Control:
        return ft.Button(content=ft.Text(self._text), icon=self._icon,
                         on_click=self._on_click, width=200)


class ClearButton(BaseUI):
    def __init__(self, on_click):
        self._on_click = on_click

    def build(self) -> ft.Control:
        return ft.OutlinedButton(content=ft.Text("Очистить историю"),
                                 on_click=self._on_click, width=200)

    class EntryRow(BaseUI):

        def __init__(self, entry: PasswordEntry):
            self._entry = entry

        def build(self) -> ft.Control:
            return ft.Container(
                content=ft.Row([
                    ft.Text(f"{self._entry.site}", width=120,
                            weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    ft.Text(self._entry.login, width=120, color=ft.Colors.WHITE),
                    ft.Text(self._entry.password, width=120, selectable=True,
                            color=ft.Colors.LIGHT_GREEN),
                    ft.Text(f"{self._entry.length}", width=60,
                            color=ft.Colors.WHITE),
                    ft.Text(self._entry.created_at.strftime("%d.%m.%Y %H:%M:%S"),
                            width=160, color=ft.Colors.WHITE),
                ]),
                padding=6,
                bgcolor=ft.Colors.BLUE_GREY_900,
                border_radius=6,
            )


class HistoryList(BaseUI):
    def __init__(self, entries: list[PasswordEntry]):
        self._entries = entries

    def build(self) -> ft.Control:
        rows = []
        for e in self._entries:
            rows.append(
                ft.Container(
                    content=ft.Row([
                        ft.Text(f"{e.site}", width=120,
                                weight=ft.FontWeight.BOLD,
                                color=ft.Colors.WHITE),
                        ft.Text(e.login, width=120, color=ft.Colors.WHITE),
                        ft.Text(e.password, width=120, selectable=True,
                                color=ft.Colors.LIGHT_GREEN),
                        ft.Text(f"{e.length}", width=60,
                                color=ft.Colors.WHITE),
                        ft.Text(e.created_at.strftime("%d.%m.%Y %H:%M:%S"),
                                width=160, color=ft.Colors.WHITE),
                    ]),
                    padding=6,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    border_radius=6,
                )
            )
        return ft.Column(rows, spacing=4, scroll=ft.ScrollMode.AUTO,
                         height=220,
                         horizontal_alignment=ft.CrossAxisAlignment.CENTER)


class StrengthIndicator(BaseUI):
    def __init__(self, text: str = ""):
        self._text = text
        self._control = ft.Text(text, size=14, italic=True,
                                text_align=ft.TextAlign.CENTER)

    @property
    def control(self) -> ft.Text:
        return self._control

    def build(self) -> ft.Control:
        return self._control


class StatusText(BaseUI):
    def __init__(self, text: str = ""):
        self._text = text
        self._control = ft.Text(text, size=14, color=ft.Colors.GREEN,
                                text_align=ft.TextAlign.CENTER)

    @property
    def control(self) -> ft.Text:
        return self._control

    def build(self) -> ft.Control:
        return self._control


class HeaderRow(BaseUI):
    def build(self) -> ft.Control:
        return ft.Container(
            content=ft.Row([
                ft.Text("Сайт", width=120, weight=ft.FontWeight.BOLD,
                        color=ft.Colors.WHITE),
                ft.Text("Логин", width=120, weight=ft.FontWeight.BOLD,
                        color=ft.Colors.WHITE),
                ft.Text("Пароль", width=120, weight=ft.FontWeight.BOLD,
                        color=ft.Colors.WHITE),
                ft.Text("Длина", width=60, weight=ft.FontWeight.BOLD,
                        color=ft.Colors.WHITE),
                ft.Text("Создан", width=160, weight=ft.FontWeight.BOLD,
                        color=ft.Colors.WHITE),
            ]),
            padding=6,
            bgcolor=ft.Colors.BLUE_GREY_700,
            border_radius=6,
        )


class CopyButton(BaseUI):
    def __init__(self, on_click):
        self._on_click = on_click

    def build(self) -> ft.Control:
        return ft.IconButton(icon=ft.Icons.COPY, tooltip="Копировать",
                             on_click=self._on_click)


# ГЛАВНОЕ ПРИЛОЖЕНИЕ

class PasswordApp:

    REPORT_FILE = "report.txt"

    def __init__(self, page: ft.Page, user: User):
        self.page = page
        self.user = user
        self.generator = PasswordGenerator()
        self.storage = LoginMap()

        self.site_field = InputField("Сайт (например, github.com)").control
        self.login_field = InputField("Логин").control
        self.result_field = InputField("Сгенерированный пароль",
                                       password=False).control
        self.length_slider = PasswordLengthSlider(self._on_length_change, 12).build()
        self.length_label = ft.Text("Длина: 12", text_align=ft.TextAlign.CENTER)

        self.cb_lower = OptionCheckbox("Строчные (a-z)", True,
                                       self._on_opt_change).build()
        self.cb_upper = OptionCheckbox("Прописные (A-Z)", True,
                                       self._on_opt_change).build()
        self.cb_digits = OptionCheckbox("Цифры (0-9)", True,
                                        self._on_opt_change).build()
        self.cb_symbols = OptionCheckbox("Спецсимволы (!@#...)", False,
                                         self._on_opt_change).build()

        self.strength = StrengthIndicator()
        self.status = StatusText()
        self.history_container = ft.Column(
            [HeaderRow().build(), HistoryList([]).build()],
            spacing=6,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        self._build_page()

    def _on_length_change(self, e):
        self.generator.length = int(e.control.value)
        self.length_label.value = f"Длина: {self.generator.length}"
        self.page.update()

    def _on_opt_change(self, e):
        self.generator.use_lower = self.cb_lower.value
        self.generator.use_upper = self.cb_upper.value
        self.generator.use_digits = self.cb_digits.value
        self.generator.use_symbols = self.cb_symbols.value

    def _on_generate(self, e):
        try:
            pwd = self.generator.generate()
            self.result_field.value = pwd
            self.strength.control.value = \
                f"Надёжность: {PasswordGenerator.estimate_strength(pwd)}"
            self.status.control.value = "Пароль сгенерирован"
        except ValueError as ex:
            self.status.control.value = f"Ошибка: {ex}"
        self.page.update()

    def _on_save(self, e):
        if not self.result_field.value:
            self.status.control.value = "Сначала сгенерируйте пароль"
            self.page.update()
            return
        site = self.site_field.value.strip() or "unknown"
        login = self.login_field.value.strip() or "user"
        entry = PasswordEntry(site, login, self.result_field.value)
        self.storage.put(entry)
        self._refresh_history()
        self.status.control.value = f"Сохранено: {entry.site}/{entry.login}"
        self.page.update()

    def _on_clear(self, e):
        self.storage = LoginMap()
        self._refresh_history()
        self.status.control.value = "История очищена"
        self.page.update()

    async def _on_copy(self, e):
        if self.result_field.value:
            await ft.Clipboard().set(self.result_field.value)
            self.status.control.value = "Пароль скопирован"
            self.page.update()

    def _refresh_history(self):
        entries = self.storage.values()
        self.history_container.controls = [
            HeaderRow().build(),
            HistoryList(entries).build(),
        ]

    def _build_page(self):
        self.page.title = "Генератор паролей"
        self.page.window_width = 720
        self.page.window_height = 780
        self.page.scroll = ft.ScrollMode.AUTO
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        self.page.add(
            ft.Column(
                [
                    TitleText("🔐 Генератор паролей").build(),
                    ft.Text(f"Пользователь: {self.user.login}",
                            text_align=ft.TextAlign.CENTER),
                    ft.Divider(),
                    self.site_field,
                    self.login_field,
                    self.length_label,
                    self.length_slider,
                    ft.Row([self.cb_lower, self.cb_upper],
                           alignment=ft.MainAxisAlignment.CENTER),
                    ft.Row([self.cb_digits, self.cb_symbols],
                           alignment=ft.MainAxisAlignment.CENTER),
                    ft.Row(
                        [self.result_field, CopyButton(self._on_copy).build()],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    self.strength.control,
                    ft.Row(
                        [ActionButton("Сгенерировать", self._on_generate,
                                      "refresh").build(),
                         ActionButton("Сохранить", self._on_save,
                                      "save").build()],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ClearButton(self._on_clear).build(),
                    self.status.control,
                    ft.Divider(),
                    ft.Text("История:", weight=ft.FontWeight.BOLD),
                    self.history_container,
                ],
                spacing=12,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            )
        )

    def save_report(self):
        self.user.time_out = datetime.now()
        fmt = "%d.%m.%Y %H:%M:%S"
        lines = [
            "+ | login | time_in | time_out |",
            "|---|---|---|---|",
        ]
        t_in = self.user.time_in.strftime(fmt) if self.user.time_in else ""
        t_out = self.user.time_out.strftime(fmt) if self.user.time_out else ""
        lines.append(f"| {self.user.login} | {t_in} | {t_out} |")
        lines.append("+")
        with open(self.REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

def main(page: ft.Page):
    user = User("UserName")
    user.time_in = datetime.now()
    app = PasswordApp(page, user)
    atexit.register(app.save_report)
    page.update()


if __name__ == "__main__":
    ft.run(main)
