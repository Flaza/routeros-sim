"""
Kivy-интерфейс для симулятора RouterOS Packet Flow.
Логика — в routeros_core.py.
"""
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.clock import Clock
from kivy.core.window import Window
import threading

from routeros_core import (
    RouterOSParser,
    PacketSimulator,
    resolve_target,
)

Window.clearcolor = (0.055, 0.086, 0.125, 1)


class MainScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=8, spacing=6, **kwargs)

        self.add_widget(Label(
            text='RouterOS Packet Flow Simulator',
            size_hint_y=None, height=32,
            color=(0.31, 0.64, 1.0, 1),
            bold=True,
        ))

        self.add_widget(Label(
            text='Конфигурация MikroTik (rsc / txt)',
            size_hint_y=None, height=24,
            color=(0.31, 0.64, 1.0, 1),
        ))
        self.config_input = TextInput(
            multiline=True, font_size=12,
            background_color=(0.043, 0.071, 0.094, 1),
            foreground_color=(0.863, 0.906, 0.949, 1),
            cursor_color=(0.31, 0.64, 1.0, 1),
            size_hint_y=None, height=240,
        )
        self.add_widget(self.config_input)

        params = GridLayout(cols=2, size_hint_y=None, height=120, spacing=4)
        params.add_widget(Label(text='Источник (src IP):', color=(0.86, 0.90, 0.95, 1)))
        self.src_input = TextInput(text='192.168.88.100', multiline=False,
                                   background_color=(0.043, 0.071, 0.094, 1),
                                   foreground_color=(0.86, 0.90, 0.95, 1))
        params.add_widget(self.src_input)

        params.add_widget(Label(text='Назначение (домен/IP):', color=(0.86, 0.90, 0.95, 1)))
        self.dst_input = TextInput(text='example.com', multiline=False,
                                   background_color=(0.043, 0.071, 0.094, 1),
                                   foreground_color=(0.86, 0.90, 0.95, 1))
        params.add_widget(self.dst_input)

        params.add_widget(Label(text='Протокол:', color=(0.86, 0.90, 0.95, 1)))
        self.proto_spinner = Spinner(text='tcp', values=('tcp', 'udp', 'icmp'),
                                     background_color=(0.075, 0.125, 0.188, 1))
        params.add_widget(self.proto_spinner)

        params.add_widget(Label(text='Порты (src / dst):', color=(0.86, 0.90, 0.95, 1)))
        ports_box = BoxLayout(spacing=4)
        self.src_port = TextInput(text='12345', multiline=False,
                                  background_color=(0.043, 0.071, 0.094, 1),
                                  foreground_color=(0.86, 0.90, 0.95, 1))
        self.dst_port = TextInput(text='443', multiline=False,
                                  background_color=(0.043, 0.071, 0.094, 1),
                                  foreground_color=(0.86, 0.90, 0.95, 1))
        ports_box.add_widget(self.src_port)
        ports_box.add_widget(self.dst_port)
        params.add_widget(ports_box)

        params.add_widget(Label(text='Состояние:', color=(0.86, 0.90, 0.95, 1)))
        self.state_spinner = Spinner(
            text='new',
            values=('new', 'established', 'related', 'invalid', 'untracked'),
            background_color=(0.075, 0.125, 0.188, 1),
        )
        params.add_widget(self.state_spinner)
        self.add_widget(params)

        btn_box = BoxLayout(size_hint_y=None, height=48, spacing=6)
        run_btn = Button(text='▶ Запустить симуляцию',
                         background_color=(0.106, 0.302, 0.478, 1),
                         bold=True)
        run_btn.bind(on_press=self.run_simulation)
        btn_box.add_widget(run_btn)

        clear_btn = Button(text='🗑 Очистить',
                           background_color=(0.075, 0.125, 0.188, 1))
        clear_btn.bind(on_press=lambda *_: self.clear_all())
        btn_box.add_widget(clear_btn)
        self.add_widget(btn_box)

        self.add_widget(Label(text='Packet Flow Log',
                              size_hint_y=None, height=24,
                              color=(0.31, 0.64, 1.0, 1)))
        log_scroll = ScrollView()
        self.log_label = Label(
            text='Готов к работе...\n',
            size_hint_y=None, halign='left', valign='top',
            font_size=11, text_size=(Window.width - 30, None),
            color=(0.86, 0.90, 0.95, 1),
        )
        self.log_label.bind(texture_size=self._update_log_size)
        Window.bind(width=self._on_width_change)
        log_scroll.add_widget(self.log_label)
        self.add_widget(log_scroll)

    def _update_log_size(self, instance, size):
        instance.height = size[1]

    def _on_width_change(self, instance, width):
        self.log_label.text_size = (width - 30, None)

    def clear_all(self):
        self.config_input.text = ''
        self.log_label.text = 'Очищено.\n'

    def run_simulation(self, instance):
        config_text = self.config_input.text
        src_ip = self.src_input.text.strip()
        dst_raw = self.dst_input.text.strip()
        proto = self.proto_spinner.text
        state = self.state_spinner.text

        try:
            src_port = int(self.src_port.text.strip())
        except ValueError:
            src_port = None
        try:
            dst_port = int(self.dst_port.text.strip())
        except ValueError:
            dst_port = None

        if len(config_text.strip()) < 20:
            self.log_label.text = "⚠ Вставьте текст конфигурации.\n"
            return

        self.log_label.text = "Парсинг и симуляция...\n"

        def worker():
            try:
                parser = RouterOSParser()
                parser.parse_config(config_text)

                domain, dst_ip, note = resolve_target(dst_raw, parser)
                if domain is None:
                    Clock.schedule_once(lambda dt: self.update_log(
                        f"⚠ Не удалось интерпретировать цель: {note}\n"))
                    return

                sim = PacketSimulator(parser)
                sim.simulate(
                    src_ip, domain, dst_ip or '0.0.0.0',
                    overrides={}, resolution_note=note,
                    protocol=proto, dst_port=dst_port,
                    src_port=src_port, conn_state=state,
                )

                log_text = '\n'.join(
                    (f"[{tag}] {line}" if tag else line)
                    for line, tag in sim.log
                )
                log_text += f"\n\n═══ ИТОГ ═══\n{sim.summary[0]}\n"

                Clock.schedule_once(lambda dt: self.update_log(log_text))
            except Exception:
                import traceback
                err = traceback.format_exc()
                Clock.schedule_once(lambda dt: self.update_log(
                    f"Ошибка:\n{err}\n"))

        threading.Thread(target=worker, daemon=True).start()

    def update_log(self, text):
        self.log_label.text = text


class RouterOSSimApp(App):
    def build(self):
        return MainScreen()


if __name__ == '__main__':
    RouterOSSimApp().run()
