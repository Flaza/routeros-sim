"""Flet-интерфейс для симулятора RouterOS Packet Flow."""
import flet as ft

from routeros_core import (
    RouterOSParser,
    PacketSimulator,
    resolve_target,
)


def main(page: ft.Page):
    page.title = "RouterOS Packet Flow Simulator"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 10
    page.scroll = ft.ScrollMode.AUTO

    config_input = ft.TextField(
        label="Конфигурация MikroTik (rsc / txt)",
        multiline=True,
        min_lines=8,
        max_lines=14,
        text_style=ft.TextStyle(font_family="monospace", size=12),
    )

    src_input = ft.TextField(label="Источник (src IP)", value="192.168.88.100")
    dst_input = ft.TextField(label="Назначение (домен/IP)", value="example.com")

    proto_dd = ft.Dropdown(
        label="Протокол",
        value="tcp",
        options=[ft.dropdown.Option(x) for x in ("tcp", "udp", "icmp")],
    )
    src_port = ft.TextField(label="src порт", value="12345", width=120)
    dst_port = ft.TextField(label="dst порт", value="443", width=120)

    state_dd = ft.Dropdown(
        label="Состояние",
        value="new",
        options=[ft.dropdown.Option(x) for x in
                 ("new", "established", "related", "invalid", "untracked")],
    )

    log_output = ft.Text(
        value="",
        selectable=True,
        font_family="monospace",
        size=11,
    )

    status = ft.Text(value="Готов", color=ft.Colors.BLUE_200)

    def run_sim(e):
        cfg = config_input.value or ""
        if len(cfg.strip()) < 20:
            status.value = "Вставьте конфигурацию."
            page.update()
            return

        try:
            parser = RouterOSParser()
            parser.parse_config(cfg)

            target_raw = (dst_input.value or "").strip()
            domain, dst_ip, note = resolve_target(target_raw, parser)
            if domain is None:
                status.value = f"Цель не распознана: {note}"
                page.update()
                return

            try:
                sp = int(src_port.value) if src_port.value else None
            except ValueError:
                sp = None
            try:
                dp = int(dst_port.value) if dst_port.value else None
            except ValueError:
                dp = None

            sim = PacketSimulator(parser)
            sim.simulate(
                src_ip=(src_input.value or "").strip(),
                dst_domain=domain,
                dst_ip=dst_ip or "0.0.0.0",
                resolution_note=note,
                protocol=proto_dd.value or "tcp",
                dst_port=dp,
                src_port=sp,
                conn_state=state_dd.value or "new",
            )

            lines = []
            for text, tag in sim.log:
                prefix = ""
                if tag == "drop":
                    prefix = "✗ "
                elif tag == "ok":
                    prefix = "✓ "
                elif tag == "warn":
                    prefix = "⚠ "
                elif tag == "stage":
                    prefix = "▶ "
                lines.append(prefix + text)
            log_output.value = "\n".join(lines)
            status.value = sim.summary[0]
        except Exception as ex:
            status.value = f"Ошибка: {ex}"
        page.update()

    page.add(
        ft.Text("RouterOS Packet Flow Simulator", size=22, weight=ft.FontWeight.BOLD),
        config_input,
        ft.Row([src_input, dst_input]),
        ft.Row([proto_dd, src_port, dst_port, state_dd]),
        ft.ElevatedButton("▶ Симулировать", on_click=run_sim),
        ft.Divider(),
        status,
        ft.Text("Packet Flow Log:", weight=ft.FontWeight.BOLD),
        log_output,
    )


ft.app(main)
