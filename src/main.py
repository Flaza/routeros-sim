"""Flet-интерфейс для симулятора RouterOS Packet Flow (мобильная версия)."""
import flet as ft

from routeros_core import (
    RouterOSParser,
    PacketSimulator,
    resolve_target,
)


def main(page: ft.Page):
    page.title = "RouterOS Sim"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 8
    page.scroll = ft.ScrollMode.AUTO

    # --- общие ссылки ---
    state = {
        "parser": None,
        "simulator": None,
        "overrides": {},
    }

    # ============ Вкладка КОНФИГ ============
    config_input = ft.TextField(
        label="Конфигурация MikroTik",
        multiline=True,
        min_lines=12,
        max_lines=20,
        text_style=ft.TextStyle(font_family="monospace", size=11),
        expand=True,
    )

    config_status = ft.Text(value="Конфиг не загружен", color=ft.Colors.ORANGE_300)

    file_picker = ft.FilePicker()

    def on_file_picked(e: ft.FilePickerResultEvent):
        if not e.files:
            return
        f = e.files[0]
        try:
            with open(f.path, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
            config_input.value = content
            config_status.value = f"Загружен: {f.name} ({len(content)} байт)"
            config_status.color = ft.Colors.GREEN_300
            parse_config()
        except Exception as ex:
            config_status.value = f"Ошибка: {ex}"
            config_status.color = ft.Colors.RED_300
        page.update()

    file_picker.on_result = on_file_picked
    page.overlay.append(file_picker)

    def pick_file(e):
        file_picker.pick_files(
            dialog_title="Выберите .rsc файл",
            allowed_extensions=["rsc", "txt", "conf"],
            allow_multiple=False,
        )

    def clear_config(e):
        config_input.value = ""
        config_status.value = "Очищено"
        config_status.color = ft.Colors.ORANGE_300
        page.update()

    def parse_config():
        cfg = config_input.value or ""
        if len(cfg.strip()) < 20:
            config_status.value = "Вставьте конфигурацию"
            config_status.color = ft.Colors.ORANGE_300
            page.update()
            return
        try:
            parser = RouterOSParser()
            parser.parse_config(cfg)
            state["parser"] = parser
            state["simulator"] = PacketSimulator(parser)

            n_mangle = len(parser.mangle_rules)
            n_nat = len(parser.nat_rules)
            n_filter = len(parser.filter_rules)
            n_raw = len(parser.raw_rules)
            n_routes = len(parser.routes) + len(parser.connected_routes)
            n_arp = len(parser.arp_entries)

            config_status.value = (
                f"v{parser.ros_version} | mangle={n_mangle} nat={n_nat} "
                f"filter={n_filter} raw={n_raw} routes={n_routes} arp={n_arp}"
            )
            config_status.color = ft.Colors.GREEN_300
            rebuild_rules()
            rebuild_src_dst()
        except Exception as ex:
            config_status.value = f"Ошибка парсинга: {ex}"
            config_status.color = ft.Colors.RED_300
        page.update()

    def parse_config_click(e):
        parse_config()

    config_tab = ft.Column(
        [
            ft.Row(
                [
                    ft.ElevatedButton("📂 Загрузить .rsc", on_click=pick_file),
                    ft.OutlinedButton("🗑 Очистить", on_click=clear_config),
                    ft.ElevatedButton("🔍 Разобрать", on_click=parse_config_click),
                ],
                wrap=True,
            ),
            config_status,
            ft.Divider(height=1),
            config_input,
        ],
        expand=True,
    )

    # ============ Вкладка ПАРАМЕТРЫ ============
    src_dd = ft.Dropdown(label="Источник (src IP)", options=[], width=400)
    dst_dd = ft.Dropdown(label="Назначение (домен/IP)", options=[], width=400)
    manual_switch = ft.Switch(label="Ручной ввод цели", value=False)
    manual_input = ft.TextField(
        label="Домен или IP",
        value="",
        visible=False,
    )

    def on_manual_toggle(e):
        manual_input.visible = manual_switch.value
        dst_dd.disabled = manual_switch.value
        page.update()

    manual_switch.on_change = on_manual_toggle

    proto_dd = ft.Dropdown(
        label="Протокол",
        value="tcp",
        options=[ft.dropdown.Option(x) for x in ("tcp", "udp", "icmp")],
        width=140,
    )
    state_dd = ft.Dropdown(
        label="State",
        value="new",
        options=[ft.dropdown.Option(x) for x in
                 ("new", "established", "related", "invalid", "untracked")],
        width=180,
    )
    src_port = ft.TextField(label="src порт", value="12345", width=140)
    dst_port = ft.TextField(label="dst порт", value="443", width=140)

    params_tab = ft.Column(
        [
            ft.Text("Источник и назначение", weight=ft.FontWeight.BOLD, size=16),
            src_dd,
            dst_dd,
            manual_switch,
            manual_input,
            ft.Divider(),
            ft.Text("Протокол и порты", weight=ft.FontWeight.BOLD, size=16),
            ft.Row([proto_dd, state_dd], wrap=True),
            ft.Row([src_port, dst_port], wrap=True),
        ],
        spacing=12,
    )

    # ============ Вкладка ПРАВИЛА ============
    rules_list = ft.ListView(expand=True, spacing=2)

    rules_tab = ft.Column(
        [
            ft.Text("Активные правила (тап — вкл/выкл)",
                    weight=ft.FontWeight.BOLD, size=16),
            rules_list,
        ],
        expand=True,
    )

    def _rule_row(kind: str, idx: int, label: str, desc: str, disabled: bool):
        key = f"{kind}_{idx}"

        def on_toggle(e):
            state["overrides"][key] = cb.value
            page.update()

        cb = ft.Checkbox(
            value=not disabled,
            on_change=on_toggle,
        )
        state["overrides"][key] = not disabled
        return ft.Row(
            [
                cb,
                ft.Column(
                    [
                        ft.Text(f"{label} #{idx}", size=11,
                                color=ft.Colors.BLUE_200),
                        ft.Text(desc, size=11,
                                font_family="monospace",
                                selectable=True),
                    ],
                    spacing=0,
                    expand=True,
                ),
            ],
            spacing=4,
        )

    def rebuild_rules():
        rules_list.controls.clear()
        p = state["parser"]
        if p is None:
            rules_list.controls.append(
                ft.Text("Сначала разберите конфиг", color=ft.Colors.ORANGE_300)
            )
            page.update()
            return

        for idx, r in enumerate(p.raw_rules):
            rules_list.controls.append(
                _rule_row("raw", idx, "RAW",
                          f"chain={r['chain']} action={r['action']}",
                          r.get("disabled", False)))
        for idx, r in enumerate(p.mangle_rules):
            rules_list.controls.append(
                _rule_row("mangle", idx, "MANGLE",
                          f"chain={r['chain']} action={r['action']}",
                          r.get("disabled", False)))
        for idx, r in enumerate(p.nat_rules):
            rules_list.controls.append(
                _rule_row("nat", idx, "NAT",
                          f"chain={r['chain']} action={r['action']}",
                          r.get("disabled", False)))
        for idx, r in enumerate(p.filter_rules):
            rules_list.controls.append(
                _rule_row("filter", idx, "FILTER",
                          f"chain={r['chain']} action={r['action']}",
                          r.get("disabled", False)))
        for idx, r in enumerate(p.routes):
            rules_list.controls.append(
                _rule_row("route", idx, "ROUTE",
                          f"dst={r['dst']} via {r['gateway']} table={r['table']}",
                          r.get("disabled", False)))
        page.update()

    # ============ Вкладка РЕЗУЛЬТАТ ============
    graph_canvas = ft.canvas.Canvas(
        width=1200,
        height=200,
        shapes=[],
    )

    log_output = ft.Text(
        value="Лог пуст. Разберите конфиг и нажмите Симулировать.",
        selectable=True,
        font_family="monospace",
        size=11,
    )

    summary = ft.Text(value="—", size=14, weight=ft.FontWeight.BOLD)

    result_tab = ft.Column(
        [
            ft.Text("Граф маршрута", weight=ft.FontWeight.BOLD, size=16),
            ft.Container(
                content=graph_canvas,
                bgcolor=ft.Colors.BLACK,
                border_radius=8,
                padding=4,
                height=210,
            ),
            ft.Divider(),
            ft.Text("Итог:", weight=ft.FontWeight.BOLD),
            summary,
            ft.Divider(),
            ft.Text("Packet Flow Log:", weight=ft.FontWeight.BOLD, size=16),
            log_output,
        ],
        spacing=10,
        scroll=ft.ScrollMode.AUTO,
    )

    def draw_graph(path):
        shapes = []
        if not path:
            graph_canvas.shapes = shapes
            page.update()
            return
        n = len(path)
        cx = 60
        cy = 100
        dx = max(120, int(1100 / max(n - 1, 1)))
        colors = {
            "SRC": ft.Colors.GREEN_400,
            "ROUTE": ft.Colors.BLUE_400,
            "NAT": ft.Colors.ORANGE_400,
            "DST": ft.Colors.PURPLE_400,
            "DROP": ft.Colors.RED_400,
        }
        positions = []
        for i in range(n):
            positions.append((cx + i * dx, cy))

        # стрелки
        for i in range(n - 1):
            x1, y1 = positions[i]
            x2, y2 = positions[i + 1]
            shapes.append(
                ft.canvas.Line(
                    x1 + 40, y1, x2 - 40, y2,
                    paint=ft.Paint(color=ft.Colors.GREY_700, stroke_width=2),
                )
            )
        # кружки
        for i, (kind, label) in enumerate(path):
            x, y = positions[i]
            color = colors.get(kind, ft.Colors.GREY_500)
            shapes.append(
                ft.canvas.Circle(
                    x, y, 38,
                    paint=ft.Paint(color=color, style=ft.PaintingStyle.STROKE, stroke_width=3),
                )
            )
            shapes.append(
                ft.canvas.Text(
                    x - 30, y - 24, 60, 16, kind,
                    paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL),
                )
            )
            first_line = label.split("\n")[0][:14]
            shapes.append(
                ft.canvas.Text(
                    x - 34, y, 68, 16, first_line,
                    paint=ft.Paint(color=ft.Colors.WHITE, style=ft.PaintingStyle.FILL),
                )
            )
        graph_canvas.shapes = shapes
        page.update()

    def run_sim(e):
        p = state["parser"]
        if p is None:
            summary.value = "Сначала разберите конфиг (вкладка Конфиг)"
            page.update()
            return
        cfg = config_input.value or ""

        try:
            # заново парсим, чтобы учесть переключённые чекбоксы
            parser = RouterOSParser()
            parser.parse_config(cfg)
            parser = copy_with_overrides(parser, state["overrides"])
            state["parser"] = parser

            src_ip = (src_dd.value or "").strip()
            if not src_ip:
                summary.value = "Выберите источник"
                page.update()
                return

            if manual_switch.value:
                target_raw = (manual_input.value or "").strip()
            else:
                target_raw = (dst_dd.value or "").strip()
                if " → " in target_raw:
                    target_raw = target_raw.split(" → ", 1)[0]

            domain, dst_ip, note = resolve_target(target_raw, parser)
            if domain is None:
                summary.value = f"Цель не распознана: {note}"
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
                src_ip=src_ip,
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
            summary.value = sim.summary[0]
            draw_graph(sim.route_path)

            # переключимся на вкладку результата
            tabs.selected_index = 3
        except Exception as ex:
            summary.value = f"Ошибка: {ex}"
        page.update()

    # ============ сборка ============
    def copy_with_overrides(parser, overrides):
        """Применяет overrides (вкл/выкл правил) к парсеру."""
        for key, enabled in overrides.items():
            kind, _, idx_s = key.partition("_")
            try:
                idx = int(idx_s)
            except ValueError:
                continue
            if kind == "raw" and 0 <= idx < len(parser.raw_rules):
                parser.raw_rules[idx]["disabled"] = not enabled
            elif kind == "mangle" and 0 <= idx < len(parser.mangle_rules):
                parser.mangle_rules[idx]["disabled"] = not enabled
            elif kind == "nat" and 0 <= idx < len(parser.nat_rules):
                parser.nat_rules[idx]["disabled"] = not enabled
            elif kind == "filter" and 0 <= idx < len(parser.filter_rules):
                parser.filter_rules[idx]["disabled"] = not enabled
            elif kind == "route" and 0 <= idx < len(parser.routes):
                parser.routes[idx]["disabled"] = not enabled
        parser._invalidate_routes_cache()
        return parser

    def rebuild_src_dst():
        p = state["parser"]
        if p is None:
            return
        src_opts = []
        for ip in sorted(p.arp_entries.keys()):
            info = p.arp_entries[ip]
            src_opts.append(ft.dropdown.Option(f"{ip}  —  {info['comment']}"))
        if not src_opts:
            src_opts = [ft.dropdown.Option("(нет записей /ip arp)")]
        src_dd.options = src_opts
        if src_dd.value is None:
            src_dd.value = src_opts[0].key

        dst_opts = []
        for name, ip in sorted(p.dns_static.items()):
            dst_opts.append(ft.dropdown.Option(f"{name} → {ip}"))
        for dom in sorted(p.all_domains):
            if dom in p.dns_static:
                continue
            dst_opts.append(ft.dropdown.Option(f"{dom} → ?"))
        if not dst_opts:
            dst_opts = [ft.dropdown.Option("example.com → ?")]
        dst_dd.options = dst_opts
        if dst_dd.value is None:
            dst_dd.value = dst_opts[0].key

    tabs = ft.Tabs(
        selected_index=0,
        animation_duration=200,
        tabs=[
            ft.Tab(text="Конфиг", content=config_tab),
            ft.Tab(text="Параметры", content=params_tab),
            ft.Tab(text="Правила", content=rules_tab),
            ft.Tab(text="Результат", content=result_tab),
        ],
        expand=True,
    )

    page.appbar = ft.AppBar(
        title=ft.Text("RouterOS Sim"),
        bgcolor=ft.Colors.BLUE_900,
        actions=[
            ft.IconButton(
                icon=ft.Icons.PLAY_ARROW,
                tooltip="Симулировать",
                on_click=run_sim,
            ),
        ],
    )

    page.add(tabs)


ft.app(main)
