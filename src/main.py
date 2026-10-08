"""Flet-интерфейс для симулятора RouterOS Packet Flow (кнопочная навигация)."""
import flet as ft
import flet_permission_handler as fph

from routeros_core import (
    RouterOSParser,
    PacketSimulator,
    resolve_target,
)

TAB_CONFIG = 0
TAB_PARAMS = 1
TAB_RULES = 2
TAB_RESULT = 3


def main(page: ft.Page):
    page.title = "RouterOS Sim"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.scroll = None

    state = {
        "parser": None,
        "simulator": None,
        "overrides": {},
        "current_tab": TAB_CONFIG,
    }

    # --- Permission handler ---
    ph = fph.PermissionHandler()
    page.overlay.append(ph)

    def request_storage(e):
        try:
            status = ph.request_permission(
                fph.PermissionType.MANAGE_EXTERNAL_STORAGE
            )
            config_status.value = f"Разрешение на файлы: {status}"
            config_status.color = ft.Colors.GREEN_300
        except Exception as ex:
            config_status.value = f"Ошибка запроса разрешения: {ex}"
            config_status.color = ft.Colors.RED_300
        page.update()

    # --- КОНФИГ ---
    config_input = ft.TextField(
        label="Конфигурация MikroTik",
        multiline=True,
        text_style=ft.TextStyle(font_family="monospace", size=11),
        expand=True,
    )

    config_status = ft.Text(value="Конфиг не загружен", color=ft.Colors.ORANGE_300)

    file_picker = ft.FilePicker()

    def on_file_picked(e: ft.FilePickerResultEvent):
        if not e.files:
            config_status.value = "Диалог закрыт без выбора файла"
            config_status.color = ft.Colors.ORANGE_300
            page.update()
            return
        f = e.files[0]
        info = f"name={f.name} path={f.path} size={f.size}"
        try:
            content = None
            if getattr(f, "bytes", None):
                content = f.bytes.decode("utf-8", errors="ignore")
                info += " [via bytes]"
            else:
                with open(f.path, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                info += " [via path]"
            config_input.value = content
            config_status.value = f"OK: {info} ({len(content)} символов)"
            config_status.color = ft.Colors.GREEN_300
            parse_config()
        except Exception as ex:
            config_status.value = f"FAIL: {info} | err={ex}"
            config_status.color = ft.Colors.RED_300
        page.update()

    file_picker.on_result = on_file_picked
    page.overlay.append(file_picker)

    def pick_file(e):
        file_picker.pick_files(
            dialog_title="Выберите .rsc файл",
            allowed_extensions=["rsc", "txt", "conf"],
            allow_multiple=False,
            with_data=True,
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

    config_content = ft.Column(
        [
            ft.Row(
                [
                    ft.ElevatedButton("🔐 Разрешение", on_click=request_storage),
                    ft.ElevatedButton("📂 Загрузить .rsc", on_click=pick_file),
                    ft.OutlinedButton("🗑 Очистить", on_click=clear_config),
                    ft.ElevatedButton("🔍 Разобрать", on_click=lambda e: parse_config()),
                ],
                wrap=True,
            ),
            config_status,
            ft.Divider(height=1),
            config_input,
        ],
        expand=True,
        scroll=ft.ScrollMode.AUTO,
    )

    # --- ПАРАМЕТРЫ ---
    src_dd = ft.Dropdown(label="Источник (src IP)", options=[], width=400)
    dst_dd = ft.Dropdown(label="Назначение (домен/IP)", options=[], width=400)
    manual_switch = ft.Switch(label="Ручной ввод цели", value=False)
    manual_input = ft.TextField(label="Домен или IP", value="", visible=False)

    def on_manual_toggle(e):
        manual_input.visible = manual_switch.value
        dst_dd.disabled = manual_switch.value
        page.update()

    manual_switch.on_change = on_manual_toggle

    proto_dd = ft.Dropdown(
        label="Протокол", value="tcp",
        options=[ft.dropdown.Option(x) for x in ("tcp", "udp", "icmp")],
        width=140,
    )
    state_dd = ft.Dropdown(
        label="State", value="new",
        options=[ft.dropdown.Option(x) for x in
                 ("new", "established", "related", "invalid", "untracked")],
        width=180,
    )
    src_port = ft.TextField(label="src порт", value="12345", width=140)
    dst_port = ft.TextField(label="dst порт", value="443", width=140)

    params_content = ft.Column(
        [
            ft.Text("Источник и назначение", weight=ft.FontWeight.BOLD, size=16),
            src_dd, dst_dd, manual_switch, manual_input,
            ft.Divider(),
            ft.Text("Протокол и порты", weight=ft.FontWeight.BOLD, size=16),
            ft.Row([proto_dd, state_dd], wrap=True),
            ft.Row([src_port, dst_port], wrap=True),
        ],
        spacing=12,
        scroll=ft.ScrollMode.AUTO,
    )

    # --- ПРАВИЛА ---
    rules_list = ft.ListView(expand=True, spacing=2)

    rules_content = ft.Column(
        [
            ft.Text("Активные правила (тап — вкл/выкл)",
                    weight=ft.FontWeight.BOLD, size=16),
            rules_list,
        ],
        expand=True,
        scroll=ft.ScrollMode.AUTO,
    )

    def _rule_row(kind: str, idx: int, label: str, desc: str, disabled: bool):
        key = f"{kind}_{idx}"
        def on_toggle(e):
            state["overrides"][key] = cb.value
            page.update()
        cb = ft.Checkbox(value=not disabled, on_change=on_toggle)
        state["overrides"][key] = not disabled
        return ft.Row(
            [
                cb,
                ft.Column(
                    [
                        ft.Text(f"{label} #{idx}", size=11, color=ft.Colors.BLUE_200),
                        ft.Text(desc, size=11, font_family="monospace", selectable=True),
                    ],
                    spacing=0, expand=True,
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
            rules_list.controls.append(_rule_row("raw", idx, "RAW",
                f"chain={r['chain']} action={r['action']}", r.get("disabled", False)))
        for idx, r in enumerate(p.mangle_rules):
            rules_list.controls.append(_rule_row("mangle", idx, "MANGLE",
                f"chain={r['chain']} action={r['action']}", r.get("disabled", False)))
        for idx, r in enumerate(p.nat_rules):
            rules_list.controls.append(_rule_row("nat", idx, "NAT",
                f"chain={r['chain']} action={r['action']}", r.get("disabled", False)))
        for idx, r in enumerate(p.filter_rules):
            rules_list.controls.append(_rule_row("filter", idx, "FILTER",
                f"chain={r['chain']} action={r['action']}", r.get("disabled", False)))
        for idx, r in enumerate(p.routes):
            rules_list.controls.append(_rule_row("route", idx, "ROUTE",
                f"dst={r['dst']} via {r['gateway']} table={r['table']}", r.get("disabled", False)))
        page.update()

    # --- РЕЗУЛЬТАТ ---
    graph_canvas = ft.Container(
        content=ft.Text("Граф появится после симуляции", size=13, color=ft.Colors.GREY_500),
        bgcolor=ft.Colors.BLACK, border_radius=8, padding=8, height=220,
        alignment=ft.alignment.center,
    )

    log_output = ft.Text(value="Лог пуст.", selectable=True,
                         font_family="monospace", size=11)
    summary = ft.Text(value="—", size=14, weight=ft.FontWeight.BOLD)

    result_content = ft.Column(
        [
            ft.Text("Граф маршрута", weight=ft.FontWeight.BOLD, size=16),
            graph_canvas,
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

    def copy_with_overrides(parser, overrides):
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

    def run_sim(e):
        p = state["parser"]
        if p is None:
            summary.value = "Сначала разберите конфиг (вкладка Конфиг)"
            switch_tab(TAB_RESULT)
            page.update()
            return
        cfg = config_input.value or ""
        try:
            parser = RouterOSParser()
            parser.parse_config(cfg)
            parser = copy_with_overrides(parser, state["overrides"])
            state["parser"] = parser

            src_ip = (src_dd.value or "").strip()
            if not src_ip:
                summary.value = "Выберите источник"
                switch_tab(TAB_RESULT)
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
                switch_tab(TAB_RESULT)
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
                src_ip=src_ip, dst_domain=domain, dst_ip=dst_ip or "0.0.0.0",
                resolution_note=note, protocol=proto_dd.value or "tcp",
                dst_port=dp, src_port=sp, conn_state=state_dd.value or "new",
            )

            lines = []
            for text, tag in sim.log:
                prefix = ""
                if tag == "drop": prefix = "✗ "
                elif tag == "ok": prefix = "✓ "
                elif tag == "warn": prefix = "⚠ "
                elif tag == "stage": prefix = "▶ "
                lines.append(prefix + text)
            log_output.value = "\n".join(lines)
            summary.value = sim.summary[0]

            if sim.route_path:
                graph_lines = []
                for kind, label in sim.route_path:
                    first = label.split("\n")[0][:40]
                    graph_lines.append(f"[{kind}] {first}")
                graph_canvas.content = ft.Text(
                    "\n".join(graph_lines), size=12,
                    font_family="monospace", color=ft.Colors.GREEN_300,
                )
            else:
                graph_canvas.content = ft.Text("Путь пуст", color=ft.Colors.GREY_500)

            switch_tab(TAB_RESULT)
        except Exception as ex:
            summary.value = f"Ошибка: {ex}"
            switch_tab(TAB_RESULT)
        page.update()

    content_area = ft.Container(expand=True)

    def switch_tab(idx: int):
        state["current_tab"] = idx
        if idx == TAB_CONFIG:
            content_area.content = config_content
        elif idx == TAB_PARAMS:
            content_area.content = params_content
        elif idx == TAB_RULES:
            content_area.content = rules_content
        elif idx == TAB_RESULT:
            content_area.content = result_content
        for i, btn in enumerate(nav_buttons):
            btn.style = ft.ButtonStyle(
                bgcolor=ft.Colors.BLUE_700 if i == idx else ft.Colors.BLUE_GREY_800,
                color=ft.Colors.WHITE,
            )
        page.update()

    def make_nav_button(text: str, idx: int):
        return ft.ElevatedButton(
            text=text,
            on_click=lambda e, i=idx: switch_tab(i),
            style=ft.ButtonStyle(
                bgcolor=ft.Colors.BLUE_GREY_800,
                color=ft.Colors.WHITE,
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            expand=True,
        )

    nav_buttons = [
        make_nav_button("Конфиг", TAB_CONFIG),
        make_nav_button("Параметры", TAB_PARAMS),
        make_nav_button("Правила", TAB_RULES),
        make_nav_button("Результат", TAB_RESULT),
    ]

    nav_bar = ft.Row(nav_buttons, spacing=4)

    switch_tab(TAB_CONFIG)

    page.add(
        ft.Container(
            content=ft.Column(
                [nav_bar, ft.Divider(height=1), content_area],
                spacing=4, expand=True,
            ),
            padding=8, expand=True,
        )
    )


ft.app(main)
