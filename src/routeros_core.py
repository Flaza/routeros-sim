"""
RouterOS Packet Flow Simulator — ядро (без GUI).
Используется из main.py (Kivy-интерфейс).

Оригинальный код mik15.py, из которого удалена только Tkinter-часть.
"""

import re
import copy
import ipaddress
import hashlib
import logging
import queue
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict, Union

logger = logging.getLogger(__name__)


# ============================================================
#  КОНСТАНТЫ
# ============================================================

MAX_RECURSIVE_DEPTH = 4
MAX_JUMP_DEPTH = 5
LOG_MAX_LINES = 5000
TREEVIEW_MAX_ROWS = 500

TABLE_MAIN = "main"
ACTION_LOOKUP = "lookup"
ACTION_LOOKUP_ONLY = "lookup-only-in-table"

STATE_NEW = "new"
STATE_ESTABLISHED = "established"
STATE_RELATED = "related"
STATE_INVALID = "invalid"
STATE_UNTRACKED = "untracked"

RPF_NO = "no"
RPF_LOOSE = "loose"
RPF_STRICT = "strict"

PROTO_TCP = "tcp"
PROTO_UDP = "udp"
PROTO_ICMP = "icmp"

PROTO_ALIAS: dict[str, tuple[str, ...]] = {
    PROTO_TCP: (PROTO_TCP, "6"),
    PROTO_UDP: (PROTO_UDP, "17"),
    PROTO_ICMP: (PROTO_ICMP, "1"),
}

DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-\.]+\.[A-Za-z]{2,}$")

_RE_ACTION = re.compile(r"action=([^\s]+)")
_RE_CHAIN = re.compile(r"chain=([^\s]+)")
_RE_PROTOCOL = re.compile(r"protocol=([^\s]+)")
_RE_SRC_ADDR = re.compile(r"src-address=([^\s]+)")
_RE_DST_ADDR = re.compile(r"dst-address=([^\s]+)")
_RE_SRC_LIST = re.compile(r"src-address-list=([^\s]+)")
_RE_DST_LIST = re.compile(r"dst-address-list=([^\s]+)")
_RE_IN_IFACE = re.compile(r"in-interface=([^\s]+)")
_RE_OUT_IFACE = re.compile(r"out-interface=([^\s]+)")
_RE_DST_PORT = re.compile(r"dst-port=([^\s]+)")
_RE_SRC_PORT = re.compile(r"src-port=([^\s]+)")
_RE_CONN_STATE = re.compile(r"connection-state=([^\s]+)")
_RE_CONN_MARK = re.compile(r"(?<!new-)connection-mark=([^\s]+)")
_RE_PKT_MARK = re.compile(r"(?<!new-)packet-mark=([^\s]+)")
_RE_ROUTING_MARK = re.compile(r"(?<!new-)routing-mark=([^\s]+)")
_RE_NEW_ROUTING_MARK = re.compile(r"new-routing-mark=([^\s]+)")
_RE_NEW_CONN_MARK = re.compile(r"new-connection-mark=([^\s]+)")
_RE_NEW_PKT_MARK = re.compile(r"new-packet-mark=([^\s]+)")
_RE_NEW_MSS = re.compile(r"new-mss=([^\s]+)")
_RE_NEW_TTL = re.compile(r"new-ttl=([^\s]+)")
_RE_NEW_DSCP = re.compile(r"new-dscp=([^\s]+)")
_RE_NEW_PRIORITY = re.compile(r"new-priority=([^\s]+)")
_RE_ADDR_LIST = re.compile(r"address-list=([^\s]+)")
_RE_ADDR_LIST_TO = re.compile(r"address-list-timeout=([^\s]+)")
_RE_JUMP_TARGET = re.compile(r"jump-target=([^\s]+)")
_RE_PASSTHROUGH = re.compile(r"passthrough=(\w+)")
_RE_TO_ADDRESSES = re.compile(r"to-addresses=([^\s]+)")
_RE_TO_PORTS = re.compile(r"to-ports=([^\s]+)")
_RE_COMMENT = re.compile(r'comment="((?:[^"\\]|\\.)*)"')
_RE_COMMENT_BARE = re.compile(r'comment=([^\s\]]+)')
_RE_ROUTING_TABLE = re.compile(r"(?<!routing-)table=([^\s]+)")
_RE_RPF_FILTER = re.compile(r"rp-filter=(\w+)")


# ============================================================
#  TYPED DICTS
# ============================================================

class AddressListItem(TypedDict):
    address: str
    comment: str
    disabled: bool


class MangleRule(TypedDict, total=False):
    action: str
    chain: str
    src_list: str | None
    dst_list: str | None
    dst_addr: str | None
    src_addr: str | None
    in_interface: str | None
    out_interface: str | None
    protocol: str | None
    dst_port: str | None
    src_port: str | None
    connection_state: str | None
    connection_mark: str | None
    packet_mark: str | None
    routing_mark: str | None
    new_routing_mark: str | None
    new_connection_mark: str | None
    new_packet_mark: str | None
    new_mss: str | None
    new_ttl: str | None
    new_dscp: str | None
    new_priority: str | None
    address_list: str | None
    address_list_timeout: str | None
    jump_target: str | None
    passthrough: bool
    comment: str
    disabled: bool


class NatRule(TypedDict, total=False):
    action: str
    chain: str
    out_interface: str | None
    in_interface: str | None
    dst_address: str | None
    dst_list: str | None
    src_list: str | None
    src_address: str | None
    to_addresses: str | None
    to_ports: str | None
    protocol: str | None
    dst_port: str | None
    src_port: str | None
    connection_state: str | None
    jump_target: str | None
    comment: str
    disabled: bool


class FilterRule(TypedDict, total=False):
    action: str
    chain: str
    protocol: str | None
    connection_state: str | None
    dst_address: str | None
    dst_list: str | None
    src_list: str | None
    src_address: str | None
    in_interface: str | None
    out_interface: str | None
    dst_port: str | None
    src_port: str | None
    connection_mark: str | None
    packet_mark: str | None
    routing_mark: str | None
    jump_target: str | None
    comment: str
    disabled: bool


class RawRule(TypedDict, total=False):
    action: str
    chain: str
    protocol: str | None
    connection_state: str | None
    src_list: str | None
    dst_list: str | None
    src_address: str | None
    dst_address: str | None
    in_interface: str | None
    out_interface: str | None
    dst_port: str | None
    src_port: str | None
    comment: str
    disabled: bool


class RouteEntry(TypedDict, total=False):
    dst: str
    gateway: str
    gateway_list: list[str]
    gateway_ip: str | None
    gateway_iface: str | None
    iface: str | None
    table: str
    comment: str
    disabled: bool
    distance: int
    scope: int
    target_scope: int
    pref_src: str | None
    type: str
    check_gateway: str | None
    vrf_interface: str | None
    route_tag: str | None
    dynamic: bool
    policy_only: bool


class RoutingRule(TypedDict, total=False):
    src_address: str | None
    dst_address: str | None
    src_list: str | None
    dst_list: str | None
    interface: str | None
    action: str
    table: str
    disabled: bool


class ArpEntry(TypedDict):
    comment: str
    interface: str
    invalid: bool
    incomplete: bool


# ============================================================
#  УТИЛИТЫ
# ============================================================

def _normalize_ip(ip: str) -> str:
    return ip.strip().split("%")[0]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _ip_in_network(ip: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except (ValueError, TypeError):
        return False


def _port_in_rule(rule_port: str | None, our_port: int | None) -> bool:
    if rule_port is None:
        return True
    if our_port is None:
        return False
    for chunk in str(rule_port).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo_s, hi_s = chunk.split("-", 1)
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
                if lo <= our_port <= hi:
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(chunk) == our_port:
                    return True
            except ValueError:
                continue
    return False


def _ecmp_hash_v7(src_ip: str, dst_ip: str,
                  src_port: int | None = None,
                  dst_port: int | None = None,
                  proto: str = "tcp",
                  routing_mark: str = TABLE_MAIN) -> int:
    parts = [src_ip, dst_ip, str(src_port or 0), str(dst_port or 0),
             proto, routing_mark or TABLE_MAIN]
    key = "|".join(parts).encode()
    h = hashlib.md5(key).hexdigest()
    return int(h, 16)


def resolve_domain_to_ips(domain: str, parser: "RouterOSParser") -> set[str]:
    domain = domain.rstrip(".").lower()
    ips: set[str] = set()
    if domain in parser.dns_static:
        ips.add(parser.dns_static[domain])
    if ("www." + domain) in parser.dns_static:
        ips.add(parser.dns_static["www." + domain])
    if domain in parser.domain_hints:
        ips.add(parser.domain_hints[domain])
    return ips


def is_ip_in_list(ip: str | None, addr_list_name: str,
                  parser: "RouterOSParser",
                  dst_domain: str | None = None) -> bool:
    negate = addr_list_name.startswith("!")
    if negate:
        addr_list_name = addr_list_name[1:]

    if addr_list_name not in parser.address_lists:
        return False

    ip_norm = _normalize_ip(ip) if ip else None
    ip_known = bool(ip_norm) and ip_norm != "0.0.0.0"

    matched = False
    for item in parser.address_lists[addr_list_name]:
        if item.get("disabled"):
            continue
        value = item["address"]
        item_negate = value.startswith("!")
        if item_negate:
            value = value[1:]

        item_match = False
        if _is_ip(value):
            if ip_known and value == ip_norm:
                item_match = True
        elif "/" in value and _is_network(value):
            if ip_known and _ip_in_network(ip_norm, value):
                item_match = True
        elif dst_domain and value.lower() == dst_domain.lower():
            item_match = True
        elif ip_known:
            resolved = resolve_domain_to_ips(value, parser)
            if ip_norm in resolved:
                item_match = True

        if item_negate:
            item_match = not item_match
        if item_match:
            matched = True
            break

    if negate:
        matched = not matched
    return matched


def resolve_target(raw: str, parser: "RouterOSParser"
                   ) -> tuple[str | None, str | None, str]:
    raw = raw.strip()
    if not raw:
        return None, None, "пустое значение"

    if "/" in raw:
        return None, None, f"'{raw}' — это сеть, а не хост. Укажите конкретный IP или домен."

    if _is_ip(raw):
        return raw, raw, ""

    if not DOMAIN_RE.match(raw):
        return None, None, f"'{raw}' не похоже ни на IP, ни на домен"

    domain = raw.rstrip(".")

    if domain in parser.dns_static:
        return domain, parser.dns_static[domain], "источник: /ip dns static"
    if domain in parser.domain_hints:
        return domain, parser.domain_hints[domain], "источник: комментарий /ip route"

    for lst_name, items in parser.address_lists.items():
        for it in items:
            if it["address"].lower() == domain.lower():
                resolved = resolve_domain_to_ips(domain, parser)
                if resolved:
                    return domain, next(iter(resolved)), \
                           f"источник: address-list '{lst_name}'"
                return domain, "0.0.0.0", \
                       f"IP неизвестен (домен есть в address-list '{lst_name}')"

    return domain, "0.0.0.0", \
           "IP неизвестен (нет ни dns static, ни комментария route, ни address-list)"


# ============================================================
#  ПАРСЕР КОНФИГУРАЦИИ RouterOS
# ============================================================

class RouterOSParser:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.address_lists: dict[str, list[AddressListItem]] = {}
        self.dns_static: dict[str, str] = {}
        self.routes: list[RouteEntry] = []
        self.connected_routes: list[RouteEntry] = []
        self.dynamic_defaults: list[RouteEntry] = []
        self.routing_rules: list[RoutingRule] = []
        self.mangle_rules: list[MangleRule] = []
        self.nat_rules: list[NatRule] = []
        self.filter_rules: list[FilterRule] = []
        self.raw_rules: list[RawRule] = []
        self.arp_entries: dict[str, ArpEntry] = {}
        self.interfaces: set[str] = set()
        self.interface_running: dict[str, bool] = {}
        self.interface_addresses: list[dict[str, str]] = []
        self.interface_lists: dict[str, set[str]] = {}
        self.dhcp_networks: list[dict[str, str]] = []
        self.all_domains: set[str] = set()
        self.all_ips: set[str] = set()
        self.domain_hints: dict[str, str] = {}
        self.has_pppoe_default = False
        self.pppoe_default_tables: list[str] = [TABLE_MAIN]
        self.pppoe_iface_name: str | None = None
        self.routing_tables: set[str] = set()
        self.routing_tables_fib: set[str] = set()
        self.vrfs: dict[str, str | None] = {}
        self.fasttrack_enabled = False
        self.fasttrack_rules: list[FilterRule] = []
        self.ros_version = 7
        self.ros_version_str = "7.x"
        self.ros_version_detected = False
        self.conntrack_enabled = True
        self.wan_ifaces: set[str] = set()
        self.lan_ifaces: set[str] = set()
        self.vrf_interfaces: dict[str, str] = {}
        self._routes_cache: dict[str, list[RouteEntry]] = {}
        self._packet_counter: int = 0
        self.rp_filter_mode: str = RPF_NO

    @staticmethod
    def _extract_comment(line: str) -> str:
        m = _RE_COMMENT.search(line)
        if m:
            val = m.group(1)
            val = val.replace('\\"', '"').replace('\\\\', '\\')
            return val
        m = _RE_COMMENT_BARE.search(line)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _extract_fields(line: str,
                        patterns: dict[str, re.Pattern]
                        ) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for key, pat in patterns.items():
            m = pat.search(line)
            out[key] = m.group(1) if m else None
        return out

    def parse_config(self, text: str) -> None:
        self.reset()
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"\\\n\s*", " ", text)
        lines = text.split("\n")

        for raw_line in lines:
            line = raw_line.strip()
            m = re.search(r'version="?([\d\.]+)', line)
            if m:
                try:
                    major = int(m.group(1).split(".")[0])
                    self.ros_version = major
                    self.ros_version_str = m.group(1)
                    self.ros_version_detected = True
                except ValueError:
                    pass
                break
            if "/system resource" in line or "/system routerboard" in line:
                continue

        if not self.ros_version_detected:
            self._detect_version_heuristically(lines)

        current_section: str | None = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("/"):
                current_section = line
                continue

            if current_section and "interface ethernet" in current_section \
                    and line.startswith("set"):
                m_def = re.search(r"default-name=([^\s\]]+)", line)
                disabled = "disabled=yes" in line
                if m_def:
                    self.interface_running[m_def.group(1)] = not disabled

            if current_section and "/interface pppoe-client" in current_section \
                    and line.startswith("add"):
                name_m = re.search(r"name=([^\s]+)", line)
                if "add-default-route=yes" in line and "disabled=yes" not in line:
                    self.has_pppoe_default = True
                    if name_m:
                        self.pppoe_iface_name = name_m.group(1)
                drt = re.search(r"default-route-tables=([^\s]+)", line)
                if drt:
                    self.pppoe_default_tables = [t for t in drt.group(1).split(",")]

            if current_section and "ip firewall filter" in current_section \
                    and line.startswith("add"):
                if "action=fasttrack-connection" in line:
                    self.fasttrack_enabled = True

            if current_section and "ip firewall address-list" in current_section \
                    and line.startswith("add"):
                self._parse_address_list(line)
            elif current_section and "ip dns static" in current_section \
                    and line.startswith("add"):
                self._parse_dns_static(line)
            elif current_section and re.match(r"/ip route", current_section) \
                    and line.startswith("add"):
                self._parse_route(line)
            elif current_section and re.match(r"/routing rule", current_section) \
                    and line.startswith("add"):
                self._parse_routing_rule(line)
            elif current_section and "ip firewall mangle" in current_section \
                    and line.startswith("add"):
                self._parse_mangle(line)
            elif current_section and "ip firewall nat" in current_section \
                    and line.startswith("add"):
                self._parse_nat(line)
            elif current_section and "ip firewall filter" in current_section \
                    and line.startswith("add"):
                self._parse_filter(line)
            elif current_section and "ip firewall raw" in current_section \
                    and line.startswith("add"):
                self._parse_raw(line)
            elif current_section and "ip arp" in current_section \
                    and line.startswith("add"):
                self._parse_arp(line)
            elif current_section and re.match(r"^/ip address", current_section) \
                    and line.startswith("add"):
                self._parse_ip_address(line)
            elif current_section and "ip dhcp-server network" in current_section \
                    and line.startswith("add"):
                self._parse_dhcp_network(line)
            elif current_section and "/interface list member" in current_section \
                    and line.startswith("add"):
                self._parse_interface_list_member(line)
            elif current_section and re.match(r"/routing table", current_section) \
                    and line.startswith("add"):
                m = re.search(r"name=([^\s]+)", line)
                if m:
                    name = m.group(1)
                    self.routing_tables.add(name)
                    if self.ros_version >= 7 and "fib=no" in line:
                        pass
                    else:
                        self.routing_tables_fib.add(name)
            elif current_section and re.match(r"/ip vrf", current_section) \
                    and line.startswith("add"):
                m_name = re.search(r"name=([^\s]+)", line)
                m_iface = re.search(r"interfaces=([^\s]+)", line)
                if m_name:
                    self.vrfs[m_name.group(1)] = (
                        m_iface.group(1) if m_iface else None)
                    if m_iface:
                        for iface in m_iface.group(1).split(","):
                            self.vrf_interfaces[iface.strip()] = m_name.group(1)
            elif current_section and re.match(r"^/ip settings", current_section) \
                    and line.startswith("set"):
                rpf_m = _RE_RPF_FILTER.search(line)
                if rpf_m:
                    self.rp_filter_mode = rpf_m.group(1)

        for a in self.interface_addresses:
            self.interfaces.add(a["interface"])
        for lst, ifaces in self.interface_lists.items():
            for i in ifaces:
                self.interfaces.add(i)

        self._build_connected_routes()
        self._build_dynamic_defaults()
        self._learn_domains_from_routes()
        self._cache_wan_lan_ifaces()
        self._invalidate_routes_cache()

    def _detect_version_heuristically(self, lines: list[str]) -> None:
        joined = "\n".join(lines)
        v7_markers = 0
        v6_markers = 0
        if re.search(r"/routing table\s", joined):
            v7_markers += 1
        if re.search(r"add-default-route=yes", joined) and \
           re.search(r"default-route-tables=", joined):
            v7_markers += 1
        if re.search(r"/ip vrf\s", joined):
            v7_markers += 1
        if re.search(r"/routing rule\s", joined) and \
           not re.search(r"/routing table\s", joined):
            v6_markers += 1
        if re.search(r"/ip route\s", joined) and \
           not re.search(r"routing-table=", joined):
            v6_markers += 1

        if v7_markers > v6_markers:
            self.ros_version = 7
            self.ros_version_str = "7.x (эвристика)"
        elif v6_markers > v7_markers:
            self.ros_version = 6
            self.ros_version_str = "6.x (эвристика)"
        else:
            self.ros_version = 7
            self.ros_version_str = "7.x (не определено)"
        self.ros_version_detected = False
        logger.info("Версия RouterOS определена эвристически: %s (v7=%d, v6=%d)",
                    self.ros_version_str, v7_markers, v6_markers)

    def _cache_wan_lan_ifaces(self) -> None:
        self.wan_ifaces = set(self.interface_lists.get("WAN", set()))
        self.lan_ifaces = set(self.interface_lists.get("LAN", set()))

    def _invalidate_routes_cache(self) -> None:
        self._routes_cache.clear()

    def _build_connected_routes(self) -> None:
        seen: set[tuple[str, str]] = set()
        for a in self.interface_addresses:
            try:
                net = ipaddress.ip_network(a["address"], strict=False)
            except ValueError:
                continue
            running = self.interface_running.get(a["interface"], True)
            if not running:
                continue

            table = TABLE_MAIN
            if a["interface"] in self.vrf_interfaces:
                table = self.vrf_interfaces[a["interface"]]

            policy_only = False
            if table != TABLE_MAIN and self.ros_version >= 7 \
                    and table not in self.routing_tables_fib:
                policy_only = True

            key = (str(net), a["interface"])
            if key in seen:
                continue
            seen.add(key)

            self.connected_routes.append({
                "dst": str(net),
                "gateway": a["interface"] + "%" + a["interface"],
                "iface": a["interface"],
                "table": table,
                "comment": "connected",
                "disabled": False,
                "distance": 0,
                "scope": 10,
                "target_scope": 10,
                "pref_src": a["address"].split("/")[0],
                "type": "unicast",
                "dynamic": True,
                "check_gateway": None,
                "vrf_interface": None,
                "gateway_list": [],
                "gateway_ip": None,
                "gateway_iface": a["interface"],
                "route_tag": None,
                "policy_only": policy_only,
            })

    def _build_dynamic_defaults(self) -> None:
        if not self.has_pppoe_default:
            return
        iface_name = self.pppoe_iface_name or "pppoe-out1"
        for tbl in self.pppoe_default_tables:
            self.dynamic_defaults.append({
                "dst": "0.0.0.0/0",
                "gateway": iface_name,
                "iface": iface_name,
                "table": tbl,
                "comment": f"dynamic default via {iface_name}",
                "disabled": False,
                "distance": 1,
                "scope": 30,
                "target_scope": 10,
                "pref_src": None,
                "type": "unicast",
                "dynamic": True,
                "check_gateway": None,
                "vrf_interface": None,
                "gateway_list": [iface_name],
                "gateway_ip": None,
                "gateway_iface": iface_name,
                "route_tag": None,
                "policy_only": False,
            })

    def _parse_address_list(self, line: str) -> None:
        addr = re.search(r"address=([^\s]+)", line)
        lst = re.search(r"list=([^\s]+)", line)
        cmt = self._extract_comment(line)
        disabled = "disabled=yes" in line
        if addr and lst:
            a = addr.group(1)
            self.address_lists.setdefault(lst.group(1), []).append({
                "address": a,
                "comment": cmt,
                "disabled": disabled,
            })
            self._register_domain_or_ip(a)

    def _parse_dns_static(self, line: str) -> None:
        addr = re.search(r"address=([^\s]+)", line)
        name = re.search(r"name=([^\s]+)", line)
        disabled = "disabled=yes" in line
        if addr and name and not disabled:
            nm = name.group(1).rstrip(".")
            self.dns_static[nm] = addr.group(1)
            self.all_domains.add(nm)
            self.all_ips.add(addr.group(1))

    def _parse_route(self, line: str) -> None:
        dst = re.search(r"dst-address=([^\s]+)", line)
        gw = re.search(r"gateway=([^\s]+)", line)
        if self.ros_version >= 7:
            rt = re.search(r"routing-table=([^\s]+)", line)
            if rt is None:
                rt = re.search(r"routing-mark=([^\s]+)", line)
        else:
            rt = re.search(r"routing-mark=([^\s]+)", line)
            if rt is None:
                rt = re.search(r"routing-table=([^\s]+)", line)
        cmt = self._extract_comment(line)
        disabled = "disabled=yes" in line
        distance = re.search(r"distance=(\d+)", line)
        scope = re.search(r"scope=(\d+)", line)
        target_scope = re.search(r"target-scope=(\d+)", line)
        pref_src = re.search(r"pref-src=([^\s]+)", line)
        rtype = re.search(r"type=([^\s]+)", line)
        check_gw = re.search(r"check-gateway=([^\s]+)", line)
        vrf_iface = re.search(r"vrf-interface=([^\s]+)", line)
        route_tag = re.search(r"route-tag=([^\s]+)", line)

        gw_value = gw.group(1) if gw else "unknown"
        gw_iface: str | None = None
        gw_ip_part = gw_value
        if gw_value and "%" in gw_value:
            gw_iface = gw_value.split("%")[-1]
            gw_ip_part = gw_value.split("%")[0]

        gw_list = [g.strip() for g in gw_value.split(",")] if gw_value else []

        table = rt.group(1) if rt else TABLE_MAIN

        policy_only = False
        if table != TABLE_MAIN and self.ros_version >= 7 \
                and table not in self.routing_tables_fib:
            policy_only = True

        self.routes.append({
            "dst": dst.group(1) if dst else "0.0.0.0/0",
            "gateway": gw_value,
            "gateway_list": gw_list,
            "gateway_ip": gw_ip_part if _is_ip(gw_ip_part) else None,
            "gateway_iface": gw_iface,
            "table": table,
            "comment": cmt,
            "disabled": disabled,
            "distance": int(distance.group(1)) if distance else 1,
            "scope": int(scope.group(1)) if scope else 30,
            "target_scope": int(target_scope.group(1)) if target_scope else 10,
            "pref_src": pref_src.group(1) if pref_src else None,
            "type": rtype.group(1) if rtype else "unicast",
            "check_gateway": check_gw.group(1) if check_gw else None,
            "vrf_interface": vrf_iface.group(1) if vrf_iface else None,
            "route_tag": route_tag.group(1) if route_tag else None,
            "dynamic": False,
            "policy_only": policy_only,
        })

    def _parse_routing_rule(self, line: str) -> None:
        f = self._extract_fields(line, {
            "src_address": _RE_SRC_ADDR,
            "dst_address": _RE_DST_ADDR,
            "action": _RE_ACTION,
            "table": _RE_ROUTING_TABLE,
            "src_list": _RE_SRC_LIST,
            "dst_list": _RE_DST_LIST,
            "interface": _RE_IN_IFACE,
        })
        self.routing_rules.append({
            "src_address": f["src_address"],
            "dst_address": f["dst_address"],
            "src_list": f["src_list"],
            "dst_list": f["dst_list"],
            "interface": f["interface"],
            "action": f["action"] or ACTION_LOOKUP,
            "table": f["table"] or TABLE_MAIN,
            "disabled": "disabled=yes" in line,
        })

    def _parse_mangle(self, line: str) -> None:
        f = self._extract_fields(line, {
            "action": _RE_ACTION,
            "chain": _RE_CHAIN,
            "src_list": _RE_SRC_LIST,
            "dst_list": _RE_DST_LIST,
            "dst_addr": _RE_DST_ADDR,
            "src_addr": _RE_SRC_ADDR,
            "in_interface": _RE_IN_IFACE,
            "out_interface": _RE_OUT_IFACE,
            "protocol": _RE_PROTOCOL,
            "dst_port": _RE_DST_PORT,
            "src_port": _RE_SRC_PORT,
            "connection_state": _RE_CONN_STATE,
            "connection_mark": _RE_CONN_MARK,
            "packet_mark": _RE_PKT_MARK,
            "routing_mark": _RE_ROUTING_MARK,
            "new_routing_mark": _RE_NEW_ROUTING_MARK,
            "new_connection_mark": _RE_NEW_CONN_MARK,
            "new_packet_mark": _RE_NEW_PKT_MARK,
            "new_mss": _RE_NEW_MSS,
            "new_ttl": _RE_NEW_TTL,
            "new_dscp": _RE_NEW_DSCP,
            "new_priority": _RE_NEW_PRIORITY,
            "address_list": _RE_ADDR_LIST,
            "address_list_timeout": _RE_ADDR_LIST_TO,
            "jump_target": _RE_JUMP_TARGET,
        })
        pt = _RE_PASSTHROUGH.search(line)
        self.mangle_rules.append({
            **f,
            "action": f["action"] or "",
            "chain": f["chain"] or "prerouting",
            "passthrough": (pt.group(1) == "yes") if pt else True,
            "comment": self._extract_comment(line),
            "disabled": "disabled=yes" in line,
        })

    def _parse_nat(self, line: str) -> None:
        f = self._extract_fields(line, {
            "action": _RE_ACTION,
            "chain": _RE_CHAIN,
            "out_interface": _RE_OUT_IFACE,
            "in_interface": _RE_IN_IFACE,
            "dst_address": _RE_DST_ADDR,
            "dst_list": _RE_DST_LIST,
            "src_list": _RE_SRC_LIST,
            "src_address": _RE_SRC_ADDR,
            "to_addresses": _RE_TO_ADDRESSES,
            "to_ports": _RE_TO_PORTS,
            "protocol": _RE_PROTOCOL,
            "dst_port": _RE_DST_PORT,
            "src_port": _RE_SRC_PORT,
            "connection_state": _RE_CONN_STATE,
            "jump_target": _RE_JUMP_TARGET,
        })
        self.nat_rules.append({
            **f,
            "action": f["action"] or "masquerade",
            "chain": f["chain"] or "srcnat",
            "comment": self._extract_comment(line),
            "disabled": "disabled=yes" in line,
        })

    def _parse_filter(self, line: str) -> None:
        f = self._extract_fields(line, {
            "action": _RE_ACTION,
            "chain": _RE_CHAIN,
            "protocol": _RE_PROTOCOL,
            "connection_state": _RE_CONN_STATE,
            "dst_address": _RE_DST_ADDR,
            "dst_list": _RE_DST_LIST,
            "src_list": _RE_SRC_LIST,
            "src_address": _RE_SRC_ADDR,
            "in_interface": _RE_IN_IFACE,
            "out_interface": _RE_OUT_IFACE,
            "dst_port": _RE_DST_PORT,
            "src_port": _RE_SRC_PORT,
            "connection_mark": _RE_CONN_MARK,
            "packet_mark": _RE_PKT_MARK,
            "routing_mark": _RE_ROUTING_MARK,
            "jump_target": _RE_JUMP_TARGET,
        })
        self.filter_rules.append({
            **f,
            "action": f["action"] or "accept",
            "chain": f["chain"] or "forward",
            "comment": self._extract_comment(line),
            "disabled": "disabled=yes" in line,
        })

    def _parse_raw(self, line: str) -> None:
        f = self._extract_fields(line, {
            "action": _RE_ACTION,
            "chain": _RE_CHAIN,
            "protocol": _RE_PROTOCOL,
            "connection_state": _RE_CONN_STATE,
            "src_list": _RE_SRC_LIST,
            "dst_list": _RE_DST_LIST,
            "src_address": _RE_SRC_ADDR,
            "dst_address": _RE_DST_ADDR,
            "in_interface": _RE_IN_IFACE,
            "out_interface": _RE_OUT_IFACE,
            "dst_port": _RE_DST_PORT,
            "src_port": _RE_SRC_PORT,
        })
        self.raw_rules.append({
            **f,
            "action": f["action"] or "accept",
            "chain": f["chain"] or "prerouting",
            "comment": self._extract_comment(line),
            "disabled": "disabled=yes" in line,
        })

    def _parse_arp(self, line: str) -> None:
        addr = re.search(r"address=([^\s]+)", line)
        cmt = self._extract_comment(line)
        iface = re.search(r"interface=([^\s]+)", line)
        disabled = "disabled=yes" in line
        invalid = "invalid=yes" in line
        incomplete = "status=incomplete" in line or "incomplete=yes" in line
        if addr and not disabled:
            self.arp_entries[addr.group(1)] = {
                "comment": cmt if cmt else "Unknown PC",
                "interface": iface.group(1) if iface else "ether3",
                "invalid": invalid,
                "incomplete": incomplete,
            }

    def _parse_ip_address(self, line: str) -> None:
        addr = re.search(r"address=([^\s]+)", line)
        iface = re.search(r"interface=([^\s]+)", line)
        if addr:
            self.interface_addresses.append({
                "address": addr.group(1),
                "interface": iface.group(1) if iface else "unknown",
            })
            if iface:
                self.interfaces.add(iface.group(1))

    def _parse_dhcp_network(self, line: str) -> None:
        addr = re.search(r"address=([^\s]+)", line)
        gw = re.search(r"gateway=([^\s]+)", line)
        cmt = self._extract_comment(line)
        if addr:
            self.dhcp_networks.append({
                "address": addr.group(1),
                "gateway": gw.group(1) if gw else "",
                "comment": cmt,
            })

    def _parse_interface_list_member(self, line: str) -> None:
        iface = re.search(r"interface=([^\s]+)", line)
        lst = re.search(r"list=([^\s]+)", line)
        disabled = "disabled=yes" in line
        if iface and lst and not disabled:
            self.interface_lists.setdefault(lst.group(1), set()).add(iface.group(1))

    def _learn_domains_from_routes(self) -> None:
        for r in self.routes:
            cmt = (r.get("comment") or "").strip()
            dst = r.get("dst", "")
            if not cmt or "/32" not in dst:
                continue
            cand = cmt.split()[0].strip(",. ;:()")
            if DOMAIN_RE.match(cand):
                ip = dst.split("/")[0]
                self.all_domains.add(cand)
                self.all_ips.add(ip)
                self.domain_hints.setdefault(cand, ip)

    def _register_domain_or_ip(self, value: str) -> None:
        v = value.strip()
        if not v:
            return
        if v.startswith("!"):
            v = v[1:]
        if "/" in v:
            return
        if _is_ip(v):
            self.all_ips.add(v)
        elif DOMAIN_RE.match(v):
            self.all_domains.add(v)

    def get_routes_for_table(self, table: str) -> list[RouteEntry]:
        if table in self._routes_cache:
            return self._routes_cache[table]
        out: list[RouteEntry] = []
        for r in self.routes:
            if r["table"] == table:
                out.append(r)
        for r in self.connected_routes:
            if r["table"] == table:
                out.append(r)
        for r in self.dynamic_defaults:
            if r["table"] == table:
                out.append(r)
        self._routes_cache[table] = out
        return out

    def table_has_fib(self, table: str) -> bool:
        if table in (TABLE_MAIN, "", None):
            return True
        if self.ros_version < 7:
            return table == TABLE_MAIN
        return table in self.routing_tables_fib

    def next_packet_counter(self) -> int:
        self._packet_counter += 1
        return self._packet_counter

    def vrf_for_iface(self, iface: str | None) -> str | None:
        if not iface:
            return None
        return self.vrf_interfaces.get(iface)


# ============================================================
#  СОСТОЯНИЕ ПАКЕТА
# ============================================================

@dataclass(slots=True)
class PacketState:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    conn_state: str = STATE_NEW
    in_iface: str | None = None
    out_iface: str | None = None

    connection_mark: str | None = None
    packet_mark: str | None = None
    routing_mark: str | None = None

    nat_src: str | None = None
    nat_dst: str | None = None

    accepted_in_mangle: bool = False
    dstnat_happened: bool = False
    pref_src: str | None = None
    fasttracked: bool = False
    raw_action: str | None = None
    notrack: bool = False
    fasttrack_candidate_idx: int | None = None

    _ecmp_hash_cache: int | None = None
    _ecmp_hash_dst: str | None = None
    _ecmp_hash_mark: str | None = None
    original_dst_ip: str | None = None

    def __post_init__(self) -> None:
        if self.original_dst_ip is None:
            self.original_dst_ip = self.dst_ip


# ============================================================
#  СИМУЛЯТОР PACKET FLOW
# ============================================================

class PacketSimulator:
    def __init__(self, parser: RouterOSParser) -> None:
        self.parser = parser
        self.reset()

    def reset(self) -> None:
        self.log: list[tuple[str, str | None]] = []
        self.route_path: list[tuple[str, str]] = []
        self.summary: tuple[str, str] = ("—", "info")

    def add(self, text: str, tag: str | None = None) -> None:
        self.log.append((text, tag))

    def _gw_iface_for_ip(self, gw_ip: str) -> str | None:
        for a in self.parser.interface_addresses:
            if _ip_in_network(gw_ip, a["address"]):
                return a["interface"]
        return None

    def _route_gateway_iface(self, gateway: str | None,
                             gateway_iface: str | None = None
                             ) -> str | None:
        if not gateway or gateway == "unknown":
            return None
        if gateway_iface:
            return gateway_iface
        if "%" in gateway:
            iface = gateway.split("%")[-1]
            if iface in self.parser.interfaces:
                return iface
        if gateway in self.parser.interfaces:
            return gateway
        gw_ip = _normalize_ip(gateway)
        iface = self._gw_iface_for_ip(gw_ip)
        if iface:
            return iface
        return gateway

    def _input_iface_for_src(self, src_ip: str) -> str | None:
        entry = self.parser.arp_entries.get(src_ip)
        if entry:
            return entry.get("interface")
        for a in self.parser.interface_addresses:
            if _ip_in_network(src_ip, a["address"]):
                return a["interface"]
        return None

    def _rule_enabled(self, kind: str, idx: int, rule: dict[str, Any],
                      overrides: dict[str, bool]) -> bool:
        key = f"{kind}_{idx}"
        if key in overrides:
            return overrides[key]
        return not rule.get("disabled", False)

    def _table_exists(self, table: str | None) -> bool:
        if table in (None, "", TABLE_MAIN):
            return True
        return table in self.parser.routing_tables

    def _is_wan_iface(self, iface: str | None) -> bool:
        if not iface:
            return False
        if iface in self.parser.wan_ifaces:
            return True
        if iface.startswith(("pppoe", "lte", "wg", "ovpn", "pptp",
                             "l2tp", "sstp")):
            return True
        return False

    def _src_valid_for_iface(self, src_ip: str, iface: str) -> bool:
        for a in self.parser.interface_addresses:
            if a["interface"] == iface and _ip_in_network(src_ip, a["address"]):
                return True
        return False

    def _iface_address(self, iface: str | None) -> str | None:
        if not iface:
            return None
        for a in self.parser.interface_addresses:
            if a["interface"] == iface:
                return a["address"].split("/")[0]
        return None

    def _iface_in_any_local_subnet(self, ip: str | None) -> str | None:
        if not ip or ip == "0.0.0.0":
            return None
        for a in self.parser.interface_addresses:
            if _ip_in_network(ip, a["address"]):
                return a["interface"]
        return None

    def _check_gateway_alive(self, route: RouteEntry) -> bool:
        cg = route.get("check_gateway")
        if not cg:
            return True
        gw = route.get("gateway_ip") or route.get("gateway", "")
        gw = _normalize_ip(gw)

        if not _is_ip(gw):
            self.add(f"   ⚠ check-gateway={cg} для интерфейсного шлюза "
                     f"'{route.get('gateway')}' — считаем живым", "warn")
            return True

        if cg == "arp":
            entry = self.parser.arp_entries.get(gw)
            if entry is None:
                self.add(f"   ⚠ check-gateway=arp: нет ARP-записи для {gw}", "warn")
                return False
            if entry.get("invalid") or entry.get("incomplete"):
                self.add(f"   ⚠ check-gateway=arp: ARP-запись для {gw} "
                         f"невалидна (incomplete/invalid)", "warn")
                return False
            return True

        if gw in self.parser.arp_entries:
            return True
        if self._gw_iface_for_ip(gw):
            return True
        self.add(f"   ⚠ check-gateway={cg}: шлюз {gw} недостижим "
                 f"(нет ARP и connected)", "warn")
        return False

    def _check_rp_filter(self, pkt: PacketState) -> tuple[bool, str]:
        mode = self.parser.rp_filter_mode
        if mode == RPF_NO:
            return True, ""
        if pkt.in_iface is None:
            return True, ""

        vrf_table = self.parser.vrf_for_iface(pkt.in_iface)
        if vrf_table:
            reverse_table = vrf_table
        elif pkt.routing_mark and pkt.routing_mark != TABLE_MAIN:
            reverse_table = pkt.routing_mark
        else:
            reverse_table = TABLE_MAIN

        if mode == RPF_STRICT and reverse_table != TABLE_MAIN:
            return True, (f"rp-filter=strict не работает с таблицами "
                          f"маршрутизации (таблица '{reverse_table}') — "
                          f"проверка пропущена")

        src_routes, _, _ = self._match_route(
            pkt.src_ip, reverse_table, {}, pkt=None, only_in_table=False)

        if not src_routes:
            return False, (f"rp-filter={mode}: нет обратного маршрута "
                           f"до {pkt.src_ip} в таблице '{reverse_table}'")

        if mode == RPF_LOOSE:
            return True, ""

        route = src_routes[0]
        out_iface = route.get("gateway_iface") or route.get("iface")
        if out_iface is None and route.get("gateway_ip"):
            out_iface = self._gw_iface_for_ip(route["gateway_ip"])
        if out_iface and out_iface != pkt.in_iface:
            return False, (f"rp-filter=strict: src {pkt.src_ip} достижим через "
                           f"{out_iface}, а пришёл через {pkt.in_iface}")
        return True, ""

    def _match_common(self, pkt: PacketState, rule: dict[str, Any],
                      dst_domain: str | None,
                      check_conn_state: bool = False) -> bool:
        if rule.get("src_list"):
            if not is_ip_in_list(pkt.src_ip, rule["src_list"], self.parser):
                return False

        if rule.get("dst_list"):
            if not is_ip_in_list(pkt.dst_ip, rule["dst_list"], self.parser,
                                 dst_domain=dst_domain):
                return False

        if rule.get("src_address"):
            s = rule["src_address"]
            negate = s.startswith("!")
            if negate:
                s = s[1:]
            if _is_ip(s):
                m = (_normalize_ip(s) == pkt.src_ip)
            elif _is_network(s):
                m = _ip_in_network(pkt.src_ip, s)
            else:
                m = False
            if negate:
                m = not m
            if not m:
                return False

        if rule.get("dst_address"):
            d = rule["dst_address"]
            negate = d.startswith("!")
            if negate:
                d = d[1:]
            if _is_network(d):
                m = _ip_in_network(pkt.dst_ip, d)
            elif _is_ip(d):
                m = (_normalize_ip(d) == pkt.dst_ip)
            else:
                m = False
            if negate:
                m = not m
            if not m:
                return False

        if rule.get("in_interface"):
            if rule["in_interface"] != pkt.in_iface:
                return False

        if rule.get("out_interface"):
            if rule["out_interface"] != pkt.out_iface:
                return False

        if rule.get("protocol"):
            p = rule["protocol"]
            allowed = PROTO_ALIAS.get(pkt.protocol, (pkt.protocol,))
            if p not in allowed:
                return False

        if pkt.protocol in (PROTO_TCP, PROTO_UDP):
            if rule.get("dst_port"):
                if not _port_in_rule(rule["dst_port"], pkt.dst_port):
                    return False

            if rule.get("src_port"):
                if not _port_in_rule(rule["src_port"], pkt.src_port):
                    return False
        else:
            if rule.get("dst_port") or rule.get("src_port"):
                return False

        if rule.get("connection_mark"):
            if pkt.connection_mark != rule["connection_mark"]:
                return False

        if rule.get("packet_mark"):
            if pkt.packet_mark != rule["packet_mark"]:
                return False

        if rule.get("routing_mark"):
            if pkt.routing_mark != rule["routing_mark"]:
                return False

        if check_conn_state and rule.get("connection_state"):
            states = [s.strip() for s in rule["connection_state"].split(",")]
            if pkt.conn_state not in states:
                return False

        return True

    def _run_raw_chain(self, chain: str, pkt: PacketState,
                       dst_domain: str | None,
                       overrides: dict[str, bool]
                       ) -> tuple[str | None, int | None, RawRule | None]:
        for idx, r in enumerate(self.parser.raw_rules):
            if r["chain"] != chain:
                continue
            if not self._rule_enabled("raw", idx, r, overrides):
                continue
            if not self._match_common(pkt, r, dst_domain, check_conn_state=True):
                continue
            act = r["action"]
            if act in ("drop", "notrack"):
                return act, idx, r
            if act == "accept":
                return "accept", idx, r
            if act == "jump":
                continue
        return None, None, None

    def _run_mangle_chain(self, chain: str, pkt: PacketState,
                          dst_domain: str | None,
                          overrides: dict[str, bool],
                          depth: int = 0) -> None:
        if depth > MAX_JUMP_DEPTH:
            return
        for idx, r in enumerate(self.parser.mangle_rules):
            if r["chain"] != chain:
                continue
            if not self._rule_enabled("mangle", idx, r, overrides):
                continue

            if not self._match_common(pkt, r, dst_domain, check_conn_state=True):
                continue

            act = r["action"]

            if act == "accept":
                pkt.accepted_in_mangle = True
                self.add(f"   ✓ mangle #{idx} (chain={chain}): accept — mangle остановлен", "ok")
                return

            if act == "mark-routing":
                new_mark = r.get("new_routing_mark") or TABLE_MAIN
                if not self._table_exists(new_mark):
                    self.add(f"   ⚠ mangle #{idx}: mark-routing={new_mark} — таблица не объявлена", "warn")
                    if not r["passthrough"]:
                        return
                    continue
                pkt.routing_mark = new_mark
                self.add(f"   ✓ mangle #{idx}: mark-routing={new_mark}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "mark-connection":
                pkt.connection_mark = r.get("new_connection_mark") or "conn"
                self.add(f"   ✓ mangle #{idx}: mark-connection={pkt.connection_mark}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "mark-packet":
                pkt.packet_mark = r.get("new_packet_mark") or "pkt"
                self.add(f"   ✓ mangle #{idx}: mark-packet={pkt.packet_mark}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "change-mss":
                self.add(f"   ✓ mangle #{idx}: change-mss={r.get('new_mss') or 'clamp-to-pmtu'}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "change-ttl":
                self.add(f"   ✓ mangle #{idx}: change-ttl={r.get('new_ttl')}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "change-dscp":
                self.add(f"   ✓ mangle #{idx}: change-dscp={r.get('new_dscp')}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "set-priority":
                self.add(f"   ✓ mangle #{idx}: set-priority={r.get('new_priority')}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act in ("add-src-to-address-list", "add-dst-to-address-list"):
                self.add(f"   ✓ mangle #{idx}: {act} list={r.get('address_list')}", "ok")
                if not r["passthrough"]:
                    return
                continue

            if act == "log":
                self.add(f"   • mangle #{idx}: log", "dim")
                continue

            if act == "jump":
                target = r.get("jump_target") or chain
                self._run_mangle_chain(target, pkt, dst_domain, overrides, depth + 1)
                if not r["passthrough"]:
                    return
                continue

            if act == "return":
                return

    def _run_dstnat(self, pkt: PacketState, dst_domain: str | None,
                    overrides: dict[str, bool], depth: int = 0) -> bool:
        if depth > MAX_JUMP_DEPTH:
            return False
        if pkt.notrack:
            self.add("   • notrack: DST-NAT пропущен (требуется conntrack)", "warn")
            return False
        for idx, r in enumerate(self.parser.nat_rules):
            if r["chain"] != "dstnat":
                continue
            if not self._rule_enabled("nat", idx, r, overrides):
                continue
            if not self._match_common(pkt, r, dst_domain, check_conn_state=True):
                continue

            act = r["action"]
            if act == "dst-nat":
                to_addr = r.get("to_addresses")
                to_ports = r.get("to_ports")
                if to_addr:
                    pkt.dst_ip = to_addr.split("-")[0]
                    pkt.nat_dst = pkt.dst_ip
                if to_ports:
                    try:
                        pkt.dst_port = int(to_ports.split("-")[0])
                    except ValueError:
                        pass
                pkt.dstnat_happened = True
                self.add(f"   ✓ dstnat #{idx}: dst-nat → {pkt.dst_ip}:{pkt.dst_port}", "ok")
                return True
            if act == "redirect":
                try:
                    pkt.dst_port = int(r.get("to_ports") or pkt.dst_port or 0)
                except ValueError:
                    pass
                pkt.dstnat_happened = True
                self.add(f"   ✓ dstnat #{idx}: redirect → port {pkt.dst_port}", "ok")
                return True
            if act == "netmap":
                if r.get("to_addresses"):
                    pkt.dst_ip = r["to_addresses"]
                    pkt.nat_dst = pkt.dst_ip
                pkt.dstnat_happened = True
                self.add(f"   ✓ dstnat #{idx}: netmap → {pkt.dst_ip}", "ok")
                return True
            if act == "same":
                pkt.dstnat_happened = True
                self.add(f"   ✓ dstnat #{idx}: same", "ok")
                return True
            if act == "accept":
                self.add(f"   ✓ dstnat #{idx}: accept — dstnat остановлен", "ok")
                return False
            if act == "log":
                self.add(f"   • dstnat #{idx}: log", "dim")
                continue
            if act == "jump":
                if self._run_dstnat(pkt, dst_domain, overrides, depth + 1):
                    return True
                continue
            if act == "return":
                return False
        return False

    def _match_route(self, dst_ip: str, table: str,
                     overrides: dict[str, bool],
                     pkt: PacketState | None = None,
                     only_in_table: bool = False
                     ) -> tuple[list[RouteEntry] | None, str, bool]:
        ip_known = bool(dst_ip) and dst_ip != "0.0.0.0"
        all_routes = self.parser.get_routes_for_table(table)

        if not self._table_exists(table):
            if only_in_table:
                self.add(f"   ✗ Таблица '{table}' не объявлена "
                         f"(lookup-only-in-table) → нет маршрута", "drop")
                return None, table, False
            self.add(f"   ⚠ Таблица '{table}' не объявлена → fallback в main", "warn")
            table = TABLE_MAIN
            all_routes = self.parser.get_routes_for_table(TABLE_MAIN)

        table_without_fib = not self.parser.table_has_fib(table)

        candidates: list[tuple[int, int, int, RouteEntry]] = []
        for idx, r in enumerate(all_routes):
            key_static = None
            if r in self.parser.routes:
                key_static = f"route_{self.parser.routes.index(r)}"
            if key_static and key_static in overrides:
                if not overrides[key_static]:
                    continue
            elif r.get("disabled"):
                continue

            if not self._check_gateway_alive(r):
                self.add(f"   ⚠ Маршрут {r['dst']} via {r['gateway']} "
                         f"деактивирован (check-gateway={r['check_gateway']})", "warn")
                continue

            dst = r["dst"]
            if dst == "0.0.0.0/0":
                specificity = 0
                matched = True
            elif _is_network(dst):
                matched = ip_known and _ip_in_network(dst_ip, dst)
                specificity = ipaddress.ip_network(dst, strict=False).prefixlen
            elif _is_ip(dst):
                matched = ip_known and (_normalize_ip(dst) == dst_ip)
                specificity = 32
            else:
                matched = False
                specificity = -1

            if matched:
                candidates.append((specificity, r["distance"], idx, r))

        if not candidates:
            if only_in_table:
                return None, table, table_without_fib
            return None, table, table_without_fib

        best_spec = max(c[0] for c in candidates)
        same_prefix = [c for c in candidates if c[0] == best_spec]
        best_dist = min(c[1] for c in same_prefix)
        best = [c[3] for c in same_prefix if c[1] == best_dist]

        if len(best) > 1 and pkt is not None:
            if self.parser.ros_version < 7:
                counter = self.parser.next_packet_counter()
                chosen = best[counter % len(best)]
                return [chosen] + [r for r in best if r is not chosen], \
                       table, table_without_fib
            else:
                if (pkt._ecmp_hash_cache is None
                        or pkt._ecmp_hash_dst != pkt.dst_ip
                        or pkt._ecmp_hash_mark != (pkt.routing_mark or TABLE_MAIN)):
                    pkt._ecmp_hash_cache = _ecmp_hash_v7(
                        pkt.src_ip, pkt.dst_ip,
                        pkt.src_port, pkt.dst_port, pkt.protocol,
                        routing_mark=pkt.routing_mark or TABLE_MAIN)
                    pkt._ecmp_hash_dst = pkt.dst_ip
                    pkt._ecmp_hash_mark = pkt.routing_mark or TABLE_MAIN
                chosen = best[pkt._ecmp_hash_cache % len(best)]
                return [chosen] + [r for r in best if r is not chosen], \
                       table, table_without_fib

        best.sort(key=lambda r: (r.get("distance", 1), r.get("dst", "")))
        return best, table, table_without_fib

    def _resolve_recursive_gateway(self, route: RouteEntry, table: str,
                                   overrides: dict[str, bool],
                                   pkt: PacketState | None = None,
                                   depth: int = 0) -> RouteEntry | None:
        if depth > MAX_RECURSIVE_DEPTH:
            self.add(f"   ⚠ Рекурсивный шлюз: превышена глубина "
                     f"{MAX_RECURSIVE_DEPTH}, результат упрощён", "warn")
            return None
        gw = route.get("gateway_ip")
        if not gw:
            return None
        if self._gw_iface_for_ip(gw):
            return None
        rec, _, _ = self._match_route(gw, table, overrides, pkt=pkt)
        if not rec:
            return None
        rec_route = rec[0]
        rec_scope = rec_route.get("scope", 0)
        orig_target = route.get("target_scope", 10)
        if rec_scope > orig_target:
            self.add(f"   ⚠ Рекурсивный nexthop {gw} имеет scope={rec_scope} > "
                     f"target-scope={orig_target} исходного маршрута — недействителен",
                     "warn")
            return None
        return rec_route

    def _apply_routing_rules(self, pkt: PacketState, routing_mark: str,
                             dst_domain: str | None = None
                             ) -> tuple[str | None, bool]:
        if self.parser.ros_version >= 7:
            if routing_mark and routing_mark != TABLE_MAIN:
                self.add(f"   • routing-rules пропущены "
                         f"(приоритет mangle mark={routing_mark})", "dim")
                return None, False
        else:
            self.add("   ℹ v6: routing rules выполняются даже при наличии mark", "dim")

        for idx, r in enumerate(self.parser.routing_rules):
            if r.get("disabled"):
                continue
            if r.get("src_address"):
                s = r["src_address"]
                if _is_network(s):
                    if not _ip_in_network(pkt.src_ip, s):
                        continue
                elif _is_ip(s):
                    if _normalize_ip(s) != pkt.src_ip:
                        continue
            if r.get("dst_address"):
                d = r["dst_address"]
                if _is_network(d):
                    if not _ip_in_network(pkt.dst_ip, d):
                        continue
                elif _is_ip(d):
                    if _normalize_ip(d) != pkt.dst_ip:
                        continue
            if r.get("src_list"):
                if not is_ip_in_list(pkt.src_ip, r["src_list"], self.parser):
                    continue
            if r.get("dst_list"):
                if not is_ip_in_list(pkt.dst_ip, r["dst_list"], self.parser,
                                     dst_domain=dst_domain):
                    continue
            if r.get("interface"):
                if r["interface"] != pkt.in_iface:
                    continue
            if r["action"] in (ACTION_LOOKUP, ACTION_LOOKUP_ONLY):
                only = (r["action"] == ACTION_LOOKUP_ONLY)
                self.add(f"   ✓ routing-rule #{idx}: table={r['table']}"
                         f"{' (only-in-table)' if only else ''}", "ok")
                return r["table"], only
        return None, False

    def _run_filter_chain(self, chain: str, pkt: PacketState,
                          dst_domain: str | None,
                          overrides: dict[str, bool],
                          depth: int = 0
                          ) -> tuple[str | None, int | None, FilterRule | None]:
        if depth > MAX_JUMP_DEPTH:
            return None, None, None
        for idx, r in enumerate(self.parser.filter_rules):
            if r["chain"] != chain:
                continue
            if not self._rule_enabled("filter", idx, r, overrides):
                continue

            if r["action"] == "fasttrack-connection":
                if not self._match_common(pkt, r, dst_domain,
                                          check_conn_state=True):
                    continue
                if pkt.routing_mark and pkt.routing_mark != TABLE_MAIN:
                    self.add(f"   ⚠ filter #{idx}: fasttrack-connection пропущен "
                             f"(routing-mark={pkt.routing_mark})", "warn")
                    continue
                if pkt.out_iface and self._iface_in_vrf(pkt.out_iface):
                    vrf = self.parser.vrf_interfaces.get(pkt.out_iface)
                    self.add(f"   ⚠ filter #{idx}: fasttrack-connection пропущен "
                             f"(VRF '{vrf}')", "warn")
                    continue
                if pkt.conn_state in (STATE_ESTABLISHED, STATE_RELATED) \
                        and not pkt.notrack:
                    pkt.fasttrack_candidate_idx = idx
                continue

            if not self._match_common(pkt, r, dst_domain, check_conn_state=True):
                continue

            act = r["action"]
            if act in ("accept", "drop", "reject"):
                return act, idx, r
            if act == "log":
                comment = r.get("comment") or ""
                self.add(f"   • filter #{idx}: log"
                         f"{(' ('+comment+')') if comment else ''}", "dim")
                continue
            if act == "jump":
                target = r.get("jump_target") or chain
                sub = self._run_filter_chain(target, pkt, dst_domain,
                                             overrides, depth + 1)
                if sub[0] in ("accept", "drop", "reject"):
                    return sub
                continue
            if act == "return":
                return None, None, None

        return None, None, None

    def _iface_in_vrf(self, iface: str | None) -> bool:
        return bool(iface) and iface in self.parser.vrf_interfaces

    def _run_srcnat(self, pkt: PacketState, dst_domain: str | None,
                    overrides: dict[str, bool],
                    depth: int = 0
                    ) -> tuple[bool, int | None]:
        if depth > MAX_JUMP_DEPTH:
            return False, None
        if pkt.notrack:
            self.add("   • notrack: SRC-NAT пропущен (требуется conntrack)", "warn")
            return False, None
        for idx, r in enumerate(self.parser.nat_rules):
            if r["chain"] != "srcnat":
                continue
            if not self._rule_enabled("nat", idx, r, overrides):
                continue

            if r.get("out_interface") and r["out_interface"] != pkt.out_iface:
                continue

            if not self._match_common(pkt, r, dst_domain, check_conn_state=True):
                continue

            act = r["action"]
            if act == "masquerade":
                pkt.nat_src = self._iface_address(pkt.out_iface) or pkt.src_ip
                self.add(f"   ✓ srcnat #{idx}: masquerade → src={pkt.nat_src}", "ok")
                return True, idx
            if act == "src-nat":
                pkt.nat_src = r.get("to_addresses") or pkt.src_ip
                if r.get("to_ports"):
                    try:
                        pkt.src_port = int(r["to_ports"].split("-")[0])
                    except ValueError:
                        pass
                self.add(f"   ✓ srcnat #{idx}: src-nat → src={pkt.nat_src}", "ok")
                return True, idx
            if act == "accept":
                self.add(f"   ✓ srcnat #{idx}: accept — srcnat остановлен", "ok")
                return False, idx
            if act == "log":
                continue
            if act == "jump":
                applied, jidx = self._run_srcnat(pkt, dst_domain, overrides,
                                                 depth + 1)
                if applied:
                    return applied, jidx
                continue
            if act == "return":
                return False, None
        return False, None

    def _is_fasttrack_applicable(self, pkt: PacketState) -> bool:
        if not self.parser.fasttrack_enabled:
            return False
        if pkt.notrack:
            return False
        if pkt.conn_state not in (STATE_ESTABLISHED, STATE_RELATED):
            return False
        if pkt.routing_mark and pkt.routing_mark != TABLE_MAIN:
            return False
        if pkt.out_iface and self._iface_in_vrf(pkt.out_iface):
            return False
        for idx, r in enumerate(self.parser.filter_rules):
            if r.get("action") != "fasttrack-connection":
                continue
            if r.get("disabled"):
                continue
            if not self._match_common(pkt, r, None, check_conn_state=True):
                continue
            return True
        return False

    def simulate(self, src_ip: str, dst_domain: str, dst_ip: str,
                 overrides: dict[str, bool] | None = None,
                 resolution_note: str = "", protocol: str = PROTO_TCP,
                 dst_port: int | None = 443,
                 src_port: int | None = 12345,
                 conn_state: str = STATE_NEW) -> None:
        if overrides is None:
            overrides = {}

        self.reset()

        src_name = "Локальный ПК"
        if src_ip in self.parser.arp_entries:
            src_name = self.parser.arp_entries[src_ip]["comment"]

        in_iface = self._input_iface_for_src(src_ip)

        ip_unknown = (dst_ip == "0.0.0.0")
        dst_ip_display = dst_ip if not ip_unknown else "?.?.?.? (внешний резолв)"

        self.add("═══ ТРАССИРОВКА ПАКЕТА ═══", "head")
        self.add(f"RouterOS версия: {self.parser.ros_version_str} "
                 f"({'v6' if self.parser.ros_version < 7 else 'v7'})", "dim")
        if not self.parser.ros_version_detected:
            self.add("ℹ Версия определена эвристически (нет version= в конфиге)", "warn")
        self.add(f"Источник  : {src_ip} ({src_name})  [in={in_iface}]")
        self.add(f"Назначение: {dst_domain} → {dst_ip_display}")
        self.add(f"Протокол  : {protocol.upper()}:{src_port} → :{dst_port}, state={conn_state}")
        if resolution_note:
            self.add(f"ℹ {resolution_note}", "dim")
        if self.parser.rp_filter_mode != RPF_NO:
            self.add(f"ℹ rp-filter = {self.parser.rp_filter_mode}", "dim")
        vrf_in = self.parser.vrf_for_iface(in_iface)
        if vrf_in:
            self.add(f"ℹ in-iface '{in_iface}' привязан к VRF '{vrf_in}'", "dim")
        self.add("")

        self.route_path.append(("SRC", f"{src_ip}\n{src_name}"))

        # 1. DNS
        self.add("▶ [1/10] DNS", "stage")
        if dst_domain in self.parser.dns_static:
            resolved = self.parser.dns_static[dst_domain]
            self.add(f"   ✓ {dst_domain} → {resolved} (/ip dns static)", "ok")
            dst_ip = resolved
        else:
            self.add(f"   • Используем IP: {dst_ip}", "info")
        self.add("")

        pkt = PacketState(src_ip, dst_ip, src_port, dst_port,
                          protocol, conn_state, in_iface=in_iface)

        fasttrack_shortcut = self._is_fasttrack_applicable(pkt)

        # 2. RAW
        self.add("▶ [2/10] raw chain=prerouting (до conntrack)", "stage")
        if fasttrack_shortcut:
            self.add("   ⚡ FastTrack: raw пропущен (пакет установленного "
                     "соединения идёт через FastPath)", "warn")
        else:
            raw_act, raw_idx, raw_rule = self._run_raw_chain(
                "prerouting", pkt, dst_domain, overrides)
            if raw_act == "drop":
                self.add(f"   ✗ raw #{raw_idx}: drop", "drop")
                self.route_path.append(("DROP", f"raw drop\n#{raw_idx}"))
                self.summary = ("DROP: raw", "drop")
                return
            elif raw_act == "notrack":
                pkt.notrack = True
                pkt.conn_state = STATE_UNTRACKED
                self.add(f"   ✓ raw #{raw_idx}: notrack (conntrack отключён)", "ok")
            elif raw_act == "accept":
                self.add(f"   ✓ raw #{raw_idx}: accept", "ok")
            else:
                self.add("   • raw: правил не совпало", "info")
        self.add("")

        # 3. Conntrack
        self.add("▶ [3/10] connection tracking", "stage")
        if pkt.notrack:
            self.add("   • notrack: conntrack пропущен, state=untracked", "warn")
        elif self.parser.conntrack_enabled:
            if conn_state == STATE_NEW:
                self.add("   ✓ new connection → создаём запись conntrack", "ok")
            elif conn_state in (STATE_ESTABLISHED, STATE_RELATED):
                self.add(f"   ✓ {conn_state} → запись найдена", "ok")
            elif conn_state == STATE_INVALID:
                self.add("   ✗ invalid → обычно drop в filter", "warn")
            else:
                self.add(f"   • state={conn_state}", "info")
        else:
            self.add("   • conntrack отключён", "warn")
        self.add("")

        # 3.5. rp-filter (uRPF)
        if self.parser.rp_filter_mode != RPF_NO and not pkt.notrack \
                and not fasttrack_shortcut:
            self.add("▶ rp-filter (uRPF)", "stage")
            ok, msg = self._check_rp_filter(pkt)
            if not ok:
                self.add(f"   ✗ {msg} → DROP", "drop")
                self.route_path.append(("DROP", "rp-filter\n(uRPF)"))
                self.summary = ("DROP: rp-filter", "drop")
                return
            else:
                if msg:
                    self.add(f"   ⚠ {msg}", "warn")
                else:
                    self.add(f"   ✓ rp-filter={self.parser.rp_filter_mode}: OK", "ok")
            self.add("")
        elif fasttrack_shortcut and self.parser.rp_filter_mode != RPF_NO:
            self.add("▶ rp-filter (uRPF)", "stage")
            self.add("   ⚡ FastTrack: rp-filter пропущен (пакет в FastPath)", "warn")
            self.add("")

        # 4. Mangle PREROUTING
        self.add("▶ [4/10] mangle chain=prerouting", "stage")
        if fasttrack_shortcut:
            self.add("   ⚡ FastTrack: mangle prerouting пропущен", "warn")
        else:
            self._run_mangle_chain("prerouting", pkt, dst_domain, overrides)
            if pkt.routing_mark:
                self.add(f"   → routing-mark = {pkt.routing_mark}", "dim")
        self.add("")

        # 5. DST-NAT
        router_ips = {a["address"].split("/")[0]
                      for a in self.parser.interface_addresses}
        is_input = pkt.dst_ip in router_ips

        self.add("▶ [5/10] nat chain=dstnat", "stage")
        if fasttrack_shortcut:
            self.add("   ⚡ FastTrack: dstnat пропущен (NAT применён на первом "
                     "пакете соединения)", "warn")
        else:
            pre_dst = pkt.dst_ip
            self._run_dstnat(pkt, dst_domain, overrides)
            if pkt.dst_ip != pre_dst:
                self.add(f"   → dst: {pre_dst} → {pkt.dst_ip}", "dim")
            else:
                self.add("   • dstnat не применился", "info")
        is_input = pkt.dst_ip in router_ips
        self.add("")

        # 6. ROUTING DECISION
        self.add("▶ [6/10] routing decision", "stage")

        vrf_default_table: str | None = self.parser.vrf_for_iface(pkt.in_iface)
        if pkt.routing_mark:
            routing_mark = pkt.routing_mark
        elif vrf_default_table:
            routing_mark = vrf_default_table
            self.add(f"   ℹ VRF '{routing_mark}' входящего интерфейса "
                     f"'{pkt.in_iface}' — таблица по умолчанию", "dim")
        else:
            routing_mark = TABLE_MAIN

        if routing_mark != TABLE_MAIN and not self._table_exists(routing_mark):
            self.add(f"   ⚠ Таблица '{routing_mark}' не объявлена → main", "warn")
            routing_mark = TABLE_MAIN

        rule_table, only_in_table = self._apply_routing_rules(pkt, routing_mark, dst_domain)
        if rule_table:
            routing_mark = rule_table

        self.add(f"   Таблица: {routing_mark}", "dim")

        if routing_mark != TABLE_MAIN and not self.parser.table_has_fib(routing_mark):
            self.add(f"   ✗ Таблица '{routing_mark}' не имеет флага fib → "
                     f"пересылка невозможна", "drop")
            self.add(f"     (в RouterOS v7 таблицы без fib существуют только "
                     f"для оценки routing policy)", "dim")
            self.route_path.append(("DROP", f"table '{routing_mark}'\nwithout fib"))
            self.summary = (f"DROP: таблица {routing_mark} без fib", "drop")
            return

        routes, actual_table, table_without_fib = self._match_route(
            pkt.dst_ip, routing_mark, overrides, pkt=pkt,
            only_in_table=only_in_table)
        if not routes:
            if only_in_table:
                self.add(f"   ✗ DROP: lookup-only-in-table — нет маршрута "
                         f"в '{routing_mark}'", "drop")
                self.route_path.append(("DROP", f"no route\nin {routing_mark}"))
                self.summary = ("DROP: lookup-only-in-table", "drop")
                return
            if ip_unknown:
                self.add(f"   ✗ DROP: цель не резолвится (IP неизвестен)", "drop")
                self.route_path.append(("DROP", "IP неизвестен"))
                self.summary = ("DROP: цель не резолвится", "drop")
            else:
                self.add(f"   ✗ DROP: нет маршрута до {pkt.dst_ip} "
                         f"в '{routing_mark}'", "drop")
                self.route_path.append(("DROP", f"no route in\n{routing_mark}"))
                self.summary = (f"DROP: нет маршрута в {routing_mark}", "drop")
            return

        route = routes[0]

        if route.get("policy_only"):
            self.add(f"   ✗ Маршрут в VRF '{actual_table}' без fib → "
                     f"пересылка невозможна", "drop")
            self.route_path.append(("DROP", f"VRF '{actual_table}'\nwithout fib"))
            self.summary = (f"DROP: VRF {actual_table} без fib", "drop")
            return

        if len(routes) > 1:
            method = "per-packet round-robin (v6)" if self.parser.ros_version < 7 \
                     else "per-connection L3/L4 hash (v7)"
            self.add(f"   ⚖ ECMP: выбрано {method} "
                     f"({len(routes)} маршрутов)", "warn")

        if route.get("type") in ("blackhole", "unreachable", "prohibit"):
            self.add(f"   ✗ Маршрут type={route['type']} → DROP", "drop")
            self.route_path.append(("DROP", f"route type\n{route['type']}"))
            self.summary = (f"DROP: route {route['type']}", "drop")
            return

        if route.get("gateway_ip") and not self._gw_iface_for_ip(route["gateway_ip"]):
            rec = self._resolve_recursive_gateway(
                route, actual_table, overrides, pkt=pkt)
            if rec:
                self.add(f"   ↻ Рекурсивный nexthop: {route['gateway']} "
                         f"достижим через {rec['gateway']}", "dim")
                route = rec

        gateway = route["gateway"]
        gateway_iface = route.get("gateway_iface")
        if route.get("iface"):
            gateway_iface = route["iface"]
        out_iface = self._route_gateway_iface(gateway, gateway_iface) or gateway
        self.add(f"   ✓ {route['dst']} via {gateway}  "
                 f"[table={route.get('table', actual_table)}]", "ok")
        if route.get('comment'):
            self.add(f"     comment: {route['comment']}", "dim")
        self.add(f"     → out={out_iface}", "info")

        if route.get("pref_src"):
            pkt.pref_src = route["pref_src"]
            self.add(f"     pref-src={route['pref_src']}", "dim")

        self.add("")
        self.route_path.append(("ROUTE",
                                f"{route['dst']}\nvia {gateway}\n"
                                f"[{route.get('table', actual_table)}]"))
        pkt.out_iface = out_iface

        if fasttrack_shortcut:
            self.add("▶ [7-10/10] FastPath — все цепочки пропущены", "stage")
            self.add("   ⚡ FastTrack: mangle forward, filter forward, "
                     "mangle postrouting, srcnat пропущены", "warn")
            self.add("     (в FastPath пакеты установленного соединения "
                     "обрабатываются аппаратно/быстрым путём)", "dim")
            pkt.nat_src = self._iface_address(pkt.out_iface) or pkt.src_ip
            self.add("")
            self.add("═══ ИТОГ ═══", "stage")
            self.summary = (f"OK: {pkt.out_iface or in_iface} "
                            f"(FastPath, NAT применён ранее)", "ok")
            self.route_path.append(("NAT", f"FastPath\nна {pkt.out_iface or in_iface}"))
            self.route_path.append(("DST", f"{dst_domain}\n{dst_ip_display}"))
            self.add(f"   {self.summary[0]}", self.summary[1])
            return

        # 7. Hairpin
        hairpin = False
        if pkt.dstnat_happened:
            src_in_local = self._iface_in_any_local_subnet(pkt.src_ip)
            orig_dst_in_local = self._iface_in_any_local_subnet(pkt.original_dst_ip)
            router_ips_check = {a["address"].split("/")[0]
                                for a in self.parser.interface_addresses}
            orig_dst_is_router = pkt.original_dst_ip in router_ips_check
            if src_in_local and orig_dst_is_router and not orig_dst_in_local:
                hairpin = True
                self.add(f"   ℹ Hairpin NAT: src в подсети {src_in_local}, "
                         f"original dst = IP роутера {pkt.original_dst_ip}", "warn")

        # 8. Filter INPUT
        if is_input:
            self.add("▶ [7/10] filter chain=input (dst = роутер)", "stage")
            f_action, f_idx, f_rule = self._run_filter_chain(
                "input", pkt, dst_domain, overrides)
            if f_action in ("drop", "reject"):
                comment = (f_rule or {}).get("comment") or ""
                self.add(f"   ✗ input filter #{f_idx}: {f_action}"
                         f"{(' ('+comment+')') if comment else ''}", "drop")
                self.route_path.append(("DROP", f"input {f_action}\n#{f_idx}"))
                self.summary = (f"DROP: input {f_action}", "drop")
                return
            elif f_action == "accept":
                self.add(f"   ✓ input filter #{f_idx}: accept", "ok")
            else:
                self.add("   ✓ input: default accept", "ok")
            self.add("")

        # 9. Mangle FORWARD
        self.add("▶ [8/10] mangle chain=forward", "stage")
        self._run_mangle_chain("forward", pkt, dst_domain, overrides)
        self.add("")

        # 10. FILTER FORWARD
        self.add("▶ [9/10] filter chain=forward", "stage")
        f_action, f_idx, f_rule = self._run_filter_chain(
            "forward", pkt, dst_domain, overrides)
        if f_action in ("drop", "reject"):
            comment = (f_rule or {}).get("comment") or ""
            self.add(f"   ✗ filter #{f_idx}: action={f_action}"
                     f"{(' ('+comment+')') if comment else ''}", "drop")
            self.route_path.append(("DROP", f"filter {f_action}\n#{f_idx}"))
            self.summary = (f"DROP: filter {f_action}", "drop")
            return
        elif f_action == "accept":
            comment = (f_rule or {}).get("comment") or ""
            self.add(f"   ✓ filter #{f_idx}: action=accept"
                     f"{(' ('+comment+')') if comment else ''}", "ok")
        else:
            self.add("   ✓ filter: default accept (правил не совпало)", "ok")

        if pkt.fasttrack_candidate_idx is not None and not pkt.notrack:
            pkt.fasttracked = True

        if pkt.fasttracked:
            self.add("   ⚡ FastTrack: соединение помечено для FastPath", "warn")
            self.add("     (все последующие пакеты соединения пойдут через FastPath,", "dim")
            self.add("      минуя mangle, filter, queue trees, simple queues, "
                     "IP accounting)", "dim")
        self.add("")

        # 11. Mangle POSTROUTING + SRC-NAT
        self.add("▶ [10/10] mangle chain=postrouting", "stage")
        self._run_mangle_chain("postrouting", pkt, dst_domain, overrides)
        self.add("")

        self.add("▶ [10/10] nat chain=srcnat (postrouting)", "stage")
        nat_applied, nat_idx = self._run_srcnat(pkt, dst_domain, overrides)

        if hairpin and not nat_applied:
            self.add("   ℹ Hairpin: принудительный masquerade на in-интерфейс", "warn")
            pkt.nat_src = self._iface_address(pkt.in_iface) or pkt.src_ip
            nat_applied = True

        if not nat_applied and not pkt.notrack:
            self.add("   ⚠ NAT не применён", "warn")
        self.add("")

        # 12. Выход
        self.add("▶ выход через интерфейс", "stage")
        final_src = pkt.nat_src or pkt.pref_src or pkt.src_ip

        if nat_applied:
            self.add(f"   source: {final_src} (после NAT)", "ok")
            self.route_path.append(("NAT", f"masquerade\nна {pkt.out_iface or in_iface}"))
        else:
            self.add(f"   source: {final_src} (без NAT)", "warn")

        if self._is_wan_iface(out_iface) and not nat_applied:
            if not self._src_valid_for_iface(final_src, out_iface):
                self.add(f"   ✗ DROP: source {final_src} невалиден для WAN "
                         f"{out_iface}", "drop")
                self.add("     (частный source без NAT через WAN не выпускается)", "dim")
                self.route_path.append(("DROP", f"invalid src\nfor {out_iface}"))
                self.summary = (f"DROP: invalid src для {out_iface}", "drop")
                return

        self.add(f"   ✓ Пакет уходит через {pkt.out_iface or in_iface}", "ok")
        self.add("")

        self.add("═══ ИТОГ ═══", "stage")
        if nat_applied:
            self.summary = (f"OK: {pkt.out_iface or in_iface} + NAT", "ok")
        else:
            self.summary = (f"OK: {pkt.out_iface or in_iface} без NAT", "ok")
        self.route_path.append(("DST", f"{dst_domain}\n{dst_ip_display}"))
        self.add(f"   {self.summary[0]}", self.summary[1])
