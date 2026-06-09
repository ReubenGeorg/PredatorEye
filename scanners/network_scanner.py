"""
Scans open ports, active network connections, and interfaces.
"""

import socket
import platform
import subprocess
import concurrent.futures
from config import SCAN_PORTS, RISKY_PORTS, PORT_SCAN_TIMEOUT, MAX_PORT_THREADS


class NetworkScanner:
    def scan(self) -> dict:
        return {
            "open_ports": self._scan_ports(),
            "active_connections": self._active_connections(),
            "interfaces": self._network_interfaces(),
            "dns_servers": self._dns_servers(),
            "routing_table": self._routing_table(),
        }

    # ------------------------------------------------------------------
    def _scan_ports(self) -> list:
        target = "127.0.0.1"
        open_ports = []

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(PORT_SCAN_TIMEOUT)
                    if s.connect_ex((target, port)) == 0:
                        banner = self._grab_banner(target, port)
                        info = RISKY_PORTS.get(port, (f"Port {port}", "Info", "Unknown service"))
                        return {
                            "port": port,
                            "service": info[0],
                            "severity": info[1],
                            "risk_note": info[2],
                            "banner": banner,
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PORT_THREADS) as executor:
            results = executor.map(check_port, SCAN_PORTS)

        for r in results:
            if r:
                open_ports.append(r)

        return sorted(open_ports, key=lambda x: x["port"])

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((host, port))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").strip()
                return banner[:100]
        except Exception:
            return ""

    def _active_connections(self) -> list:
        connections = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    except Exception:
                        proc_name = "Unknown"
                    connections.append({
                        "local": laddr,
                        "remote": raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process": proc_name,
                    })
        except ImportError:
            if platform.system() == "Windows":
                try:
                    out = subprocess.check_output(
                        ["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines():
                        if "ESTABLISHED" in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                connections.append({
                                    "local": parts[1],
                                    "remote": parts[2],
                                    "status": parts[3],
                                    "pid": parts[4],
                                    "process": "N/A",
                                })
                except Exception:
                    pass
        return connections[:50]

    def _network_interfaces(self) -> list:
        interfaces = []
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                iface = {"name": name, "addresses": []}
                for addr in addrs:
                    iface["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                    })
                interfaces.append(iface)
        except ImportError:
            pass
        return interfaces

    def _dns_servers(self) -> list:
        servers = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    if "DNS Servers" in line or "DNS Server" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            ip = parts[-1].strip()
                            if ip:
                                servers.append(ip)
            except Exception:
                pass
        return servers

    def _routing_table(self) -> list:
        routes = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["route", "print", "-4"], text=True, stderr=subprocess.DEVNULL
                )
                in_table = False
                for line in out.splitlines():
                    if "Network Destination" in line:
                        in_table = True
                        continue
                    if in_table:
                        parts = line.split()
                        if len(parts) >= 4:
                            routes.append({
                                "destination": parts[0],
                                "netmask": parts[1],
                                "gateway": parts[2],
                                "interface": parts[3],
                            })
            except Exception:
                pass
        return routes[:20]
