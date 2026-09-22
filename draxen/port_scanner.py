import socket

from .core import public_ip

DEFAULT_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (465, "SMTPS"),
    (587, "Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Proxy"),
    (8443, "HTTPS-Alt"),
    (8888, "HTTP-Alt2"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]


def clean_text(raw_bytes):
    if not raw_bytes:
        return ""
    text = raw_bytes.decode("utf-8", errors="replace")
    return "".join(c if c.isprintable() and c != "\r" else " " for c in text).strip()[:180]


def grab_banner(sock, port, ip):
    sock.settimeout(1.5)
    try:
        if port in (21, 22, 23, 25, 110, 143, 465, 587, 993, 995):
            data = sock.recv(512)
            return clean_text(data)
        if port in (80, 8080, 8443, 8888, 9200):
            req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: SZOBO-DRAXEN\r\n\r\n".encode("ascii")
            sock.sendall(req)
            data = sock.recv(1024)
            text = data.decode("latin-1", errors="replace")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()[:150]
            return clean_text(data[:120])
        if port == 3306:
            data = sock.recv(256)
            if len(data) > 5:
                null_idx = data.find(b"\x00", 5)
                if null_idx > 5:
                    ver = data[5:null_idx].decode("latin-1", errors="replace")
                    return f"MySQL {ver}".strip()
            return clean_text(data[:100])
        if port == 6379:
            sock.sendall(b"INFO\r\n")
            data = sock.recv(256)
            text = data.decode("latin-1", errors="replace")
            for line in text.splitlines():
                if line.startswith("redis_version:"):
                    return f"Redis {line.split(':', 1)[1].strip()}"
            return clean_text(data[:100])
    except Exception:
        pass
    return ""


def probe_port(ip, port, service_name, timeout=2.0):
    if not public_ip(ip):
        return {"port": port, "service": service_name, "open": False, "banner": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = grab_banner(sock, port, ip)
            return {
                "port": port,
                "service": service_name,
                "open": True,
                "banner": banner,
            }
    except Exception:
        return {"port": port, "service": service_name, "open": False, "banner": ""}


class PortScanner:
    def __init__(self, report, ports=None, timeout=2.0, client=None):
        self.report = report
        self.ports = list(ports) if ports else list(DEFAULT_PORTS)
        self.timeout = timeout
        self.client = client

    def scan_ip(self, ip):
        if not public_ip(ip):
            return []
        if self.client is not None and not hasattr(self.client, "opener"):
            mock_data = getattr(self.client, "mock_ports", None)
            if mock_data is None:
                return []
            results = []
            for item in mock_data:
                self.report.add("open_port", f"{item['port']}/tcp ({item['service']})", f"socket://{ip}:{item['port']}", "port_probe", subject=ip, relation="open_port", details=item)
                if item.get("banner"):
                    self.report.add("service_banner", f"{item['port']}/tcp [{item['service']}]: {item['banner']}", f"socket://{ip}:{item['port']}", "banner_grab", subject=ip, relation="service_banner", details=item)
                results.append(item)
            return results
        results = []
        for port, service in self.ports:
            res = probe_port(ip, port, service, timeout=self.timeout)
            if res["open"]:
                results.append(res)
                self.report.add(
                    "open_port",
                    f"{port}/tcp ({service})",
                    f"socket://{ip}:{port}",
                    "port_probe",
                    subject=ip,
                    relation="open_port",
                    details=res,
                )
                if res["banner"]:
                    self.report.add(
                        "service_banner",
                        f"{port}/tcp [{service}]: {res['banner']}",
                        f"socket://{ip}:{port}",
                        "banner_grab",
                        subject=ip,
                        relation="service_banner",
                        details=res,
                    )
        return results
