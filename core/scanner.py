import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Well-known ports ──────────────────────────────────────────────────────────
COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

WEB_PORTS  = {80, 443, 8080, 8443, 8000, 3000, 5000, 8888}
_print_lock = threading.Lock()


# ── Banner grabbing ───────────────────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in WEB_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            return " | ".join(banner.splitlines())[:120]
    except Exception:
        return ""


# ── Single port probe ─────────────────────────────────────────────────────────

def probe_port(ip: str, port: int, timeout: float, grab: bool) -> dict:
    """
    Full TCP connect scan on one port.

    connect_ex() returns:
      0   → open   (SYN-ACK received — 3-way handshake completed)
      111 → closed (RST received)
      timeout → filtered (firewall dropping packets silently)
    """
    result = {
        "port":    port,
        "state":   "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner":  "",
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                result["state"] = "open"
                if grab:
                    result["banner"] = grab_banner(ip, port, timeout)

    except ConnectionRefusedError:
        result["state"] = "closed"
    except socket.timeout:
        result["state"] = "filtered"
    except OSError:
        result["state"] = "error"

    return result


# ── Public API ────────────────────────────────────────────────────────────────

def resolve(target: str) -> str | None:
    """Resolve hostname → IP. Returns None on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan(
    ip:       str,
    ports:    list[int],
    threads:  int   = 100,
    timeout:  float = 1.0,
    grab:     bool  = False,
    callback = None,          # optional: called with each result as it arrives
) -> list[dict]:
    """
    Scan a list of ports concurrently.
    Returns only open ports, sorted by port number.

    `callback(result)` fires the moment each port resolves —
    lets the CLI print results in real time without waiting for
    the full scan to finish.
    """
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(probe_port, ip, p, timeout, grab): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if callback:
                callback(result)
            if result["state"] == "open":
                open_ports.append(result)

    return sorted(open_ports, key=lambda r: r["port"])