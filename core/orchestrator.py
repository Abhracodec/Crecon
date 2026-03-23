import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from crecon.core import scanner, recon, enumerator, nuclei, cve

from crecon.core import scanner, recon, enumerator, nuclei

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000, 5000, 8888}

DEFAULT_CREDS = [
    ("root",   "root"),
    ("root",   "toor"),
    ("admin",  "admin"),
    ("admin",  "password"),
    ("pi",     "raspberry"),
    ("ubuntu", "ubuntu"),
    ("user",   "user"),
]


def run_nmap(target, ports="1-1024", timeout=120):
    if not shutil.which("nmap"):
        return None, "nmap not found in PATH"

    cmd = ["nmap", "-sV", "-sC", "--open", "-T4", f"-p{ports}", "-oX", "-", target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in (0, 1):
            return None, proc.stderr[:300]
        return proc.stdout, None
    except subprocess.TimeoutExpired:
        return None, "nmap timed out"
    except Exception as e:
        return None, str(e)


def parse_nmap_xml(xml):
    hosts = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr     = host.find("address[@addrtype='ipv4']")
        ip       = addr.get("addr") if addr is not None else "?"
        hn       = host.find(".//hostname")
        hostname = hn.get("name") if hn is not None else ""

        os_match = host.find(".//osmatch")
        os_guess = f"{os_match.get('name')} ({os_match.get('accuracy')}%)" \
                   if os_match is not None else ""

        ports = []
        for p in host.findall(".//port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service") or ET.Element("service")
            ports.append({
                "port":     int(p.get("portid", 0)),
                "protocol": p.get("protocol", "tcp"),
                "service":  svc.get("name", "unknown"),
                "product":  svc.get("product", ""),
                "version":  svc.get("version", ""),
            })

        hosts.append({
            "ip":       ip,
            "hostname": hostname,
            "os":       os_guess,
            "ports":    ports,
        })

    return hosts


def trigger_dir_scan(host, port, wordlist, callback=None):
    scheme = "https" if port["port"] in (443, 8443) else "http"
    target = host["hostname"] or host["ip"]
    url    = f"{scheme}://{target}:{port['port']}"
    return enumerator.dir_scan(url, wordlist, callback=callback)


def trigger_recon(host, port, callback=None):
    scheme = "https" if port["port"] in (443, 8443) else "http"
    target = host["hostname"] or host["ip"]
    url    = f"{scheme}://{target}:{port['port']}"
    return recon.crawl(url, max_pages=10, delay=0.3, callback=callback)


def trigger_ssh(host, port, creds=None, timeout=5.0, callback=None):
    if not HAS_PARAMIKO:
        return [], "paramiko not installed"

    creds = creds or DEFAULT_CREDS
    ip    = host["ip"]
    p     = port["port"]
    hits  = []

    for username, password in creds:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname       = ip,
                port           = p,
                username       = username,
                password       = password,
                timeout        = timeout,
                banner_timeout = timeout,
                auth_timeout   = timeout,
                look_for_keys  = False,
                allow_agent    = False,
            )
            hit = {"username": username, "password": password, "host": ip, "port": p}
            hits.append(hit)
            if callback:
                callback(hit)
            client.close()
        except paramiko.AuthenticationException:
            pass
        except Exception:
            break
        finally:
            client.close()

    return hits, None


def run(target, ports="1-1024", wordlist=None, no_ssh=False,
        dry_run=False, callback=None):

    report = {
        "meta": {
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            "dry_run":   dry_run,
        },
        "hosts":    [],
        "dirs":     [],
        "recon":    [],
        "nuclei":   [],
        "ssh_hits": [],
        "errors":   [],
    }

    if callback:
        callback({"phase": "nmap", "msg": f"Scanning {target} ports {ports}"})

    if not dry_run:
        xml, err = run_nmap(target, ports)
        if err:
            report["errors"].append(err)
            return report
        hosts = parse_nmap_xml(xml)

        # enrich each host's ports with CVE data
        if callback:
            callback({"phase": "cve", "msg": "Looking up CVEs for detected services"})
        for host in hosts:
            if host["ports"]:
                host["ports"] = cve.lookup_ports(host["ports"])
    else:
        hosts = []

    report["hosts"] = hosts

    if not hosts:
        return report

    seen_web = set()

    for host in hosts:
        for port in host["ports"]:
            pnum = port["port"]

            if pnum in WEB_PORTS:
                if callback:
                    callback({"phase": "enum", "msg": f"Port {pnum} open → dir scan"})

                if wordlist and not dry_run:
                    dirs = trigger_dir_scan(host, port, wordlist, callback=callback)
                    report["dirs"].extend(dirs)

                if host["ip"] not in seen_web and not dry_run:
                    seen_web.add(host["ip"])

                    if callback:
                        callback({"phase": "recon", "msg": f"Port {pnum} open → web recon"})
                    pages = trigger_recon(host, port, callback=callback)
                    report["recon"].extend(pages)

                    if callback:
                        callback({"phase": "nuclei", "msg": f"Running nuclei against {host['ip']}"})
                    scheme     = "https" if pnum in (443, 8443) else "http"
                    target_url = f"{scheme}://{host['hostname'] or host['ip']}:{pnum}"
                    findings, err = nuclei.scan(target_url, callback=callback)
                    if err and callback:
                        callback({"warning": f"nuclei: {err}"})
                    report["nuclei"].extend(findings)

            elif pnum == 22 and not no_ssh and not dry_run:
                if callback:
                    callback({"phase": "ssh", "msg": f"Port 22 open → testing credentials"})
                hits, err = trigger_ssh(host, port, callback=callback)
                if err:
                    report["errors"].append(err)
                report["ssh_hits"].extend(hits)

    return report