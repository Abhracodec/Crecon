from colorama import Fore, Back, Style, init as colorama_init
colorama_init(autoreset=True)

W  = Fore.WHITE
C  = Fore.CYAN
G  = Fore.GREEN
Y  = Fore.YELLOW
R  = Fore.RED
M  = Fore.MAGENTA
DG = Fore.LIGHTBLACK_EX
B  = Style.BRIGHT
D  = Style.RESET_ALL


BANNER = f"""
{DG}{'─' * 58}{D}
{B}{C}                                                        {D}
{B}{C}    ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗  {D}
{B}{C}   ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║  {D}
{B}{C}   ██║     ██████╔╝█████╗  ██║     ██║  ██║██╔██╗██║  {D}
{B}{C}   ██║     ██╔══██╗██╔══╝  ██║     ██║  ██║██║╚████║  {D}
{B}{C}   ╚██████╗██║  ██║███████╗╚██████╗██████╔╝██║ ╚███║  {D}
{B}{C}    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═════╝ ╚═╝  ╚══╝  {D}
{B}{C}                                                        {D}
{DG}  Automated Recon Toolkit                    v0.1.0       {D}
{DG}  {'─' * 54}{D}
{DG}  github {W}https://github.com/Abhracodec{DG}                    {D}
{DG}{'─' * 58}{D}
"""


def banner():
    print(BANNER)


def phase(name):
    labels = {
        "nmap":   f"{B}{C} NMAP  {D}",
        "enum":   f"{B}{Y} ENUM  {D}",
        "recon":  f"{B}{W} RECON {D}",
        "ssh":    f"{B}{R} SSH   {D}",
        "nuclei": f"{B}{M} NUCLEI{D}",
        "cve":    f"{B}{Y} CVE   {D}",
    }
    return labels.get(name, f" {name.upper()} ")


def phase_header(name, msg):
    label = phase(name)
    print(f"\n  {DG}┌{'─' * 56}┐{D}")
    print(f"  {DG}│{D} {label}  {B}{W}{msg:<48}{D} {DG}│{D}")
    print(f"  {DG}└{'─' * 56}┘{D}")


def info(msg):
    print(f"  {DG}·{D}  {msg}")


def success(msg):
    print(f"  {G}{B}✓{D}  {G}{msg}{D}")


def warn(msg):
    print(f"  {Y}{B}!{D}  {Y}{msg}{D}")


def error(msg):
    print(f"  {R}{B}✗{D}  {R}{msg}{D}")


def finding(label, value, color=G):
    print(f"  {DG}│{D}  {color}{B}{label:<16}{D}  {value}")


def section(title):
    print(f"\n  {B}{C}{'═' * 58}{D}")
    print(f"  {B}{C}  {title}{D}")
    print(f"  {B}{C}{'═' * 58}{D}\n")


def divider():
    print(f"  {DG}{'─' * 58}{D}")


def port_line(port, service, product="", version="", cves=None):
    ver = f"{product} {version}".strip()

    # color code by risk
    if port == 22:
        port_color = Y    # SSH — medium risk
    elif port in (80, 443, 8080, 8443):
        port_color = C    # web — interesting
    elif port in (21, 23, 3389, 5900):
        port_color = R    # high risk services
    else:
        port_color = G

    print(f"\n  {port_color}{B}  ▸ {port}/tcp{D}   {B}{W}{service:<14}{D}  {DG}{ver}{D}")

    if cves:
        for c in cves[:3]:
            score    = c['score'] or "?"
            sev      = c['severity'].upper()
            desc     = c['description'][:75]

            if sev == "CRITICAL":
                sev_color = f"{B}{R}"
                badge     = "CRITICAL"
            elif sev == "HIGH":
                sev_color = R
                badge     = "HIGH    "
            elif sev == "MEDIUM":
                sev_color = Y
                badge     = "MEDIUM  "
            else:
                sev_color = DG
                badge     = "LOW     "

            print(f"    {DG}└─{D} {sev_color}{badge}{D}  {B}{c['id']}{D}  "
                  f"{DG}CVSS:{score}{D}  {desc}...")


def ssh_hit(username, password, host, port):
    print(f"\n  {R}{B}{'!' * 58}{D}")
    print(f"  {R}{B}  VALID SSH CREDENTIALS FOUND{D}")
    print(f"  {R}{B}{'!' * 58}{D}")
    print(f"  {B}{W}  {username}:{password}{D}  →  {host}:{port}")
    print(f"  {R}{B}{'!' * 58}{D}\n")


def nuclei_hit(finding_dict):
    sev = finding_dict.get("severity", "").upper()
    if sev == "CRITICAL":
        color = f"{B}{R}"
    elif sev == "HIGH":
        color = R
    elif sev == "MEDIUM":
        color = Y
    else:
        color = DG

    name    = finding_dict.get("name", "")
    matched = finding_dict.get("matched", "")
    tmpl    = finding_dict.get("template", "")

    print(f"  {color}▸ [{sev}]{D}  {B}{name}{D}")
    print(f"    {DG}template:{D} {tmpl}")
    print(f"    {DG}matched: {D} {matched}")


def summary(report):
    hosts      = report.get("hosts", [])
    dirs       = report.get("dirs", [])
    recon_data = report.get("recon", [])
    ssh_hits   = report.get("ssh_hits", [])
    nuclei_hits= report.get("nuclei", [])

    all_emails = set()
    all_phones = set()
    all_tech   = []
    all_cves   = []

    for page in recon_data:
        all_emails.update(page.get("emails", []))
        all_phones.update(page.get("phones", []))
        all_tech.extend(page.get("tech", []))

    for host in hosts:
        for port in host.get("ports", []):
            all_cves.extend(port.get("cves", []))

    open_count  = sum(len(h["ports"]) for h in hosts)
    tech_dedup  = list(dict.fromkeys(all_tech))

    # critical/high CVEs
    critical_cves = [c for c in all_cves if c.get("severity") in ("CRITICAL", "HIGH")]

    section("Scan Complete — Summary")

    print(f"  {DG}  Target     {D}  {B}{report['meta']['target']}{D}")
    print(f"  {DG}  Timestamp  {D}  {report['meta']['timestamp']}")
    divider()

    finding("Hosts up",      len(hosts))
    finding("Open ports",    open_count)
    finding("CVEs found",    len(all_cves),
            color=R if critical_cves else Y)
    finding("Critical/High", len(critical_cves),
            color=R if critical_cves else DG)
    finding("Nuclei hits",   len(nuclei_hits),
            color=R if nuclei_hits else DG)
    finding("Dirs found",    len(dirs))
    finding("Emails",        len(all_emails),
            color=Y if all_emails else DG)
    finding("Phones",        len(all_phones),
            color=Y if all_phones else DG)
    finding("SSH hits",      len(ssh_hits),
            color=R if ssh_hits else DG)

    if tech_dedup:
        finding("Tech stack", ", ".join(tech_dedup), color=C)

    # show critical CVEs
    if critical_cves:
        print(f"\n  {R}{B}  High Priority CVEs:{D}")
        divider()
        for c in critical_cves[:5]:
            print(f"  {R}{B}  ▸ {c['id']}{D}  "
                  f"CVSS:{c['score']}  {DG}{c['description'][:70]}...{D}")

    # show emails
    if all_emails:
        print(f"\n  {Y}{B}  Emails Found:{D}")
        divider()
        for e in sorted(all_emails):
            print(f"    {Y}·{D} {e}")

    # show SSH hits
    if ssh_hits:
        print(f"\n  {R}{B}  Valid SSH Credentials:{D}")
        divider()
        for h in ssh_hits:
            print(f"    {R}{B}▸{D} {h['username']}:{h['password']}"
                  f"  →  {h['host']}:{h['port']}")

    # show nuclei hits
    if nuclei_hits:
        print(f"\n  {M}{B}  Nuclei Findings:{D}")
        divider()
        for n in nuclei_hits:
            sev = n.get('severity','').upper()
            print(f"    {M}▸{D} [{sev}]  {n.get('name','')}  "
                  f"{DG}{n.get('matched','')}{D}")

    print()