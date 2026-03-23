import argparse
import json
import sys
from pathlib import Path

from crecon.utils.output import (
    banner, phase, phase_header, info, success, warn, error,
    port_line, summary, section, divider
)
from crecon.utils.config import add_key, remove_key, list_keys, has_keys
from crecon.utils import ai
from crecon.core import scanner, recon, enumerator, orchestrator


def handle_callback(event):
    if not isinstance(event, dict):
        return

    if "phase" in event:
        phase_header(event["phase"], event["msg"])
        return

    if "warning" in event:
        warn(event["warning"])
        return

    if "code" in event and "url" in event:
        code  = event["code"]
        color = "\033[32m" if code == 200 else "\033[33m"
        reset = "\033[0m"
        redir = f"  → {event['redirect']}" if event.get("redirect") else ""
        print(f"    {color}[{code}]{reset}  {event['url']}{redir}")
        return

    if "emails" in event:
        for e in event.get("emails", []):
            success(f"email  {e}")
        tech = event.get("tech", [])
        if tech:
            info(f"tech   {', '.join(tech)}")
        return

    if "username" in event:
        success(f"SSH valid  {event['username']}:{event['password']}")
        return

    if "template" in event:
        from crecon.utils.output import nuclei_hit
        nuclei_hit(event)
        return


def _render_ai(text):
    import re
    from colorama import Fore, Style
    B  = Style.BRIGHT
    D  = Style.RESET_ALL
    C  = Fore.CYAN
    Y  = Fore.YELLOW
    G  = Fore.GREEN
    R  = Fore.RED
    M  = Fore.MAGENTA
    DG = Fore.LIGHTBLACK_EX
    W  = Fore.WHITE

    for line in text.splitlines():
        stripped = line.strip()

        # skip empty lines but add spacing
        if not stripped:
            print()
            continue

        # h1 — # Title
        if stripped.startswith("# ") and not stripped.startswith("##"):
            title = stripped[2:].upper()
            print(f"\n  {B}{C}{'━' * 56}{D}")
            print(f"  {B}{C}  {title}{D}")
            print(f"  {B}{C}{'━' * 56}{D}")

        # h2 — ## Title
        elif stripped.startswith("## ") and not stripped.startswith("###"):
            title = stripped[3:]
            print(f"\n  {B}{W}  ▌ {title}{D}")
            print(f"  {DG}  {'─' * 50}{D}")

        # h3 — ### Title
        elif stripped.startswith("### "):
            title = stripped[4:]
            print(f"\n  {B}{Y}  ◆ {title}{D}")

        # h4 — #### Title
        elif stripped.startswith("#### "):
            title = stripped[5:]
            print(f"\n  {M}  ▸ {title}{D}")

        # bullet points
        elif stripped.startswith(("* ", "- ", "• ")):
            content = stripped[2:]
            # highlight key terms
            content = re.sub(r'\*\*(.+?)\*\*', f'{B}{W}\\1{D}', content)
            content = re.sub(r'`(.+?)`',        f'{G}\\1{D}',    content)

            # color code by keyword
            if any(k in content.lower() for k in ("critical", "exploit", "payload", "command")):
                print(f"  {R}  ●{D} {content}")
            elif any(k in content.lower() for k in ("high", "vulnerability", "weakness", "attack")):
                print(f"  {Y}  ●{D} {content}")
            elif any(k in content.lower() for k in ("medium", "note", "suggest")):
                print(f"  {C}  ●{D} {content}")
            else:
                print(f"  {DG}  ●{D} {content}")

        # numbered list
        elif re.match(r'^\d+\.', stripped):
            num, rest = stripped.split(".", 1)
            rest = rest.strip()
            rest = re.sub(r'\*\*(.+?)\*\*', f'{B}{W}\\1{D}', rest)
            rest = re.sub(r'`(.+?)`',        f'{G}\\1{D}',    rest)
            print(f"\n  {B}{C}  {num}.{D} {rest}")

        # severity lines
        elif "severity" in stripped.lower():
            line_clean = re.sub(r'\*\*(.+?)\*\*', f'{B}{W}\\1{D}', stripped)
            if "critical" in stripped.lower():
                print(f"  {B}{R}  ⚠ {line_clean}{D}")
            elif "high" in stripped.lower():
                print(f"  {R}  ⚠ {line_clean}{D}")
            elif "medium" in stripped.lower():
                print(f"  {Y}  ⚠ {line_clean}{D}")
            else:
                print(f"  {DG}  ⚠ {line_clean}{D}")

        # code blocks / commands
        elif stripped.startswith("```") or stripped.endswith("```"):
            print(f"  {DG}  {'─' * 48}{D}")

        # regular paragraph text
        else:
            content = re.sub(r'\*\*(.+?)\*\*', f'{B}{W}\\1{D}', stripped)
            content = re.sub(r'`(.+?)`',        f'{G}\\1{D}',    content)
            print(f"  {DG}  {content}{D}")


def run_ai(mode, data, flag):
    if not flag:
        return
    if not has_keys():
        error("No API key found. Run: crecon config --add-key <key>")
        return
    section("AI Vulnerability Analysis")
    info("Analyzing findings — this may take a moment...")
    result = ai.analyze(mode, data)
    if result:
        print()
        _render_ai(result)
        print()
    else:
        warn("AI analysis failed — check your keys with: crecon config --list-keys")


def cmd_config(args):
    if args.add_key:
        add_key(args.add_key, provider=args.provider)
    elif args.remove_key:
        remove_key(args.remove_key)
    elif args.list_keys:
        list_keys()
    else:
        error("No option given. Try: crecon config --add-key <key>")


def cmd_scan(args):
    ip = scanner.resolve(args.target)
    if not ip:
        error(f"Cannot resolve {args.target}")
        sys.exit(1)

    info(f"Target   {args.target}  ({ip})")
    info(f"Ports    {args.start}–{args.end}")
    info(f"Threads  {args.threads}")
    divider()

    ports   = list(range(args.start, args.end + 1))
    results = []
    done    = [0]
    total   = len(ports)

    def on_result(r):
        results.append(r)
        done[0] += 1
        pct = done[0] / total * 100
        bar = "█" * int(pct / 4) + "░" * (25 - int(pct / 4))
        print(f"\r  [{bar}] {pct:5.1f}%", end="", flush=True)
        if r["state"] == "open":
            print()
            port_line(
                r["port"], r["service"],
                version = r.get("banner", ""),
                cves    = r.get("cves", []),
            )

    scanner.scan(ip, ports, threads=args.threads,
                 timeout=args.timeout, grab=args.banners, callback=on_result)

    print()
    open_ports = [r for r in results if r["state"] == "open"]
    divider()
    info(f"{len(open_ports)} open port(s) found.")

    if args.output:
        Path(args.output).write_text(
            json.dumps(open_ports, indent=2), encoding="utf-8"
        )
        info(f"Saved to {args.output}")

    run_ai("scan", {"target": args.target, "open_ports": open_ports}, args.ai)


def cmd_recon(args):
    info(f"Target  {args.url}")
    info(f"Pages   up to {args.depth}")
    divider()

    results = recon.crawl(
        args.url,
        max_pages = args.depth,
        delay     = 0.5,
        callback  = handle_callback,
    )

    divider()
    if args.output:
        recon.save_csv(results, args.output)
        info(f"CSV saved to {args.output}")

    run_ai("recon", {"url": args.url, "pages": results}, args.ai)


def cmd_enum(args):
    results = []

    if args.mode == "dirs":
        info(f"Dir scan  {args.url}")
        divider()
        results = enumerator.dir_scan(
            args.url,
            args.wordlist,
            threads  = args.threads,
            callback = handle_callback,
        )
        divider()
        info(f"{len(results)} path(s) found.")
        run_ai("enum", {"type": "dirs", "url": args.url, "found": results}, args.ai)

    elif args.mode == "subs":
        info(f"Subdomain scan  {args.domain}")
        divider()
        ns = [s.strip() for s in args.resolvers.split(",") if s.strip()] \
             if args.resolvers else None
        results = enumerator.subdomain_scan(
            args.domain,
            args.wordlist,
            threads     = args.threads,
            nameservers = ns,
            callback    = handle_callback,
        )
        divider()
        info(f"{len(results)} subdomain(s) found.")
        run_ai("enum", {"type": "subs", "domain": args.domain, "found": results}, args.ai)


def cmd_auto(args):
    info(f"Target    {args.target}")
    info(f"Ports     {args.ports}")
    if args.wordlist:
        info(f"Wordlist  {args.wordlist}")
    if args.ai:
        info(f"AI mode   enabled")
    divider()

    report = orchestrator.run(
        target   = args.target,
        ports    = args.ports,
        wordlist = args.wordlist,
        no_ssh   = args.no_ssh,
        dry_run  = args.dry_run,
        callback = handle_callback,
    )

    summary(report)

    if args.output:
        safe = json.dumps(report, indent=2, default=lambda o: list(o)
                          if isinstance(o, set) else str(o))
        Path(args.output).write_text(safe, encoding="utf-8")
        info(f"Report saved to {args.output}")

    run_ai("auto", report, args.ai)


def main():
    banner()

    parser = argparse.ArgumentParser(
        prog="crecon",
        description="Automated recon toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── config ────────────────────────────────────────────────────────────────
    cp = sub.add_parser("config", help="Manage API keys")
    cp.add_argument("--add-key",    metavar="KEY", help="Add an API key")
    cp.add_argument("--remove-key", metavar="N",   type=int, help="Remove key by index")
    cp.add_argument("--list-keys",  action="store_true", help="List all saved keys")
    cp.add_argument("--provider",   default="anthropic",
                    choices=["anthropic", "openai", "groq", "gemini", "github"],
                    help="Provider for the key (default: anthropic)")

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="TCP port scanner")
    sp.add_argument("target")
    sp.add_argument("--start",   type=int,   default=1)
    sp.add_argument("--end",     type=int,   default=1000)
    sp.add_argument("--threads", type=int,   default=100)
    sp.add_argument("--timeout", type=float, default=1.0)
    sp.add_argument("--banners", action="store_true")
    sp.add_argument("--output",  default="")
    sp.add_argument("--ai",      action="store_true", help="AI vulnerability analysis")

    # ── recon ─────────────────────────────────────────────────────────────────
    rp = sub.add_parser("recon", help="Web crawler + contact extractor")
    rp.add_argument("--url",    required=True)
    rp.add_argument("--depth",  type=int, default=20)
    rp.add_argument("--output", default="recon.csv")
    rp.add_argument("--ai",     action="store_true", help="AI vulnerability analysis")

    # ── enum ──────────────────────────────────────────────────────────────────
    ep     = sub.add_parser("enum", help="Directory and subdomain brute-force")
    ep_sub = ep.add_subparsers(dest="mode", required=True)

    dp = ep_sub.add_parser("dirs")
    dp.add_argument("--url",      required=True)
    dp.add_argument("--wordlist", required=True)
    dp.add_argument("--threads",  type=int, default=15)
    dp.add_argument("--ai",       action="store_true", help="AI vulnerability analysis")

    sp2 = ep_sub.add_parser("subs")
    sp2.add_argument("--domain",    required=True)
    sp2.add_argument("--wordlist",  required=True)
    sp2.add_argument("--threads",   type=int, default=20)
    sp2.add_argument("--resolvers", default="")
    sp2.add_argument("--ai",        action="store_true", help="AI vulnerability analysis")

    # ── auto ──────────────────────────────────────────────────────────────────
    ap = sub.add_parser("auto", help="Full auto recon (chains all tools)")
    ap.add_argument("target")
    ap.add_argument("--ports",    default="1-1024")
    ap.add_argument("--wordlist", default=None)
    ap.add_argument("--no-ssh",   action="store_true")
    ap.add_argument("--dry-run",  action="store_true")
    ap.add_argument("--output",   default="report.json")
    ap.add_argument("--ai",       action="store_true", help="AI vulnerability analysis")

    args = parser.parse_args()

    dispatch = {
        "config": cmd_config,
        "scan":   cmd_scan,
        "recon":  cmd_recon,
        "enum":   cmd_enum,
        "auto":   cmd_auto,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()