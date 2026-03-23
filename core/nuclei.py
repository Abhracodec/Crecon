import subprocess
import json
import shutil
from pathlib import Path


def is_installed():
    return shutil.which("nuclei") is not None


def update_templates(silent=True):
    try:
        subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=silent,
            timeout=60,
        )
    except Exception:
        pass


def scan(target, severity="critical,high,medium", templates=None,
         timeout=120, callback=None):
    """
    Run nuclei against a target and return findings.

    severity: comma-separated — critical,high,medium,low,info
    templates: specific template path or tag (e.g. 'cves' 'exposures')
               None = nuclei decides based on target
    """
    if not is_installed():
        return [], "nuclei not found in PATH"

    cmd = [
        "nuclei",
        "-target",   target,
        "-severity", severity,
        "-jsonl",                  # output one JSON object per line
        "-silent",                 # no banner
        "-no-color",               # clean output
        "-timeout",  "10",
    ]

    if templates:
        cmd += ["-tags", templates]
    else:
        cmd += ["-automatic-scan"]  # nuclei picks templates based on tech

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "template":    finding.get("template-id", ""),
                    "name":        finding.get("info", {}).get("name", ""),
                    "severity":    finding.get("info", {}).get("severity", ""),
                    "description": finding.get("info", {}).get("description", ""),
                    "matched":     finding.get("matched-at", ""),
                    "curl":        finding.get("curl-command", ""),
                })
                if callback:
                    callback(findings[-1])
            except json.JSONDecodeError:
                continue

        return findings, None

    except subprocess.TimeoutExpired:
        return [], "nuclei timed out"
    except Exception as e:
        return [], str(e)


def scan_cves(target, callback=None):
    return scan(target, severity="critical,high", templates="cves", callback=callback)


def scan_exposures(target, callback=None):
    return scan(target, severity="critical,high,medium", templates="exposures", callback=callback)


def scan_misconfigs(target, callback=None):
    return scan(target, severity="critical,high,medium", templates="misconfigurations", callback=callback)