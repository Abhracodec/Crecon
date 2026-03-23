import requests
import time

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search(product, version, max_results=5):
    """
    Query NVD for CVEs matching a product and version.
    Returns a list of dicts with id, score, severity, description.
    Falls back silently on any error.
    """
    if not product or product in ("unknown", "tcpwrapped"):
        return []

    keyword = f"{product} {version}".strip() if version else product

    try:
        resp = requests.get(
            NVD_URL,
            params={
                "keywordSearch":  keyword,
                "resultsPerPage": max_results,
            },
            timeout=10,
            headers={"User-Agent": "crecon-scanner/0.1"},
        )
        resp.raise_for_status()
        data = resp.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve     = item.get("cve", {})
            cve_id  = cve.get("id", "")
            metrics = cve.get("metrics", {})
            desc    = cve.get("descriptions", [{}])[0].get("value", "")

            # get CVSS score — try v31 first, then v30, then v2
            score    = None
            severity = "UNKNOWN"

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m        = metrics[key][0]
                    score    = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    break

            if cve_id:
                results.append({
                    "id":          cve_id,
                    "score":       score,
                    "severity":    severity,
                    "description": desc[:200],
                })

        # sort by score descending
        results.sort(key=lambda x: x["score"] or 0, reverse=True)
        return results

    except Exception:
        return []


def lookup_ports(ports):
    """
    Takes a list of port dicts from Nmap and enriches them with CVEs.
    Adds a 'cves' key to each port dict in place.
    Respects NVD rate limit of 6 requests per 30 seconds.
    """
    enriched = []
    for i, port in enumerate(ports):
        product = port.get("product", "") or port.get("service", "")
        version = port.get("version", "")

        cves = search(product, version)
        port["cves"] = cves

        enriched.append(port)

        # NVD rate limit — 1 request every 6 seconds to stay safe
        if i < len(ports) - 1:
            time.sleep(6)

    return enriched