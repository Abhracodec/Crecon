import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def make_session():
    s = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist={500, 502, 503, 504})
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    return s


def check_wildcard_http(base_url, session, timeout):
    import random, string
    junk = "".join(random.choices(string.ascii_lowercase, k=18))
    try:
        r = session.head(f"{base_url}/{junk}", timeout=timeout, allow_redirects=False)
        return r.status_code == 200
    except Exception:
        return False


def check_wildcard_dns(domain):
    if not HAS_DNS:
        return False
    import random, string
    junk = "".join(random.choices(string.ascii_lowercase, k=18))
    try:
        dns.resolver.resolve(f"{junk}.{domain}", "A")
        return True
    except Exception:
        return False


def probe_path(session, base_url, word, codes, timeout):
    url = f"{base_url.rstrip('/')}/{word.strip()}"
    try:
        r = session.head(url, timeout=timeout, allow_redirects=False)
        if r.status_code == 405:
            r = session.get(url, timeout=timeout, allow_redirects=False)
        if r.status_code in codes:
            return {
                "url":      url,
                "code":     r.status_code,
                "length":   r.headers.get("Content-Length", "?"),
                "redirect": r.headers.get("Location", ""),
            }
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass
    return None


def probe_subdomain(domain, word, resolver):
    fqdn    = f"{word.strip()}.{domain}"
    records = {}
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            answers      = resolver.resolve(fqdn, rtype)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            break
        except Exception:
            pass

    if not records:
        return None

    ip = "?"
    try:
        ip = str(resolver.resolve(fqdn, "A")[0])
    except Exception:
        pass

    return {"subdomain": fqdn, "ip": ip, "records": records}


def dir_scan(base_url, wordlist, codes={200,301,302,403}, threads=15,
             timeout=5.0, callback=None):
    session = make_session()
    words   = Path(wordlist).read_text(errors="replace").splitlines()
    words   = [w.strip() for w in words if w.strip()]

    if check_wildcard_http(base_url, session, timeout):
        if callback:
            callback({"warning": "Wildcard detected — results may be noisy"})

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe_path, session, base_url, w, codes, timeout): w
                   for w in words}
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                results.append(hit)
                if callback:
                    callback(hit)

    return sorted(results, key=lambda r: r["url"])


def subdomain_scan(domain, wordlist, threads=20, nameservers=None, callback=None):
    if not HAS_DNS:
        raise RuntimeError("dnspython not installed — run: pip install dnspython")

    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 4.0

    if check_wildcard_dns(domain):
        if callback:
            callback({"warning": f"Wildcard DNS on *.{domain} — expect false positives"})

    words   = Path(wordlist).read_text(errors="replace").splitlines()
    words   = [w.strip() for w in words if w.strip()]
    results = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe_subdomain, domain, w, resolver): w
                   for w in words}
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                results.append(hit)
                if callback:
                    callback(hit)

    return sorted(results, key=lambda r: r["subdomain"])
