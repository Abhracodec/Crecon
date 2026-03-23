import re
import csv
import time
from urllib.parse import urljoin, urlparse
from collections import deque
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup


EMAIL_RE = re.compile(
    r"(?<![a-zA-Z0-9._%+\-])([a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63})*\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)

PHONE_RE = re.compile(
    r"(?:(?:\+|00)[1-9]\d{0,2}[\s\-\.])?"
    r"(?:\(?\d{2,4}\)?[\s\-\.])?"
    r"\d{3,4}[\s\-\.]\d{3,4}"
    r"(?:[\s\-\.]?\d{1,4})?",
)

TECH_SIGNATURES = [
    (r"wp-content|wp-includes",       "WordPress"),
    (r"__NEXT_DATA__|data-reactroot", "React/Next.js"),
    (r"__nuxt__|data-v-\w{8}",        "Vue/Nuxt"),
    (r"ng-version|angular\.js",       "Angular"),
    (r"shopify\.com/cdn",             "Shopify"),
    (r"Server:\s*nginx",              "nginx"),
    (r"Server:\s*Apache",             "Apache"),
    (r"Server:\s*cloudflare",         "Cloudflare"),
    (r"X-Powered-By:\s*PHP",          "PHP"),
    (r"X-Powered-By:\s*ASP\.NET",     "ASP.NET"),
    (r"PHPSESSID",                    "PHP session"),
    (r"__stripe_mid",                 "Stripe"),
]
TECH_RES = [(re.compile(p, re.IGNORECASE), label) for p, label in TECH_SIGNATURES]


def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist={500, 502, 503})
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    return s


def get_emails(html, text):
    found = {m.group(1).lower() for m in EMAIL_RE.finditer(html)}
    found |= {m.group(1).lower() for m in EMAIL_RE.finditer(text)}
    return {e for e in found if not re.search(r'\.(png|jpg|gif|svg|woff|ttf)$', e)}


def get_phones(text):
    seen, phones = set(), set()
    for m in PHONE_RE.finditer(text):
        raw    = m.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        if 7 <= len(digits) <= 15 and digits not in seen:
            seen.add(digits)
            phones.add(raw)
    return phones


def get_links(soup, base_url):
    host  = urlparse(base_url).netloc
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        full = urljoin(base_url, href)
        p    = urlparse(full)
        if p.scheme in ("http", "https") and p.netloc == host:
            links.add(p._replace(fragment="").geturl())
    return links


def get_tech(response, html):
    blob  = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    blob += "\n" + " ".join(response.cookies.keys())
    blob += "\n" + html[:50_000]
    return [label for pat, label in TECH_RES if pat.search(blob)]


def get_meta(soup):
    meta  = {}
    title = soup.find("title")
    if title:
        meta["title"] = title.get_text(strip=True)[:200]
    for tag in soup.find_all("meta"):
        name    = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content", "")
        if name in ("description", "og:description") and "description" not in meta:
            meta["description"] = content[:200]
        if name == "generator":
            meta["generator"] = content
    return meta


def fetch_page(session, url, timeout=10.0):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        if "text" not in r.headers.get("Content-Type", ""):
            return None

        html = r.text
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ")

        return {
            "url":    url,
            "status": r.status_code,
            "emails": sorted(get_emails(html, text)),
            "phones": sorted(get_phones(text)),
            "tech":   get_tech(r, html),
            "links":  get_links(soup, url),
            "meta":   get_meta(soup),
        }
    except Exception:
        return None


def crawl(start_url, max_pages=20, delay=0.5, timeout=10.0, callback=None):
    session = make_session()
    visited = set()
    queue   = deque([start_url])
    results = []

    while queue and len(results) < max_pages:
        url = queue.popleft().rstrip("/") + "/"
        if url in visited:
            continue
        visited.add(url)

        page = fetch_page(session, url, timeout)
        if not page:
            continue

        results.append(page)
        if callback:
            callback(page)

        for link in page["links"] - visited:
            queue.append(link)

        time.sleep(delay)

    return results


CSV_FIELDS = ["timestamp", "url", "status", "emails", "phones", "tech",
              "title", "description", "generator"]

def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow({
                "timestamp":   datetime.now().isoformat(timespec="seconds"),
                "url":         r["url"],
                "status":      r["status"],
                "emails":      "; ".join(r.get("emails", [])),
                "phones":      "; ".join(r.get("phones", [])),
                "tech":        "; ".join(r.get("tech", [])),
                "title":       r.get("meta", {}).get("title", ""),
                "description": r.get("meta", {}).get("description", ""),
                "generator":   r.get("meta", {}).get("generator", ""),
            })