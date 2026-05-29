"""
http_crawler.py
crawls web UIs on devices -- finds all pages, forms, endpoints
useful for mapping out router admin panels, NAS interfaces, IP cameras etc
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
from collections import deque
from typing import Set, List, Dict, Optional
from datetime import datetime


MAX_PAGES = 40  # dont go crazy
MAX_DEPTH = 3
TIMEOUT = 4


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url: str, https: bool = False) -> Optional[tuple]:
    """Returns (html, final_url, status_code) or None."""
    try:
        ctx = _make_ctx() if https else None
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        html = resp.read(32768).decode("utf-8", errors="ignore")
        return html, resp.url, resp.status
    except urllib.error.HTTPError as e:
        return None, url, e.code
    except Exception:
        return None


def _extract_links(html: str, base_url: str) -> List[str]:
    """Pull all href links from html, resolve relative paths."""
    links = []
    parsed_base = urllib.parse.urlparse(base_url)
    base = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for match in re.finditer(r'href=["\']([^"\'#?]+)', html, re.IGNORECASE):
        href = match.group(1).strip()
        if href.startswith("http://") or href.startswith("https://"):
            # only follow links on same host
            if urllib.parse.urlparse(href).netloc == parsed_base.netloc:
                links.append(href)
        elif href.startswith("/"):
            links.append(base + href)
        elif href and not href.startswith("javascript") and not href.startswith("mailto"):
            # relative path
            current_dir = base_url.rsplit("/", 1)[0]
            links.append(current_dir + "/" + href)

    return links


def _extract_forms(html: str) -> List[Dict]:
    """Find all forms and their inputs -- useful for spotting login pages."""
    forms = []
    for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        form_html = form_match.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        form = {
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": inputs,
        }
        forms.append(form)
    return forms


def _get_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return re.sub(r'\s+', ' ', match.group(1)).strip()[:80]
    return ""


def crawl(ip: str, port: int, https: bool = False) -> Dict:
    """
    Crawl a web UI starting from the root.
    Returns dict with pages found, forms, interesting endpoints.
    """
    scheme = "https" if https else "http"
    start_url = f"{scheme}://{ip}:{port}/"

    visited: Set[str] = set()
    queue = deque([(start_url, 0)])
    pages = []
    login_pages = []
    interesting = []
    all_forms = []

    interesting_patterns = [
        (r'login|signin|auth', "login page"),
        (r'admin|manage|dashboard|panel', "admin panel"),
        (r'config|settings|setup|wizard', "config page"),
        (r'api/', "api endpoint"),
        (r'upload|file', "file upload"),
        (r'backup|restore', "backup/restore"),
        (r'firmware|update|upgrade', "firmware update"),
        (r'logs?|events?|syslog', "log page"),
        (r'camera|video|stream|live', "camera/stream"),
        (r'reboot|restart|reset', "reboot page"),
        (r'passwd|password|credentials', "credential page"),
        (r'ssh|telnet|console|shell', "remote access"),
        (r'mqtt|iot|zigbee|zwave', "iot config"),
        (r'vpn|tunnel|wireguard|openvpn', "vpn config"),
        (r'users?|accounts?|roles?', "user management"),
    ]

    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.popleft()

        # normalize url
        url = url.rstrip("/") + "/" if url.count("/") == 2 else url
        if url in visited:
            continue
        visited.add(url)

        result = _fetch(url, https=https)
        if not result or result[0] is None:
            if result and result[2]:
                pages.append({"url": url, "status": result[2], "title": "", "forms": []})
            continue

        html, final_url, status = result
        title = _get_title(html)
        forms = _extract_forms(html)
        all_forms.extend(forms)

        page_info = {
            "url": url,
            "status": status,
            "title": title,
            "forms": len(forms),
        }
        pages.append(page_info)

        # check for interesting pages
        url_lower = url.lower()
        for pattern, label in interesting_patterns:
            if re.search(pattern, url_lower):
                interesting.append({"url": url, "type": label, "title": title})
                break

        # check if its a login page from content
        html_lower = html.lower()
        if any(x in html_lower for x in ["password", "login", "sign in", "username"]) and forms:
            login_pages.append(url)

        # queue new links
        if depth < MAX_DEPTH:
            for link in _extract_links(html, final_url):
                if link not in visited:
                    queue.append((link, depth + 1))

    return {
        "start_url": start_url,
        "pages_crawled": len(pages),
        "pages": pages[:20],  # cap output
        "login_pages": list(set(login_pages)),
        "interesting": interesting,
        "total_forms": len(all_forms),
        "crawled_at": datetime.now().isoformat(),
    }


def crawl_device(ip: str, open_ports: Dict) -> Dict:
    """Crawl all web ports found on a device."""
    results = {}
    web_ports = {
        p: s for p, s in open_ports.items()
        if s in ("http", "http-alt", "http-dev", "roku", "chromecast", "jellyfin")
    }
    ssl_ports = {
        p: s for p, s in open_ports.items()
        if s in ("https", "https-alt")
    }

    for port in list(web_ports.keys())[:3]:
        result = crawl(ip, port, https=False)
        if result["pages_crawled"] > 0:
            results[port] = result

    for port in list(ssl_ports.keys())[:2]:
        result = crawl(ip, port, https=True)
        if result["pages_crawled"] > 0:
            results[port] = result

    return results
