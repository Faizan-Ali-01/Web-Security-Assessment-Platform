from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, str]] = []
        self.scripts: List[str] = []
        self.stylesheets: List[str] = []
        self.images: List[str] = []
        self.iframes: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        tag = tag.lower()

        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"] or "")
        elif tag == "form":
            self.forms.append(
                {
                    "method": (attributes.get("method") or "GET").upper(),
                    "action": attributes.get("action") or "",
                }
            )
        elif tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"] or "")
        elif tag == "link" and "stylesheet" in (attributes.get("rel") or "").lower().split():
            if attributes.get("href"):
                self.stylesheets.append(attributes["href"] or "")
        elif tag == "img" and attributes.get("src"):
            self.images.append(attributes["src"] or "")
        elif tag == "iframe" and attributes.get("src"):
            self.iframes.append(attributes["src"] or "")


def _resolve_url(value: str, base_url: str) -> Optional[str]:
    resolved = urljoin(base_url, value.strip())
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return resolved


def _unique(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def analyze_html_resources(html: str, base_url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "links": [],
        "forms": [],
        "scripts": [],
        "stylesheets": [],
        "images": [],
        "iframes": [],
        "internal_urls": [],
        "external_domains": [],
        "api_candidates": [],
    }
    if not isinstance(html, str) or not html.strip():
        return result

    parser = _ResourceParser()
    try:
        parser.feed(html)
        parser.close()
    except (ValueError, TypeError):
        pass

    parsed_base = urlparse(base_url)
    base_hostname = (parsed_base.hostname or "").lower()

    def resolve_all(values: List[str]) -> List[str]:
        return _unique(
            resolved
            for value in values
            if (resolved := _resolve_url(value, base_url)) is not None
        )

    links = resolve_all(parser.links)
    scripts = resolve_all(parser.scripts)
    stylesheets = resolve_all(parser.stylesheets)
    images = resolve_all(parser.images)
    iframes = resolve_all(parser.iframes)

    resolved_forms: List[Dict[str, str]] = []
    seen_forms: Set[tuple[str, str]] = set()
    for form in parser.forms:
        action = _resolve_url(form["action"], base_url) or base_url
        key = (form["method"], action)
        if key not in seen_forms:
            seen_forms.add(key)
            resolved_forms.append({"method": form["method"], "action": action})

    discovered_urls = _unique(links + scripts + stylesheets + images + iframes)
    internal_urls = [
        url for url in discovered_urls if (urlparse(url).hostname or "").lower() == base_hostname
    ]
    external_domains = _unique(
        (urlparse(url).hostname or "").lower()
        for url in discovered_urls
        if (urlparse(url).hostname or "").lower() != base_hostname
    )

    def is_api_candidate(url: str) -> bool:
        path = urlparse(url).path.lower()
        return (
            path == "/api"
            or path.startswith(("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))
        )

    api_candidates = [
        url
        for url in discovered_urls
        if is_api_candidate(url)
    ]

    result.update(
        {
            "links": links,
            "forms": resolved_forms,
            "scripts": scripts,
            "stylesheets": stylesheets,
            "images": images,
            "iframes": iframes,
            "internal_urls": internal_urls,
            "external_domains": external_domains,
            "api_candidates": api_candidates,
        }
    )
    return result


__all__ = ["analyze_html_resources"]
