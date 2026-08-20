import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse


class _InlineScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_script = False
        self._current: List[str] = []
        self.scripts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "script" and not any(
            name.lower() == "src" and value for name, value in attrs
        ):
            self._in_script = True
            self._current = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self.scripts.append("".join(self._current))
            self._in_script = False
            self._current = []

    def finish(self) -> None:
        if self._in_script and self._current:
            self.scripts.append("".join(self._current))
            self._in_script = False
            self._current = []


_CANDIDATE_PATTERN = re.compile(
    r"(['\"`])((?:https?://[^'\"`\s]+|/[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%-]+))\1"
)


def _resolve_candidate(value: str, base_url: str) -> Optional[str]:
    resolved = urljoin(base_url, value)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return resolved


def analyze_javascript(html: str, base_url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"endpoint_candidates": []}
    if not isinstance(html, str) or not html.strip():
        return result

    parser = _InlineScriptParser()
    try:
        parser.feed(html)
        parser.close()
        parser.finish()
    except (TypeError, ValueError):
        return result

    candidates: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for script in parser.scripts:
        for match in _CANDIDATE_PATTERN.finditer(script):
            raw_value = match.group(2)
            resolved_url = _resolve_candidate(raw_value, base_url)
            if not resolved_url or resolved_url in seen:
                continue

            seen.add(resolved_url)
            start = max(0, match.start() - 40)
            end = min(len(script), match.end() + 40)
            evidence = " ".join(script[start:end].split())
            candidates.append(
                {
                    "url": resolved_url,
                    "source": "inline_script",
                    "evidence": evidence,
                }
            )

    result["endpoint_candidates"] = candidates
    return result


__all__ = ["analyze_javascript"]
