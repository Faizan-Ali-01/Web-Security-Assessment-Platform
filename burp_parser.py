import json
import re
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse, urlunparse


MAX_RAW_SIZE = 2 * 1024 * 1024
MAX_RESPONSE_SIZE = 5 * 1024 * 1024
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:pass|password|secret|token|api[_-]?key|authorization|session|cookie)",
    re.IGNORECASE,
)
JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _split_message(raw: str) -> tuple[str, str]:
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def _parse_headers(lines: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    current_name: Optional[str] = None
    for line in lines:
        if not line.strip():
            continue
        if line[:1] in {" ", "\t"} and current_name:
            headers[current_name] = f"{headers[current_name]} {line.strip()}"
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name:
            continue
        current_name = name
        if name in headers:
            headers[name] = f"{headers[name]}, {value.strip()}"
        else:
            headers[name] = value.strip()
    return headers


def _header_value(headers: Dict[str, str], name: str) -> str:
    name = name.lower()
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return ""


def _normalize_url(target: str, headers: Dict[str, str]) -> str:
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return target

    host = _header_value(headers, "Host")
    if not host:
        raise ValueError("The request needs a Host header when the target is relative.")

    scheme = "https" if _header_value(headers, "X-Forwarded-Proto").lower() == "https" else "http"
    return f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"


def _mask_value(value: str, sensitive: bool) -> str:
    if not sensitive:
        return value
    if len(value) <= 4:
        return "******"
    return f"{value[:2]}******{value[-2:]}"


def _parameter(name: str, value: str, location: str) -> Dict[str, str]:
    sensitive = bool(SENSITIVE_NAME_PATTERN.search(name)) or bool(JWT_PATTERN.match(value))
    return {
        "name": name,
        "value": value,
        "location": location,
        "masked_value": _mask_value(value, sensitive),
        "sensitive": "true" if sensitive else "false",
    }


def _extract_json_parameters(value: Any, location: str = "JSON body", prefix: str = "") -> List[Dict[str, str]]:
    parameters: List[Dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list)):
                parameters.extend(_extract_json_parameters(child, location, name))
            else:
                parameters.append(_parameter(name, str(child), location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            if isinstance(child, (dict, list)):
                parameters.extend(_extract_json_parameters(child, location, name))
            else:
                parameters.append(_parameter(name, str(child), location))
    return parameters


def _extract_parameters(url: str, body: str, content_type: str) -> List[Dict[str, str]]:
    parsed = urlparse(url)
    parameters = [
        _parameter(name, value, "Query")
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    if body and "application/x-www-form-urlencoded" in content_type.lower():
        parameters.extend(
            _parameter(name, value, "Form body")
            for name, value in parse_qsl(body, keep_blank_values=True)
        )
    elif body and "application/json" in content_type.lower():
        try:
            parameters.extend(_extract_json_parameters(json.loads(body)))
        except (json.JSONDecodeError, TypeError):
            pass
    return parameters


def _extract_cookies(headers: Dict[str, str]) -> Dict[str, str]:
    raw_cookie = _header_value(headers, "Cookie")
    if not raw_cookie:
        return {}
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
        return {key: morsel.value for key, morsel in cookie.items()}
    except Exception:
        return {
            part.split("=", 1)[0].strip(): part.split("=", 1)[1].strip()
            for part in raw_cookie.split(";")
            if "=" in part
        }


def parse_http_request(raw_request: str) -> Dict[str, Any]:
    if not isinstance(raw_request, str) or not raw_request.strip():
        raise ValueError("Request text is empty.")
    if len(raw_request.encode("utf-8", errors="ignore")) > MAX_RAW_SIZE:
        raise ValueError("Request text is too large to import.")

    header_text, body = _split_message(raw_request)
    lines = header_text.replace("\r\n", "\n").split("\n")
    request_line = next((line.strip() for line in lines if line.strip()), "")
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("Could not parse the request line. Expected METHOD TARGET HTTP/VERSION.")

    method = parts[0].upper()
    target = parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = _parse_headers(lines[1:])
    url = _normalize_url(target, headers)
    parsed_url = urlparse(url)
    content_type = _header_value(headers, "Content-Type")

    return {
        "method": method,
        "target": target,
        "url": url,
        "host": parsed_url.netloc,
        "path": parsed_url.path or "/",
        "query_string": parsed_url.query,
        "http_version": http_version,
        "headers": headers,
        "body": body,
        "content_type": content_type,
        "cookies": _extract_cookies(headers),
        "parameters": _extract_parameters(url, body, content_type),
    }


def parse_http_response(raw_response: str) -> Dict[str, Any]:
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise ValueError("Response text is empty.")
    if len(raw_response.encode("utf-8", errors="ignore")) > MAX_RESPONSE_SIZE:
        raise ValueError("Response text is too large to import.")

    header_text, body = _split_message(raw_response)
    lines = header_text.replace("\r\n", "\n").split("\n")
    status_line = next((line.strip() for line in lines if line.strip()), "")
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("Could not parse the response status line.")

    headers = _parse_headers(lines[1:])
    return {
        "status_code": int(parts[1]),
        "status_text": parts[2] if len(parts) > 2 else "",
        "http_version": parts[0],
        "headers": headers,
        "body": body,
        "content_type": _header_value(headers, "Content-Type"),
    }


__all__ = ["parse_http_request", "parse_http_response"]
