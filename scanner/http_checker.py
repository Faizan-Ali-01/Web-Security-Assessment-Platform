from __future__ import annotations

from urllib.parse import urlparse

import requests


def _normalize_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    cleaned_url = url.strip()
    if not cleaned_url:
        raise ValueError("URL is required.")

    if "://" not in cleaned_url:
        cleaned_url = "https://" + cleaned_url

    parsed = urlparse(cleaned_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format.")

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    return cleaned_url


def check_website_url(url: str, timeout: int = 10) -> dict:
    normalized_url = url
    try:
        normalized_url = _normalize_url(url)
    except ValueError as exc:
        return {
            "url": url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": str(exc),
        }

    try:
        response = requests.get(
            normalized_url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "WebSecurityAssessmentPlatform/1.0"},
        )
    except requests.exceptions.Timeout:
        return {
            "url": normalized_url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": "Request timed out.",
        }
    except requests.exceptions.SSLError:
        return {
            "url": normalized_url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": "SSL certificate verification failed.",
        }
    except requests.exceptions.ConnectionError:
        return {
            "url": normalized_url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": "Connection error while contacting the website.",
        }
    except requests.exceptions.InvalidURL:
        return {
            "url": normalized_url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": "Invalid URL.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "url": normalized_url,
            "final_url": None,
            "status_code": None,
            "https_used": False,
            "http_to_https_redirect": False,
            "headers": {},
            "ok": False,
            "error": f"Request failed: {exc}",
        }

    final_url = response.url or normalized_url
    final_scheme = urlparse(final_url).scheme
    original_scheme = urlparse(normalized_url).scheme

    return {
        "url": normalized_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "https_used": final_scheme == "https",
        "http_to_https_redirect": (
            original_scheme == "http" and final_scheme == "https" and bool(response.history)
        ),
        "headers": dict(response.headers),
        "ok": response.ok,
        "error": None,
    }


__all__ = ["check_website_url"]
