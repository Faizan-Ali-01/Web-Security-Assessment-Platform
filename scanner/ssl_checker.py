"""
SSL/TLS Certificate Inspector Module

Safely inspects the SSL/TLS certificate of an HTTPS website using Python's standard library.
Extracts certificate metadata with certificate verification enabled.
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, Optional


def check_ssl_certificate(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Inspects the TLS certificate of an HTTPS website using a single connection.

    Args:
        url (str): The website URL to check (e.g., "https://example.com").
        timeout (int): Connection timeout in seconds (default: 10).

    Returns:
        Dict[str, Any]: A dictionary containing:
            - is_https (bool): Whether the URL is HTTPS.
            - certificate_present (bool): Whether a certificate was retrieved.
            - subject (str): Certificate subject (CN).
            - issuer (str): Certificate issuer (CN).
            - valid_from (str): Certificate valid-from date (ISO format).
            - valid_until (str): Certificate valid-until date (ISO format).
            - days_remaining (int): Days until certificate expiration.
            - is_valid (bool): Whether the certificate is currently valid.
            - error (Optional[str]): Error message if any occurred.

    Raises:
        No exceptions are raised; all errors are captured in the returned dictionary.
    """
    result: Dict[str, Any] = {
        "is_https": False,
        "certificate_present": False,
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "is_valid": False,
        "error": None,
    }

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            result["error"] = "Invalid URL: missing scheme (http/https)"
            return result

        if not parsed.netloc:
            result["error"] = "Invalid URL: missing hostname"
            return result

        if parsed.scheme.lower() != "https":
            result["is_https"] = False
            result["error"] = (
                f"URL is {parsed.scheme.upper()}, not HTTPS. Certificate check requires HTTPS."
            )
            return result

        result["is_https"] = True

        hostname = parsed.hostname
        if not hostname:
            result["error"] = "Could not extract hostname from URL"
            return result

        port = parsed.port or 443

        # Create an SSL context with certificate verification enabled
        context = ssl.create_default_context()

        # Single connection: retrieve certificate with SNI enabled
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                # Get the certificate dictionary
                cert_dict = ssock.getpeercert()

        if not cert_dict:
            result["error"] = "Failed to retrieve certificate information"
            return result

        result["certificate_present"] = True

        subject = _extract_subject_cn(cert_dict)
        result["subject"] = subject

        issuer = _extract_issuer_cn(cert_dict)
        result["issuer"] = issuer

        not_before_str = cert_dict.get("notBefore")
        not_after_str = cert_dict.get("notAfter")

        if not_before_str:
            not_before = datetime.datetime.strptime(
                not_before_str, "%b %d %H:%M:%S %Y %Z"
            )
            result["valid_from"] = not_before.isoformat()

        if not_after_str:
            not_after = datetime.datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            )
            result["valid_until"] = not_after.isoformat()

            now = datetime.datetime.now()
            days_left = (not_after - now).days
            result["days_remaining"] = max(days_left, 0)

            result["is_valid"] = now < not_after

        return result

    except socket.timeout:
        result["error"] = f"Connection timeout (>{timeout}s): server did not respond in time"
        return result
    except socket.gaierror:
        result["error"] = "DNS resolution error: could not resolve hostname"
        return result
    except socket.error as e:
        result["error"] = f"Connection error: {str(e)}"
        return result
    except ssl.SSLError as e:
        result["is_https"] = True
        result["error"] = f"SSL/TLS error: {str(e)}"
        return result
    except ValueError as e:
        result["error"] = f"Invalid URL or parsing error: {str(e)}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        return result


def _extract_subject_cn(cert_dict: Dict[str, Any]) -> Optional[str]:
    subject = cert_dict.get("subject")
    if not subject:
        return None

    for entry in subject:
        for field in entry:
            if field[0] == "commonName":
                return field[1]

    return None


def _extract_issuer_cn(cert_dict: Dict[str, Any]) -> Optional[str]:
    issuer = cert_dict.get("issuer")
    if not issuer:
        return None

    for entry in issuer:
        for field in entry:
            if field[0] == "commonName":
                return field[1]

    return None
