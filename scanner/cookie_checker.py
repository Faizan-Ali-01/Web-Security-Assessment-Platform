from typing import Dict, List, Any, Optional

def analyze_cookies(headers: Dict[str, Any]) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []

    if not headers:
        return observations

    set_cookie_values = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_values.extend(value)
            else:
                set_cookie_values.append(value)

    if not set_cookie_values:
        return observations

    for cookie_str in set_cookie_values:
        observation = _parse_cookie(cookie_str)
        if observation:
            observations.append(observation)

    return observations


def _parse_cookie(cookie_str: str) -> Optional[Dict[str, Any]]:
    parts = [part.strip() for part in cookie_str.split(";")]

    if not parts or "=" not in parts[0]:
        return None

    name_value = parts[0]
    cookie_name = name_value.split("=")[0].strip()

    secure = False
    httponly = False
    samesite = False
    samesite_value = None

    for part in parts[1:]:
        part_lower = part.lower()

        if part_lower == "secure":
            secure = True
        elif part_lower == "httponly":
            httponly = True
        elif part_lower.startswith("samesite"):
            samesite = True
            if "=" in part:
                samesite_value = part.split("=", 1)[1].strip()

    issues = []
    if not secure:
        issues.append("Missing Secure attribute")
    if not httponly:
        issues.append("Missing HttpOnly attribute")
    if not samesite:
        issues.append("Missing SameSite attribute")

    severity = "low" if issues else "info"

    recommendation = "Set the Secure, HttpOnly, and SameSite attributes for this cookie to enhance security and protect against common cookie-based attacks."

    return {
        "name": cookie_name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "samesite_value": samesite_value,
        "severity": severity,
        "issues": issues,
        "recommendation": recommendation,
    }