from typing import Any, Dict, List


def analyze_cors(headers: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Analyze CORS-related HTTP response headers.

    This module is passive and does not make network requests.
    """

    observations: List[Dict[str, str]] = []

    if not headers:
        return observations

    normalized = {
        str(key).lower(): value
        for key, value in headers.items()
    }

    allow_origin = normalized.get("access-control-allow-origin")
    allow_credentials = normalized.get("access-control-allow-credentials")
    allow_methods = normalized.get("access-control-allow-methods")
    allow_headers = normalized.get("access-control-allow-headers")

    if allow_origin is None:
        return observations

    origin_value = str(allow_origin).strip()
    credentials_value = (
        str(allow_credentials).strip().lower()
        if allow_credentials is not None
        else ""
    )

    # Wildcard origin
    if origin_value == "*":
        if credentials_value == "true":
            observations.append(
                {
                    "type": "Permissive CORS with Credentials",
                    "severity": "high",
                    "value": "*",
                    "description": (
                        "The server allows requests from any origin while "
                        "also allowing credentials. This combination can "
                        "create a serious cross-origin security risk depending "
                        "on the application's authentication and data exposure."
                    ),
                    "recommendation": (
                        "Avoid wildcard origins when credentials are allowed. "
                        "Restrict Access-Control-Allow-Origin to trusted origins "
                        "and review credentialed cross-origin access."
                    ),
                }
            )
        else:
            observations.append(
                {
                    "type": "Wildcard CORS Origin",
                    "severity": "low",
                    "value": "*",
                    "description": (
                        "The server allows cross-origin requests from any origin. "
                        "This may be intentional for public resources but should "
                        "be reviewed for sensitive endpoints."
                    ),
                    "recommendation": (
                        "If cross-origin access is not required for public "
                        "resources, restrict Access-Control-Allow-Origin to "
                        "trusted origins."
                    ),
                }
            )

    else:
        observations.append(
            {
                "type": "CORS Configuration",
                "severity": "info",
                "value": origin_value,
                "description": (
                    "The server specifies an allowed cross-origin origin."
                ),
                "recommendation": (
                    "Verify that the configured origin is trusted and required "
                    "by the application."
                ),
            }
        )

    if allow_credentials is not None:
        observations.append(
            {
                "type": "CORS Credentials",
                "severity": "info",
                "value": str(allow_credentials),
                "description": (
                    "The server specifies whether browser credentials may "
                    "be included in cross-origin requests."
                ),
                "recommendation": (
                    "Ensure credentialed cross-origin requests are limited "
                    "to trusted origins."
                ),
            }
        )

    if allow_methods is not None:
        observations.append(
            {
                "type": "CORS Allowed Methods",
                "severity": "info",
                "value": str(allow_methods),
                "description": (
                    "The server advertises HTTP methods permitted for "
                    "cross-origin requests."
                ),
                "recommendation": (
                    "Allow only the HTTP methods required by the application."
                ),
            }
        )

    if allow_headers is not None:
        observations.append(
            {
                "type": "CORS Allowed Headers",
                "severity": "info",
                "value": str(allow_headers),
                "description": (
                    "The server advertises request headers permitted for "
                    "cross-origin requests."
                ),
                "recommendation": (
                    "Allow only the request headers required by the application."
                ),
            }
        )

    return observations


__all__ = ["analyze_cors"]