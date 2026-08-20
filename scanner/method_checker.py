from typing import Any, Dict, List


def analyze_http_methods(headers: Dict[str, Any]) -> List[Dict[str, str]]:
	allow_value = next(
		(value for name, value in headers.items() if name.lower() == "allow"),
		None,
	)
	if not isinstance(allow_value, str):
		return []

	observations = []
	for method in (part.strip().upper() for part in allow_value.split(",")):
		if not method:
			continue

		if method == "TRACE":
			severity = "low"
			description = (
				"TRACE is explicitly advertised by the server. "
				"Its security impact depends on the server configuration."
			)
			recommendation = (
				"Disable TRACE unless it is required, and review the server "
				"configuration for unintended exposure."
			)
		else:
			severity = "info"
			description = f"The server advertises the {method} HTTP method."
			recommendation = (
				"Confirm that this method is required and configured according "
				"to the application's needs."
			)

		observations.append(
			{
				"method": method,
				"severity": severity,
				"description": description,
				"recommendation": recommendation,
			}
		)

	return observations

__all__ = ["analyze_http_methods"]