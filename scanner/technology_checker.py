from typing import Any, Dict, List

def analyze_technologies(headers: Dict[str, Any]) -> List[Dict[str, str]]:
	observations: List[Dict[str, str]] = []
	detected = set()

	if not headers:
		return observations

	headers_lower = {
		key.lower(): (key, value)
		for key, value in headers.items()
		if isinstance(key, str)
	}

	def add_observation(
		technology: str,
		header_name: str,
		confidence: str,
		description: str,
	) -> None:
		if technology in detected:
			return

		header = headers_lower.get(header_name)
		if not header or not isinstance(header[1], str):
			return

		source, evidence = header
		observations.append(
			{
				"technology": technology,
				"source": source,
				"evidence": evidence,
				"confidence": confidence,
				"description": description,
			}
		)
		detected.add(technology)

	def value_contains(header_name: str, text: str) -> bool:
		header = headers_lower.get(header_name)
		return bool(header and isinstance(header[1], str) and text in header[1].lower())

	server_value = headers_lower.get("server", (None, ""))[1]
	server_text = server_value.lower() if isinstance(server_value, str) else ""

	if "cloudflare" in server_text:
		add_observation(
			"Cloudflare",
			"server",
			"high",
			"The response identifies Cloudflare as part of the server infrastructure.",
		)
	elif "cf-ray" in headers_lower:
		add_observation(
			"Cloudflare",
			"cf-ray",
			"high",
			"The CF-Ray header indicates that Cloudflare handled the response.",
		)

	if "nginx" in server_text:
		add_observation(
			"Nginx",
			"server",
			"high",
			"The Server header identifies Nginx as the web server.",
		)

	if "apache" in server_text:
		add_observation(
			"Apache",
			"server",
			"high",
			"The Server header identifies Apache as the web server.",
		)

	if "microsoft-iis" in server_text or "iis" in server_text:
		add_observation(
			"Microsoft IIS",
			"server",
			"high",
			"The Server header identifies Microsoft IIS as the web server.",
		)

	if value_contains("x-powered-by", "php"):
		add_observation(
			"PHP",
			"x-powered-by",
			"high",
			"The X-Powered-By header identifies PHP as an application technology.",
		)

	if (
		"x-aspnet-version" in headers_lower
		or "x-aspnetmvc-version" in headers_lower
		or value_contains("x-powered-by", "asp.net")
	):
		source_name = (
			"x-aspnet-version"
			if "x-aspnet-version" in headers_lower
			else "x-aspnetmvc-version"
			if "x-aspnetmvc-version" in headers_lower
			else "x-powered-by"
		)
		add_observation(
			"ASP.NET",
			source_name,
			"high",
			"The response headers identify ASP.NET as an application technology.",
		)

	if value_contains("x-powered-by", "express"):
		add_observation(
			"Express",
			"x-powered-by",
			"high",
			"The X-Powered-By header identifies Express as the application framework.",
		)

	if value_contains("x-powered-by", "next.js") or "x-nextjs-cache" in headers_lower:
		add_observation(
			"Next.js",
			"x-powered-by" if value_contains("x-powered-by", "next.js") else "x-nextjs-cache",
			"high",
			"The response headers identify Next.js as an application framework.",
		)

	if value_contains("x-generator", "wordpress"):
		add_observation(
			"WordPress",
			"x-generator",
			"high",
			"The X-Generator header identifies WordPress as the content management system.",
		)

	if value_contains("x-powered-by", "laravel"):
		add_observation(
			"Laravel",
			"x-powered-by",
			"high",
			"The X-Powered-By header identifies Laravel as the application framework.",
		)
	elif value_contains("x-generator", "laravel"):
		add_observation(
			"Laravel",
			"x-generator",
			"high",
			"The X-Generator header identifies Laravel as the application framework.",
		)

	return observations


__all__ = ["analyze_technologies"]
