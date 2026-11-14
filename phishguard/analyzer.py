"""Rule-based URL analysis. Submitted destinations are never fetched."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .brand_detection import detect_brand_impersonation, split_domain_labels

SUSPICIOUS_TLDS = {
    "click", "country", "gq", "icu", "info", "link", "live", "monster",
    "online", "rest", "site", "support", "top", "xyz", "zip",
}
SUSPICIOUS_TERMS = {
    "account", "auth", "billing", "confirm", "login", "password",
    "recover", "secure", "security", "signin", "update", "verify",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    detail: str
    points: int
    severity: str

    def to_dict(self) -> dict:
        return asdict(self)


def _normalise_input(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("URL must be provided as text.")
    value = value.strip()
    if not value:
        raise ValueError("Enter a URL to analyse.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("The URL contains control characters.")
    if any(char.isspace() for char in value):
        raise ValueError("The URL must not contain unescaped whitespace.")
    # Backslashes are interpreted inconsistently by URL parsers and browsers.
    if "\\" in value:
        raise ValueError("Backslashes are not accepted in URLs.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def _hostname_ascii(hostname: str) -> str:
    try:
        result = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The hostname contains an invalid internationalised label.") from exc
    if not result:
        raise ValueError("The URL must contain a valid hostname.")
    if "%" in result:
        raise ValueError("Percent-encoding is not accepted in hostnames.")
    try:
        ipaddress.ip_address(result.strip("[]"))
        return result
    except ValueError:
        pass
    if len(result) > 253:
        raise ValueError("The hostname is too long.")
    labels = result.split(".")
    if any(not label for label in labels):
        raise ValueError("The hostname contains an empty domain label.")
    for label in labels:
        if len(label) > 63:
            raise ValueError("A hostname label exceeds 63 characters.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Hostname labels cannot start or end with a hyphen.")
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise ValueError("The hostname contains unsupported characters.")
    return result


def _looks_like_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(raw_url: str) -> dict:
    """Return a deterministic, explainable heuristic assessment."""
    candidate = _normalise_input(raw_url)
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname or ""
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL is malformed. Check its hostname and port.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.netloc or not hostname:
        raise ValueError("The URL must contain a valid hostname.")

    host = _hostname_ascii(hostname)
    findings: list[Finding] = []

    def add(code: str, title: str, detail: str, points: int, severity: str) -> None:
        findings.append(Finding(code, title, detail, points, severity))

    if parsed.scheme.lower() == "http":
        add("no_https", "HTTPS is not used",
            "The URL uses HTTP. Data sent to the site may not be protected in transit.",
            12, "medium")

    if _looks_like_ip(host):
        add("ip_host", "IP address used as hostname",
            "The destination is written as an IP address rather than a conventional domain name.",
            18, "high")

    if "@" in parsed.netloc:
        add("at_symbol", "At-sign in URL authority",
            "The text before @ is user information; the host after @ receives the request.",
            22, "high")

    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", "Internationalised domain encoding",
            "The hostname contains a Punycode label. This can be legitimate, but can also be used in lookalike domains.",
            16, "medium")

    registrable, subdomains, labels = split_domain_labels(host)
    if len(subdomains) >= 3:
        add("many_subdomains", "Unusually many subdomains",
            f"The hostname contains {len(subdomains)} subdomain label(s) before '{registrable}'.",
            10, "low")

    if len(candidate) > 120:
        add("long_url", "Unusually long URL",
            f"The URL is {len(candidate)} characters long.",
            8, "low")

    if re.search(r"%[0-9a-fA-F]{2}", candidate):
        add("encoded_chars", "Percent-encoded characters",
            "The URL contains encoded characters. This is common on the web, but may obscure parts of a link.",
            5, "low")

    if host in SHORTENERS:
        add("shortener", "URL shortener domain",
            "The destination is hidden behind a URL-shortening service and cannot be determined from the text alone.",
            12, "medium")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add("uncommon_tld", "TLD sometimes seen in suspicious links",
            f"The .{tld} top-level domain is sometimes used in abusive campaigns. A TLD alone does not establish malicious intent.",
            8, "low")

    host_terms = set(re.findall(r"[a-z0-9]+", host))
    path_query = set(re.findall(r"[a-z0-9]+", (parsed.path + " " + parsed.query).lower()))
    matched_terms = sorted((host_terms | path_query) & SUSPICIOUS_TERMS)
    if len(matched_terms) >= 2:
        add("credential_terms", "Multiple account-related terms",
            "The URL contains these terms: " + ", ".join(matched_terms[:6]) +
            ". Such wording is sometimes used in credential-harvesting links.",
            10, "medium")

    for signal in detect_brand_impersonation(host):
        add(signal["code"], signal["title"], signal["detail"],
            signal["points"], signal["severity"])

    if not findings:
        add("no_obvious_signals", "No obvious heuristic signals",
            "This URL did not trigger the current checks. That does not prove the site is safe.",
            0, "info")

    score = min(100, sum(item.points for item in findings))
    if score >= 60:
        level = "high"
        summary = "Several strong warning signs were found. Do not enter credentials or payment details unless you independently verify the destination."
    elif score >= 30:
        level = "medium"
        summary = "Some warning signs were found. Verify the domain through a trusted source before interacting with the site."
    else:
        level = "low"
        summary = "Few or no warning signs were found by these checks. This is not a safety guarantee."

    return {
        "input": raw_url.strip(),
        "normalised_url": candidate,
        "hostname": host,
        "registrable_domain_estimate": registrable,
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "findings": [item.to_dict() for item in findings],
        "analysis_type": "local_heuristics",
        "disclaimer": (
            "PhishGuard analyses URL text only. It does not visit the site, verify "
            "ownership, check domain age, inspect page content, or guarantee that "
            "a URL is safe or malicious. Domain splitting uses a limited local "
            "suffix list and may be incorrect for uncommon suffixes."
        ),
    }
