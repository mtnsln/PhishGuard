"""Local, explainable brand-impersonation heuristics.

The suffix table is intentionally conservative and incomplete. This module
does not claim to implement the Public Suffix List.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

BRANDS = {
    "amazon", "apple", "facebook", "google", "instagram", "linkedin",
    "microsoft", "netflix", "paypal", "telegram", "whatsapp", "yahoo",
}

MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
    "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.my", "com.mx", "com.tr", "com.ua",
    "com.az", "com.ar", "com.pl", "com.tw", "com.vn", "co.in",
    "firm.in", "net.in", "org.in", "gen.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "com.ru",
}


def split_domain_labels(hostname: str) -> tuple[str, list[str], list[str]]:
    """Return (registrable_domain, subdomain_labels, all_labels).

    This is a best-effort split based on a small bundled suffix set. Unknown
    suffixes use the common one-label suffix assumption.
    """
    labels = [part for part in hostname.lower().strip(".").split(".") if part]
    if len(labels) < 2:
        return hostname.lower(), [], labels
    suffix = ".".join(labels[-2:])
    suffix_size = 2 if suffix in MULTI_LABEL_SUFFIXES else 1
    index = max(0, len(labels) - suffix_size - 1)
    return ".".join(labels[index:]), labels[:index], labels


def _similar_brand(label: str) -> tuple[str, float] | None:
    cleaned = re.sub(r"[^a-z0-9]", "", label.lower())
    if not cleaned:
        return None
    best = None
    for brand in BRANDS:
        if cleaned == brand:
            continue
        ratio = SequenceMatcher(None, cleaned, brand).ratio()
        if ratio >= 0.82 and abs(len(cleaned) - len(brand)) <= 2:
            if best is None or ratio > best[1]:
                best = (brand, ratio)
    return best


def detect_brand_impersonation(hostname: str) -> list[dict]:
    """Find likely brand references outside the brand's registrable domain."""
    registrable, subdomains, labels = split_domain_labels(hostname)
    if len(labels) < 2:
        return []

    registered_label = registrable.split(".")[0]
    findings: list[dict] = []

    for label in subdomains:
        if label in BRANDS:
            findings.append({
                "code": "brand_in_subdomain",
                "title": "Brand name appears in an unrelated subdomain",
                "detail": (
                    f"The subdomain contains '{label}', but the registrable "
                    f"domain is '{registrable}'. The hostname is not thereby "
                    "shown to belong to that brand."
                ),
                "points": 35,
                "severity": "high",
            })
            return findings

    tokens = [token for token in re.split(r"[^a-z0-9]+", registered_label) if token]
    embedded = next((token for token in tokens if token in BRANDS), None)
    if embedded and registered_label != embedded:
        findings.append({
            "code": "brand_in_domain",
            "title": "Brand name embedded in an unrelated domain",
            "detail": (
                f"The registrable domain label '{registered_label}' contains "
                f"the brand name '{embedded}' alongside other text."
            ),
            "points": 30,
            "severity": "high",
        })
        return findings

    for label in subdomains:
        tokens = [token for token in re.split(r"[^a-z0-9]+", label) if token]
        embedded = next((token for token in tokens if token in BRANDS), None)
        if embedded:
            findings.append({
                "code": "brand_in_subdomain",
                "title": "Brand name appears in an unrelated subdomain",
                "detail": (
                    f"The subdomain label '{label}' contains '{embedded}', "
                    f"while the registrable domain is '{registrable}'."
                ),
                "points": 30,
                "severity": "high",
            })
            return findings

    match = _similar_brand(registered_label)
    if match:
        brand, similarity = match
        findings.append({
            "code": "brand_lookalike",
            "title": "Possible brand lookalike domain",
            "detail": (
                f"The registrable domain label '{registered_label}' resembles "
                f"'{brand}' ({similarity:.0%} string similarity). This is a "
                "heuristic warning, not proof of impersonation."
            ),
            "points": 32,
            "severity": "high",
        })

    for label in subdomains:
        match = _similar_brand(label)
        if match:
            brand, similarity = match
            findings.append({
                "code": "brand_lookalike_subdomain",
                "title": "Possible brand lookalike in subdomain",
                "detail": (
                    f"The subdomain label '{label}' resembles '{brand}' "
                    f"({similarity:.0%} string similarity)."
                ),
                "points": 24,
                "severity": "high",
            })
            break

    return findings
