# Changelog

## 2.0.0

- Tightened URL validation for whitespace, backslashes, malformed labels, percent-encoded hosts and oversized input.
- Added best-effort registrable-domain estimate to reports.
- Improved explanations for brand signals and subdomain counts.
- Aligned UI, API and package version.
- Expanded tests for malformed inputs, IDNs, brand patterns and API responses.
- Clarified that the suffix table is incomplete and scores are not probabilities.

## 1.1.0

- Added detection for brand names placed in subdomains of unrelated domains.
- Added detection for brand names combined with other text in the registrable domain label.
- Improved typo-lookalike checks for registered domain labels.
