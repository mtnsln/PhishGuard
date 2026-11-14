# Architecture

## Request flow

1. The browser sends URL text to `POST /api/analyze`.
2. FastAPI validates the request length and passes the string to `analyze_url`.
3. The analyser normalises and validates the URL, parses it and extracts hostname characteristics.
4. Independent deterministic rules produce findings. Each finding has a stable code, explanation, severity and point weight.
5. The score is the sum of rule weights capped at 100. Thresholds map the score to low, medium or high.
6. The API returns a JSON report. The browser renders report values using `textContent`, not HTML interpretation.

## Privacy and security boundaries

- Submitted URLs are never fetched, crawled, pinged or downloaded.
- The application does not persist submitted URLs.
- No external threat-intelligence provider is contacted.
- The URL input is limited to 2,048 characters.
- Backslashes, whitespace in URLs, malformed labels and unsupported schemes are rejected.
- The browser uses text nodes for untrusted report fields.

For public deployment, add rate limiting, HTTPS at a reverse proxy, structured access-log review, dependency scanning, a privacy notice and an operational abuse policy. Avoid logging submitted URLs because they may contain private tokens or personal data.

## Domain and brand detection

Brand detection separates subdomains from a best-effort registrable-domain estimate using a small bundled suffix table. It detects exact brand labels in unrelated subdomains, brand tokens combined with other text, and selected close spelling variants.

This is not a complete Public Suffix List implementation. The returned `registrable_domain_estimate` can be wrong for uncommon or newly introduced suffixes. Brand coverage is limited and similarity heuristics can produce false positives and false negatives.

## Scoring

Rule weights are prioritisation heuristics, not probabilities. They have not been trained or calibrated against a representative labelled dataset. The score must not be described as model confidence or detection accuracy.

## Extension rules

New checks should be deterministic, side-effect free, have stable finding codes, explain their rationale, include positive and negative tests, and document likely false positives.
