# PhishGuard

**Explainable URL risk analysis without opening the submitted website.**

PhishGuard is a local web application and command-line tool that inspects URL text for characteristics sometimes associated with phishing. It returns a heuristic score and explains which checks contributed to it.

> **Important:** PhishGuard is an educational security aid, not a verdict engine. A low score does not prove that a website is safe, and a high score does not prove that it is malicious.

## Features

- URL normalisation and strict input validation.
- Checks for HTTP, IP-address hosts, `@` in URL authority, Punycode, long URLs, URL shorteners, selected TLDs and account-related wording.
- Brand impersonation heuristics for selected brands, subdomains and spelling lookalikes.
- Explainable findings with stable codes and point contributions.
- Risk score from 0 to 100 with low, medium and high bands.
- Browser dashboard, JSON API and CLI.
- No external URL scanning service; submitted destinations are never fetched.

## Deliberate limitations

PhishGuard does not:
- Open, crawl, ping or download content from submitted URLs.
- Inspect page content, redirects, scripts or downloads.
- Determine registration age, ownership, hosting provider or certificate history.
- Verify a domain against an authoritative brand ownership database.
- Produce a calibrated probability of phishing.

The registrable-domain estimate uses a small bundled suffix table, not a complete Public Suffix List. It may be incorrect for uncommon suffixes. The brand list is limited. Rules can miss malicious URLs and flag legitimate ones.

## Requirements

- Python 3.10+
- pip

## Run locally

```bash
git clone https://github.com/YOUR-USERNAME/PhishGuard.git
cd PhishGuard
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install and run:

```bash
python -m pip install -r requirements.txt
python -m uvicorn phishguard.api:app --reload
```

Open `http://127.0.0.1:8000`. Interactive API documentation: `http://127.0.0.1:8000/docs`.

## CLI

```bash
python -m phishguard.cli example.com
python -m phishguard.cli https://example.com/login --json
```

## API

`POST /api/analyze`

```json
{
  "url": "https://example.com/login"
}
```

The response includes the input, normalised URL, hostname, best-effort registrable-domain estimate, risk score, findings, analysis type and disclaimer. Invalid input returns HTTP 422.

Health check: `GET /health`.

## Tests

```bash
python -m pip install -e ".[dev]"
pytest -q
```

Passing tests validates the tested software behaviours only. It does not measure real-world phishing detection accuracy.

## Docker

```bash
docker build -t phishguard .
docker run --rm -p 8000:8000 phishguard
```

Open `http://127.0.0.1:8000`.

## Project structure

```text
phishguard/       URL analysis engine, API and CLI
static/           Browser interface
tests/            Automated tests
docs/             Architecture, testing and roadmap
```

## Scoring

Each rule contributes a fixed number of points. The total is capped at 100.

| Score | Label | Meaning |
|---:|---|---|
| 0–29 | Low | Few or no current heuristic signals |
| 30–59 | Medium | Signals deserve manual review |
| 60–100 | High | Multiple or stronger warning signs |

These weights are not probabilities and have not been calibrated on a representative production dataset.

## Responsible use

Use PhishGuard to inspect links you are authorised to review. For account, payment or sensitive activity, navigate to the organisation's known official website rather than relying on a link in a message.

## Licence

MIT. See `LICENSE`.
