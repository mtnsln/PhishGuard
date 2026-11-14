# Testing

Run:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

The suite covers URL normalisation, supported schemes, malformed hostnames, ambiguous backslashes, control/whitespace handling, input length, HTTP, IP hosts, at-sign authority, Punycode, brand impersonation patterns, legitimate brand-domain examples, score bounds, API validation and homepage serving.

Before a public release, evaluate on a legally reusable labelled dataset and report:

- Precision and recall for the phishing class
- False-positive and false-negative rates
- Confusion matrix and class balance
- Held-out evaluation separated by domain and time where feasible
- Performance by TLD and URL language where the dataset supports it

Passing unit tests is not evidence of production detection accuracy.
