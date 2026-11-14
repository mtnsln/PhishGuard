# Roadmap

## 2.0 — Reliability release

- [x] Stronger URL input validation and consistent rejection of ambiguous backslash forms.
- [x] Brand detection for selected subdomain, domain-label and typo patterns.
- [x] Explicit best-effort registrable-domain estimate.
- [x] Expanded regression tests for malformed URLs and legitimate domains.
- [x] API version and UI version aligned.
- [x] Security and scoring limitations documented.

## Next: evaluation before ML

- [ ] Replace the bundled suffix approximation with a maintained Public Suffix List implementation.
- [ ] Build a legally reusable, labelled dataset with provenance and collection dates.
- [ ] Split data by time and domain to reduce leakage.
- [ ] Measure precision, recall, false-positive rate, false-negative rate and confusion matrix.
- [ ] Compare the heuristic baseline with a reproducible ML baseline.
- [ ] Calibrate score thresholds against the intended use case.
- [ ] Add rate limiting before any public deployment.

## Later product work

- [ ] Optional reputation lookups through a documented provider, disabled by default.
- [ ] Saved scan history only with explicit retention and privacy controls.
- [ ] Exportable reports and browser extension that analyses URL text without visiting destinations.

Do not report synthetic-data accuracy as real-world performance. Do not add ML until there is enough labelled data to evaluate it honestly.
