import argparse
import json
import sys

from .analyzer import analyze_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse URL text locally with PhishGuard.")
    parser.add_argument("url", help="URL text to analyse")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report")
    args = parser.parse_args()
    try:
        report = analyze_url(args.url)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"Risk: {report['risk_level'].upper()} ({report['risk_score']}/100)")
        print(report["summary"])
        print(f"Host: {report['hostname']}")
        print(f"Estimated registrable domain: {report['registrable_domain_estimate']}")
        for finding in report["findings"]:
            print(f"- {finding['title']} (+{finding['points']}): {finding['detail']}")
        print("\nNote:", report["disclaimer"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
