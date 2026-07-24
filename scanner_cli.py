"""
FINAL STEP: A real CLI, with proper argument parsing and exit codes
suitable for CI/CD integration (GitHub Actions, pre-commit hooks, etc.)
"""

import argparse
import json
import os
import sys

# Import everything from our history scanner -- reusing all the
# detection logic we already built and tested.
from step5 import scan_git_history


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="git-secret-scanner",
        description="Scan a git repository's FULL commit history for leaked secrets.",
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        help="Path to the git repository to scan (default: current directory)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress output entirely -- rely only on the exit code (useful in CI logs)",
    )
    return parser


def print_text_report(findings):
    if not findings:
        print("No secrets found.")
        return
    for r in findings:
        extra = f" (entropy={r['score']})" if r["method"] == "entropy" else ""
        print(f"  commit {r['commit']}  [{r['type']}]{extra}")
        print(f"    file: {r['file']}")
        print(f"    value: {r['value']}\n")
    print(f"Total findings: {len(findings)}")


def print_json_report(findings):
    print(json.dumps(findings, indent=2))


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if not os.path.isdir(os.path.join(args.repo_path, ".git")):
        print(f"Error: '{args.repo_path}' is not a git repository (no .git folder found).",
              file=sys.stderr)
        sys.exit(2)  # distinct exit code for "usage error" vs "secrets found"

    findings = scan_git_history(args.repo_path)

    if not args.quiet:
        if args.output == "json":
            print_json_report(findings)
        else:
            print_text_report(findings)

    # THE KEY LINE for CI/CD integration:
    # exit 0 = clean, exit 1 = secrets found. This is the contract
    # every CI system understands without any special configuration.
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()