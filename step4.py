"""
STEP 4: Scan real files on disk, combining both detectors (Step 2 pattern-
based + Step 3 entropy-based) into one, and skip known-noisy files entirely
via an allowlist -- instead of trying to out-clever them with charset tricks.
"""

import re
import math
import os
from collections import Counter

# ------------------------------------------------------------------
# Detector 1: known patterns (from Step 2)
# ------------------------------------------------------------------
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b')},
    {"name": "GitHub Personal Access Token", "pattern": re.compile(r'\bghp_[A-Za-z0-9]{36}\b')},
    {"name": "Slack Token", "pattern": re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,72}\b')},
]

# ------------------------------------------------------------------
# Detector 2: entropy-based (from Step 3)
# ------------------------------------------------------------------
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=_-]{20,}')
ENTROPY_THRESHOLD = 4.0


def shannon_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ------------------------------------------------------------------
# NEW: the allowlist. Files matching these names are skipped entirely
# -- we never even read their content. This is the lever we chose
# over restricting the charset, because it doesn't cause false
# negatives on real secrets elsewhere.
# ------------------------------------------------------------------
ALLOWLISTED_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
}

# Directories we should never descend into (version control internals,
# dependency folders -- these are noisy and not the developer's own code)
ALLOWLISTED_DIRS = {".git", "node_modules", "venv", "__pycache__", ".venv"}


def scan_text_combined(text):
    """Run both detectors on a block of text, return unified findings."""
    findings = []

    for secret_type in SECRET_PATTERNS:
        for match in secret_type["pattern"].findall(text):
            findings.append({"type": secret_type["name"], "value": match, "method": "pattern"})

    for candidate in TOKEN_PATTERN.findall(text):
        score = shannon_entropy(candidate)
        if score >= ENTROPY_THRESHOLD:
            findings.append({"type": "High-entropy string", "value": candidate,
                              "method": "entropy", "score": round(score, 3)})

    return findings


def scan_file(filepath):
    """Scan a single file, respecting the allowlist. Returns findings list."""
    filename = os.path.basename(filepath)
    if filename in ALLOWLISTED_FILENAMES:
        return []  # skip entirely -- known noisy, don't even read it

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
    except (IsADirectoryError, PermissionError):
        return []

    findings = scan_text_combined(content)
    for f_ in findings:
        f_["file"] = filepath
    return findings


def scan_directory(root_dir):
    """Walk a directory tree, scanning every file except allowlisted ones."""
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames IN PLACE to prevent os.walk from descending
        # into allowlisted directories at all (this is the documented
        # way to prune os.walk's traversal)
        dirnames[:] = [d for d in dirnames if d not in ALLOWLISTED_DIRS]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            all_findings.extend(scan_file(filepath))

    return all_findings


if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {os.path.abspath(target_dir)}\n")

    results = scan_directory(target_dir)
    for r in results:
        extra = f" (entropy={r['score']})" if r["method"] == "entropy" else ""
        print(f"  [{r['type']}]{extra}\n    {r['file']}\n    {r['value']}\n")

    print(f"Total findings: {len(results)}")