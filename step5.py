"""
STEP 5: Walk full git history, not just the current working tree.

Algorithm:
  for every commit in the repo's history:
    for every file that changed in that commit:
      fetch that file's full content AS IT EXISTED at that commit
      run our combined scanner (patterns + entropy) against it

This is what catches secrets that were committed and later "deleted" --
they're gone from the working tree, but git show can still retrieve
their content from the commit where they existed.
"""

import re
import math
import os
import subprocess
from collections import Counter

# ------------------------------------------------------------------
# Same detectors as Step 4 -- unchanged.
# ------------------------------------------------------------------
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b')},
    {"name": "GitHub Personal Access Token", "pattern": re.compile(r'\bghp_[A-Za-z0-9]{36}\b')},
    {"name": "Slack Token", "pattern": re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,72}\b')},
]
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=_-]{20,}')
ENTROPY_THRESHOLD = 4.0
ALLOWLISTED_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Cargo.lock", "go.sum",
}


def shannon_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ------------------------------------------------------------------
# NEW: known placeholder/example values that real companies publish
# in their OWN documentation, specifically so tools like ours (and
# their own internal systems) can recognize and ignore them. Flagging
# these is a pure false positive -- they were never secret to begin
# with, they're example code from a tutorial.
# ------------------------------------------------------------------
KNOWN_PLACEHOLDER_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",                        # AWS's own docs example access key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",     # AWS's own docs example secret key
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",     # common tutorial placeholder token
}


def is_known_placeholder(value):
    """
    Two checks:
      1. Exact match against a known list of published example values.
      2. Heuristic: AWS (and many others) deliberately embed the literal
         word "EXAMPLE" in their placeholder keys for exactly this
         purpose -- so a case-insensitive substring check catches
         variants we haven't explicitly listed yet.
    """
    if value in KNOWN_PLACEHOLDER_VALUES:
        return True
    if "example" in value.lower():
        return True
    return False


def scan_text_combined(text):
    findings = []
    for secret_type in SECRET_PATTERNS:
        for match in secret_type["pattern"].findall(text):
            if is_known_placeholder(match):
                continue
            findings.append({"type": secret_type["name"], "value": match, "method": "pattern"})
    for candidate in TOKEN_PATTERN.findall(text):
        score = shannon_entropy(candidate)
        if score >= ENTROPY_THRESHOLD:
            findings.append({"type": "High-entropy string", "value": candidate,
                              "method": "entropy", "score": round(score, 3)})
    return findings


# ------------------------------------------------------------------
# NEW: git interaction functions. Each one shells out to a real git
# command via subprocess and parses its plain-text output.
# ------------------------------------------------------------------

def run_git(repo_path, args):
    """Run a git command in repo_path, return (success, stdout)."""
    result = subprocess.run(
        ["git"] + args,
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stdout


def get_all_commit_hashes(repo_path):
    """git log --format=%H  ->  one full commit hash per line."""
    ok, output = run_git(repo_path, ["log", "--format=%H"])
    if not ok or not output.strip():
        return []
    return output.strip().split("\n")


def get_changed_files(repo_path, commit_hash):
    """
    git diff-tree --no-commit-id --name-only -r <hash>
    --root is needed too, otherwise the very first commit (which has
    no parent to diff against) reports zero changed files.
    """
    ok, output = run_git(repo_path, [
        "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commit_hash
    ])
    if not ok or not output.strip():
        return []
    return output.strip().split("\n")


def get_file_content_at_commit(repo_path, commit_hash, filepath):
    """
    git show <hash>:<filepath>  ->  full file content at that snapshot.
    Returns None if the file doesn't exist at that commit (e.g. it was
    deleted in this very commit -- there's nothing to fetch).
    """
    ok, output = run_git(repo_path, ["show", f"{commit_hash}:{filepath}"])
    return output if ok else None


def scan_git_history(repo_path):
    """The main algorithm: walk every commit, every changed file in it."""
    all_findings = []
    commits = get_all_commit_hashes(repo_path)

    for commit_hash in commits:
        changed_files = get_changed_files(repo_path, commit_hash)

        for filepath in changed_files:
            filename = os.path.basename(filepath)
            if filename in ALLOWLISTED_FILENAMES:
                continue

            content = get_file_content_at_commit(repo_path, commit_hash, filepath)
            if content is None:
                continue  # file was deleted in this commit, nothing to scan

            findings = scan_text_combined(content)
            for f in findings:
                f["file"] = filepath
                f["commit"] = commit_hash[:8]  # short hash for readability
            all_findings.extend(findings)

    return all_findings


if __name__ == "__main__":
    import sys
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning full git history of: {os.path.abspath(repo_path)}\n")

    results = scan_git_history(repo_path)
    for r in results:
        extra = f" (entropy={r['score']})" if r["method"] == "entropy" else ""
        print(f"  commit {r['commit']}  [{r['type']}]{extra}")
        print(f"    file: {r['file']}")
        print(f"    value: {r['value']}\n")

    print(f"Total findings across all history: {len(results)}")