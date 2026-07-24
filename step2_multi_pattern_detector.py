"""
STEP 2: Generalize to multiple secret types, structured so adding more
is easy later. Also fixes the false-positive risk we found in Step 1
by adding word boundaries (\b) around each pattern.
"""

import re

# ------------------------------------------------------------------
# \b is a "word boundary" -- it matches the INVISIBLE position between
# a word character (letter/digit/underscore) and a non-word character
# (space, quote, start/end of string, punctuation, etc.), without
# consuming any characters itself.
#
# So \bAKIA[0-9A-Z]{16}\b means:
#   "AKIA + 16 chars, but ONLY if nothing word-like touches it on
#    either side" -- this stops it from matching in the middle of a
#    longer identifier like AKIAIOSFODNN7EXAMPLEUSER_ID, because
#    there's no boundary right after the 16th matched character there
#    (the next character is still a letter, U, not a boundary).
# ------------------------------------------------------------------

# Each entry: a human-readable name + the compiled pattern that
# detects it. Structured as a list so adding a new secret type later
# is just "add one more dict to this list" -- no other code changes.
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    },
    {
        "name": "GitHub Personal Access Token",
        # GitHub PATs (new format) start with ghp_ followed by 36
        # alphanumeric characters.
        "pattern": re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
    },
    {
        "name": "Slack Token",
        # Slack tokens look like xoxb-..., xoxp-..., xoxa-..., etc.
        # followed by a long alphanumeric/hyphen string.
        "pattern": re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,72}\b'),
    },
]


def scan_text(text):
    """
    Scan a block of text against every known pattern.
    Returns a list of (secret_type_name, matched_string) tuples.
    """
    findings = []
    for secret_type in SECRET_PATTERNS:
        for match in secret_type["pattern"].findall(text):
            findings.append((secret_type["name"], match))
    return findings


# Sample text with one of each type, PLUS the false-positive trap from
# Step 1 (a long identifier that starts like an AWS key but isn't one)
sample_text = """
# config.py
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
SLACK_WEBHOOK_TOKEN = "xoxb_FAKE_TOKEN"
NOT_A_SECRET = "AKIAIOSFODNN7EXAMPLEUSER_ID"
DEBUG = True
"""

if __name__ == "__main__":
    print("Scanning sample text...\n")
    results = scan_text(sample_text)

    if not results:
        print("  No secrets found.")
    for secret_type, value in results:
        print(f"  [{secret_type}] {value}")

    print(f"\nTotal findings: {len(results)}")