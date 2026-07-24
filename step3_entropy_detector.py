"""
STEP 3: Generic (format-unknown) secret detection using entropy.

Two-stage approach, as we discussed:
  1. Extract "token-shaped" substrings -- no whitespace, plausible secret
     charset, minimum length. This alone rules out English sentences.
  2. Score ONLY those candidates with Shannon entropy, flag ones above
     a tuned threshold.
"""

import re
import math
from collections import Counter


def shannon_entropy(s):
    """Bits of entropy per character. Higher = more random-looking."""
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Stage 1: what does a "candidate token" even look like?
#   - [A-Za-z0-9+/=_-]  -- base64-ish charset (letters, digits, and the
#                          handful of symbols base64/tokens commonly use)
#   - {20,}             -- at least 20 characters long. Short strings
#                          give unreliable entropy estimates, and most
#                          real secrets (API keys, tokens) are long.
# No \s (whitespace) is possible in this charset at all, so sentences
# are automatically excluded -- we don't even need to check for spaces
# separately.
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=_-]{20,}')

# Tuned threshold. We'll calibrate this shortly by testing against
# real generated secrets vs real non-secret strings.
ENTROPY_THRESHOLD = 4.0


def scan_for_high_entropy_strings(text):
    findings = []
    for candidate in TOKEN_PATTERN.findall(text):
        score = shannon_entropy(candidate)
        if score >= ENTROPY_THRESHOLD:
            findings.append((candidate, score))
    return findings


if __name__ == "__main__":
    import secrets as secrets_module  # Python's built-in secrets module,
                                       # for generating REAL random tokens
                                       # to test against -- not related to
                                       # our tool's name, just a coincidence
                                       # of naming.

    real_random_secret = secrets_module.token_urlsafe(32)
    print(f"Real random secret (token_urlsafe): {real_random_secret}")
    print(f"  entropy = {shannon_entropy(real_random_secret):.3f}\n")

    sample_text = f"""
# config.py
API_KEY = "{real_random_secret}"
PACKAGE_NAME = "django-rest-framework-simplejwt-extension-package"
COMMENT = "this is just a long english sentence about configuration settings"
LOCK_HASH = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
"""

    print("Scanning sample text for high-entropy strings...\n")
    results = scan_for_high_entropy_strings(sample_text)
    for value, score in results:
        print(f"  entropy={score:.3f}  {value}")

    print(f"\nTotal findings: {len(results)}")