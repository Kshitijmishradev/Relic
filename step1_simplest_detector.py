"""
STEP 1: The simplest possible secret detector.

Goal: match ONE known secret format (AWS access keys) inside a block of text.
No git, no files, no complexity yet -- just prove the core idea works.
"""

import re

# AWS access keys always look like: AKIA + 16 uppercase letters/digits
# Example real-looking (but fake) key: AKIAIOSFODNN7EXAMPLE
#
# Let's break down the regex piece by piece:
#   AKIA          -- literal characters, must match exactly
#   [0-9A-Z]      -- a character class: any single digit 0-9, OR any
#                    uppercase letter A-Z
#   {16}          -- exactly 16 repetitions of the character class above
#
# So the whole pattern reads as: "the literal text AKIA, followed by
# exactly 16 characters that are each either a digit or an uppercase letter"
AWS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')

# Some sample text pretending to be a config file, with a real-looking
# fake AWS key hidden in it, to prove the detector works.
sample_text = """
# config.py
DATABASE_URL = "postgres://localhost/mydb"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DEBUG = True
"""

matches = AWS_KEY_PATTERN.findall(sample_text)

print("Scanning sample text for AWS keys...\n")
if matches:
    for m in matches:
        print(f"  FOUND: {m}")
else:
    print("  No matches found.")