# RELIC

A command-line tool that scans a git repository's **full commit history**
— not just the current files — for leaked secrets: API keys, tokens, and
high-entropy strings that look like credentials.

## Why history, not just files?

Most naive secret scanners only check the files sitting on disk right now.
But if a secret was committed and later deleted, it's still fully
recoverable from git history — `git show <commit>:<file>` retrieves it
even though it's invisible in the working directory. This tool walks
every commit, checking every file as it existed at that point in time,
so deleted-but-not-purged secrets don't slip through.

## Detection methods

1. **Pattern matching** — known secret formats with recognizable
   signatures (AWS access keys, GitHub personal access tokens, Slack
   tokens), matched with word-boundary-aware regex to avoid matching
   inside longer unrelated identifiers.
2. **Entropy analysis** — for secrets with no known format (random API
   keys, custom tokens), using Shannon entropy to flag token-shaped
   strings that are statistically too random to be normal text.
3. **Allowlisting** — known-noisy files (`package-lock.json`,
   `yarn.lock`, etc.) are skipped entirely, since they legitimately
   contain long high-entropy hashes that aren't secrets.

## Usage

```bash
# Scan a repo, human-readable output
python3 scanner_cli.py /path/to/repo

# JSON output, for piping into other tools
python3 scanner_cli.py /path/to/repo --output json

# Quiet mode -- no output, rely only on exit code (for CI logs)
python3 scanner_cli.py /path/to/repo --quiet
```

**Exit codes** (designed for CI/CD integration):
- `0` — no secrets found
- `1` — secrets found (use this to block a merge/deploy)
- `2` — usage error (not a valid git repository)

### Example: as a pre-commit / CI gate

```bash
python3 scanner_cli.py . --quiet || {
  echo "Secrets detected in git history -- blocking."
  exit 1
}
```

## Project structure

| File | Purpose |
|---|---|
| `scanner_cli.py` | CLI entry point — argument parsing, exit codes, output formatting |
| `step5_git_history_scanner.py` | Core detection logic + git history traversal |
| `demo_repo/` | Small fixture repo with a secret committed then deleted, for testing |

## Known limitations

- Entropy-based detection can produce false positives on long
  hyphenated identifiers (package names, URLs) that happen to have
  high character diversity without being secrets.
- No allowlist yet for well-known placeholder/example values (e.g.
  AWS's own documentation example key `AKIAIOSFODNN7EXAMPLE`).
- Scans every commit in full history, which doesn't yet scale to very
  large repositories (no incremental/since-last-scan mode).

## What this project demonstrates

Built as a hands-on deep dive into: regex-based signature detection,
Shannon entropy and information theory, git internals (commit
snapshots vs. diffs, `git show`, `git diff-tree`), and false-positive
tradeoffs in security tooling design.
