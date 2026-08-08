#!/usr/bin/env python3
"""Validate ladder ruleset files.

Upstream (everywall/ladder-rules) auto-merges concatenated YAML with zero validation, and
ladder is fail-soft on a bad source: it logs a warning and serves without those rules. A
syntax error therefore silently zeroes a whole ruleset at the next nightly restart instead
of failing loudly. This script is the check upstream does not have.

Usage: validate-ruleset.py FILE [FILE ...]
Exits non-zero on the first failure, naming the file, rule index and offending key.
"""

import re
import sys

import yaml

# Keys ladder's Go struct (pkg/ruleset.Rule) actually reads.
KNOWN_KEYS = {
    "domain",
    "domains",
    "paths",
    "headers",
    "googleCache",
    "useFlareSolverr",
    "regexRules",
    "urlMods",
    "injections",
}

# Keys upstream ships that the Go struct has no field for. yaml.v3 discards them silently.
# Tolerated so a verbatim upstream sync still validates; never required, never added by us.
TOLERATED_KEYS = {"tests"}

HEADER_KEYS = {
    "user-agent",
    "x-forwarded-for",
    "referer",
    "cookie",
    "content-security-policy",
}
INJECTION_KEYS = {"position", "append", "prepend", "replace"}
REGEX_KEYS = {"match", "replace"}
URLMOD_KEYS = {"domain", "path", "query"}

warnings: list[str] = []


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"WARN: {msg}", file=sys.stderr)


def check_nested(path: str, mapping, allowed: set) -> None:
    """Nested typos are advisory only.

    Upstream's live ruleset already carries one (`ueser-agent` on the nytimes rule), so
    hard-failing here would make a verbatim upstream sync unmergeable. The Go struct
    ignores the bad key exactly as it ignores `tests`, so the rule still loads — the
    header just never applies.
    """
    if not isinstance(mapping, dict):
        return
    for key in mapping:
        if key not in allowed:
            warn(f"{path}: unrecognised key {key!r} (ladder will ignore it)")


def validate_file(filename: str) -> int:
    try:
        with open(filename, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        fail(f"{filename}: not valid YAML: {exc}")
    except OSError as exc:
        fail(f"{filename}: cannot read: {exc}")

    if not isinstance(doc, list):
        fail(f"{filename}: top level must be a list of rules, got {type(doc).__name__}")
    if not doc:
        fail(f"{filename}: contains no rules")

    for index, rule in enumerate(doc):
        where = f"{filename}[{index}]"
        if not isinstance(rule, dict):
            fail(f"{where}: rule must be a mapping, got {type(rule).__name__}")

        for key in rule:
            if key in KNOWN_KEYS:
                continue
            if key in TOLERATED_KEYS:
                warn(f"{where}: key {key!r} is not in ladder's Go struct and is discarded")
                continue
            fail(f"{where}: unknown key {key!r}")

        if not (rule.get("domain") or rule.get("domains")):
            fail(f"{where}: needs a non-empty 'domain' or 'domains'")

        check_nested(f"{where}.headers", rule.get("headers"), HEADER_KEYS)
        for j, injection in enumerate(rule.get("injections") or []):
            check_nested(f"{where}.injections[{j}]", injection, INJECTION_KEYS)
        urlmods = rule.get("urlMods")
        check_nested(f"{where}.urlMods", urlmods, URLMOD_KEYS)

        for j, regex_rule in enumerate(rule.get("regexRules") or []):
            check_nested(f"{where}.regexRules[{j}]", regex_rule, REGEX_KEYS)
            pattern = (regex_rule or {}).get("match")
            if not pattern:
                fail(f"{where}.regexRules[{j}]: missing 'match'")
            # Python's re is not Go's RE2, so this is a close-enough proxy: it catches real
            # typos (unbalanced brackets/parens) without claiming RE2 equivalence.
            try:
                re.compile(pattern)
            except re.error as exc:
                fail(f"{where}.regexRules[{j}]: 'match' does not compile: {exc}")

    print(f"OK: {filename} — {len(doc)} rules")
    return len(doc)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    total = sum(validate_file(name) for name in argv[1:])
    print(f"OK: {total} rules across {len(argv) - 1} file(s), {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
