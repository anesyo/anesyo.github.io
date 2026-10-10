#!/usr/bin/env python3
"""Decide whether a PR's newest verdict is a PASS the publisher may act on.

    gh pr view <n> --json comments,commits \
      | python3 scripts/verify_verdict.py <head sha> .agentflow/reviewers.txt

Prints the reviewer's identity ("key:<name>" or "login:<login>") and exits 0 when the
newest verdict is a PASS by a listed reviewer for exactly this head commit. Otherwise:
    2  no verdict on the PR
    3  the newest verdict is not a PASS
    4  the PASS is not from a listed reviewer (no valid signature, or unlisted login)
    5  the reviewer authored a commit on the PR (login mode only)
    6  the PASS is for a different commit

Two kinds of reviewer in .agentflow/reviewers.txt:

  key    A line in OpenSSH allowed_signers format: `<name> ssh-ed25519 AAAA...`.
         The default for a single owner whose sessions all post under one GitHub
         login: a login proves nothing there, a signature does. The verdict comment
         ends with an SSH signature block over the exact bytes "PASS <full sha>",
         made with `ssh-keygen -Y sign -n reviewer`. Only the Reviewer session holds
         the private half.
  login  A line with one word: a GitHub login. For teams where the reviewer is a
         different person. The PASS must be posted by that login, which authored no
         commit on the PR, and must quote the head commit.

Both kinds may be listed; a PASS counts if either rule accepts it.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

NAMESPACE = "reviewer"
SIG_BLOCK = re.compile(r"-----BEGIN SSH SIGNATURE-----.*?-----END SSH SIGNATURE-----", re.S)
VERDICT = re.compile(r"^VERDICT:\s*(PASS|BLOCK|CHANGES)\b", re.M)
SHA = re.compile(r"\b[0-9a-f]{40}\b")


def read_reviewers(path: Path) -> tuple[list[str], set[str]]:
    keys: list[str] = []
    logins: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            keys.append(line)
        elif len(parts) == 1:
            logins.add(parts[0])
    return keys, logins


def signed_for(sig: str, keys: list[str], sha: str) -> str | None:
    """The principal whose listed key signed "PASS <sha>", or None."""
    with tempfile.TemporaryDirectory() as d:
        allowed = Path(d, "allowed_signers")
        allowed.write_text("\n".join(keys) + "\n", encoding="utf-8")
        sigfile = Path(d, "verdict.sig")
        sigfile.write_text(sig.strip() + "\n", encoding="utf-8")
        found = subprocess.run(["ssh-keygen", "-Y", "find-principals", "-s", str(sigfile), "-f", str(allowed)],
                               capture_output=True, text=True)
        for principal in found.stdout.split():
            ok = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", principal,
                                 "-n", NAMESPACE, "-s", str(sigfile)],
                                input=f"PASS {sha}".encode(), capture_output=True)
            if ok.returncode == 0:
                return principal
    return None


def decide(data: dict, head: str, keys: list[str], logins: set[str]) -> tuple[int, str]:
    verdicts = [c for c in data.get("comments", []) if VERDICT.search(c.get("body", ""))]
    if not verdicts:
        return 2, "no verdict"
    last = verdicts[-1]
    body = last.get("body", "")
    if VERDICT.search(body).group(1) != "PASS":
        return 3, "newest verdict is not PASS"
    sig = SIG_BLOCK.search(body)
    if keys and sig:
        who = signed_for(sig.group(0), keys, head)
        if who:
            return 0, f"key:{who}"
        for other in set(SHA.findall(body)) - {head}:
            if signed_for(sig.group(0), keys, other):
                return 6, f"signed PASS is for {other[:7]}, not the head {head[:7]}"
        return 4, "signature does not verify against any listed reviewer key"
    if logins:
        who = (last.get("author") or {}).get("login")
        if who not in logins:
            return 4, f"{who} is not a listed reviewer"
        authors = {(c.get("author") or {}).get("login") for c in data.get("commits", [])}
        authors |= {a.get("login") for c in data.get("commits", []) for a in c.get("authors", [])}
        if who in authors:
            return 5, f"{who} authored a commit on this PR"
        if head[:7] not in body:
            return 6, "PASS does not name the head commit"
        return 0, f"login:{who}"
    return 4, "PASS carries no signature and no login reviewers are listed"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    head, reviewers = argv[0], Path(argv[1])
    keys, logins = read_reviewers(reviewers)
    code, msg = decide(json.load(sys.stdin), head, keys, logins)
    print(msg if code == 0 else f"verdict: {msg}", file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
