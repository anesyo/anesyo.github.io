#!/usr/bin/env python3
"""Release one signed version of the registry's page (decision file 0120, answer A).

This file lives in the public copy, which only the owner changes; it never comes
from the version it checks. The owner presses « Run workflow » with a pull request
number and its head commit, approves the release environment, and:

    python3 release/release.py fetch --out <dir>      # holds the read key; runs no project code
    python3 release/release.py drop-root              # gives up root before any project code runs
    python3 release/release.py build --src <dir> --out <page>   # no key; runs the signed build

fetch refuses, with one plain line and nothing written for the page, unless:
  - the inputs are a pull request number and a full 40-character commit;
  - the pull request's head is that commit and the pull request is merged;
  - its newest verdict is a PASS signed with a key in release/reviewers.txt for
    exactly that commit (release/verify_verdict.py, the project's own verifier).
Then it fetches the project at that commit. build runs that tree's own build
(tools/build/build.py), the code the reviewer drove, with no key in its environment.

The key stays in the runner's memory for the whole job, and a hosted runner gives
every step passwordless root, which can read that memory. So before the build,
drop-root takes root away for the rest of the job: the sudo rules are replaced by
root's alone, the container socket is closed to the runner, and attaching to other
processes is limited to root. It then checks each of those and refuses the release
unless all three hold. What remains assumed: the runner's image has no other way to
root (a set-user-id helper or another privileged group).

Environment for fetch: RELEASE_PR, RELEASE_SHA, RELEASE_REPO (owner/name of the
private project), RELEASE_TOKEN (read-only: contents and pull requests), and
RELEASE_API (default https://api.github.com; the tests serve a fake one).
A refusal never prints an answer body, a comment or a header: status and reason only.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PR = re.compile(r"^[1-9][0-9]{0,8}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
VERIFIER_LINES = {
    2: "the pull request carries no verdict",
    3: "the pull request's newest verdict is not a PASS",
    4: "the PASS is not signed with the reviewer's key",
    5: "the PASS is not signed with the reviewer's key",
    6: "the signed PASS is for another commit",
}
KEY_WORDS = ("TOKEN", "KEY", "SECRET", "PASSWORD")
SUDO = os.environ.get("RELEASE_SUDO", "sudo")  # the tests drive a stand-in
DOCKER_SOCKET = Path(os.environ.get("RELEASE_DOCKER_SOCKET", "/var/run/docker.sock"))
PTRACE_SCOPE = Path(os.environ.get("RELEASE_PTRACE_SCOPE", "/proc/sys/kernel/yama/ptrace_scope"))
ROOT_ONLY = ("printf 'root ALL=(ALL:ALL) ALL\\n' > /etc/sudoers.release"
             " && chmod 440 /etc/sudoers.release && visudo -cf /etc/sudoers.release"
             " && rm -f /etc/sudoers.d/* && mv /etc/sudoers.release /etc/sudoers")


class Refused(Exception):
    pass


def inputs() -> tuple[str, str, str, str, str]:
    pr, sha = os.environ.get("RELEASE_PR", ""), os.environ.get("RELEASE_SHA", "")
    repo, token = os.environ.get("RELEASE_REPO", ""), os.environ.get("RELEASE_TOKEN", "")
    api = os.environ.get("RELEASE_API", "https://api.github.com").rstrip("/")
    if not PR.match(pr):
        raise Refused("the pull request must be a number")
    if not SHA.match(sha):
        raise Refused("the version must be a full 40-character commit, lower-case")
    if not REPO.match(repo):
        raise Refused("the project's name is not set (the PROJECT variable of the release environment)")
    if not token:
        raise Refused("the read key is not set (the PROJECT_READ_KEY secret of the release environment)")
    return pr, sha, repo, token, api


def get(api: str, token: str, path: str, what: str, raw: bool = False):
    req = urllib.request.Request(f"{api}{path}", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "registre-release"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise Refused("the read key has expired or is not valid; create a new one (step 2)") from None
        if e.code in (403, 404):
            raise Refused(f"the read key cannot read {what}: it needs read access to the project's "
                          "contents and pull requests") from None
        raise Refused(f"GitHub answered {e.code} when reading {what}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Refused(f"GitHub could not be reached when reading {what}") from None
    if raw:
        return data
    try:
        return json.loads(data)
    except ValueError:
        raise Refused(f"GitHub's answer for {what} was not readable") from None


def pages(api: str, token: str, path: str, what: str) -> list:
    out, page = [], 1
    while True:
        batch = get(api, token, f"{path}?per_page=100&page={page}", what)
        if not isinstance(batch, list):
            raise Refused(f"GitHub's answer for {what} was not readable")
        out += batch
        if len(batch) < 100:
            return out
        page += 1


def check_signature(pr_data: dict, comments: list, commits: list, sha: str) -> str:
    data = {"comments": [{"body": c.get("body") or "", "author": {"login": (c.get("user") or {}).get("login")}}
                         for c in comments],
            "commits": [{"oid": c.get("sha"), "authors": []} for c in commits]}
    r = subprocess.run([sys.executable, str(HERE / "verify_verdict.py"), sha, str(HERE / "reviewers.txt")],
                       input=json.dumps(data), capture_output=True, text=True)
    if r.returncode != 0:
        raise Refused(VERIFIER_LINES.get(r.returncode, "the verdict could not be checked"))
    who = r.stdout.strip()
    if not re.fullmatch(r"key:[A-Za-z0-9_.@-]+", who):
        raise Refused("the PASS is not signed with the reviewer's key")
    return who


def extract(tarball: bytes, dest: Path) -> Path:
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as t:
            tops = {m.name.split("/", 1)[0] for m in t.getmembers()}
            if len(tops) != 1:
                raise Refused("the project's archive is not one folder")
            t.extractall(dest, filter="data")  # no links out, no absolute paths, no devices
    except (tarfile.TarError, OSError):
        raise Refused("the project's archive could not be unpacked") from None
    return dest / tops.pop()


def cmd_fetch(out: Path) -> str:
    pr, sha, repo, token, api = inputs()
    if out.exists() and any(out.iterdir()):
        raise Refused("the release folder is not empty: a version is fetched into a fresh one")
    base = f"/repos/{repo}"
    pr_data = get(api, token, f"{base}/pulls/{pr}", "the pull request")
    head = ((pr_data or {}).get("head") or {}).get("sha")
    if head != sha:
        raise Refused("that commit is not the pull request's head: only the head the reviewer signed is released")
    if not pr_data.get("merged_at"):
        raise Refused("the pull request is not merged: only what reached the main line is released")
    comments = pages(api, token, f"{base}/issues/{pr}/comments", "the pull request's comments")
    commits = pages(api, token, f"{base}/pulls/{pr}/commits", "the pull request's commits")
    who = check_signature(pr_data, comments, commits, sha)
    tarball = get(api, token, f"{base}/tarball/{sha}", "the project at that commit", raw=True)
    out.mkdir(parents=True, exist_ok=True)
    tree = extract(tarball, out / "unpacked")
    if not (tree / "tools/build/build.py").is_file():
        raise Refused("that version has no build")
    (out / "src").symlink_to(tree.resolve(), target_is_directory=True)
    (out / "release.json").write_text(json.dumps({"pr": int(pr), "commit": sha, "signed_by": who}) + "\n")
    return f"release: pull request {pr} at {sha} carries the reviewer's signed PASS ({who}); fetched"


def cmd_build(src: Path, out: Path) -> str:
    build = src / "tools/build/build.py"
    if not build.is_file():
        raise Refused("nothing fetched to build")
    env = {k: v for k, v in os.environ.items() if not any(w in k.upper() for w in KEY_WORDS)}
    r = subprocess.run([sys.executable, str(build), "--out", str(out)], cwd=src.resolve(), env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise Refused("that version's build failed")
    if not (out / "index.html").is_file():
        raise Refused("that version's build made no page")
    return f"release: page built, {sum(1 for p in out.rglob('*') if p.is_file())} files"


def cmd_drop_root() -> str:
    def as_root(*cmd: str) -> None:
        subprocess.run([SUDO, "-n", *cmd], capture_output=True, stdin=subprocess.DEVNULL, timeout=60)

    as_root("sysctl", "-w", "kernel.yama.ptrace_scope=2")  # only root may attach to a process
    if DOCKER_SOCKET.exists():
        as_root("chmod", "600", str(DOCKER_SOCKET))  # a container could mount the runner's disk
    as_root("sh", "-c", ROOT_ONLY)  # last: after it, nothing above can be undone
    still = subprocess.run([SUDO, "-n", "true"], capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
    if still.returncode == 0:
        raise Refused("root could not be given up before the build")
    if DOCKER_SOCKET.exists() and os.access(DOCKER_SOCKET, os.W_OK):
        raise Refused("the container socket is still open before the build")
    try:
        scope = int(PTRACE_SCOPE.read_text().strip())
    except (OSError, ValueError):
        raise Refused("the limit on attaching to processes could not be read") from None
    if scope < 2:
        raise Refused("attaching to processes is still allowed before the build")
    return "release: root given up for the rest of the job; the build may run"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--out", required=True, type=Path)
    sub.add_parser("drop-root")
    b = sub.add_parser("build")
    b.add_argument("--src", required=True, type=Path)
    b.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "fetch":
            print(cmd_fetch(a.out))
        elif a.cmd == "drop-root":
            print(cmd_drop_root())
        else:
            print(cmd_build(a.src, a.out))
    except Refused as e:
        print(f"release refused: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
