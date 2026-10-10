# The registry's page

This repository publishes the anaesthesia registry's page and nothing else. Nothing
in it holds patient data: the registry stays on the doctor's devices and drive.

## How a new version goes out

1. You are told the number of a pull request and its version (40 characters).
2. In Actions, open « release », choose « Run workflow », and type both.
3. GitHub asks for your approval. Approve only a version you were told about.
   Only the reviewer's PASS is signed: an objection the reviewer posted after it
   could be deleted by anyone acting as you, and the signature alone would not
   show it. Your approval of the version you were told about is the guard.
4. The release checks the reviewer's signature on exactly that version and refuses
   anything else with one plain line. Nothing is published when it refuses.

## Before the first release

Do not run a release until the fence test has passed on all three routes (the
roles' tool, a plain web push, and a key kept on the roles' machine). You will be
shown its receipt. Until then a role could still change this repository.

## When something changes

- A new reviewer key: replace the key line in `release/reviewers.txt` with the new
  one you are given. Until you do, versions signed with the new key are refused.
- The read key expires after a year: the release then refuses with a line saying
  so. Create a new one with the same two read permissions and replace the secret.
- A change to anything in `release/` or `.github/` comes to you as a file to copy
  here, already checked by the reviewer. Nothing else may change these files.
