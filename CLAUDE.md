# CLAUDE.md

All project instructions live in `AGENTS.md` and apply to Claude Code as well:

@AGENTS.md

Key rules, in short:
- Never push to a remote. All git work stays local.
- Never add `Co-Authored-By:` (or any other attribution) lines to commit messages.
- Every change is made in its own branch (`fix/...`, `feature/...`, ...), never directly on `master`.
- One branch = one bug or one feature. No giga PRs; do not bundle unrelated changes.
- Follow the coding rules in `AGENTS.md` (`.clang-format`, C++11, no new dependencies, no edits to `deps/`).
