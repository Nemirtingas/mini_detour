# CLAUDE.md

All project instructions live in `AGENTS.md` and apply to Claude Code as well:

@AGENTS.md

Developer specific instructions, when the file exists (it is never committed):

@AGENTS_custom.md

Key rules, in short:
- Never push to a remote. All git work stays local.
- No reference to an AI, an LLM or a coding agent in anything committed or published: commit messages (no `Co-Authored-By:` or "Generated with" lines), branch names, pull requests, comments, code, docs.
- Every change is made in its own branch (`fix/...`, `feature/...`, ...), never directly on `master`.
- One branch = one bug or one feature. No giga PRs; do not bundle unrelated changes.
- Everything committed is in English: code, comments, docs (including `BUGS.md`) and commit messages.
- Follow the coding rules in `AGENTS.md` (`.clang-format`, C++11, no new dependencies, no edits to `deps/`).
