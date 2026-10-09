# AGENTS.md

Instructions for AI coding agents (and humans) working on **mini_detour**, a minimalistic cross-platform function hooking library (Windows / Linux / macOS, x86 / x64 / ARM / ARM64).

## Git workflow

### Never push to a remote
- All git work stays **local**. Never run `git push` (to any remote, any branch), never open pull requests on a remote, never change remote configuration.
- Branches are created, committed and merged locally only. Publishing is done by the maintainer.

### Every change goes through a branch
- Never commit directly to `master`.
- Before modifying any file, create a dedicated branch from the local `master`:
  ```bash
  git checkout master
  git checkout -b <type>/<short-description>
  ```
- Branch name prefixes:
  - `fix/` — bug fix (e.g. `fix/trampoline-slot-overflow`)
  - `feature/` — new functionality (e.g. `feature/macos-export-hook`)
  - `refactor/` — no behavior change
  - `build/` — CMake / CI changes
  - `docs/` — documentation only
- Each branch is reviewed by the maintainer before being merged into `master` (locally).

### Keep branches small: one branch = one bug or one feature
- One branch fixes **one** bug or adds **one** feature. Do not bundle unrelated changes.
- No "giga PRs": if a task touches several independent problems (for example several entries of `BUGS.md`), use one branch per problem.
- Do not mix reformatting, renaming or opportunistic cleanups with a fix. If a cleanup is needed, do it in its own branch.
- If a fix depends on another one, land the dependency first, then branch the next fix from the updated `master`.
- Commit messages: short imperative summary line (≤ 72 chars), then a body explaining *why*. Reference the bug (e.g. `BUGS.md #1`) when relevant.
- Never add co-author trailers (`Co-Authored-By:` or similar attribution lines) to commit messages.
- Update `BUGS.md` in the same branch when a listed bug is fixed (remove the entry or mark it fixed).

### Everything committed is in English
- All code and everything that goes into a commit **must** be written in English: identifiers, comments, log messages, test names, documentation (`README.md`, `BUGS.md`, `AGENTS.md`, ...) and commit messages.
- This applies whatever language is used to discuss the task: translate before committing.

## Coding rules

### Formatting
- Follow `.clang-format` (run `clang-format -i` on the files you touch, and only on those):
  - Allman braces, 4-space indentation, no tabs, LF line endings.
  - 180-column limit.
  - `case` labels indented; short `if` statements are never on a single line.
  - Includes are **not** reordered (`SortIncludes: false`): keep the existing include order.
- Match the style of the surrounding code: naming, comment density and idioms.

### Language and dependencies
- The library is **C++11** (`CMAKE_CXX_STANDARD 11`). Do not use C++14/17 features in `src/` or `include/`. Tests may use C++14.
- The only runtime dependency is the vendored **Capstone** in `deps/capstone`. Do not add new dependencies.
- Never modify vendored code (`deps/`, `include/spdlog/`, `tests/catch.hpp`).
- Logging uses the `SPDLOG_*` macros only; they compile to nothing when `USE_SPDLOG` is not defined, so never put side effects inside them.

### Architecture
- Public API lives in `include/mini_detour/mini_detour.h`:
  - Exported functions are C functions declared with `MINIDETOUR_EXPORT(...)` and prefixed `MiniDetour<Namespace><Function>`.
  - The C++ API (`MiniDetour::...` namespaces, `Hook_t`) is a thin `inline` wrapper over the C functions. Keep the two in sync.
  - Do not break the ABI/API without an explicit request.
- Platform code goes in `src/mini_detour_<os>.h` (`windows`, `linux`, `macos`); architecture code in `src/mini_detour_<arch>.h` (`x86`, `x64`, `arm`, `arm64`). Keep `#if defined(MINIDETOUR_OS_*)` / `MINIDETOUR_ARCH_*` checks out of shared code when a per-platform header can hold the logic.
- When changing behavior shared by several platforms or architectures, update **all** of them, or state clearly in the commit message which ones are not covered.

### Naming
- Types and public functions: `PascalCase` (`HookFunc`, `MemoryProtect`, `RegionInfos_t`).
- Struct/typedef names end with `_t`.
- Private members and internal helpers start with an underscore (`_OriginalFuncAddress`, `_GetRelocatableSize`).
- Local variables: `camelCase` (existing `snake_case` locals may stay as they are).

### Safety rules for this codebase
- Always check return values of OS calls (`mmap` returns `MAP_FAILED`, not `nullptr`; `VirtualAlloc` / `mach_vm_*` return codes).
- Restore memory protections and flush the instruction cache (`FlushInstructionCache`) after writing code.
- Never read or write past an allocated region (trampoline slots, jump tables, code buffers).
- Any new relocation logic must handle or explicitly refuse every instruction form it can encounter. Refusing to hook is always better than generating wrong code.

## Build and tests
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMINIDETOUR_BUILD_TESTS=ON
cmake --build build
```
Then run the `tests` executable from the build output directory (`build/Debug/tests.exe` with MSVC, `build/tests` elsewhere). It needs `export_hook_test_library` in the working directory.

- A branch must build and pass the tests on the platforms it touches before it is handed over for review.
- Every bug fix should come with a test in `tests/test.cpp` that fails without the fix, when it is testable.
- CI is defined in `.github/workflows/main.yml` (Windows x86/x64, Linux x86/x64/ARM/ARM64 under QEMU, macOS).
