# AGENTS.md

Instructions for coding agents (and humans) working on **mini_detour**, a minimalistic cross-platform function hooking
library: inline hooks, export and import table replacement, memory helpers. Windows / Linux / macOS, x86 / x64 / ARM
(Thumb) / ARM64. C API with a thin C++ wrapper, one dependency (Capstone, vendored).

All the code follows this file. Code found not following it is a bug to fix, not an example to copy.

## Personal instructions
- Each developer can keep their own instructions in `AGENTS_custom.md` at the root (language, test machines, remotes,
  local paths). Read it first when it exists and follow it along with this file.
- It is listed in `.gitignore` and never committed.
- It only adds instructions: it overrides no rule of this file. When the two disagree, this file wins.

## Git workflow

### Branches
- Never commit on `master`. Every change starts from an up to date local `master`:
  `git checkout master && git checkout -b <type>/<short-description>`.
- Prefixes: `fix/` and `feature/` only, `docs/` when nothing but documentation changes.
  - `fix/`: something is wrong: a bug, a broken build or test, code that doesn't follow this file.
  - `feature/`: something new: functionality, platform support, tests or CI jobs that didn't exist.
- One branch = one bug or one feature. A fix depending on another one is branched after the first one is merged.
- Code found not following this file is fixed in a `fix/` branch of its own, not in the middle of another change.
- A change that renames something this file mentions updates this file in the same branch.

### Commits
- Summary line: imperative, plain English, no prefix or tag, at most 72 characters
  (`Replace the imports of shared cache libraries on recent macOS`, `Hook code on Apple Silicon`).
- Body wrapped at 72 columns, in prose: what was wrong or missing, why, how it is fixed, and what the test checks.
- Never `git add -A` / `git add .`: build directories and local notes sit untracked in the working tree. Add the files
  you changed by name.

### Publishing
- All work stays local by default. Push and open pull requests only when the maintainer asks, to the remote named in
  `AGENTS_custom.md` or by the maintainer. Never change remote configuration on your own.
- Never force-push a branch you didn't create without asking first.
- A pull request description says what changes, why, and how it was tested. Leave out figures that only hold when
  written (files, lines, commits) and observations that are not about the change (flaky tests seen elsewhere, plans):
  report those in the conversation instead.

### Language and attribution
- Everything committed or published is in English: identifiers, comments, logs, test names, docs, commit messages,
  branch names, pull requests.
- Nothing committed or published mentions an AI, an LLM or a coding agent, or that one was used: no `Co-Authored-By:`,
  no "Generated with ..." line, even if the tool adds them by default. Only the agent instruction files themselves
  (`AGENTS.md`, `CLAUDE.md`, `AGENTS_custom.md`) talk about agents.

## Build and tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMINIDETOUR_BUILD_TESTS=ON
cmake --build build --parallel 4
```

- Run `tests` from its output directory (`build/tests`, or `build/<Config>/tests.exe` with Visual Studio): it loads
  `export_hook_test_library` from the working directory. On macOS, run `./macos_permission_fix tests` after every
  relink, before `./tests`.
- Logs: the test build (`mini_detour_test`) is compiled with `USE_SPDLOG`. Only warnings are shown unless
  `MINIDETOUR_TEST_LOG_LEVEL=info` (or `debug`) is set. A test can be run alone by tag: `./tests "[hook_twice]"`.
- CI (`.github/workflows/main.yml`), Debug and Release: Windows x86/x64/ARM64, Linux x86/x64/ARM64, Linux ARM
  (cross compiled, run natively on the arm64 runner through the ARM loader), macOS ARM64. macOS x64 is only tested on
  a local machine.
- A branch builds without warnings (`/W4`, `-Wall -Wextra` on the library) and passes the tests, in Debug and
  Release, on every platform and architecture it touches before it is handed over. Say which ones could not be run.

## Repository layout
- `include/mini_detour/mini_detour.h`: the only public header (C API + inline C++ wrapper).
- `src/mini_detour.cpp`: the single translation unit. It includes one architecture header and one platform header:
  - `src/mini_detour_<arch>.h` (`x86`, `x64`, `arm`, `arm64`): jump encodings, thunk following, relocation.
  - `src/mini_detour_<os>.h` (`windows`, `linux`, `macos`): memory, thread freezing, module imports/exports.
  - `src/capstone_arch.h`: force-included in the Capstone sources, so only the target disassembler is built.
- `tests/`: Catch2 tests (`test.cpp` holds `main`, one `test_<subject>.cpp` per subject), `test_utils.h`, test
  libraries, toolchains, CMake consumer projects.
- Vendored, never modified: `deps/capstone/`, `include/spdlog/`, `tests/catch.hpp`.

## Architecture rules

### What each header provides
- An architecture header defines: `memory_t` (trampoline slot), `AbsJump`, `RelJump` (`WriteOpcodes`,
  `GetOpcodeSize`, `constexpr GetMaxOpcodeSize`), `_AddressesAreRelativeJumpable`, `_GetCodeMode`, `_GetCodeAddress`,
  `_GetCallAddress`, `_InitDisasm`, `_EnterRecursiveThunk`, `_GetRelocatableSize`, `_RelocateCode`.
- A platform header defines `_OtherThreadsFreezer_t` (`Freeze`, `Unfreeze`), the `_Query*` functions used by
  `Globals_t`, the `MemoryManipulation::Implementation` entry points (`GetRegionInfos`, `GetAllRegions`,
  `GetFreeRegions`, `MemoryProtect`, `MemoryFree`, `_MemoryAllocAt`, `_MemoryAllocAnywhere`, `SafeMemoryRead`,
  `SafeMemoryWrite`, `FlushInstructionCache`) and the `ModuleManipulation::Implementation` ones
  (`_QueryModuleFunctions`, `GetAllExportedSymbols`, `GetAllIATSymbols`, `Replace/RestoreModuleExports`,
  `Replace/RestoreModuleIATs`). A platform without writable and executable memory defines
  `MINIDETOUR_JIT_CODE_MEMORY` and its `_JitCode*` / `_WriteFunctionCodeByRemap` functions (macOS).
- The same helper has the same name on every platform (`_MemoryProtectRightsToNative`, `_NativeToMemoryRights`, ...)
  and the same concept has the same name everywhere (`dynamicSymbolsNames`, not `dynStr` in one function).
- Platform and architecture specifics stay in their header. `#if defined(MINIDETOUR_OS_*)` in `mini_detour.cpp` is
  only for what must be declared before the platform header is included (`ModuleFunctions_t`).
- A change of behavior shared by several platforms or architectures is made in all of them, or the commit message
  says which ones are not covered.

### Writing code and tables
- Code the library owns (jump slots, trampolines) comes from `AllocCode` and is only written between
  `BeginCodeWrite` and `EndCodeWrite` (which flushes the instruction cache).
- Code the library doesn't own (the hooked function) is written through `_FunctionCodeWriter`: `Prepare` (may
  allocate), then `Write` while `_OtherThreadsFreezer_t` holds the other threads, then `Finish`. It keeps the original
  rights of the page.
- Never make code `mem_rwx` with `MemoryProtect` directly: Apple Silicon and the hardened runtime refuse writable and
  executable memory.
- Import slots and export entries are written with `_ExchangeTableEntry` (keeps the page rights, never adds execute);
  on macOS through `_WriteProtected`.
- Between `Freeze` and `Unfreeze`: no heap allocation, no logging, no call that could be hooked. A suspended thread
  can hold the heap lock or a lock the detour needs. Every thread is resumed before any handle or port is released.
- The C entry points that write code or tables take `Globals_t::HookMutex`. The `Implementation` functions don't.

### Correctness first
- Refusing to hook is always better than generating wrong code: a relocation handles, or explicitly refuses, every
  instruction form it can meet. An instruction that can't be copied as is (IP-relative, branch) is rewritten by a
  dedicated case or stops the relocation.
- Never write past a slot: trampolines fit in the slot data, jumps in `AbsJump::GetMaxOpcodeSize()`, code reads in
  the local buffers. Reading code near the end of a mapping goes through `_ReadCode` (safe read).
- Following thunks is bounded (8 jumps): a thunk jumping to itself must not hang.
- Check every OS return value (`mmap` gives `MAP_FAILED`, `VirtualAlloc` `nullptr`, `mach_vm_*` a `kern_return_t`).
- A failed operation leaves no partial state (slots freed, rights restored). The cleanup is done by objects whose
  destructor or `Finish` undoes what was acquired (RAII), not by `goto`.

### Loader functions
- The library calls the loader (`GetModuleHandleExA`, `GetProcAddress`, `GetModuleFileNameW`, `dlinfo`, `dlopen`,
  `dlclose`, `dlsym`) only through `Globals_t::ModuleFunctions`, resolved once at start: the imports of the image
  linking the library may be replaced by the user.
- Never take `&function` of an imported function, in the library or in the tests: it can be the image's thunk, stub or
  PLT entry. Ask the loader (`GetProcAddress`, `dlsym(RTLD_NEXT)` on Linux, `dlsym(RTLD_DEFAULT)` on macOS).

### Static data
- No static objects: what the library keeps for the whole process goes in the singleton `MiniDetour::Globals_t`
  (`src/mini_detour.cpp`), built in declaration order:
  - objects with a constructor or a destructor (mutex, memory manager);
  - values computed once and cached because they never change while the process runs (page size, address bounds,
    whether writable and executable memory exists, loader functions).
- `constexpr` values and constant tables stay plain statics.
- Per-thread state is the only exception: it is a `static thread_local` next to the code using it, with a comment
  saying why it is per thread (the macOS JIT write depth).
- A value only needed for one call stays a local variable.
- `Globals_t` is never destroyed (hooks with static storage are restored during static destruction). Its constructor
  must not call `Globals_t::Instance()`.

## Public API
- C first: every function is `MINIDETOUR_EXPORT(type) MiniDetour<Group><Function>(...)` (`Utils`, `MemoryManipulation`,
  `ModuleManipulation`, `HookT`), and the C++ API (`MiniDetour::...`, `Hook_t`) is an `inline` wrapper over it. Keep
  both in sync.
- The header compiles as C and as C++11: booleans are `int` (1/0) in C, never `bool` or `<stdbool.h>`
  (`tests/test_c_api.c` checks it). C prototypes without parameters are written `(void)`.
- No exception crosses the C API (`new (std::nothrow)`). C entry points check their pointers and counts before use.
- Patterns to keep: a null output array returns the count only (`GetAllExportedSymbols(h, nullptr, 0)`), and that
  count is exactly what a large enough array receives; output fields are reset at entry so a failed entry is null;
  variable-size structures start with `StructSize`.
- A parameter that means the same thing behaves the same on every platform (a null or empty module name matches any
  module). When a platform can't give a value the same meaning (ordinals), the documentation says what it is on each
  platform.
- Never break the API or ABI without an explicit request from the maintainer.

### Documentation
- Every public function and every field of the public structures is documented on the C declaration, in Doxygen
  form:

  ```c
  /// @brief Safely reads memory: unreadable or unallocated memory doesn't crash the process.
  /// @param address Where to read.
  /// @param buffer Receives the bytes read.
  /// @param size Number of bytes to read.
  /// @return The number of bytes read: size when everything was read. The copy stops at the first page that can't be
  /// read.
  ```

- Structure fields say whether they are IN, OUT or both, for each function using them. Per-platform differences are
  written out. No empty `@brief`, `@param` or `@return`.

## Coding style

### Format
- Run `clang-format -i` (`.clang-format`) on the files you touch, and only on those. If your clang-format version
  changes lines you didn't touch, revert those hunks.
- Allman braces, 4 spaces, no tabs (comments included), 180 columns, includes never reordered.
- Every text file is LF (`.gitattributes`). CMake uses 2 spaces, no tabs, no trailing spaces.

### Language
- The library is C++11 (`CMAKE_CXX_STANDARD 11`): no C++14 in `src/` or `include/`, except code under
  `#ifdef USE_SPDLOG`, which is only built by the C++14 test build. Tests are C++14.
- No new dependency.
- Logging uses the `SPDLOG_*` macros only, defined as nothing without `USE_SPDLOG`: no side effect in their arguments,
  and no `#ifdef USE_SPDLOG` around them. `#ifdef USE_SPDLOG` only surrounds code that exists for logging (building a
  string to log).
- C++ casts only (`static_cast`, `reinterpret_cast`, `const_cast`), never C casts, including when parsing PE, ELF or
  Mach-O structures.
- `nullptr`, never `NULL` or `0` for pointers. `std::min` / `std::max` without parentheses (`NOMINMAX` is defined).
- `#if defined(MINIDETOUR_OS_*)` / `MINIDETOUR_ARCH_*` for platforms, `#ifdef` for feature macros (`USE_SPDLOG`).
- Early returns, no `goto`.
- No magic numbers: encodings carry a comment giving the instruction (`0xE9 // jmp rel32`), and flags or kinds get
  named constants (an enum of bits for the jump kinds returned by `CodeDisasm::GetJumpType`).
- Functions and types local to the library are `static` (`static inline` is fine).

### Naming
| What | Convention | Examples |
|---|---|---|
| Types (classes, structs, enums, aliases) | `PascalCase_t`, never a leading `_` | `Globals_t`, `ModuleFunctions_t`, `ElfDyn_t` |
| Internal helper functions, private methods | leading `_` + PascalCase | `_ReadCode`, `_GetCodeMode`, `_TryFreeze` |
| Implementation entry points, public methods | PascalCase, same name as the API | `MemoryProtect`, `GetRegionInfos`, `Freeze` |
| Public data members | PascalCase | `PageSize`, `HookMutex`, `Name`, `Slot` |
| Private data members | `_` + PascalCase | `_Threads`, `_SavedCode` |
| Locals and parameters (public C functions included) | camelCase | `relocatableSize`, `moduleHandle`, `addressHint` |
| Macros | `MINIDETOUR_*` (library), `TEST_*` (tests) | `MINIDETOUR_JIT_CODE_MEMORY` |

- On functions and members, a leading `_` means private or internal, nothing else: a public member or method has no
  `_`, an internal helper function always has one. Types never start with `_`, they always end with `_t`.
- Exceptions: the public C names kept for compatibility (`mem_r`, `mem_rwx`, `MiniDetourMemoryManipulationMemoryRights`,
  `minidetour_hook_handle_t`), the OS and file format names (`Elf64_Dyn`, `PIMAGE_*`, `nbuckets`), and the instruction
  field names taken from the architecture manuals (`S`, `J1`, `imm10`).

### Comments
- English sentences, present tense, no "we", no "I". They say **why** or what the system does, not what the next line
  does: `// VirtualAlloc treats NULL as "anywhere".`, `// mmap refuses the addresses below vm.mmap_min_addr.`
- Every non trivial function or type has a comment above it: what it does, its contract, the platform facts it
  relies on (loader behavior, OS version, encoding). Instruction encodings are written out next to the code.
- Short explanations are joined with a colon rather than "because": `// Free memory has no rights, as in GetAllRegions.`
- A comment made wrong by a change is fixed in the same commit. No commented-out code.
- A `TODO` says what is missing and why it isn't done yet: `// TODO: <what>. <why not now>.`

## Tests
- A bug fix comes with a test that fails without the fix, when it can be tested. A feature comes with tests on every
  platform it supports.
- One subject per file: `tests/test_<subject>.cpp` (or `tests/test_<os>_<subject>.cpp`), picked up by the CMake glob.
  `tests/test.cpp` only holds `main`. The tag of every test of a file is its subject in snake_case: `[<subject>]`
  (`test_hook_twice.cpp` → `[hook_twice]`).
- The test name is a sentence stating the expected behavior (`"A hook object in use refuses to hook another
  function"`). A comment above the test says what used to go wrong.
- Platform-specific tests are guarded with `#if defined(MINIDETOUR_OS_*)` / `MINIDETOUR_ARCH_*`, never skipped at run
  time. Build a deterministic layout rather than replacing an assertion with a conditional `WARN`: a `WARN` is only
  for a limit of the environment the test can't control (qemu hiding its own mappings).
- `REQUIRE` for preconditions (library loaded, buffer allocated), `CHECK` for the behavior.
- Hand-written code goes through `CodeBuffer` and `GeneratedCode` (`tests/test_utils.h`): never writable and
  executable memory, Thumb addresses through `GeneratedCode::FunctionAddress`.
- A test replacing a system function forwards to the real one (taken from the loader), and calls the replaced imports
  itself through a `noinline` helper, so the optimizer keeps the import.
- New test libraries use `minidetour_add_test_library` in `CMakeLists.txt`.

