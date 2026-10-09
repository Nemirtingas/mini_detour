# mini_detour — Bug list and proposed fixes

Static review of the code (`src/`, `include/`, `tests/`, `CMakeLists.txt`). No fix has been applied yet.
Severity: 🔴 critical (crash / memory corruption / wrong behavior) · 🟠 important · 🟡 minor / build / API.

---

## Core (`src/mini_detour.cpp`)

### ✅ 1. Trampoline array overflow (`GetFreeTrampoline`) — fixed in `fix/trampoline-slot-overflow`
[mini_detour.cpp:427](src/mini_detour.cpp:427)
```cpp
memory_t* end = memory + _RegionSize() / sizeof(memory_t) + 1;
```
The `+ 1` walks one slot more than the page holds. On x64, `sizeof(memory_t) == 65` → 63 slots fit in 4096 bytes, but 64 are used: the 64th trampoline is written **past the end of the page** (segfault or corruption of the neighboring memory). Same on x86 (33), ARM (44), ARM64 (52).

**Fix:**
```cpp
memory_t* end = memory + _RegionSize() / sizeof(memory_t);
```

### ✅ 2. Static destruction order (`static MemoryManager mm`) — fixed in `fix/memory-manager-lifetime`
[mini_detour.cpp:466](src/mini_detour.cpp:466)
The user's global `Hook_t` objects (e.g. `puts_hook` in the tests) call `RestoreFunc()` → `mm.FreeJump()` / `mm.FreeTrampoline()` in their destructor. The destruction order across translation units is unspecified: `mm` (and its `std::vector`s) may already be destroyed → use-after-free at program exit.

**Fix:** a singleton that is never destroyed.
```cpp
static MemoryManager& GetMemoryManager()
{
    static MemoryManager* instance = new MemoryManager();
    return *instance;
}
#define mm GetMemoryManager()
```
(or replace every `mm.` with `GetMemoryManager().`)

### ✅ 3. `RestoreFunc`: the "overwritten hook" branch re-enables the hook instead of neutralizing it — fixed in `fix/bypass-overwritten-hook`
[mini_detour.cpp:913-931](src/mini_detour.cpp:913)
When the hook code was modified by a third party, the intent is to make the hook transparent. But the code writes into `_TrampolineAddress` a jump to… `_DetourCallFunc`, which is exactly what was already there. The detour stays active. Moreover `func_mode` is read from `_TrampolineAddress & 1` (always 0) instead of the original function mode, and the protected size is `_SavedCode.size()` instead of the jump size.

**Fix:**
```cpp
const size_t jumpSize = AbsJump::GetMaxOpcodeSize();
if (!MemoryManipulation::MemoryProtect(_TrampolineAddress, jumpSize, MemoryManipulation::MemoryRights::mem_rwx))
    return res;

int func_mode = 0;
int dest_mode = 0;
#if defined(MINIDETOUR_ARCH_ARM)
func_mode = reinterpret_cast<uintptr_t>(_OriginalTrampolineCallAddress) & 1; // mode of the hooked function
dest_mode = func_mode;
#endif
// Redirect the jump to the original trampoline => the hook becomes transparent
AbsJump::WriteOpcodes(_TrampolineAddress, _OriginalTrampolineAddress, func_mode, dest_mode);

MemoryManipulation::MemoryProtect(_TrampolineAddress, jumpSize, MemoryManipulation::MemoryRights::mem_rx);
MemoryManipulation::FlushInstructionCache(_TrampolineAddress, jumpSize);
```

### ✅ 4. `HookFunc` doesn't check whether the object is already in use — fixed in `fix/refuse-hook-when-already-hooked`
[mini_detour.cpp:730](src/mini_detour.cpp:730)
`CanHook` refuses if `_OriginalFuncAddress != nullptr`, but `HookFunc` doesn't. Calling `HookFunction` twice on the same `Hook_t` overwrites the state: the first hook can't be restored anymore, and its trampoline/jump leak.

**Fix:** at the start of `HookFunc`:
```cpp
if (_OriginalFuncAddress != nullptr)
    return nullptr; // or RestoreFunc() first
```

### ✅ 5. `GetOriginalFunction()` returns a stale pointer after restoring — fixed in `fix/clear-hook-state-on-restore`
[mini_detour.cpp:579-596](src/mini_detour.cpp:579)
`Reset()` doesn't clear `_OriginalTrampolineCallAddress`, `_DetourCallFunc`, `_DetourFunc`. After `RestoreFunction()`, `GetOriginalFunction()` returns a **freed** trampoline, which can be given to another hook → the wrong function is called.

**Fix:** in `Reset()`:
```cpp
_OriginalTrampolineCallAddress = nullptr;
_DetourCallFunc = nullptr;
_DetourFunc = nullptr;
```
(For `Reset(false)`, keep `_TrampolineAddress` elsewhere if needed, but don't expose it through the API anymore.)

### ✅ 6. Return value of `_RelocateCode` ignored — fixed in `fix/check-relocate-code-result`
[mini_detour.cpp:786](src/mini_detour.cpp:786)
`_RelocateCode` can return 0 **without writing the jump back** ([mini_detour_x64.h:369](src/mini_detour_x64.h:369), [mini_detour_x86.h:318](src/mini_detour_x86.h:318)). The trampoline is then incomplete and `GetOriginalFunction()` runs zeroed memory.

**Fix:**
```cpp
if (_RelocateCode(functionToHook, _OriginalTrampolineAddress, disasm, relativeJumpSize) < relativeJumpSize)
{
    SPDLOG_ERROR("Failed to relocate code.");
    goto error;
}
```

### 🟠 7. Underestimated trampoline size (`relocatedOriginalCodeSize`)
[mini_detour.cpp:759](src/mini_detour.cpp:759), [mini_detour_x64.h:214-288](src/mini_detour_x64.h:214), [mini_detour_x86.h:165-239](src/mini_detour_x86.h:165)
On x86/x64, `relocatedOriginalCodeSize` is only increased for special instructions (jmp/call/RIP relative), not for the instructions copied as is. For a relocated `call`, 5 is added while the trampoline writes a `push` (13 bytes on x64). `totalOriginalTrampolineSize` is therefore wrong → `FlushInstructionCache` / `MemoryProtect` don't cover the whole trampoline (a real problem on ARM, latent on x86). It is also computed with `absoluteJumpSize` while the relocation stops at `relativeJumpSize`.

**Fix:** make `_RelocateCode` return the number of bytes **written** in the trampoline (in addition to the bytes consumed), and use that value for protect/flush. Otherwise, protect/flush `sizeof(memory_t::data)`.

### 🟡 8. Intermediate states not restored on error
[mini_detour.cpp:778-798](src/mini_detour.cpp:778)
On `goto error` after `MemoryProtect(functionToHook, rwx)`, the function page stays RWX. Add `MemoryProtect(functionToHook, ..., mem_rx)` in the `error` path if the protection was changed.

### ✅ 9. `RestoreFunc` on freed memory leaves the object "hooked" — fixed in `fix/restore-on-freed-memory`
[mini_detour.cpp:892-893](src/mini_detour.cpp:892)
Returns `nullptr` without `Reset()`: the jump and the trampoline leak, and the destructor will try again. Call `Reset(true)` (the `mm` regions are still valid) before returning.

### ✅ 10. No synchronization in `MemoryManager` — fixed in `fix/memory-manager-lock`
`jumps_regions` / `trampolines_regions` and the bitmaps are modified without a lock. Two threads hooking at the same time can get the same slot. Add a `std::mutex` to `MemoryManager` (locked in `GetFreeJump`, `FreeJump`, `GetFreeTrampoline`, `FreeTrampoline`).

---

## x86 / x64 (`src/mini_detour_x64.h`, `src/mini_detour_x86.h`)

### ✅ 11. Conditional jumps (`jcc`, `jrcxz`, `loop`) are relocated as unconditional `jmp`s — fixed in `fix/jcc-relocation`
[mini_detour_x64.h:244](src/mini_detour_x64.h:244), [:316](src/mini_detour_x64.h:316) — same on x86 [:195](src/mini_detour_x86.h:195), [:267](src/mini_detour_x86.h:267)
In Capstone, `jne`/`je`/… have the `BRANCH_RELATIVE` + `JUMP` groups (checked in `X86MappingInsn.inc`: same signature as `jmp`), so `GetJumpType() == 3`. The trampoline then **always** jumps to the target → the semantics of the original function are broken (e.g. `test ecx,ecx; je ...` in a prologue).

**Fix:** only relocate `X86_INS_JMP`; refuse (or rewrite) the conditional ones.
```cpp
else if (disasm.GetJumpType() == 3 && disasm.GetInstruction().id == X86_INS_JMP)
{ ... }
```
To support them: write `jcc +N` (inverted or not) to an absolute jump in the trampoline.

### ✅ 12. `mov reg, [rip+X]` relocated as `lea` + unhandled registers — fixed in `fix/rip-relative-load-relocation`
[mini_detour_x64.h:265-270](src/mini_detour_x64.h:265) and [:341-363](src/mini_detour_x64.h:341)
- The code replaces every `reg, [rip+disp]` instruction with `movabs reg, address`. That is right for `lea`, **wrong for `mov`** (the address is loaded instead of the value).
- Only RAX/RCX/RDX/RBX are encoded. For RSI, RDI, R8-R15 or a 32-bit register (`mov eax, [rip+X]`), the code writes `0x48` then **no opcode** → corrupted instruction in the trampoline. Yet `_GetRelocatableSize` accepts any register.

**Fix:**
```cpp
auto const& insn = disasm.GetInstruction();
auto const& op0 = insn.detail->x86.operands[0];
auto const& op1 = insn.detail->x86.operands[1];
uint64_t target = insn.address + insn.size + op1.mem.disp;

uint8_t regNum;            // 0..15
if (!X64RegToNum(op0.reg, regNum) || op0.size != 8) return 0; // refuse what can't be encoded

// movabs reg, target    : REX.W(+B) B8+r imm64
*pTrampolineCode++ = 0x48 | (regNum >= 8 ? 0x01 : 0x00);
*pTrampolineCode++ = 0xB8 + (regNum & 7);
memcpy(pTrampolineCode, &target, 8); pTrampolineCode += 8;

if (insn.id == X86_INS_MOV)
{   // mov reg, [reg]     : REX.W(+R+B) 8B modrm
    // (special case rsp/rbp/r12/r13: SIB or disp8 required)
    ...
}
else if (insn.id != X86_INS_LEA)
    return 0;
```
and do the same check (`id` and register) in `_GetRelocatableSize` so both functions stay consistent.

### ✅ 13. `_EnterRecursiveThunk` follows `call`s (`E8`) — fixed in `fix/thunk-follows-call`
[mini_detour_x64.h:201](src/mini_detour_x64.h:201), [mini_detour_x86.h:152](src/mini_detour_x86.h:152)
A function starting with a `call` (e.g. `call __fentry__` with `-pg`, `call _RTC_...`, `call __chkstk`) is taken for a thunk: **the called function** gets hooked. Only `E9` (jmp rel32), `EB` (jmp rel8) and `FF 25` are thunks.

**Fix:**
```cpp
else if (pCode[0] == 0xE9)
    pCode = (uint8_t*)relative_addr_to_absolute(pCode, *(int32_t*)(pCode + 1));
else if (pCode[0] == 0xEB)
    pCode = pCode + 2 + *(int8_t*)(pCode + 1);
```
Also add an iteration limit (infinite loop on a cyclic thunk).

### ✅ 14. x64 `CpuPush`: sign extension of `push imm32` — fixed in `fix/x64-push-sign-extension`
[mini_detour_x64.h:157](src/mini_detour_x64.h:157)
`push imm32` sign-extends to 64 bits. If the return address is for example `0x00000000_8xxxxxxx`, the high part is zero so the `mov [rsp+4], high` is skipped → the pushed address becomes `0xFFFFFFFF_8xxxxxxx`.

**Fix:**
```cpp
bool fitsSignExtended = static_cast<int64_t>(static_cast<int32_t>(value)) == static_cast<int64_t>(value);
if (!fitsSignExtended) { /* write the 13 bytes */ }
```
(same in `GetOpcodeSize`), or always write the 13 bytes version.

### ✅ 15. Fixed 80 bytes read after the function start — fixed in `fix/bounded-code-read`
[mini_detour_x64.h:228](src/mini_detour_x64.h:228), [:305](src/mini_detour_x64.h:305), x86 [:179](src/mini_detour_x86.h:179), [:256](src/mini_detour_x86.h:256), same on ARM/ARM64
`memcpy(code_buffer, pCode, 80)` can go past the end of the mapped region (small function at the end of `.text`) → segfault.

**Fix:** bound the read to the end of the region:
```cpp
MiniDetour::MemoryManipulation::RegionInfos_t infos;
MiniDetour::MemoryManipulation::GetRegionInfos(pCode, &infos);
size_t code_size = std::min<size_t>(sizeof(code_buffer), infos.End - (uintptr_t)pCode);
memcpy(code_buffer, pCode, code_size);
```
or use `SafeMemoryRead`, reducing the size until it succeeds.

### ✅ 16. 32-bit x86: absolute `disp32` addressing is handled as "RIP relative" — fixed in `fix/x86-absolute-addressing`
[mini_detour_x86.h:212-229](src/mini_detour_x86.h:212), [:290-293](src/mini_detour_x86.h:290)
In 32-bit mode, `mod=00 rm=101` means an absolute `[disp32]` address, which **doesn't need** to be relocated. The code stops the relocation (and tests `X86_REG_RIP` in `_RelocateCode`, a typo for `EIP`, which doesn't exist in 32-bit mode anyway). Result: perfectly hookable functions are refused.

**Fix:** remove the `modrm == 0x05` block in `mini_detour_x86.h`; the instructions are copied as is.

---

## ARM / ARM64 (`src/mini_detour_arm.h`, `src/mini_detour_arm64.h`)

### 🔴 17. Thumb: the trampoline jump back is always written in ARM mode
[mini_detour_arm.h:279-280](src/mini_detour_arm.h:279), [:308-312](src/mini_detour_arm.h:308)
`func_mode = pCode & 1` and `hook_mode = pTrampoline & 1`, but the address was already cleaned (`& ~1`) in `_InitializeHookState`, and the trampoline is aligned: both are always 0. For a Thumb function, the trampoline (run in Thumb) ends with an ARM encoded `ldr pc, [pc, #-4]` → crash.

**Fix:** pass the mode explicitly.
```cpp
size_t _RelocateCode(void* pCode, void* pTrampoline, CodeDisasm& disasm, size_t wanted, int func_mode);
...
AbsJump::WriteOpcodes(pTrampolineCode, originalCodeTarget, func_mode, func_mode);
```
(and adapt the signature of the other archs, or use a default parameter).

### 🔴 18. Relative jump size computed to the wrong destination → `_HookCode` overflow
[mini_detour.cpp:670](src/mini_detour.cpp:670), [:826-827](src/mini_detour.cpp:826)
`relativeJumpSize` is computed to `newFunction`, but the written jump goes to `jump_mem` (allocated later). In Thumb, the size can be 2 while the real jump takes 4: `RelJump::WriteOpcodes` writes 4 bytes into a 2 bytes `std::vector` (heap overflow) and only 2 bytes were saved/relocated.

**Fix:** use the maximum size (`RelJump::GetMaxOpcodeSize()`) for the relocation, or compute it again once `jump_mem` is known:
```cpp
relativeJumpSize = RelJump::GetMaxOpcodeSize();
```

### 🔴 19. PC relative instructions not detected
- ARM: [mini_detour_arm.h:209-218](src/mini_detour_arm.h:209) — `_UsesInstructionPointer` only looks at **register** operands. `ldr r0, [pc, #8]` (very common in prologues to load literals) has a **memory** operand with a `PC` base → copied as is → wrong value.
  ```cpp
  if (op.type == ARM_OP_MEM && op.mem.base == ARM_REG_PC) return true;
  ```
- ARM64: [mini_detour_arm64.h:227-243](src/mini_detour_arm64.h:227) — only `adr`/`adrp` are detected. `LDR (literal)`, `LDRSW (literal)`, `PRFM (literal)` (mask `0x3B000000 == 0x18000000`) are copied as is.
  ```cpp
  uint32_t raw = *reinterpret_cast<const uint32_t*>(disasm.GetInstruction().bytes);
  bool isAdr        = (raw & 0x9F000000) == 0x10000000 || (raw & 0x9F000000) == 0x90000000;
  bool isLdrLiteral = (raw & 0x3B000000) == 0x18000000;
  if (isAdr || isLdrLiteral) { ... }
  ```
  (same test to duplicate in `_RelocateCode`).

### 🟠 20. Thumb `B.W`: ±16 MB range but the check accepts ±32 MB
[mini_detour_arm.h:16-21](src/mini_detour_arm.h:16)
`_AddressesAreRelativeJumpable` uses the ARM range (`0x1FFFFFC`). For a Thumb source, a jump between 16 and 32 MB is truncated when encoded → jump to a random address.

**Fix:** add the mode as a parameter, or use the smallest one: `(max_addr - min_addr) <= 0xFFFFFC`.

### 🟡 21. Thumb absolute jump: writes below `sp` without reserving the stack
[mini_detour_arm.h:58-73](src/mini_detour_arm.h:58)
`str r0, [sp, #-8]` then `push {r0}`: a signal arriving in between overwrites the saved value of `r0`. Prefer the literal form:
```
ldr.w pc, [pc, #0]   ; f8df f000
.word addr|1
```
(8 bytes, align the literal on 4).

---

## Windows (`src/mini_detour_windows.h`)

### ✅ 22. Missing export / import directories not detected — fixed in `fix/windows-missing-pe-directories`
- [mini_detour_windows.h:435-438](src/mini_detour_windows.h:435): `moduleHandle + RVA` is never `nullptr`. If the module has no exports (RVA = 0), the DOS header is read as an `IMAGE_EXPORT_DIRECTORY`.
- [mini_detour_windows.h:457](src/mini_detour_windows.h:457): `&&` instead of `||`; same problem for a module without imports (the `MZ...` DOS header is walked as a descriptor list → crash).

**Fix:**
```cpp
auto& dir = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
if (imageNTHeaders->Signature != IMAGE_NT_SIGNATURE || dir.VirtualAddress == 0 || dir.Size == 0)
    return false;
```
```cpp
if (imageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
    imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
    imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    return false;
```

### ✅ 23. Export jump placed below the module base (negative RVA) on x64 — fixed in `fix/export-jump-above-module`
[mini_detour_windows.h:490](src/mini_detour_windows.h:490)
`GetFreeJump(moduleBase)` guarantees ±2 GB, but an export RVA is an unsigned `DWORD`: if the slot is **below** `moduleBase`, `exportJump - moduleBase` wraps around and `GetProcAddress` returns anything.

**Fix:** after `GetFreeJump`, check `_AddressIsRepresentableAsRva(moduleBase, exportJump)` (otherwise `FreeJump` + failure); ideally add an "above the address" search to `MemoryManager`.

### ✅ 24. `MemoryAllocNear`: the downward search never works — fixed in `fix/alloc-near-overflow` and `fix/windows-alloc-near-granularity`
[mini_detour_windows.h:345-348](src/mini_detour_windows.h:345)
`start = region.End - pageSize` then the condition `(allocAddress + size) < region.End` with `size == pageSize` is false from the first iteration. Moreover `VirtualAlloc` rounds reservations to `dwAllocationGranularity` (64 KB), not to the page.

- ✅ Start of the downward search — fixed in `fix/alloc-near-overflow` (#47). Left: the 64 KB `VirtualAlloc` granularity and the sort by closest edge.

**Fix:**
```cpp
SYSTEM_INFO si; GetSystemInfo(&si);
const uintptr_t gran = si.dwAllocationGranularity;
uintptr_t lo = (region.Start + gran - 1) & ~(gran - 1);
uintptr_t hi = (region.End - size) & ~(gran - 1);
if (lo > hi) continue;
uintptr_t start = region.Start > addressHint ? lo : hi;
intptr_t  step  = region.Start > addressHint ? (intptr_t)gran : -(intptr_t)gran;
for (uintptr_t a = start; a >= lo && a <= hi; a += step) { ... }
```
Also sort by the distance to the closest edge (`End` if the region is below the hint).

### ✅ 25. `_GetRegionName`: one byte written past the buffer — fixed in `fix/windows-region-name-overflow`
[mini_detour_windows.h:128-129](src/mini_detour_windows.h:128)
If the name fits exactly in `regionNameSize` bytes, `WideCharToMultiByte` returns `regionNameSize` and `regionName[regionNameSize] = '\0'` overflows.

**Fix:** pass `regionNameSize - 1` to `WideCharToMultiByte`.

### ✅ 26. Incomplete rights conversion — fixed in `fix/windows-protection-mapping`
[mini_detour_windows.h:92-103](src/mini_detour_windows.h:92), [:241](src/mini_detour_windows.h:241)
`PAGE_WRITECOPY` and `PAGE_EXECUTE_WRITECOPY` give `mem_none` (but `RestoreFunc` takes `mem_none` as "freed memory" and gives up restoring). And in `_GetRegions`, `Protect` isn't masked with `0xFF` (PAGE_GUARD/NOCACHE → `mem_none`).

**Fix:** add `case PAGE_WRITECOPY: return mem_rw;` and `case PAGE_EXECUTE_WRITECOPY: return mem_rwx;`, and mask `Protect & 0xFF` everywhere.

### ✅ 27. Imports without `OriginalFirstThunk` — fixed in `fix/windows-imports-without-original-thunk`
[mini_detour_windows.h:540](src/mini_detour_windows.h:540), [:619](src/mini_detour_windows.h:619), [:633](src/mini_detour_windows.h:633)
Some binaries (old linkers, bound imports) have `OriginalFirstThunk == 0` → `moduleBase` is read. Use `FirstThunk` as a fallback. `stricmp` → `_stricmp` for MSVC.

---

## Linux (`src/mini_detour_linux.h`)

### ✅ 28. `mmap`: undetected failure and destructive `MAP_FIXED` — fixed in `fix/linux-mmap-failure`
[mini_detour_linux.h:263-267](src/mini_detour_linux.h:263), [:296](src/mini_detour_linux.h:296)
- `mmap` returns `MAP_FAILED` (`(void*)-1`), not `nullptr` → a failure is taken for a success and `(void*)-1` is used as memory.
- `MAP_FIXED` **silently replaces** any existing mapping. The free regions list comes from a `/proc/self/maps` snapshot: if another thread mapped something in the meantime, it is destroyed.

**Fix:**
```cpp
static inline bool MemoryAllocWithProtection(void** address, size_t size, MemoryRights rights, int flags)
{
    void* hint = *address;
    void* res = mmap(hint, size, _MemoryProtectRightsToNative(rights), flags, -1, 0);
    if (res == MAP_FAILED) { *address = nullptr; return false; }
    if (hint != nullptr && res != hint) { munmap(res, size); *address = nullptr; return false; }
    *address = res;
    return true;
}
...
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
MemoryAllocWithProtection(&address, size, rights, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS);
```
(On kernels < 4.17, `MAP_FIXED_NOREPLACE` is ignored and behaves like a hint; the `res != hint` test covers that case.)

### ✅ 29. `_LoadModuleDynamicTable` assumes `l_addr` points to the ELF header — fixed in `fix/linux-link-map-base`
[mini_detour_linux.h:428](src/mini_detour_linux.h:428)
The `dlopen` handle is a `struct link_map*` whose first field is `l_addr` = **load bias**, not the header address. For a non-PIE executable (`dlopen(nullptr)`), `l_addr == 0` → null dereference. Moreover, on musl/bionic the `.dynamic` `d_ptr`s aren't relocated.

**Fix:** use `dlinfo(handle, RTLD_DI_LINKMAP, &lm)` then `lm->l_ld` (dynamic table directly) and `lm->l_addr` as the base; or `dl_iterate_phdr` comparing `dlpi_addr`/`dlpi_name`. For the `d_ptr`s, add `l_addr` if the value is below the base.

### ✅ 30. GNU hash: index underflow — fixed in `fix/linux-gnu-hash-empty`
[mini_detour_linux.h:400-410](src/mini_detour_linux.h:400)
If every bucket is 0 (no hashed symbol), `max_sym == 0` and `chains[max_sym - symndx]` reads out of the table.

**Fix:**
```cpp
if (max_sym < hash_table->symndx)
    *dynamicSymbolsEnd = *dynamicSymbolsStart + hash_table->symndx;
else { while (...) ++max_sym; *dynamicSymbolsEnd = *dynamicSymbolsStart + max_sym + 1; }
```

### ✅ 31. `_GetExportAddress` accepts imported symbols (`SHN_UNDEF`) — fixed in `fix/linux-export-skip-undefined`
[mini_detour_linux.h:552](src/mini_detour_linux.h:552)
A module that *imports* `foo` has a `foo` entry in `.dynsym` with `st_shndx == SHN_UNDEF`. `ReplaceModuleExports` then modifies that entry, which changes the symbol resolution of the module.

**Fix:** add `|| symbol->st_shndx == SHN_UNDEF || symbol->st_value == 0` to the `continue` conditions (as `GetAllExportedSymbols` already does).

### ✅ 32. Restoring `mem_unset` rights → `PROT_NONE` — fixed in `fix/refuse-unset-protection`
[mini_detour_linux.h:244-255](src/mini_detour_linux.h:244) (and the `_Replace*` callers)
If `GetRegionInfos` doesn't find the address, `oldRights == mem_unset`, and the restore calls `mprotect(..., PROT_NONE)` → the page becomes inaccessible.

**Fix:** in `MemoryProtect` (every platform), refuse `rights == mem_unset` (return `false` without doing anything).

### ✅ 33. `_LoadModuleCommonDetails` tests the pointer instead of the value — fixed in `fix/linux-strsz-check`
[mini_detour_linux.h:471](src/mini_detour_linux.h:471)
`dynamicSymbolsNamesSize != 0` → always true. Replace with `*dynamicSymbolsNamesSize != 0`.

### ✅ 34. RWX IAT/GOT — fixed in `fix/iat-write-without-exec` and `fix/linux-iat-glob-dat`
[mini_detour_linux.h:853](src/mini_detour_linux.h:853), [:897](src/mini_detour_linux.h:897) (same on Windows [:769](src/mini_detour_windows.h:769), [:806](src/mini_detour_windows.h:806))
The GOT/IAT is data: `mem_rw` is enough, RWX is needlessly permissive. `R_GLOBAL_DATA` relocations (code built with `-fno-plt`) aren't handled.

- ✅ RWX rights — fixed in `fix/iat-write-without-exec` (the page keeps its rights, only write access is added).

---

## macOS (`src/mini_detour_macos.h`)

### ✅ 35. Null dereference if the module isn't found — fixed in `fix/macos-module-not-found`
[mini_detour_macos.h:555-557](src/mini_detour_macos.h:555)
If no `dlopen(imageFilePath)` matches the handle (e.g. the `dlopen(NULL)` handle or the main executable), `foundModuleBase == nullptr` then `machHeader->magic` crashes.

**Fix:** `if (foundModuleBase == nullptr) return false;` before the magic test. Use `RTLD_NOLOAD` in the lookup `dlopen` so no new image is loaded.

### ✅ 36. `GetRegionInfos` leaves `Rights` uninitialized — fixed in `fix/macos-region-infos-init`
[mini_detour_macos.h:219](src/mini_detour_macos.h:219)
The local variable `rights = mem_unset` is never assigned to `regionInfos->Rights`. If the address is free, `Rights`/`Start`/`End` hold indeterminate values (read by `RestoreFunc` and `MemoryProtect(..., &oldRights)`).

**Fix:** at the start of the function:
```cpp
regionInfos->Rights = MemoryRights::mem_unset;
regionInfos->Start = 0;
regionInfos->End = 0;
regionInfos->ModuleName[0] = '\0';
```

### ✅ 37. Symbol addresses ignore the slide — fixed in `fix/macos-symbol-slide`
[mini_detour_macos.h:634](src/mini_detour_macos.h:634)
`n_value` is an unslid virtual address (e.g. `0x100000xxx` for an executable). `moduleBase + n_value` is only right when `__TEXT.vmaddr == 0` (dylib). Compute `slide = moduleBase - textSegment->vmaddr` then `slide + n_value`. The `+ 1` that strips the `_` must check that the name does start with `_`.

### ✅ 38. `FlushInstructionCache` does nothing — fixed in `fix/macos-flush-instruction-cache`
[mini_detour_macos.h:383-386](src/mini_detour_macos.h:383)
On Apple Silicon, the instruction cache must be invalidated after writing code.
```cpp
#include <libkern/OSCacheControl.h>
sys_icache_invalidate(address, size);
```

---

## Public API (`include/mini_detour/mini_detour.h`)

### ✅ 39. `Hook_t::operator=(Hook_t&&)` leaks the current handle — fixed in `fix/hook-move-assignment`
[mini_detour.h:480-486](include/mini_detour/mini_detour.h:480)
The existing handle is overwritten without `MiniDetourHookTFree`; no protection against self-assignment.
```cpp
inline Hook_t& operator=(Hook_t&& other) noexcept
{
    if (this != &other)
    {
        MiniDetourHookTFree(_hookHandle);
        _hookHandle = other._hookHandle;
        other._hookHandle = nullptr;
    }
    return *this;
}
```
Same remark for `Implementation::Hook_t::operator=` ([mini_detour.cpp:551](src/mini_detour.cpp:551)), which should first call `RestoreFunc()` if `_RestoreOnDestroy`.

### ✅ 40. The "C" API doesn't compile as C — fixed in `fix/c-compatible-header`
[mini_detour.h:112-135](include/mini_detour/mini_detour.h:112), [:225-331](include/mini_detour/mini_detour.h:225)
- `bool` used without `#include <stdbool.h>`.
- `MiniDetourMemoryManipulationRegionInfos_t*` and `MiniDetourMemoryManipulationMemoryRights` used without `struct`/`enum` → error in C.
- The `mem_r`, `mem_none`… enumerators are global (namespace pollution).

**Fix:**
```c
#ifndef __cplusplus
#include <stdbool.h>
#endif
typedef enum MiniDetourMemoryManipulationMemoryRights { ... } MiniDetourMemoryManipulationMemoryRights;
typedef struct MiniDetourMemoryManipulationRegionInfos_t { ... } MiniDetourMemoryManipulationRegionInfos_t;
/* same for the other structs */
```
and prefix the enumerators (`MINIDETOUR_MEM_R`…) while keeping C++ aliases in `MiniDetour::MemoryManipulation`.

### ✅ 41. Wrong documentation — fixed in `docs/fix-api-comments`
- [mini_detour.h:209](include/mini_detour/mini_detour.h:209): `PageRound` rounds **down** (the comment says "upper value").
- [mini_detour.h:268](include/mini_detour/mini_detour.h:268): `FlushInstructionCache` is implemented on Linux too.
- `WriteAbsoluteJump(nullptr, nullptr)` underestimates the size on ARM64 (the size depends on the destination): document that the real destination must be passed, or return `GetMaxOpcodeSize()` when `address == nullptr`.

---

## Build (`CMakeLists.txt`)

### ✅ 42. The installed package can't be used with `find_package` — fixed in `build/fix-installed-package`
[CMakeLists.txt:329](CMakeLists.txt:329), [:345](CMakeLists.txt:345)
- `install(EXPORT ... FILE MiniDetourConfig.cmake)` then `configure_package_config_file` installs **another** `MiniDetourConfig.cmake` at the same place, which includes `MiniDetourTargets.cmake`… never generated.
- `write_basic_package_version_file(VERSION 0.0.0)` while the project is 1.1.4 → `find_package(MiniDetour 1.1)` fails.

**Fix:**
```cmake
install(EXPORT MiniDetourTargets
  FILE MiniDetourTargets.cmake
  NAMESPACE Nemirtingas::
  DESTINATION lib/cmake/MiniDetour)
...
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/MiniDetourConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)
```

### ✅ 43. Global changes leaking into the parent project — fixed in `build/dont-clear-parent-standard-libraries`
[CMakeLists.txt:10](CMakeLists.txt:10), [:13-14](CMakeLists.txt:13)
`CMAKE_C/CXX_STANDARD_LIBRARIES` is **forced to empty in the cache** (removes `kernel32.lib`, `user32.lib`… for any project doing `add_subdirectory(mini_detour)`), and `-stdlib=libc++` is added to the global `CMAKE_CXX_FLAGS`.

**Fix:** remove those lines; if needed, use `target_compile_options(mini_detour PRIVATE ...)` / `target_link_options` on the target only.

---

## Tests (`tests/test.cpp`)

### ✅ 44. Wrong test `_EnterRecursiveThunk` on x64 — fixed in `fix/test-recursive-thunk`
[tests/test.cpp:43-46](tests/test.cpp:43)
It decodes `FF 25` as an absolute address (x86 form), while on x64 it is `[rip + disp32]`. Reuse the `mini_detour_x64.h` version under an architecture `#if`.

### ✅ 45. A string literal is modified — fixed in `fix/test-string-literal`
[tests/test.cpp:638](tests/test.cpp:638), [:663](tests/test.cpp:663)
The test executable code is a `const` literal in `.rodata`, modified after `MemoryProtect`. Undefined behavior; prefer a buffer allocated with `MemoryAlloc(..., mem_rwx)`.

### ✅ 46. Missing coverage — fixed in `docs/close-coverage-entry`
Add tests for: hooking a function whose prologue holds a `jcc` (#11), a `mov reg, [rip+X]` (#12), more than 63 simultaneous hooks (#1), `GetOriginalFunction()` after `RestoreFunction()` (#5), `HookFunction` twice on the same object (#4), a module without exports/imports (#22).

All covered by the tests added with the fixes: `test_jcc_relocation.cpp` (#11), `test_rip_relative_relocation.cpp` (#12), `test_trampoline_slots.cpp` (#1, 300 hooks), `test_hook_state_after_restore.cpp` (#5), `test_hook_twice.cpp` (#4), `test_windows_pe_directories.cpp` and `test_linux_gnu_hash_without_exports.cpp` (#22, #30).

### ✅ 47. `MemoryAllocNear`: `allocAddress + size` overflow — fixed in `fix/alloc-near-overflow`
[mini_detour_linux.h](src/mini_detour_linux.h), [mini_detour_windows.h](src/mini_detour_windows.h), [mini_detour_macos.h](src/mini_detour_macos.h)
With a huge size, `allocAddress + size` wraps around: the loop condition stays true and the search tries every page of the address space (hours long hang on x64). The bounds are now computed from the region size (`End - size`), which also fixes the start of the downward search (#24).

### ✅ 48. macOS: `__PAGEZERO` listed as free memory — fixed in `fix/macos-pagezero-not-free`
[mini_detour_macos.h](src/mini_detour_macos.h)
`__PAGEZERO` is reserved from 0 up to the main executable (its end follows the ASLR slide), but `mach_vm_region` doesn't report it: `GetFreeRegions` listed it as free, and `MemoryAllocNear` tried (in vain) every page of it before going elsewhere. The executable is found by its `MH_EXECUTE` type: with `DYLD_INSERT_LIBRARIES`, image 0 is the inserted library.

---

## Recommended order
1. #1, #28, #11, #12, #13 — memory corruptions / wrong semantics on x86/x64 and Linux (platforms tested in CI).
2. #2, #3, #5, #6, #22 — robustness of the hooks lifecycle.
3. #17, #18, #19 — ARM/ARM64 (the CI ARM tests run with `|| echo "Failed"`, so these failures go unnoticed).
4. #42, #43 — packaging.
5. The rest.
