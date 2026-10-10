# mini_detour

Minimalistic cross-platform function hooking library, with a C API and a thin C++ wrapper.

- Inline hooks: the first instructions of a function are replaced by a jump to your function, and a trampoline lets you
  call the original one.
- Export and import table replacement: `GetProcAddress` / `dlsym` and the calls through the import table of a module
  return or reach your function, without writing code into the target.
- Memory helpers used by the library: region listing, protection changes, allocation near an address, safe reads and
  writes.

The only dependency is [Capstone](https://www.capstone-engine.org/), vendored in `deps/capstone` and built with the library.

## Supported platforms

|                               | x86 | x64 | ARM / Thumb | ARM64 |
|-------------------------------|:---:|:---:|:-----------:|:-----:|
| Windows                       | ✅  | ✅  |      ¹      |   ¹   |
| Linux                         | ✅  | ✅  |     ✅      |  ✅   |
| macOS                         |     | ✅  |             |   ¹   |

¹ Built, but not tested.

On macOS, code can only be hooked in images whose segments allow it: see [macOS](#macos).

The tests run on Windows x86/x64, Linux x86/x64, ARM and ARM64 (under qemu) and macOS x64.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

| Option                       | Default | Description                                              |
|------------------------------|---------|----------------------------------------------------------|
| `BUILD_SHARED_LIBS`          | `OFF`   | Build a shared library instead of a static one.          |
| `MINIDETOUR_DYNAMIC_RUNTIME` | `ON`    | Windows: link with the DLL C runtime (`/MD`).            |
| `MINIDETOUR_BUILD_TESTS`     | `OFF`   | Build the `tests` executable and its test libraries.     |

The library needs C++11. It can be used from another CMake project with `add_subdirectory`, or installed and found with
`find_package`:

```cmake
find_package(MiniDetour 1.1 REQUIRED)
target_link_libraries(my_target PRIVATE Nemirtingas::MiniDetour)
```

## Usage

### Hooking a function

```cpp
#include <mini_detour/mini_detour.h>

static MiniDetour::Hook_t addHook;

static int MyAdd(int a, int b)
{
    // Call the original function through its trampoline.
    return addHook.GetOriginalFunction<decltype(&MyAdd)>()(a, b) * 10;
}

void Install()
{
    if (addHook.HookFunction(reinterpret_cast<void*>(&add), reinterpret_cast<void*>(&MyAdd)) == nullptr)
    {
        // The function can't be hooked (too short, or starts with instructions that can't be relocated).
    }
}

void Uninstall()
{
    addHook.RestoreFunction();
}
```

- `HookFunction` returns the address to call the original function, or `nullptr` when the hook can't be set. The library
  refuses to hook rather than generate wrong code: a function too short for a jump, or starting with instructions it
  can't relocate, is not hooked. `CanHook` tells it without hooking.
- A `Hook_t` restores its hook when destroyed, unless `RestoreOnDestroy(false)` was called. It can't be copied, only moved.
- `Hook_t::ReplaceFunction(function, newFunction)` overwrites the start of a function with a jump, without trampoline:
  the original function can't be called anymore.

### Replacing a module export

```cpp
MiniDetour::ModuleManipulation::ExportReplaceParameter_t parameter{ "add", reinterpret_cast<void*>(&MyAdd), nullptr };

void* module = dlopen("./library.so", RTLD_NOW); // LoadLibraryA on Windows
if (MiniDetour::ModuleManipulation::ReplaceModuleExports(module, &parameter, 1) == 1)
{
    // dlsym(module, "add") now returns MyAdd, parameter.ExportCallAddress is the original add.
    MiniDetour::ModuleManipulation::RestoreModuleExports(module, &parameter, 1);
}
```

`ReplaceModuleIATs` / `RestoreModuleIATs` do the same with the import table (IAT on Windows, GOT on Linux) of a module,
and `GetAllExportedSymbols` / `GetAllIATSymbols` list them: pass `nullptr` to get the count first.

### C API

Every C++ function is an inline wrapper over a C function, declared in the same header:

```c
minidetour_hook_handle_t hook = MiniDetourHookTAlloc();
void* original = MiniDetourHookTHookFunction(hook, (void*)&add, (void*)&MyAdd);
/* ... */
MiniDetourHookTRestoreFunction(hook);
MiniDetourHookTFree(hook);
```

The C structures with a variable size (`MiniDetourMemoryManipulationRegionInfos_t`) start with a `StructSize` field to
set before calling: the module name is written in the room left after the structure.

## Logs

Define `USE_SPDLOG` when building the library to get its logs through the vendored spdlog (the test build does).

## Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMINIDETOUR_BUILD_TESTS=ON
cmake --build build
cd build && ./tests            # build/Debug/tests.exe with Visual Studio
```

The tests need `export_hook_test_library` in the working directory. On macOS, run `./macos_permission_fix tests` first.

## macOS

A segment can't be given more rights than its `maxprot`, and executables are linked with a read-execute `maxprot` for
`__TEXT`: their functions can't be made writable. `macos_permission_fix <executable>` rewrites the `__TEXT` `maxprot` of
an executable to read-write-execute (the tests use it on `tests`).

Recent kernels may also lock the memory of a process and refuse to add execute rights (`map_disallow_new_exec`):

- Page lockdown: [vm_user.c](https://github.com/apple/darwin-xnu/blob/main/osfmk/vm/vm_user.c#L3287-L3300)
- Protection change refused: [vm_map.c](https://github.com/apple/darwin-xnu/blob/main/osfmk/vm/vm_map.c#L5961-L5967)

Export and import replacement are not implemented on macOS yet.

## License

See [LICENSE](LICENSE).
