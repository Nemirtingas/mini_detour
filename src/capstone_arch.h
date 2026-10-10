#ifndef MINI_DETOUR_CAPSTONE_ARCH_H
#define MINI_DETOUR_CAPSTONE_ARCH_H

// Included before every Capstone source: only the disassembler of the architecture being compiled is built. It is
// decided by the preprocessor, like the rest of the library, so it also works when one build compiles several
// architectures (macOS universal binaries) or cross compiles.
#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
#define CAPSTONE_HAS_X86
// Only the Intel syntax is used.
#define CAPSTONE_X86_ATT_DISABLE
#elif defined(MINIDETOUR_ARCH_ARM)
#define CAPSTONE_HAS_ARM
#elif defined(MINIDETOUR_ARCH_ARM64)
#define CAPSTONE_HAS_ARM64
#endif

#endif // MINI_DETOUR_CAPSTONE_ARCH_H
