#ifndef MINI_DETOUR_LINUX_H
#define MINI_DETOUR_LINUX_H

#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    using ElfHeader_t = Elf64_Ehdr;
    using ElfSectionHeader_t = Elf64_Shdr;
    using ElfProgramHeader_t = Elf64_Phdr;
    using ElfSymbol_t = Elf64_Sym;
    using ElfAddr_t = Elf64_Addr;
    using ElfRel_t = Elf64_Rel;
    using ElfRela_t = Elf64_Rela;
    using ElfDyn_t = Elf64_Dyn;
    using ElfSxword_t = Elf64_Sxword;
    using ElfRelocation_t = ElfRela_t;

    #define ELF_ST_BIND       ELF64_ST_BIND
    #define ELF_ST_TYPE       ELF64_ST_TYPE
    #define ELF_R_SYM         ELF64_R_SYM
    #define ELF_R_TYPE        ELF64_R_TYPE
    #define ELF_R_INFO        ELF64_R_INFO
    #define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY

    #if defined(MINIDETOUR_ARCH_X64)
        #define R_JUMP_SLOT   R_X86_64_JUMP_SLOT
        #define R_GLOBAL_DATA R_X86_64_GLOB_DAT
    #elif defined(MINIDETOUR_ARCH_ARM64)
        #define R_JUMP_SLOT   R_AARCH64_JUMP_SLOT
        #define R_GLOBAL_DATA R_AARCH64_GLOB_DAT
    #endif

#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    using ElfHeader_t = Elf32_Ehdr;
    using ElfSectionHeader_t = Elf32_Shdr;
    using ElfProgramHeader_t = Elf32_Phdr;
    using ElfSymbol_t = Elf32_Sym;
    using ElfAddr_t = Elf32_Addr;
    using ElfRel_t = Elf32_Rel;
    using ElfRela_t = Elf32_Rela;
    using ElfDyn_t = Elf32_Dyn;
    using ElfSxword_t = Elf32_Sxword;
    using ElfRelocation_t = ElfRel_t;

    #define ELF_ST_BIND       ELF32_ST_BIND
    #define ELF_ST_TYPE       ELF32_ST_TYPE
    #define ELF_R_SYM         ELF32_R_SYM
    #define ELF_R_TYPE        ELF32_R_TYPE
    #define ELF_R_INFO        ELF32_R_INFO
    #define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY

    #if defined(MINIDETOUR_ARCH_X86)
        #define R_JUMP_SLOT   R_386_JMP_SLOT
        #define R_GLOBAL_DATA R_386_GLOB_DAT
    #elif defined(MINIDETOUR_ARCH_ARM)
        #define R_JUMP_SLOT   R_ARM_JUMP_SLOT
        #define R_GLOBAL_DATA R_ARM_GLOB_DAT
    #endif
#endif

struct GnuHashHeader_t
{
  uint32_t nbuckets;
  uint32_t symndx;    /* Index of the first accessible symbol in .dynsym */
  uint32_t maskwords; /* Nyumber of elements in the Bloom Filter */
  uint32_t shift2;    /* Shift count for the Bloom Filter */
  size_t bloom_filter[/*maskwords*/];
  //uint32_t buckets[nbuckets];
  //uint32_t values[dynsymcount - symndx];
};

namespace MiniDetour {
namespace MemoryManipulation {
namespace Implementation {
#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffefffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffff000);
#endif

    int _MemoryProtectRightsToNative(MemoryRights rights)
    {
        switch (rights)
        {
            case MemoryRights::mem_r  : return PROT_READ;
            case MemoryRights::mem_w  : return PROT_WRITE;
            case MemoryRights::mem_x  : return PROT_EXEC;
            case MemoryRights::mem_rw : return PROT_WRITE | PROT_READ;
            case MemoryRights::mem_rx : return PROT_READ  | PROT_EXEC;
            case MemoryRights::mem_wx : return PROT_WRITE | PROT_EXEC;
            case MemoryRights::mem_rwx: return PROT_WRITE | PROT_READ | PROT_EXEC;

            default: return PROT_NONE;
        }
    }

    bool _GetRegionInfo(uintptr_t target, const char* mapLine, size_t mapLineLength, MiniDetourMemoryManipulationRegionInfos_t& region)
    {
        // remove const because of strtoul
        auto* mapLineStart = (char*)mapLine;
        auto* mapLineEnd = mapLineStart + mapLineLength;

        auto start = (uintptr_t)strtoul(mapLineStart, &mapLineStart, 16);
        auto end = (uintptr_t)strtoul(mapLineStart + 1, &mapLineStart, 16);
        
        if (start == 0 || end == 0 || (target != 0 && (target < start || end <= target)))
            return false;

        region.Rights = MemoryRights::mem_none;
        region.Start = start;
        region.End = end;

        ++mapLineStart;
        if (mapLineStart[0] == 'r')
            (int&)region.Rights |= (int)MemoryRights::mem_r;

        if (mapLineStart[1] == 'w')
            (int&)region.Rights |= (int)MemoryRights::mem_w;

        if (mapLineStart[2] == 'x')
            (int&)region.Rights |= (int)MemoryRights::mem_x;

        //  Skip 4 fields from here \/, TODO find latest field instead
        // 7d3b3fa1d000-7d3b3fa1e000 r--p 00000000 fc:01 38300752                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        for (int i = 0; i < 4; ++i)
        {
            while (*mapLineStart != ' ' && mapLineStart < mapLineEnd)
            {
                ++mapLineStart;
            }
            while (*mapLineStart == ' ' && mapLineStart < mapLineEnd)
            {
                ++mapLineStart;
            }
        }

        strncpy(region.ModuleName, mapLineStart, region.StructSize - (sizeof(region) - sizeof(region.ModuleName)));
        region.ModuleName[region.StructSize - (sizeof(region) - sizeof(region.ModuleName)) - 1] = '\0';
        return true;
    }

    size_t _GetRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount, bool onlyFree)
    {
        uintptr_t start;
        uintptr_t oldEnd(0);
        size_t writtenRegionCount = 0;
        size_t currentRegionCount = 0;

        std::ifstream f("/proc/self/maps");
        std::string s;

        while (std::getline(f, s))
        {
            if (!s.empty())
            {
                auto* mapLine = (char*)s.data();
                auto start = (uintptr_t)strtoul(mapLine, &mapLine, 16);
                auto end = (uintptr_t)strtoul(mapLine + 1, &mapLine, 16);

                if (start != 0 && end != 0)
                {
                    if (oldEnd != start)
                    {
                        if (regions != nullptr && writtenRegionCount < regionCount)
                        {
                            auto& region = *regions;
                            if (region.StructSize >= sizeof(region))
                            {
                                regions = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t*>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);

                                region.Rights = MemoryRights::mem_unset;
                                region.Start = oldEnd;
                                region.End = start;
                                region.ModuleName[0] = '\0';
                                ++writtenRegionCount;
                            }
                        }
                        ++currentRegionCount;
                    }

                    if (!onlyFree)
                    {
                        if (regions != nullptr && writtenRegionCount < regionCount)
                        {
                            auto& region = *regions;
                            if (region.StructSize >= sizeof(region))
                            {
                                if (_GetRegionInfo(0, s.data(), s.length(), region))
                                {
                                    regions = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t*>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);
                                    ++writtenRegionCount;
                                }
                            }
                        }

                        ++currentRegionCount;
                    }

                    oldEnd = end;
                }
            }
        }

        return currentRegionCount;
    }

    size_t PageSize()
    {
        return sysconf(_SC_PAGESIZE);
    }

    void GetRegionInfos(void* address, MiniDetourMemoryManipulationRegionInfos_t* regionInfos)
    {
        std::ifstream f("/proc/self/maps");
        std::string s;

        regionInfos->Rights = MemoryRights::mem_unset;
        regionInfos->Start = 0;
        regionInfos->End = 0;
        regionInfos->ModuleName[0] = '\0';

        while (std::getline(f, s))
        {
            if (!s.empty() && _GetRegionInfo((uintptr_t)address, s.data(), s.length(), *regionInfos))
                return;
        }
    }

    inline size_t GetAllRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
    {
        return _GetRegions(regions, regionCount, false);
    }

    inline size_t GetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
    {
        return _GetRegions(regions, regionCount, true);
    }

    bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* oldRights)
    {
        if (oldRights != nullptr)
        {
            MiniDetour::MemoryManipulation::RegionInfos_t infos;
            MemoryManipulation::GetRegionInfos(address, &infos);
            *oldRights = infos.Rights;
        }

        bool res = mprotect(PageRound(address, PageSize()), _PageAddrSize(address, size, PageSize()), _MemoryProtectRightsToNative(rights)) == 0;
        return res;
    }

    void MemoryFree(void* address, size_t size)
    {
        if (address != nullptr)
            munmap(address, size);
    }

    static inline bool MemoryAllocWithProtection(void** address, size_t size, MemoryRights rights, int flags)
    {
        *address = mmap(*address, size, _MemoryProtectRightsToNative(rights), flags, -1, 0);
        return *address != nullptr;
    }

    static inline void* MemoryAllocNear(uintptr_t addressHint, size_t size, MemoryRights rights, size_t pageSize)
    {
        void* address;

        auto freeRegionCount = GetFreeRegions(nullptr, 0);
        std::vector<RegionInfos_t> freeRegions((size_t)(freeRegionCount * 1.5));
        freeRegionCount = GetFreeRegions(freeRegions.data(), freeRegions.size());
        if (freeRegionCount < freeRegions.size())
            freeRegions.resize(freeRegionCount);

        std::sort(freeRegions.begin(), freeRegions.end(), [addressHint](MemoryManipulation::RegionInfos_t const& l, MemoryManipulation::RegionInfos_t const& r)
        {
            return std::max(addressHint, l.Start) - std::min(addressHint, l.Start) <
                std::max(addressHint, r.Start) - std::min(addressHint, r.Start);
        });

        for (auto const& region : freeRegions)
        {
            auto start = region.Start > addressHint ? region.Start : (region.End - pageSize);
            auto increment = static_cast<int32_t>(region.Start > addressHint ? pageSize : -pageSize);

            for (auto allocAddress = start; allocAddress >= region.Start && (allocAddress + size) <= region.End; allocAddress += increment)
            {
                if (allocAddress > (uintptr_t)max_user_address)
                    break;

                address = (void*)allocAddress;
                MemoryAllocWithProtection(&address, size, rights, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS);
                if (address != nullptr)
                    return address;
            }
        }

        // Fallback to anywhere alloc
        address = nullptr;
        MemoryAllocWithProtection(&address, size, rights, MAP_PRIVATE | MAP_ANONYMOUS);

        return address;
    }

    void* MemoryAlloc(void* _addressHint, size_t size, MemoryRights rights)
    {
        if (_addressHint > max_user_address)
            _addressHint = (void*)max_user_address;

        auto pageSize = PageSize();
        auto addressHint = reinterpret_cast<uintptr_t>(PageRound(_addressHint, pageSize));
        size = _PageAddrSize((void*)addressHint, size, pageSize);

        if (_addressHint == nullptr)
        {
            void* address = nullptr;
            MemoryAllocWithProtection(&address, size, rights, MAP_PRIVATE | MAP_ANONYMOUS);
            return address;
        }

        return MemoryAllocNear(addressHint, size, rights, pageSize);
    }

    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size)
    {
        struct iovec local;
        struct iovec remote;

        local.iov_base = buffer;
        local.iov_len = size;
        remote.iov_base = (void*)address;
        remote.iov_len = size;

        if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0) != size)
            return false;

        return true;
    }

    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
    {
        struct iovec local;
        struct iovec remote;

        local.iov_base = (void*)buffer;
        local.iov_len = size;
        remote.iov_base = (void*)address;
        remote.iov_len = size;

        if (process_vm_writev(getpid(), &local, 1, &remote, 1, 0) != size)
            return false;

        return true;
    }

    int FlushInstructionCache(void* address, size_t size)
    {
        return 1;
    }
}//namespace Implementation
}//namespace MemoryManipulation

namespace ModuleManipulation {
namespace Implementation {
    static ElfDyn_t* _FindElfDynFromTag(ElfDyn_t* dynamicSegment, ElfSxword_t tag)
    {
        for (; dynamicSegment->d_tag != DT_NULL; ++dynamicSegment)
        {
            if (dynamicSegment->d_tag == tag)
                return dynamicSegment;
        }

        return nullptr;
    }

    static bool _LoadModuleExportSymbolsCount(ElfDyn_t* dynamicTableStart, ElfSymbol_t** dynamicSymbolsStart, ElfSymbol_t** dynamicSymbolsEnd, size_t* dynamicSymbolsSize)
    {
        auto dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_SYMTAB);
        if (dynamicEntry == nullptr)
            return false;

        *dynamicSymbolsStart = (ElfSymbol_t*)dynamicEntry->d_un.d_ptr;

        dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_HASH);
        if (dynamicEntry == nullptr)
        {
            dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_GNU_HASH);
            if (dynamicEntry == nullptr)
                return false;

            GnuHashHeader_t* hash_table = (GnuHashHeader_t*)dynamicEntry->d_un.d_ptr;
            uint32_t* buckets = (uint32_t*)(hash_table->bloom_filter + hash_table->maskwords);
            uint32_t* chains  = (uint32_t*)(buckets + hash_table->nbuckets);

            uint32_t max_sym = 0;
            for (uint32_t i = 0; i < hash_table->nbuckets; ++i)
            {
                if (buckets[i] > max_sym)
                    max_sym = buckets[i];
            }

            while (!(chains[max_sym - hash_table->symndx] & 1))
                ++max_sym;

            *dynamicSymbolsEnd = *dynamicSymbolsStart + max_sym + 1;
        }
        else
        {
            uint32_t* hash_table = (uint32_t*)dynamicEntry->d_un.d_ptr;
            *dynamicSymbolsEnd = *dynamicSymbolsStart + hash_table[1];
        }

        dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_SYMENT);
        if (dynamicEntry == nullptr)
            return false;

        *dynamicSymbolsSize = dynamicEntry->d_un.d_val;
        return true;
    }

    static bool _LoadModuleDynamicTable(void* moduleHandle, void** moduleBase, ElfDyn_t** dynamicTable)
    {
        ElfHeader_t* elfHeader = *(ElfHeader_t**)moduleHandle;

        if (elfHeader->e_ident[EI_MAG0] != ELFMAG0 ||
            elfHeader->e_ident[EI_MAG1] != ELFMAG1 ||
            elfHeader->e_ident[EI_MAG2] != ELFMAG2 ||
            elfHeader->e_ident[EI_MAG3] != ELFMAG3)
        {
            return false;
        }

        ElfProgramHeader_t* programHeadersStart = (ElfProgramHeader_t*)((uintptr_t)elfHeader + elfHeader->e_phoff);
        ElfProgramHeader_t* programHeadersEnd = (ElfProgramHeader_t*)((uintptr_t)programHeadersStart + elfHeader->e_phentsize * elfHeader->e_phnum);

        for (ElfProgramHeader_t* programHeader = programHeadersStart; programHeader < programHeadersEnd; programHeader = (ElfProgramHeader_t*)((uintptr_t)programHeader + elfHeader->e_phentsize))
        {
            if (programHeader->p_type == PT_DYNAMIC)
            {
                *moduleBase = (void*)elfHeader;
                *dynamicTable = (ElfDyn_t*)((uintptr_t)elfHeader + programHeader->p_vaddr);
                return true;
            }
        }

        return false;
    }

    static bool _LoadModuleCommonDetails(ElfDyn_t* dynamicTableStart, const char** dynamicSymbolsNames, size_t* dynamicSymbolsNamesSize)
    {
        *dynamicSymbolsNames = nullptr;
        *dynamicSymbolsNamesSize = 0;

        auto dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_STRTAB);
        if (dynamicEntry == nullptr)
            return false;

        *dynamicSymbolsNames = (const char*)dynamicEntry->d_un.d_ptr;

        dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_STRSZ);
        if (dynamicEntry == nullptr)
            return false;

        *dynamicSymbolsNamesSize = dynamicEntry->d_un.d_val;

        return *dynamicSymbolsNames != nullptr && dynamicSymbolsNamesSize != 0;
    }

    static bool _LoadModuleExportDetails(void* moduleHandle, void** moduleBase, ElfSymbol_t** dynamicSymbolsStart, ElfSymbol_t** dynamicSymbolsEnd, size_t* dynamicSymbolsSize, const char** dynamicSymbolsNames, size_t* dynamicSymbolsNamesSize)
    {
        ElfDyn_t* dynamicTableStart;

        if (!_LoadModuleDynamicTable(moduleHandle, moduleBase, &dynamicTableStart))
            return false;

        if (!_LoadModuleCommonDetails(dynamicTableStart, dynamicSymbolsNames, dynamicSymbolsNamesSize))
            return false;

        if (!_LoadModuleExportSymbolsCount(dynamicTableStart, dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolsSize))
            return false;

        return true;
    }

    static bool _ReplaceModuleExportInPlace(void* moduleBase, ElfAddr_t* exportAddress, void** exportCallAddress, void* newExportAddress)
    {
        MemoryManipulation::MemoryRights oldRights;

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
            goto Error;

        *exportCallAddress = (void*)((char*)moduleBase + *exportAddress);
        *exportAddress = (uintptr_t)newExportAddress - (uintptr_t)moduleBase;

        MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

        return true;

    Error:
        *exportCallAddress = nullptr;
        return false;
    }

    static bool _ReplaceModuleExportWithTrampoline(void* moduleBase, ElfAddr_t* exportAddress, void** exportCallAddress, void* newExportAddress)
    {
        MemoryManipulation::MemoryRights oldRights;

        auto exportJump = mm.GetFreeJump(moduleBase);
        if (exportJump == nullptr)
            goto Error;

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
            goto ErrorFree;

        if (!MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx, nullptr))
            goto ErrorFree;

        MemoryManipulation::WriteAbsoluteJump(exportJump, newExportAddress);

        if (exportCallAddress != nullptr)
            *exportCallAddress = (void*)((char*)moduleBase + *exportAddress);

        *exportAddress = (uintptr_t)exportJump - (uintptr_t)moduleBase;

        MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rx, nullptr);
        MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

        return true;

    ErrorFree:
        mm.FreeJump(exportJump);
    Error:
        *exportCallAddress = nullptr;
        return false;
    }

    static inline ElfAddr_t* _GetExportAddress(ElfSymbol_t* dynamicSymbolsStart, ElfSymbol_t* dynamicSymbolsEnd, size_t dynamicSymbolsSize, const char* dynamicSymbolsNames, size_t dynamicSymbolsNamesSize, const char* symbolName)
    {
        for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
        {
            auto symbolBind = ELF_ST_BIND(symbol->st_info);
            auto symbolType = ELF_ST_TYPE(symbol->st_info);

            if ((symbol->st_name + 1) > dynamicSymbolsNamesSize)
                continue;

            if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT) || strcmp(dynamicSymbolsNames + symbol->st_name, symbolName) != 0)
                continue;

            return &symbol->st_value;
        }

        return nullptr;
    }

    static bool _LoadModuleIATDetails(void* moduleHandle, void** moduleBase, ElfRelocation_t** relSectionStart, ElfRelocation_t** relSectionEnd, ElfSymbol_t** dynamicSymbolsStart, ElfSymbol_t** dynamicSymbolsEnd, size_t* dynamicSymbolSize, const char** dynamicSymbolsNames, size_t* dynamicSymbolsNamesSize)
    {
        ElfDyn_t* dynamicTableStart;

        if (!_LoadModuleDynamicTable(moduleHandle, moduleBase, &dynamicTableStart))
            return false;

        if (!_LoadModuleCommonDetails(dynamicTableStart, dynamicSymbolsNames, dynamicSymbolsNamesSize))
            return false;

        if (!_LoadModuleExportSymbolsCount(dynamicTableStart, dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolSize))
            return false;

        auto dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_JMPREL);
        if (dynamicEntry == nullptr)
            return false;

        *relSectionStart = (ElfRelocation_t*)dynamicEntry->d_un.d_ptr;

        dynamicEntry = _FindElfDynFromTag(dynamicTableStart, DT_PLTRELSZ);
        if (dynamicEntry == nullptr)
            return false;

        *relSectionEnd = (ElfRelocation_t*)((uintptr_t)*relSectionStart + dynamicEntry->d_un.d_val);

        return true;
    }

    static inline void** _GetIATAddress(void* moduleBase, ElfRelocation_t* iatSymbolsStart, ElfRelocation_t* iatSymbolsEnd, ElfSymbol_t* dynamicSymbolsStart, size_t dynamicSymbolSize, const char* dynamicSymbolsNames, size_t dynamicSymbolsNamesSize, const char* symbolName)
    {
        for (auto relocation = iatSymbolsStart; relocation < iatSymbolsEnd; ++relocation)
        {
            size_t symbolType = ELF_R_TYPE(relocation->r_info);
            size_t dynamicSymbolIndex = ELF_R_SYM(relocation->r_info);
            size_t dynamicSymbolNameIndex = ((ElfSymbol_t*)((uintptr_t)dynamicSymbolsStart + dynamicSymbolIndex * dynamicSymbolSize))->st_name;

            if (symbolType != R_JUMP_SLOT)
            {
                SPDLOG_INFO("Symbol is not a jump slot");
                continue;
            }

            if (dynamicSymbolNameIndex + 1 > dynamicSymbolsNamesSize)
            {
                SPDLOG_WARN("Symbol name index exceeds symbols string table.");
                continue;
            }

            if (strcmp(symbolName, dynamicSymbolsNames + dynamicSymbolNameIndex) == 0)
                return (void**)((uintptr_t)moduleBase + relocation->r_offset);
        }

        return nullptr;
    }

    size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount)
    {
        void* moduleBase = nullptr;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolsSize = 0;
        const char* dynamicSymbolsNames = nullptr;
        size_t dynamicSymbolsNamesSize = 0;
        size_t result = 0;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames, &dynamicSymbolsNamesSize))
            return result;

        if (exportDetails == nullptr)
        {
            for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
            {
                auto symbolBind = ELF_ST_BIND(symbol->st_info);
                auto symbolType = ELF_ST_TYPE(symbol->st_info);
                //auto symbolVisiblity = ELF_ST_VISIBILITY(symbol->st_other);

                if ((symbol->st_name + 1) > dynamicSymbolsNamesSize)
                    continue;

                if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT) || symbol->st_value == 0)
                    continue;

                ++result;
            }

            return result;
        }

        for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd && result < exportDetailsCount; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
        {
            auto symbolBind = ELF_ST_BIND(symbol->st_info);
            auto symbolType = ELF_ST_TYPE(symbol->st_info);
            //auto symbolVisiblity = ELF_ST_VISIBILITY(symbol->st_other);

            if ((symbol->st_name + 1) > dynamicSymbolsNamesSize)
                continue;

            if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT) || symbol->st_value == 0)
                continue;

            exportDetails[result].ExportName = dynamicSymbolsNames + symbol->st_name;
            exportDetails[result].ExportCallAddress = (void*)((uintptr_t)moduleBase + symbol->st_value);
            exportDetails[result++].ExportOrdinal = symbol - dynamicSymbolsStart;
        }

        return result;
    }

    size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* iatDetails, size_t iatDetailsCount)
    {
        void* moduleBase = nullptr;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolSize = 0;
        const char* dynStr;
        size_t dynStrSize;
        ElfRelocation_t* relocationsStart;
        ElfRelocation_t* relocationsEnd;
        size_t result = 0;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &relocationsStart, &relocationsEnd, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolSize, &dynStr, &dynStrSize))
            return result;

        if (iatDetails == nullptr)
        {
            for (auto relocation = relocationsStart; relocation < relocationsEnd; ++relocation)
            {
                size_t symbolType = ELF_R_TYPE(relocation->r_info);
                size_t dynamicSymbolIndex = ELF_R_SYM(relocation->r_info);
                size_t dynamicSymbolNameIndex = dynamicSymbolsStart[dynamicSymbolIndex].st_name;

                if (symbolType != R_JUMP_SLOT)
                {
                    SPDLOG_INFO("Symbol is not a jump slot");
                    continue;
                }

                if (dynamicSymbolNameIndex + 1 > dynStrSize)
                {
                    SPDLOG_WARN("Symbol name index exceeds symbols string table.");
                    continue;
                }

                ++result;
            }

            return result;
        }

        for (auto relocation = relocationsStart; relocation < relocationsEnd; ++relocation)
        {
            size_t symbolType = ELF_R_TYPE(relocation->r_info);
            size_t dynamicSymbolIndex = ELF_R_SYM(relocation->r_info);
            size_t dynamicSymbolNameIndex = dynamicSymbolsStart[dynamicSymbolIndex].st_name;

            if (symbolType != R_JUMP_SLOT)
            {
                SPDLOG_INFO("Symbol is not a jump slot");
                continue;
            }

            if (dynamicSymbolNameIndex + 1 > dynStrSize)
            {
                SPDLOG_WARN("Symbol name index exceeds symbols string table.");
                continue;
            }

            iatDetails[result].ImportOrdinal = relocation - relocationsStart;
            iatDetails[result].ImportName = dynStr + dynamicSymbolNameIndex;
            iatDetails[result].ImportCallAddress = *reinterpret_cast<void**>(reinterpret_cast<char*>(moduleBase) + relocation->r_offset);
            iatDetails[result++].ImportModuleName = "";
        }

        return result;
    }

    size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        int64_t relocationOffset = 0;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolsSize = 0;
        const char* dynamicSymbolsNames = nullptr;
        size_t dynamicSymbolsNamesSize = 0;
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].ExportCallAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames, &dynamicSymbolsNamesSize))
            return result;

        SPDLOG_INFO("Program base address: {:016X}, Dynamic symbol start: {:016X}, Dynamic symbol stop: {:016X}", (uintptr_t)moduleBase, (uintptr_t)dynamicSymbolsStart, (uintptr_t)dynamicSymbolsEnd);

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            auto exportAddress = _GetExportAddress(dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolsSize, dynamicSymbolsNames, dynamicSymbolsNamesSize, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
            {
                exportReplaceDetails[i].ExportCallAddress = nullptr;
                continue;
            }

            if (_AddressesAreRelativeJumpable(moduleBase, exportReplaceDetails[i].NewExportAddress))
            {
                if (_ReplaceModuleExportInPlace(moduleBase, exportAddress, &exportReplaceDetails[i].ExportCallAddress, exportReplaceDetails[i].NewExportAddress))
                    ++result;
            }
            else
            {
                if (_ReplaceModuleExportWithTrampoline(moduleBase, exportAddress, &exportReplaceDetails[i].ExportCallAddress, exportReplaceDetails[i].NewExportAddress))
                    ++result;
            }
        }

        return result;
    }

    size_t RestoreModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        int64_t relocationOffset = 0;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolsSize = 0;
        const char* dynamicSymbolsNames = nullptr;
        size_t dynamicSymbolsNamesSize = 0;
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].NewExportAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames, &dynamicSymbolsNamesSize))
            return result;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            auto exportAddress = _GetExportAddress(dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolsSize, dynamicSymbolsNames, dynamicSymbolsNamesSize, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
            {
                exportReplaceDetails[i].NewExportAddress = nullptr;
                continue;
            }

            MemoryManipulation::MemoryRights oldRights;

            if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
                continue;

            exportReplaceDetails[i].NewExportAddress = (void*)((uintptr_t)*exportAddress + (uintptr_t)moduleBase);
            auto oldJumpAddress = (void*)((uintptr_t)moduleBase + *exportAddress);
            *exportAddress = (uintptr_t)exportReplaceDetails[i].ExportCallAddress - (uintptr_t)moduleBase;

            MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

            mm.FreeJump(oldJumpAddress);

            ++result;
        }

        return result;
    }

    size_t ReplaceModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        ElfSymbol_t* dynamicSymbolsStart;
        ElfSymbol_t* dynamicSymbolsEnd;
        size_t dynamicSymbolSize;
        const char* dynStr;
        size_t dynStrSize;
        ElfRelocation_t* iatStart;
        ElfRelocation_t* iatEnd;
        size_t result = 0;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].IATCallAddress = nullptr;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &iatStart, &iatEnd, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolSize, &dynStr, &dynStrSize))
            return result;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        {
            auto iatAddress = _GetIATAddress(moduleBase, iatStart, iatEnd, dynamicSymbolsStart, dynamicSymbolSize, dynStr, dynStrSize, iatReplaceDetails[i].IATName);
            if (iatAddress == nullptr)
            {
                iatReplaceDetails[i].IATCallAddress = nullptr;
                continue;
            }

            MiniDetour::MemoryManipulation::MemoryRights oldRights;
            if (!MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &oldRights))
            {
                iatReplaceDetails[i].IATCallAddress = nullptr;
                continue;
            }

            iatReplaceDetails[i].IATCallAddress = *iatAddress;
            *iatAddress = iatReplaceDetails[i].NewIATAddress;
            MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), oldRights, nullptr);
            ++result;
        }

        return result;
    }

    size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        ElfSymbol_t* dynamicSymbolsStart;
        ElfSymbol_t* dynamicSymbolsEnd;
        size_t dynamicSymbolSize;
        const char* dynStr;
        size_t dynStrSize;
        ElfRelocation_t* iatStart;
        ElfRelocation_t* iatEnd;
        size_t iatEntrySize;
        size_t result = 0;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].NewIATAddress = nullptr;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &iatStart, &iatEnd, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolSize, &dynStr, &dynStrSize))
            return result;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        {
            auto iatAddress = _GetIATAddress(moduleBase, iatStart, iatEnd, dynamicSymbolsStart, dynamicSymbolSize, dynStr, dynStrSize, iatReplaceDetails[i].IATName);
            if (iatAddress == nullptr)
            {
                iatReplaceDetails[i].NewIATAddress = nullptr;
                continue;
            }

            MiniDetour::MemoryManipulation::MemoryRights oldRights;
            if (!MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &oldRights))
            {
                iatReplaceDetails[i].NewIATAddress = nullptr;
                continue;
            }

            iatReplaceDetails[i].NewIATAddress = *iatAddress;
            *iatAddress = iatReplaceDetails[i].IATCallAddress;
            MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), oldRights, nullptr);
            ++result;
        }

        return result;
    }

}//namespace Implementation
}//namespace ModuleManipulation
}//namespace MiniDetour

#endif//MINI_DETOUR_LINUX_H