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

#define ELF_ST_BIND(val) ELF64_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
using ElfHeader_t = Elf32_Ehdr;
using ElfSectionHeader_t = Elf32_Shdr;
using ElfProgramHeader_t = Elf32_Phdr;
using ElfSymbol_t = Elf32_Sym;
using ElfAddr_t = Elf32_Addr;

#define ELF_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#endif

namespace MiniDetour {
namespace MemoryManipulation {
#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffefffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffff000);
#endif

    int _MemoryProtectRightsToNative(MemoryRights rights)
    {
        switch (rights)
        {
            case mem_r  : return PROT_READ;
            case mem_w  : return PROT_WRITE;
            case mem_x  : return PROT_EXEC;
            case mem_rw : return PROT_WRITE | PROT_READ;
            case mem_rx : return PROT_READ  | PROT_EXEC;
            case mem_wx : return PROT_WRITE | PROT_EXEC;
            case mem_rwx: return PROT_WRITE | PROT_READ | PROT_EXEC;

            default: return PROT_NONE;
        }
    }

    size_t PageSize()
    {
        return sysconf(_SC_PAGESIZE);
    }

    RegionInfos_t GetRegionInfos(void* address)
    {
        RegionInfos_t res{};

        char* str_it;
        const char* str_end;

        uintptr_t target = (uintptr_t)address;
        uintptr_t start;
        uintptr_t end;
        std::ifstream f("/proc/self/maps");
        std::string s;
        unsigned int rights = mem_unset;

        while (std::getline(f, s))
        {
            if (!s.empty())
            {
                str_it = &s[0];
                str_end = s.data() + s.length();

                start = (uintptr_t)strtoul(str_it, &str_it, 16);
                end = (uintptr_t)strtoul(str_it + 1, &str_it, 16);
                if (start != 0 && end != 0 && start <= target && target < end) {
                    res.start = start;
                    res.end = end;

                    rights = mem_none;

                    ++str_it;
                    if (str_it[0] == 'r')
                        rights |= mem_r;

                    if (str_it[1] == 'w')
                        rights |= mem_w;

                    if (str_it[2] == 'x')
                        rights |= mem_x;

                    for (int i = 0; i < 4; ++i)
                    {
                        while (*str_it != ' ' && str_it < str_end)
                        {
                            ++str_it;
                        }
                        while (*str_it == ' ' && str_it < str_end)
                        {
                            ++str_it;
                        }
                    }

                    res.module_name = str_it;

                    break;
                }
            }
        }

        res.rights = (MemoryRights)rights;
        return res;
    }

    std::vector<RegionInfos_t> GetAllRegions()
    {
        std::vector<RegionInfos_t> mappings;

        char* str_it;
        const char* str_end;
        uintptr_t start;
        uintptr_t end;
        uintptr_t old_end(0);
        unsigned int rights;

        std::ifstream f("/proc/self/maps");
        std::string s;

        while (std::getline(f, s))
        {
            if (!s.empty())
            {
                str_it = &s[0];
                str_end = s.data() + s.length();
                start = (uintptr_t)strtoul(str_it, &str_it, 16);
                end = (uintptr_t)strtoul(str_it + 1, &str_it, 16);
                if (start != 0 && end != 0)
                {
                    if (old_end != start)
                    {
                        mappings.emplace_back(
                            MemoryRights::mem_unset,
                            old_end,
                            start,
                            std::string()
                        );
                    }

                    old_end = end;

                    rights = MemoryRights::mem_none;

                    ++str_it;
                    if (str_it[0] == 'r')
                        rights |= mem_r;

                    if (str_it[1] == 'w')
                        rights |= mem_w;

                    if (str_it[2] == 'x')
                        rights |= mem_x;

                    for (int i = 0; i < 4; ++i)
                    {
                        while (*str_it != ' ' && str_it < str_end)
                        {
                            ++str_it;
                        }
                        while (*str_it == ' ' && str_it < str_end)
                        {
                            ++str_it;
                        }
                    }

                    mappings.emplace_back(
                        (MemoryRights)rights,
                        start,
                        end,
                        str_it
                    );
                }
            }
        }

        return mappings;
    }

    std::vector<RegionInfos_t> GetFreeRegions()
    {
        std::vector<RegionInfos_t> mappings;

        char* str_it;
        const char* str_end;
        uintptr_t start;
        uintptr_t end;
        uintptr_t old_end(0);

        std::ifstream f("/proc/self/maps");
        std::string s;

        while (std::getline(f, s))
        {
            if (!s.empty())
            {
                str_it = &s[0];
                str_end = s.data() + s.length();
                start = (uintptr_t)strtoul(str_it, &str_it, 16);
                end = (uintptr_t)strtoul(str_it + 1, &str_it, 16);
                if (start != 0 && end != 0)
                {
                    if (old_end != start)
                    {
                        mappings.emplace_back(
                            MemoryRights::mem_unset,
                            old_end,
                            start,
                            std::string()
                        );
                    }

                    old_end = end;
                }
            }
        }

        return mappings;
    }

    bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* old_rights)
    {
        RegionInfos_t infos;
        if (old_rights != nullptr)
            infos = GetRegionInfos(address);

        bool res = mprotect(PageRound(address, PageSize()), _PageAddrSize(address, size, PageSize()), _MemoryProtectRightsToNative(rights)) == 0;

        if (old_rights != nullptr)
            *old_rights = infos.rights;

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

        auto freeRegions = GetFreeRegions();

        std::sort(freeRegions.begin(), freeRegions.end(), [addressHint](MemoryManipulation::RegionInfos_t const& l, MemoryManipulation::RegionInfos_t const& r)
        {
            return std::max(addressHint, l.start) - std::min(addressHint, l.start) <
                std::max(addressHint, r.start) - std::min(addressHint, r.start);
        });

        for (auto const& region : freeRegions)
        {
            auto start = region.start > addressHint ? region.start : (region.end - pageSize);
            auto increment = static_cast<int32_t>(region.start > addressHint ? pageSize : -pageSize);

            for (auto allocAddress = start; allocAddress >= region.start && (allocAddress + size) < region.end; allocAddress += increment)
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
}//namespace MemoryManipulation

namespace ModuleManipulation {
    static bool _LoadModuleExportDetails(void* moduleHandle, void** moduleBase, ElfSymbol_t** dynamicSymbolsStart, ElfSymbol_t** dynamicSymbolsEnd, size_t* dynamicSymbolsSize, const char** dynamicSymbolsNames)
    {
        ElfHeader_t* elfHeader = *(ElfHeader_t**)moduleHandle;

        ElfProgramHeader_t* programHeadersStart = (ElfProgramHeader_t*)((uintptr_t)elfHeader + elfHeader->e_phoff);
        ElfProgramHeader_t* programHeadersEnd = (ElfProgramHeader_t*)((uintptr_t)programHeadersStart + elfHeader->e_phentsize * elfHeader->e_phnum);
        ElfSectionHeader_t* sectionHeadersStart = nullptr;
        ElfSectionHeader_t* sectionHeadersEnd = nullptr;
        ElfSectionHeader_t* stringSectionHeader = nullptr;
        const char* sectionNames = nullptr;
        int64_t relocationOffset = 0;

        *dynamicSymbolsStart = nullptr;
        *dynamicSymbolsEnd = nullptr;
        *dynamicSymbolsSize = 0;
        *dynamicSymbolsNames = nullptr;

        if (elfHeader->e_ident[EI_MAG0] != ELFMAG0 ||
            elfHeader->e_ident[EI_MAG1] != ELFMAG1 ||
            elfHeader->e_ident[EI_MAG2] != ELFMAG2 ||
            elfHeader->e_ident[EI_MAG3] != ELFMAG3)
        {
            return false;
        }

        for (ElfProgramHeader_t* programHeader = programHeadersStart; programHeader < programHeadersEnd; programHeader = (ElfProgramHeader_t*)((uintptr_t)programHeader + elfHeader->e_phentsize))
        {
            // Not sure about this, but something is required to compute the new sections headers address.
            // It doesn't work on libc
            relocationOffset = programHeader->p_vaddr - programHeader->p_offset;
            if (relocationOffset != 0)
                break;

            //SPDLOG_INFO("Program header offset: {}, Program header vaddr: {}, Program header paddr: {}, Program header filesz: {}, Program header memsz: {}, Program header align: {}",
            //    programHeader->p_offset, programHeader->p_vaddr, programHeader->p_paddr, programHeader->p_filesz, programHeader->p_memsz, programHeader->p_align);
        }


        sectionHeadersStart = (ElfSectionHeader_t*)((char*)elfHeader + elfHeader->e_shoff + relocationOffset);
        sectionHeadersEnd = (ElfSectionHeader_t*)((char*)sectionHeadersStart + elfHeader->e_phentsize * elfHeader->e_shnum);

        stringSectionHeader = (ElfSectionHeader_t*)((char*)sectionHeadersStart + elfHeader->e_shstrndx * elfHeader->e_shentsize);
        sectionNames = ((char*)elfHeader + stringSectionHeader->sh_offset + relocationOffset);

        for (ElfSectionHeader_t* sectionHeader = sectionHeadersStart; sectionHeader < sectionHeadersEnd; sectionHeader = (ElfSectionHeader_t*)((uintptr_t)sectionHeader + elfHeader->e_shentsize))
        {
            const char* sectionName = sectionNames + sectionHeader->sh_name;
            // Dynamic sections data don't seem to be relocated.
            if (sectionHeader->sh_type == SHT_STRTAB && strcmp(sectionName, ".dynstr") == 0)
            {
                if (*dynamicSymbolsNames != nullptr)
                {
                    SPDLOG_WARN("Multiple SHT_DYNSTR.");
                }
                *dynamicSymbolsNames = (const char*)((uintptr_t)elfHeader + sectionHeader->sh_offset);
            }
            else if (sectionHeader->sh_type == SHT_DYNSYM)
            {
                if (*dynamicSymbolsStart != nullptr)
                {
                    SPDLOG_WARN("Multiple SHT_DYNSYM.");
                }
                *dynamicSymbolsStart = (ElfSymbol_t*)((char*)elfHeader + sectionHeader->sh_offset);
                *dynamicSymbolsEnd = (ElfSymbol_t*)((char*)*dynamicSymbolsStart + sectionHeader->sh_size);
                *dynamicSymbolsSize = sectionHeader->sh_entsize;
            }
        }

        *moduleBase = (void*)elfHeader;

        return *dynamicSymbolsNames != nullptr && *dynamicSymbolsStart != nullptr;
    }

    static bool _ReplaceModuleExportInPlace(void* moduleBase, ElfAddr_t* exportAddress, void** exportCallAddress, void* newExportAddress)
    {
        MemoryManipulation::MemoryRights oldRights;

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
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

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
            goto ErrorFree;

        if (!MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::mem_rwx, nullptr))
            goto ErrorFree;

        MemoryManipulation::WriteAbsoluteJump(exportJump, newExportAddress);

        if (exportCallAddress != nullptr)
            *exportCallAddress = (void*)((char*)moduleBase + *exportAddress);

        *exportAddress = (uintptr_t)exportJump - (uintptr_t)moduleBase;

        MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::mem_rx, nullptr);
        MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

        return true;

    ErrorFree:
        mm.FreeJump(exportJump);
    Error:
        *exportCallAddress = nullptr;
        return false;
    }

    static inline ElfAddr_t* _GetExportAddress(ElfSymbol_t* dynamicSymbolsStart, ElfSymbol_t* dynamicSymbolsEnd, size_t dynamicSymbolsSize, const char* dynamicSymbolsNames, const char* symbolName)
    {
        for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
        {
            auto symbolBind = ELF_ST_BIND(symbol->st_info);
            auto symbolType = ELF_ST_TYPE(symbol->st_info);

            if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT) || strcmp(dynamicSymbolsNames + symbol->st_name, symbolName) != 0)
                continue;

            return &symbol->st_value;
        }

        return nullptr;
    }

    static bool _LoadModuleIATDetails(void* moduleHandle, void** moduleBase)
    {

        return false;
    }

    size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount)
    {
        void* moduleBase = nullptr;
        int64_t relocationOffset = 0;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolsSize = 0;
        const char* dynamicSymbolsNames = nullptr;
        size_t result = 0;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames))
            return result;

        if (exportDetails == nullptr)
        {
            for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
            {
                auto symbolBind = ELF_ST_BIND(symbol->st_info);
                auto symbolType = ELF_ST_TYPE(symbol->st_info);

                if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT))
                    continue;

                ++result;
            }

            return result;
        }

        for (ElfSymbol_t* symbol = dynamicSymbolsStart; symbol < dynamicSymbolsEnd && result < exportDetailsCount; symbol = (ElfSymbol_t*)((uintptr_t)symbol + dynamicSymbolsSize))
        {
            auto symbolBind = ELF_ST_BIND(symbol->st_info);
            auto symbolType = ELF_ST_TYPE(symbol->st_info);

            if ((symbolBind != STB_GLOBAL && symbolBind != STB_WEAK) || (symbolType != STT_FUNC && symbolType != STT_OBJECT) || symbol->st_value == 0)
                continue;

            exportDetails[result].ExportName = dynamicSymbolsNames + symbol->st_name;
            exportDetails[result].ExportCallAddress = (void*)((uintptr_t)moduleBase + symbol->st_value);
            exportDetails[result++].ExportOrdinal = symbol - dynamicSymbolsStart;
        }

        return result;
    }

    size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* exportDetails, size_t iatDetailsCount)
    {
        return 0;
    }

    size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        int64_t relocationOffset = 0;
        ElfSymbol_t* dynamicSymbolsStart = nullptr;
        ElfSymbol_t* dynamicSymbolsEnd = nullptr;
        size_t dynamicSymbolsSize = 0;
        const char* dynamicSymbolsNames = nullptr;
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].ExportCallAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames))
            return result;

        SPDLOG_INFO("Program base address: {:016X}, Dynamic symbol start: {:016X}, Dynamic symbol stop: {:016X}", (uintptr_t)moduleBase, (uintptr_t)dynamicSymbolsStart, (uintptr_t)dynamicSymbolsEnd);

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            ElfAddr_t* exportAddress = _GetExportAddress(dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolsSize, dynamicSymbolsNames, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
                continue;

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
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].NewExportAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbolsStart, &dynamicSymbolsEnd, &dynamicSymbolsSize, &dynamicSymbolsNames))
            return result;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            ElfAddr_t* exportAddress = _GetExportAddress(dynamicSymbolsStart, dynamicSymbolsEnd, dynamicSymbolsSize, dynamicSymbolsNames, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
                continue;

            MemoryManipulation::MemoryRights oldRights;

            if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
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

    size_t ReplaceModuleIATs(const char* moduleName, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].IATCallAddress = nullptr;

        return 0;
    }

    size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        return 0;
    }
}//namespace ModuleManipulation

}//namespace MiniDetour

#endif//MINI_DETOUR_LINUX_H