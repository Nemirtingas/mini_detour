#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#include <string.h>

// SafeMemoryRead/Write returned a boolean, all or nothing: a copy reaching an inaccessible page gave no data at all.
// They now return the number of bytes copied, the copy stopping at the first page that can't be accessed.
TEST_CASE("Safe memory copies stop at the first inaccessible page", "[safe_memory_byte_count]")
{
    uint8_t probe     = 0x5A;
    uint8_t probeCopy = 0;
    if (MiniDetour::MemoryManipulation::SafeMemoryRead(&probe, &probeCopy, 1) != 1)
    {
        // qemu user mode doesn't implement process_vm_readv/process_vm_writev.
        WARN("Safe memory access isn't supported here, test skipped.");
        return;
    }

    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();
    auto pages            = static_cast<uint8_t *>(MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, pageSize * 2, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    REQUIRE(pages != nullptr);
    for (size_t i = 0; i < pageSize * 2; ++i)
        pages[i] = static_cast<uint8_t>(i);

    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(pages + pageSize, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_none));

    // 16 bytes before the inaccessible page, 16 in it.
    uint8_t *start = pages + pageSize - 16;
    uint8_t buffer[32];
    memset(buffer, 0, sizeof(buffer));
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(start, buffer, sizeof(buffer)) == 16);
    CHECK(memcmp(buffer, start, 16) == 0);

    const uint8_t data[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryWrite(start, data, sizeof(data)) == 16);
    CHECK(memcmp(start, data, 16) == 0);

    // Entirely readable, entirely inaccessible, nothing to copy, no buffer.
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(pages, buffer, sizeof(buffer)) == sizeof(buffer));
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(pages + pageSize, buffer, sizeof(buffer)) == 0);
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(pages, buffer, 0) == 0);
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(pages, nullptr, sizeof(buffer)) == 0);

    // A copy over several pages that are all accessible.
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(pages + pageSize, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(start, buffer, sizeof(buffer)) == sizeof(buffer));
    CHECK(memcmp(buffer, start, sizeof(buffer)) == 0);

    MiniDetour::MemoryManipulation::MemoryFree(pages, pageSize * 2);
}
