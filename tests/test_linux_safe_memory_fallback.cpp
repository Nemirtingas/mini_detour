#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

// Makes process_vm_readv/writev fail with EPERM, as Docker's default seccomp profile does.
static void BlockProcessVm()
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    struct sock_fprog program = {static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])), filter};

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static bool ProcessVmReadUnavailable()
{
    uint8_t value = 1;
    uint8_t copy  = 0;
    struct iovec local;
    struct iovec remote;
    local.iov_base  = &copy;
    local.iov_len   = 1;
    remote.iov_base = &value;
    remote.iov_len  = 1;
    return syscall(__NR_process_vm_readv, getpid(), &local, 1, &remote, 1, 0) < 0 && (errno == EPERM || errno == ENOSYS);
}

// Runs in a child process, which keeps the filter to itself. Returns the first check that failed, 0 if none did.
static int CheckSafeMemoryWithoutProcessVm()
{
    // qemu user mode doesn't install seccomp filters, but it doesn't implement process_vm_readv/writev either: either
    // way, they are unavailable here.
    BlockProcessVm();
    if (!ProcessVmReadUnavailable())
        return 1;

    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();
    auto pages            = static_cast<uint8_t *>(MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, pageSize * 2, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    if (pages == nullptr)
        return 2;

    for (size_t i = 0; i < pageSize * 2; ++i)
        pages[i] = static_cast<uint8_t>(i);

    if (!MiniDetour::MemoryManipulation::MemoryProtect(pages + pageSize, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_none))
        return 3;

    // 16 bytes before the inaccessible page, 16 in it: the copies stop at the page.
    uint8_t *start = pages + pageSize - 16;
    uint8_t buffer[32];
    memset(buffer, 0, sizeof(buffer));
    if (MiniDetour::MemoryManipulation::SafeMemoryRead(start, buffer, sizeof(buffer)) != 16 || memcmp(buffer, start, 16) != 0)
        return 4;

    const uint8_t data[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    if (MiniDetour::MemoryManipulation::SafeMemoryWrite(start, data, sizeof(data)) != 16 || memcmp(start, data, 16) != 0)
        return 5;

    // Read-only memory can be read, not written.
    if (!MiniDetour::MemoryManipulation::MemoryProtect(pages, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_r))
        return 6;

    if (MiniDetour::MemoryManipulation::SafeMemoryRead(pages, buffer, sizeof(buffer)) != sizeof(buffer) || memcmp(buffer, pages, sizeof(buffer)) != 0)
        return 7;

    if (MiniDetour::MemoryManipulation::SafeMemoryWrite(pages, data, sizeof(data)) != 0 || pages[0] != 0)
        return 8;

    // Freed memory can't be read.
    MiniDetour::MemoryManipulation::MemoryFree(pages, pageSize * 2);
    if (MiniDetour::MemoryManipulation::SafeMemoryRead(pages, buffer, sizeof(buffer)) != 0)
        return 9;

    return 0;
}

// SafeMemoryRead/Write only used process_vm_readv/writev: they copied nothing where those are missing (qemu user mode)
// or blocked (seccomp filters, Docker's default profile).
TEST_CASE("Safe memory copies work without process_vm_readv/writev", "[safe_memory_fallback]")
{
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0)
        _exit(CheckSafeMemoryWithoutProcessVm());

    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    INFO("Failed check: " << WEXITSTATUS(status));
    CHECK(WEXITSTATUS(status) == 0);
}
#endif
