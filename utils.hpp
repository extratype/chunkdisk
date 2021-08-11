/**
 * @file utils.hpp
 *
 * @copyright 2021 extratype
 *
 * System utilities and utilities for WinSpd.
 */

#ifndef CHUNKDISK_UTILS_HPP_
#define CHUNKDISK_UTILS_HPP_

#include <memory>
#include <string>
#include <winspd/winspd.h>
#include "types.hpp"

namespace chunkdisk
{

// text may or may not be null-terminated
DWORD ConvertUTF8(const u8* text, int size, std::wstring& result);

// match to SpdStorageUnitStartDispatcher() behavior
DWORD GetThreadCount(PDWORD ThreadCount);

// like lock_guard<SRWLOCK>
// can be reset
// NOTE: it's a programming error to try to acquire an SRW lock recursively.
class SRWLockGuard
{
public:
    SRWLockGuard() : lock_(nullptr), is_exclusive_(false) {}

    explicit SRWLockGuard(PSRWLOCK lock, bool is_exclusive)
        : lock_(lock), is_exclusive_(is_exclusive)
    {
        if (!*this) return;
        is_exclusive_ ? AcquireSRWLockExclusive(lock_) : AcquireSRWLockShared(lock_);
    }

    ~SRWLockGuard() { reset(); }

    SRWLockGuard(const SRWLockGuard&) = delete;

    SRWLockGuard(SRWLockGuard&& other) noexcept : SRWLockGuard(nullptr, false) { swap(*this, other); }

    explicit operator bool() const noexcept { return lock_ != nullptr; }

    bool is_exclusive() const noexcept { return is_exclusive_; }

    void reset()
    {
        if (!*this) return;
        is_exclusive_ ? ReleaseSRWLockExclusive(lock_) : ReleaseSRWLockShared(lock_);
        lock_ = nullptr;
    }

    // release *this and take the ownership of other
    void reset(SRWLockGuard&& other) { swap(*this, other); }

protected:
    PSRWLOCK lock_;

    bool is_exclusive_;

    friend void swap(SRWLockGuard& a, SRWLockGuard& b) noexcept
    {
        using std::swap;
        swap(a.lock_, b.lock_);
        swap(a.is_exclusive_, b.is_exclusive_);
    }
};

struct HandleDeleter
{
    void operator()(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};

struct FileHandleDeleter : HandleDeleter
{
    struct pointer
    {
        pointer(HANDLE h) : value(h) {}

        operator HANDLE() const { return value; }

        pointer(std::nullptr_t = nullptr) : value(INVALID_HANDLE_VALUE) {}

        explicit operator bool() const { return value != INVALID_HANDLE_VALUE; }

        friend bool operator==(pointer lhs, pointer rhs) { return lhs.value == rhs.value; }

        HANDLE value;
    };
};

// reset to nullptr
using GenericHandle = std::unique_ptr<void, HandleDeleter>;

// reset to INVALID_HANDLE_VALUE
using FileHandle = std::unique_ptr<void, FileHandleDeleter>;

struct PagesDeleter
{
    void operator()(LPVOID p) noexcept
    {
        VirtualFree(p, 0, MEM_RELEASE);
    }
};

using Pages = std::unique_ptr<void, PagesDeleter>;

void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc);
void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc, u64 info);

}   // namespace chunkdisk

template <class... Ts>
static void SpdLogInfo(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_INFORMATION_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
static void SpdLogWarn(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_WARNING_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
static void SpdLogErr(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_ERROR_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

#define SpdWarnOnce(expr)               \
    do                                  \
    {                                   \
        static LONG Once;               \
        if (!(expr) &&                  \
            InterlockedCompareExchange(&Once, 1, 0) == 0)\
            SpdLogWarn(L"WARNONCE(%S) failed at %S:%d", #expr, __func__, __LINE__);\
    } while (0,0)

#endif
