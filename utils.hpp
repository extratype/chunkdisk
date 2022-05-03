/**
 * @file utils.hpp
 *
 * @copyright 2021-2022 extratype
 *
 * System utilities and utilities for WinSpd.
 */

#ifndef CHUNKDISK_UTILS_HPP_
#define CHUNKDISK_UTILS_HPP_

#include <memory>
#include <string>
#include <shared_mutex>
#include <winspd/winspd.h>
#include "types.hpp"

namespace chunkdisk
{

// shared_mutex is an SRW lock in Windows
// unique_lock or shared_lock
template <class Derived>
class SRWLockBase
{
    std::unique_lock<std::shared_mutex> ulock_;
    std::shared_lock<std::shared_mutex> slock_;

public:
    SRWLockBase() = default;

    SRWLockBase(std::shared_mutex& m, bool is_exclusive)
    {
        if (is_exclusive)
        {
            ulock_ = std::unique_lock(m);
            static_cast<Derived*>(this)->on_locked(true);
        }
        else
        {
            slock_ = std::shared_lock(m);
            static_cast<Derived*>(this)->on_locked(false);
        }
    }

    SRWLockBase(std::shared_mutex& m, bool is_exclusive, std::defer_lock_t t)
    {
        if (is_exclusive)
        {
            ulock_ = std::unique_lock(m, t);
        }
        else
        {
            slock_ = std::shared_lock(m, t);
        }
    }

    SRWLockBase(std::shared_mutex& m, bool is_exclusive, std::adopt_lock_t t)
    {
        if (is_exclusive)
        {
            ulock_ = std::unique_lock(m, t);
        }
        else
        {
            slock_ = std::shared_lock(m, t);
        }
    }

    SRWLockBase(SRWLockBase&& other) noexcept = default;

    ~SRWLockBase()
    {
        if (!*this) return;
        unlock();
    }

    SRWLockBase& operator=(SRWLockBase&& other) noexcept = default;

    // always false if no mutex associated
    bool is_exclusive() const noexcept { return ulock_.mutex() != nullptr; }

    auto* mutex() const noexcept { return is_exclusive() ? ulock_.mutex() : slock_.mutex(); }

    explicit operator bool() const noexcept { return bool(ulock_) || bool(slock_); }

    void lock()
    {
        if (*this) throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur));
        if (ulock_.mutex() != nullptr)
        {
            ulock_.lock();
            static_cast<Derived*>(this)->on_locked(true);
        }
        else if (slock_.mutex() != nullptr)
        {
            slock_.lock();
            static_cast<Derived*>(this)->on_locked(false);
        }
        else
        {
            throw std::system_error(std::make_error_code(std::errc::operation_not_permitted));
        }
    }

    bool try_lock()
    {
        if (*this) throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur));
        if (ulock_.mutex() != nullptr)
        {
            auto locked = ulock_.try_lock();
            if (locked) static_cast<Derived*>(this)->on_locked(true);
            return locked;
        }
        else if (slock_.mutex() != nullptr)
        {
            auto locked = slock_.try_lock();
            if (locked) static_cast<Derived*>(this)->on_locked(false);
            return locked;
        }
        else
        {
            throw std::system_error(std::make_error_code(std::errc::operation_not_permitted));
        }
    }

    void unlock()
    {
        if (!*this) throw std::system_error(std::make_error_code(std::errc::operation_not_permitted));
        if (ulock_.mutex() != nullptr)
        {
            static_cast<Derived*>(this)->on_unlock(true);
            ulock_.unlock();
        }
        else if (slock_.mutex() != nullptr)
        {
            static_cast<Derived*>(this)->on_unlock(false);
            slock_.unlock();
        }
        else
        {
            throw std::system_error(std::make_error_code(std::errc::operation_not_permitted));
        }
    }

    // switch between exclusive and shared lock
    bool switch_lock()
    {
        auto excl = is_exclusive();
        auto* m = mutex();
        if (m == nullptr) return false;
        auto owns = bool(*this);

        if (owns) unlock();

        if (excl)
        {
            ulock_.release();
            slock_ = std::shared_lock(*m, std::defer_lock);
        }
        else
        {
            slock_.release();
            ulock_ = std::unique_lock(*m, std::defer_lock);
        }

        if (owns) lock();

        return !excl;
    }

    auto* release() noexcept
    {
        auto* um = ulock_.release();
        auto* sm = slock_.release();
        return um != nullptr ? um : sm;
    }

    void on_locked(bool is_exclusive);

    void on_unlock(bool is_exclusive);
};

class SRWLock : public SRWLockBase<SRWLock>
{
public:
    SRWLock() : SRWLockBase() {}

    SRWLock(std::shared_mutex& m, bool is_exclusive)
        : SRWLockBase(m, is_exclusive) {}

    SRWLock(std::shared_mutex& m, bool is_exclusive, std::defer_lock_t t)
        : SRWLockBase(m, is_exclusive, t) {}

    SRWLock(std::shared_mutex& m, bool is_exclusive, std::adopt_lock_t t)
        : SRWLockBase(m, is_exclusive, t) {}

    SRWLock(SRWLock&& other) noexcept = default;

    SRWLock& operator=(SRWLock&& other) noexcept = default;

    void on_locked(bool is_exclusive) {}

    void on_unlock(bool is_exclusive) {}
};

template <class T, class Deleter, size_t defval = 0>
struct GenericDeleter
{
    void operator()(T x) noexcept
    {
        Deleter()(x);
    }

    struct pointer
    {
        pointer(T x) : value(x) {}

        operator T() const { return value; }

        pointer(std::nullptr_t = nullptr) : value(recast<T>(defval)) {}

        explicit operator bool() const { return value != recast<T>(defval); }

        friend bool operator==(pointer lhs, pointer rhs) { return lhs.value == rhs.value; }

        T value;
    };
};

struct HandleDeleter
{
    void operator()(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};

using GenericHandle = std::unique_ptr<void, GenericDeleter<HANDLE, HandleDeleter>>;

using FileHandle = std::unique_ptr<void, GenericDeleter<HANDLE, HandleDeleter, size_t(-1)>>;

struct PagesDeleter
{
    void operator()(LPVOID p) noexcept
    {
        VirtualFree(p, 0, MEM_RELEASE);
    }
};

// deleted by VirtualFree()
using Pages = std::unique_ptr<void, PagesDeleter>;

// text may or may not be null-terminated
DWORD ConvertUTF8(const u8* text, int size, std::wstring& result);

// match to SpdStorageUnitStartDispatcher() behavior
DWORD GetThreadCount(PDWORD ThreadCount);

u64 GetSystemFileTime();

void SetScsiError(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc);
void SetScsiError(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc, u64 info);

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
