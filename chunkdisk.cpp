/**
 * @file chunkdisk.cpp
 *
 * @copyright 2021 extratype
 */
/*
 * Mount a disk image split over files (chunks) in multiple directories (parts)
 *
 * Parameters: disk_name.chunkdisk
 * Chunk files: part_dirname\part### (no leading zeros)
 *
 * Chunk: must be of the specified length if nonzero
 * Chunk empty (0 bytes): zeros until written then use that part
 * Chunk file not present: zeros until written then chunks placed from first to last part
 *
 * TRIM (Unmap): make chunk empty if whole, fill zero otherwise
 * TODO: check partition -> TRIM -> shrink -> delete orphan empty chunks
 * TODO: sparse chunk
 * TODO: asynchronous (overlapped) file operations
 */

#include <type_traits>
#include <cstddef>
#include <utility>
#include <memory>
#include <cwchar>
#include <string>
#include <vector>
#include <deque>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include <numeric>
#include <filesystem>
#include <winspd/winspd.h>

template <class T, class U>
constexpr T recast(U arg)
{
    return reinterpret_cast<T>(arg);
}

typedef INT32  i32;
typedef INT64  i64;
typedef UINT8  u8;
typedef UINT32 u32;
typedef UINT64 u64;

using std::size_t;
using std::make_pair;
using std::bad_alloc;
using std::unique_ptr;
using std::wstring;
using std::vector;
using std::deque;
using std::unordered_set;
using std::unordered_map;

namespace fs = std::filesystem;

struct pair_hash
{
    template <class T1, class T2>
    size_t operator() (std::pair<T1, T2> const& p) const
    {
        size_t h1 = std::hash<T1>()(p.first);
        size_t h2 = std::hash<T2>()(p.second);
        return h1 ^ h2;
    }
};

// unordered_map
// keep the insertion order
template <class KT, class VT>
struct Map
{
    struct VIt
    {
        VT val;
        typename std::list<const KT*>::iterator it; // iterator in key_order_
    };

    // iterate in the insertion order
    // invalidated if invalidated in map_
    struct iterator
    {
        iterator() = default;

        explicit iterator(unordered_map<KT, VIt>* map,
                          typename unordered_map<KT, VIt>::iterator map_it,
                          typename std::list<const KT*>::iterator end_it)
            : map_(map), it_(std::move(map_it)), end_it_(std::move(end_it)) {}

        std::pair<const KT&, VT&> operator*() const noexcept
        {
            auto& p = *it_;
            return std::make_pair(std::ref(p.first), std::ref(p.second.val));
        }

        auto operator++() noexcept
        {
            // follow key_order_
            auto vit = it_->second.it;
            it_ = (++vit == end_it_) ? map_->end() : map_->find(**vit);
            return *this;
        }

        auto operator==(const iterator& other) const noexcept
        {
            return map_ == other.map_ && it_ == other.it_ && end_it_ == other.end_it_;
        }

    private:
        friend struct Map;

        unordered_map<KT, VIt>* map_ = nullptr;
        typename unordered_map<KT, VIt>::iterator it_;
        typename std::list<const KT*>::iterator end_it_;    // key_order_.end()
    };

    auto front() { return *find(*key_order_.front()); }

    auto back() { return *find(*key_order_.back()); }

    auto begin() noexcept
    {
        if (map_.empty()) return end();
        return iterator(&map_, map_.find(*key_order_.front()), key_order_.end());
    }

    auto end() noexcept
    {
        return iterator(&map_, map_.end(), key_order_.end());
    }

    bool empty() const noexcept { return map_.empty(); }

    size_t size() const noexcept { return map_.size(); }

    void clear() noexcept
    {
        map_.clear();
        key_order_.clear();
    }

    template <class... Args>
    auto emplace(Args&&... args)
    {
        auto [it, emplaced] = map_.emplace(std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(const KT& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(k, std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(KT&& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(std::move(k), std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return std::make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    // invalidates only key_order_ iterator
    void reinsert_front(iterator it)
    {
        auto* key = &((*it).first);
        key_order_.erase(it.it_->second.it);
        it.it_->second.it = key_order_.emplace(key_order_.begin(), key);
    }

    // invalidates only key_order_ iterator
    void reinsert_back(iterator it)
    {
        auto* key = &((*it).first);
        key_order_.erase(it.it_->second.it);
        it.it_->second.it = key_order_.emplace(key_order_.end(), key);
    }

    void pop_front()
    {
        erase(find(*key_order_.front()));
    }

    void pop_back()
    {
        erase(find(*key_order_.back()));
    }

    size_t erase(const KT& key)
    {
        auto it = map_.find(key);
        if (it == map_.end()) return 0;

        auto& vit = it->second.it;
        key_order_.erase(vit);
        map_.erase(it);
        return 1;
    }

    void erase(iterator pos)
    {
        key_order_.erase(pos.it_->second.it);
        map_.erase(pos.it_);
    }

    auto find(const KT& key)
    {
        return iterator(&map_, map_.find(key), key_order_.end());
    }

    void reserve(size_t count) { map_.reserve(count); }

private:
    unordered_map<KT, VIt> map_;
    std::list<const KT*> key_order_;
};

// match to SpdStorageUnitStartDispatcher() behavior
static DWORD GetThreadCount(PDWORD ThreadCount)
{
    DWORD Result;
    DWORD_PTR ProcessMask, SystemMask;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask))
        return GetLastError();

    for (Result = 0; 0 != ProcessMask; ProcessMask >>= 1)
        Result += ProcessMask & 1;

    *ThreadCount = Result;
    return ERROR_SUCCESS;
}

// text may or may not be null-terminated
static DWORD ConvertUTF8(const u8* text, int size, wstring& result)
{
    try
    {
        auto wchar_size = MultiByteToWideChar(
            CP_UTF8, 0,
            recast<LPCCH>(text), size, nullptr, 0);
        if (!wchar_size) return GetLastError();

        auto wbuf = unique_ptr<WCHAR[]>(new WCHAR[wchar_size + 1]());
        wchar_size = MultiByteToWideChar(
            CP_UTF8, 0,
            recast<LPCCH>(text), size, wbuf.get(), wchar_size + 1);
        if (!wchar_size) return GetLastError();

        if (wbuf[wchar_size - 1] == '\0') wchar_size -= 1;
        result.append(wbuf.get(), wchar_size);
        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS
{
    FileAccessInformation = 8, // FILE_ACCESS_INFORMATION
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_ACCESS_INFORMATION
{
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, * PFILE_ACCESS_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    _In_ NTSTATUS Status
);

#ifdef __cplusplus
}
#endif

DWORD GetFileAccessFlags(HANDLE h, ACCESS_MASK* mask)
{
    IO_STATUS_BLOCK iosb;
    FILE_ACCESS_INFORMATION info;

    auto status = ZwQueryInformationFile(h, &iosb, &info, sizeof(info),
                                         FileAccessInformation);
    if (status < 0) return RtlNtStatusToDosError(status);
    *mask = info.AccessFlags;
    return ERROR_SUCCESS;
}

template <class... Ts>
void info(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_INFORMATION_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
void warn(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_WARNING_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
void logerr(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_ERROR_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

#define WARNONCE(expr)                  \
    do                                  \
    {                                   \
        static LONG Once;               \
        if (!(expr) &&                  \
            InterlockedCompareExchange(&Once, 1, 0) == 0)\
            warn(L"WARNONCE(%S) failed at %S:%d", #expr, __func__, __LINE__);\
    } while (0,0)

// like unique_ptr<HANDLE>
// reset to INVALID_HANDLE_VALUE
// invalid for nullptr OR INVALID_HANDLE_VALUE
struct FileHandle
{
    FileHandle() noexcept : handle_(INVALID_HANDLE_VALUE) {}

    explicit FileHandle(HANDLE h) noexcept : handle_(h) {}

    virtual ~FileHandle() noexcept { if (*this) CloseHandle(handle_); }

    FileHandle(const FileHandle&) = delete;

    FileHandle(FileHandle&& other) noexcept : FileHandle() { swap(*this, other); }

    FileHandle& operator=(FileHandle& other) = delete;

    FileHandle& operator=(FileHandle&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    operator bool() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    HANDLE get() const noexcept { return handle_; }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept
    {
        FileHandle temp(h);
        swap(*this, temp);
    }

private:
    HANDLE handle_;

    friend void swap(FileHandle& a, FileHandle& b) noexcept
    {
        using std::swap;
        swap(a.handle_, b.handle_);
    }
};

// like lock_guard<SRWLOCK>
struct SRWLockGuard
{
    SRWLockGuard() : lock_(nullptr), is_exclusive_(false) {}

    explicit SRWLockGuard(PSRWLOCK lock, bool is_exclusive) noexcept
        : lock_(lock), is_exclusive_(is_exclusive)
    {
        if (!*this) return;
        is_exclusive_ ? AcquireSRWLockExclusive(lock_) : AcquireSRWLockShared(lock_);
    }

    virtual ~SRWLockGuard() { reset(); }

    SRWLockGuard(const SRWLockGuard&) = delete;

    SRWLockGuard(SRWLockGuard&& other) noexcept : SRWLockGuard(nullptr, false) { swap(*this, other); }

    operator bool() const noexcept { return lock_ != nullptr; }

    bool is_exclusive() const noexcept { return is_exclusive_; }

    void reset()
    {
        if (!*this) return;
        is_exclusive_ ? ReleaseSRWLockExclusive(lock_) : ReleaseSRWLockShared(lock_);
        lock_ = nullptr;
    }

    // release *this and take the ownership of other
    void reset(SRWLockGuard&& other) noexcept { swap(*this, other); }

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

// [start_idx, end_idx], [start_off, end_off), 0 < end_off <= chunk_length
struct ChunkRange
{
    const u64 start_idx;
    const u64 start_off;
    const u64 end_idx;
    const u64 end_off;
};

// [start_idx, end_idx], [start_off, end_off), 0 < end_off <= page_length
struct PageRange
{
    const u64 start_idx;
    const u32 start_off;
    const u64 end_idx;
    const u32 end_off;
};

struct PageDeleter
{
    void operator()(LPVOID p) noexcept
    {
        VirtualFree(p, 0, MEM_RELEASE);
    }
};

using Page = unique_ptr<void, PageDeleter>;

struct PageEntry
{
    Page vmem;
    SRWLOCK lock = SRWLOCK_INIT;    // acquire it while using vmem
};

// current thread only
struct AcquiredPage
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    SRWLockGuard guard;             // hold while using ptr

    LPVOID ptr = nullptr;           // ChunkDisk::page_size
    const bool is_write = false;    // ChunkDisk::AcquirePage()
    const bool is_hit = false;      // ptr is zero initialized if !is_hit
};

struct ChunkDisk
{
    // max_handles, max_pages: MUST be positive
    ChunkDisk(u64 block_count, u32 block_size, u64 chunk_count, u64 chunk_length,
              vector<u64> part_max, vector<wstring> part_dirname, u32 max_handles, u32 max_pages)
            : block_count(block_count), block_size(block_size), chunk_count(chunk_count), chunk_length(chunk_length),
              part_max(std::move(part_max)), part_dirname(std::move(part_dirname)),
              max_handles(max_handles), page_length(page_size / block_size), max_pages(max_pages)
    {
        chunk_handles_.reserve(max_handles);
        cached_pages_.reserve(max_pages);
    }

    virtual ~ChunkDisk()
    {
        FlushAll();
        if (storage_unit != nullptr) SpdStorageUnitDelete(storage_unit);
    }

    DWORD LockParts()
    {
        auto num_parts = part_dirname.size();

        try
        {
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto path = part_dirname[i] + L"\\.lock";
                auto h = FileHandle(CreateFileW(
                    path.data(),
                    GENERIC_READ | GENERIC_WRITE,
                    0, nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr));
                if (!h) return GetLastError();

                part_lock_.emplace_back(std::move(h));
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        return ERROR_SUCCESS;
    }

    // read parts and chunks, check consistency
    DWORD ReadParts()
    {
        // from part_max, part_dirname...
        auto num_parts = part_dirname.size();

        try
        {
            // make sure parts exist, no dups
            auto part_ids = unordered_set<std::pair<u32, u64>, pair_hash>();
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto h = FileHandle(CreateFileW(
                    (part_dirname[i] + L'\\').data(),
                    FILE_READ_ATTRIBUTES, 0, nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, nullptr));
                if (!h) return GetLastError();

                auto file_info = BY_HANDLE_FILE_INFORMATION();
                if (!GetFileInformationByHandle(h.get(), &file_info)) return GetLastError();

                if (!part_ids.emplace(make_pair(
                        file_info.dwVolumeSerialNumber,
                        file_info.nFileIndexLow + (u64(file_info.nFileIndexHigh) << 32))).second)
                {
                    return ERROR_INVALID_PARAMETER; // dup found
                }
            }
            part_ids.clear();

            // read parts
            auto part_current = vector<u64>(num_parts, 0);
            auto chunk_parts = unordered_map<u64, size_t>();
            for (size_t i = 0; i < num_parts; ++i)
            {
                for (auto& p : fs::directory_iterator(part_dirname[i] + L'\\'))
                {
                    auto fname = p.path().filename().wstring();
                    if (_wcsnicmp(fname.data(), L"chunk", 5) != 0) continue;

                    auto* endp = PWSTR();
                    auto idx = wcstoull(fname.data() + 5, &endp, 10);
                    if (fname.data() + 5 == endp || *endp != L'\0' || errno == ERANGE || idx >= chunk_count) continue;

                    if (!chunk_parts.emplace(idx, i).second) return ERROR_FILE_EXISTS;
                    if (++part_current[i] > part_max[i]) return ERROR_PARAMETER_QUOTA_EXCEEDED;
                }
            }

            // done
            part_current_ = std::move(part_current);
            chunk_parts_ = std::move(chunk_parts);
        }
        catch (const std::system_error& e)
        {
            return e.code().value();
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        return ERROR_SUCCESS;
    }

    ChunkRange BlockChunkRange(u64 block_addr, u32 count) const
    {
        auto start_idx = block_addr / chunk_length;
        auto start_off = block_addr % chunk_length;
        auto end_idx = start_idx;

        // start_idx: [start_off, chunk_length)
        if (count <= chunk_length - start_off)
        {
            return ChunkRange{start_idx, start_off, end_idx, start_off + count};
        }

        // align to the next chunk
        count -= chunk_length - start_off;
        end_idx += 1 + (count / chunk_length);
        auto end_off = count % chunk_length;
        if (end_off == 0)
        {
            end_idx -= 1;
            end_off = chunk_length;
        }
        return ChunkRange{start_idx, start_off, end_idx, end_off};
    }

    // start_off, end_off: block offsets
    PageRange BlockPageRange(u64 start_off, u64 end_off) const
    {
        auto count = end_off - start_off;

        auto sidx = start_off / page_length;
        auto soff = u32(start_off % page_length);
        auto eidx = sidx;

        // sidx: [soff, page_length)
        if (count <= page_length - soff)
        {
            return PageRange{sidx, soff, eidx, u32(soff + count)};
        }

        // align to the next page
        count -= page_length - soff;
        eidx += 1 + (count / page_length);
        auto eoff = u32(count % page_length);
        if (eoff == 0)
        {
            eidx -= 1;
            eoff = page_length;
        }
        return PageRange{sidx, soff, eidx, eoff};
    }

    // chunks are not deleted (truncated when unmapped) so remember the last result
    // not thread safe
    size_t ChunkNewPart()
    {
        auto num_parts = part_dirname.size();
        for (auto new_part = part_current_new_; new_part < num_parts; ++new_part)
        {
            if (part_current_[new_part] < part_max[new_part])
            {
                part_current_new_ = new_part;
                return new_part;
            }
        }
        for (size_t new_part = 0; new_part < part_current_new_; ++new_part)
        {
            if (part_current_[new_part] < part_max[new_part])
            {
                part_current_new_ = new_part;
                return new_part;
            }
        }
        // not found (should not happen)
        return num_parts;
    }

    // get chunk handle (from pool)
    // no handle returned if chunk file is empty or does not exist
    DWORD ChunkOpen(u64 chunk_idx, bool is_write, FileHandle& handle_out)
    {
        if (chunk_idx >= chunk_count) { return ERROR_INVALID_PARAMETER; }

        // combination of GENERIC_READ and GENERIC_WRITE
        const auto desired_access = GENERIC_READ | (is_write ? GENERIC_WRITE : 0);

        // check pool and pull handle
        auto h = FileHandle();
        {
            auto g = SRWLockGuard(&lock_handles_, true);

            auto it = chunk_handles_.find(chunk_idx);
            if (it != chunk_handles_.end())
            {
                auto& dq = (*it).second;
                h = std::move(dq.back());
                dq.pop_back();
                if (dq.empty()) chunk_handles_.erase(it);
                --num_handles_;
            }
        }

        if (h)
        {
            // check access rights and reopen if necessary
            // GENERIC_READ  -> FILE_GENERIC_READ
            // GENERIC_WRITE -> FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES
            auto desired_flags = DWORD(FILE_READ_ATTRIBUTES);
            if (desired_access & GENERIC_READ)  desired_flags |= FILE_GENERIC_READ;
            if (desired_access & GENERIC_WRITE) desired_flags |= FILE_GENERIC_WRITE;

            auto flags = ACCESS_MASK();
            auto err = GetFileAccessFlags(h.get(), &flags);
            if (err != ERROR_SUCCESS) return err;
            if ((flags & desired_flags) == desired_flags)
            {
                handle_out = std::move(h);
                return ERROR_SUCCESS;
            }

            auto hnew = ReOpenFile(h.get(),
                                         desired_access,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         0);
            if (hnew == INVALID_HANDLE_VALUE) return GetLastError();
            handle_out.reset(hnew);
            return ERROR_SUCCESS;
        }

        // handle not in pool
        try
        {
            // check existence
            auto g = SRWLockGuard(&lock_parts_, true);

            auto part_it = chunk_parts_.find(chunk_idx);
            auto part_found = part_it != chunk_parts_.end();
            auto part_idx = part_found ? part_it->second : ChunkNewPart();

            auto path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
            h.reset(CreateFileW(path.data(),
                                  desired_access,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr));
            if (part_found != bool(h))
            {
                if (!part_found) return ERROR_FILE_EXISTS;
                auto err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND) return err;
            }
            if (!part_found && is_write)
            {
                h.reset(CreateFileW(path.data(),
                                      desired_access,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                      CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL,
                                      nullptr));
                if (!h) return GetLastError();

                ++part_current_[part_idx];
                chunk_parts_[chunk_idx] = part_idx;
            }

            // check size, extend if necessary
            if (h)
            {
                auto chunk_bytes = LONGLONG(chunk_length * block_size);
                if (chunk_bytes <= 0) return ERROR_ARITHMETIC_OVERFLOW;

                auto file_size = LARGE_INTEGER();
                if (!GetFileSizeEx(h.get(), &file_size)) return GetLastError();
                if (file_size.QuadPart != 0 && file_size.QuadPart != chunk_bytes) return ERROR_INCORRECT_SIZE;

                if (file_size.QuadPart == 0)
                {
                    if (!is_write)
                    {
                        h.reset();
                    }
                    else
                    {
                        file_size.QuadPart = chunk_bytes;
                        if (!SetFilePointerEx(h.get(), file_size, nullptr, FILE_BEGIN)) return GetLastError();
                        if (!SetEndOfFile(h.get())) return GetLastError();
                    }
                }
            }

            // empty or not present -> empty handle
            handle_out = std::move(h);
            return ERROR_SUCCESS;
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    // return handle to pool
    // old handles in the pool are closed automatically
    DWORD ChunkClose(u64 chunk_idx, FileHandle handle)
    {
        if (chunk_idx >= chunk_count) { return ERROR_INVALID_PARAMETER; }

        try
        {
            auto g = SRWLockGuard(&lock_handles_, true);

            while (num_handles_ >= max_handles)
            {
                auto it = chunk_handles_.begin();
                (*it).second.pop_front();
                if ((*it).second.empty()) chunk_handles_.erase(it);
                --num_handles_;
            }

            auto it = chunk_handles_.try_emplace(chunk_idx).first;
            (*it).second.push_back(std::move(handle));
            chunk_handles_.reinsert_back(it);
            ++num_handles_;
            return ERROR_SUCCESS;
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    // empty chunk
    DWORD ChunkUnmap(u64 chunk_idx)
    {
        if (chunk_idx >= chunk_count) { return ERROR_INVALID_PARAMETER; }

        auto gp = SRWLockGuard(&lock_parts_, false);

        auto part_it = chunk_parts_.find(chunk_idx);
        if (part_it == chunk_parts_.end()) return ERROR_SUCCESS; // not present

        // close handles in pool
        {
            auto gh = SRWLockGuard(&lock_handles_, true);

            auto handles_it = chunk_handles_.find(chunk_idx);
            if (handles_it != chunk_handles_.end())
            {
                auto nhandles = (*handles_it).second.size();
                chunk_handles_.erase(handles_it);
                num_handles_ -= nhandles;
            }
        }

        auto part_idx = part_it->second;
        auto path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
        auto h = FileHandle(CreateFileW(path.data(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) return GetLastError();
        if (!SetEndOfFile(h.get())) return GetLastError();

        return ERROR_SUCCESS;
    }

    // release resources for all chunks >= chunk_idx
    DWORD FlushAll(u64 chunk_idx = 0)
    {
        auto gh = SRWLockGuard(&lock_handles_, true);

        if (chunk_idx == 0)
        {
            chunk_handles_.clear();
            num_handles_ = 0;
        }
        else
        {
            for (auto it = chunk_handles_.begin(); it != chunk_handles_.end();)
            {
                auto [idx, dq] = *it;
                if (idx < chunk_idx) {
                    ++it;
                    continue;
                }

                auto count = dq.size();
                auto it_next = it;
                ++it_next;
                chunk_handles_.erase(it);
                num_handles_ -= count;
                it = it_next;
            }
        }

        auto gp = SRWLockGuard(&lock_pages_, true);

        for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
        {
            auto [idx, pe] = *it;
            if ((idx * page_length / chunk_length) < chunk_idx)
            {
                ++it;
                continue;
            }

            // wait for I/O to complete
            {
                auto gm = SRWLockGuard(&pe.lock, true);
            }
            auto it_next = it;
            ++it_next;
            cached_pages_.erase(it);
            it = it_next;
        }

        return ERROR_SUCCESS;
    }

    // get or create page for buffering
    // is_write: write or remove access to existing page
    AcquiredPage AcquirePage(u64 page_idx, bool is_write)
    {
        try
        {
            auto g1 = SRWLockGuard(&lock_pages_, false);
            auto it1 = cached_pages_.find(page_idx);
            auto is_hit = false;

            if (it1 == cached_pages_.end())
            {
                g1.reset();
                auto g2 = SRWLockGuard(&lock_pages_, true);

                // try to create page
                auto [it2, emplaced] = cached_pages_.try_emplace(page_idx);

                if (emplaced)
                {
                    (*it2).second.vmem.reset(VirtualAlloc(
                        nullptr, page_size, MEM_COMMIT, PAGE_READWRITE));

                    // try to evict
                    while (cached_pages_.size() > max_pages)
                    {
                        auto progress = false;
                        for (auto it3 = cached_pages_.begin(); it3 != cached_pages_.end();)
                        {
                            if (it3 == it2)
                            {
                                ++it3;
                                continue;
                            }

                            auto& entry = (*it3).second;
                            if (TryAcquireSRWLockExclusive(&entry.lock))
                            {
                                // page not in use for I/O
                                ReleaseSRWLockExclusive(&entry.lock);
                                auto it3_next = it3;
                                ++it3_next;
                                cached_pages_.erase(it3);
                                it3 = it3_next;
                                progress = true;
                                break;
                            }

                            ++it3;
                        }
                        if (!progress) break;
                    }
                }
                else
                {
                    is_hit = true;
                }

                it1 = it2;
                g1.reset(std::move(g2));
            }
            else
            {
                is_hit = true;
            }

            return AcquiredPage{
                ERROR_SUCCESS,
                SRWLockGuard(&((*it1).second.lock), is_hit ? is_write : true),
                (*it1).second.vmem.get(),
                is_write,
                is_hit};
        }
        catch (const bad_alloc&)
        {
            return AcquiredPage{.error = ERROR_NOT_ENOUGH_MEMORY};
        }
    }

    DWORD RemovePages(PageRange r)
    {
        auto gp = SRWLockGuard(&lock_pages_, true);

        if (cached_pages_.empty()) return ERROR_SUCCESS;

        for (auto i = r.start_idx; i <= r.end_idx; ++i)
        {
            auto it = cached_pages_.find(i);
            if (it == cached_pages_.end()) continue;

            // wait for I/O to complete
            {
                auto gm = SRWLockGuard(&((*it).second.lock), true);
            }
            cached_pages_.erase(it);
        }

        return ERROR_SUCCESS;
    }

    SPD_STORAGE_UNIT* storage_unit = nullptr;
    const u64 block_count = 0;            // disk size = block_count * block_size
    const u32 block_size = 0;             // in bytes
    const u64 chunk_count = 0;            // disk size = chunk_count * chunk_length * block_size
    const u64 chunk_length = 0;           // in blocks
    const vector<u64> part_max;           // part index -> max. # of chunks
    const vector<wstring> part_dirname;   // part index -> chunk directory

    const u32 max_handles = 1;

    const u32 page_size = 4096;              // in bytes
    const u32 page_length;                   // in blocks
    const u32 max_pages = 1;                 // may exceed if page is being used for I/O

private:
    vector<FileHandle> part_lock_;              // part index -> .lock

    SRWLOCK lock_parts_ = SRWLOCK_INIT;
    vector<u64> part_current_;                  // part index -> # of chunks
    size_t part_current_new_ = 0;               // part index for new chunks
    unordered_map<u64, size_t> chunk_parts_;    // chunk index -> part index

    SRWLOCK lock_handles_ = SRWLOCK_INIT;
    // push_back to add, pop_back to use, pop_front to evict
    // deque is not empty
    Map<u64, deque<FileHandle>> chunk_handles_;
    // total number of FileHandle's
    u32 num_handles_ = 0;

    SRWLOCK lock_pages_ = SRWLOCK_INIT;
    // 512 bytes sector -> 4096 bytes page (VirtualAlloc)
    // read cache, write through
    // push_back to add, pop_front to evict
    // TODO: reinsert_back() if hit
    Map<u64, PageEntry> cached_pages_;
};

static ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
}

// sense: 0 -> no sense, 1 -> read error, 2 -> write error
static void SetMediumError(SPD_STORAGE_UNIT_STATUS* status, i32 sense, bool addr_valid = false, u64 addr = 0)
{
    u8 asc;

    switch (sense)
    {
    case 1:
        asc = SCSI_ADSENSE_UNRECOVERED_ERROR;
        break;

    case 2:
        asc = SCSI_ADSENSE_WRITE_ERROR;
        break;

    default:
        asc = SCSI_ADSENSE_NO_SENSE;
        break;
    }

    SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR, asc, addr_valid ? &addr : nullptr);
}

// seek to the page before calling
// advance to the next page
static DWORD InternalReadPage(ChunkDisk* cdisk, HANDLE h,
                              PVOID& buffer, u64 page_idx, u32 start_off, u32 end_off,
                              SPD_STORAGE_UNIT_STATUS* Status)
{
    auto page = cdisk->AcquirePage(page_idx, false);
    if (page.error != ERROR_SUCCESS)
    {
        SetMediumError(Status, 1);
        return 1;
    }

    if (!page.is_hit)
    {
        auto length_read = DWORD();
        if (!ReadFile(h, page.ptr, cdisk->page_size, &length_read, nullptr)
            || length_read != cdisk->page_size)
        {
            SetMediumError(Status, 1, true,
                           page_idx * cdisk->page_length + (length_read + 1) / cdisk->block_size);
            return 2;
        }
    }
    else
    {
        // advance pointer as if read from file
        if (!SetFilePointerEx(h, LARGE_INTEGER{.QuadPart = cdisk->page_size}, nullptr, FILE_CURRENT))
        {
            SetMediumError(Status, 1);
            return 1;
        }
    }

    auto size = (end_off - start_off) * cdisk->block_size;
    memcpy(buffer, recast<u8*>(page.ptr) + u64(start_off) * cdisk->block_size, size);
    buffer = recast<u8*>(buffer) + size;
    return ERROR_SUCCESS;
}

// seek to the page before calling it
// advance to the next page
// buffer == nullptr for partial unmap
static DWORD InternalWritePage(ChunkDisk* cdisk, HANDLE h,
                               PVOID& buffer, u64 page_idx, u32 start_off, u32 end_off,
                               SPD_STORAGE_UNIT_STATUS* Status)
{
    auto sense = buffer != nullptr ? 2 : 0;

    auto page = cdisk->AcquirePage(page_idx, true);
    if (page.error != ERROR_SUCCESS)
    {
        SetMediumError(Status, sense);
        return 1;
    }

    if (!page.is_hit && (start_off != 0 || end_off != cdisk->page_length))
    {
        // writing to page partially, read it first
        auto pos = LARGE_INTEGER();
        if (!SetFilePointerEx(h, LARGE_INTEGER(), &pos, FILE_CURRENT))
        {
            SetMediumError(Status, sense, false);
            return 1;
        }

        auto length_read = DWORD();
        if (!ReadFile(h, page.ptr, cdisk->page_size, &length_read, nullptr)
            || length_read != cdisk->page_size)
        {
            SetMediumError(Status, sense, true,
                           page_idx * cdisk->page_length + (length_read + 1) / cdisk->block_size);
            return 2;
        }

        if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, sense, false);
            return 1;
        }
    }

    auto size = (end_off - start_off) * cdisk->block_size;
    if (buffer != nullptr)
    {
        memcpy(recast<u8*>(page.ptr) + u64(start_off) * cdisk->block_size, buffer, size);
    }
    else
    {
        memset(recast<u8*>(page.ptr) + u64(start_off) * cdisk->block_size, 0, size);
    }

    // write through
    auto length_written = DWORD();
    if (!WriteFile(h, page.ptr, cdisk->page_size, &length_written, nullptr)
        || length_written != cdisk->page_size)
    {
        SetMediumError(Status, sense, true,
                       page_idx * cdisk->page_length + (length_written + 1) / cdisk->block_size);
        return 2;
    }

    if (buffer != nullptr) buffer = recast<u8*>(buffer) + size;
    return ERROR_SUCCESS;
}

static DWORD InternalReadChunk(ChunkDisk* cdisk, PVOID& buffer,
                               u64 chunk_idx, u64 start_off, u64 end_off,
                               SPD_STORAGE_UNIT_STATUS* Status)
{
    auto h = FileHandle();
    auto err = cdisk->ChunkOpen(chunk_idx, false, h);
    if (err != ERROR_SUCCESS) return 1;

    auto length_bytes = (end_off - start_off) * cdisk->block_size;
    if (!h)
    {
        memset(buffer, 0, length_bytes);
        buffer = recast<u8*>(buffer) + length_bytes;
        return ERROR_SUCCESS;
    }

    auto r = cdisk->BlockPageRange(start_off, end_off);

    if (r.start_off == 0 && r.end_off == cdisk->page_length && (recast<size_t>(buffer) % cdisk->page_size) == 0)
    {
        // aligned to page
        cdisk->RemovePages(r);  // Windows caches buffer

        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(start_off * cdisk->block_size)};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, 1);
            return 1;
        }

        auto length_read = DWORD();
        if (!ReadFile(h.get(), buffer, DWORD(length_bytes), &length_read, nullptr)
            || length_bytes != length_read)
        {
            SetMediumError(Status, 1, true,
                           chunk_idx * cdisk->chunk_length + start_off + (length_read + 1) / cdisk->block_size);
            return 2;
        }
        buffer = recast<u8*>(buffer) + length_bytes;
    }
    else
    {
        // not aligned to page
        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(r.start_idx * cdisk->page_size)};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, 1);
            return 1;
        }

        auto base_idx = chunk_idx * cdisk->chunk_length / cdisk->page_length;
        err = InternalReadPage(
            cdisk, h.get(), buffer, base_idx + r.start_idx,
            r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->page_length, Status);
        if (err != ERROR_SUCCESS) return err;

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = InternalReadPage(
                    cdisk, h.get(), buffer, base_idx + i,
                    0, cdisk->page_length, Status);
                if (err != ERROR_SUCCESS) return err;
            }
            err = InternalReadPage(cdisk, h.get(), buffer, base_idx + r.end_idx,
                                   0, r.end_off, Status);
            if (err != ERROR_SUCCESS) return err;
        }
    }

    // we may discard h on error
    cdisk->ChunkClose(chunk_idx, std::move(h));
    return ERROR_SUCCESS;
}

// buffer == nullptr for partial unmap
static DWORD InternalWriteChunk(ChunkDisk* cdisk, PVOID& buffer,
                                u64 chunk_idx, u64 start_off, u64 end_off,
                                SPD_STORAGE_UNIT_STATUS* Status)
{
    auto sense = buffer != nullptr ? 2 : 0;

    auto h = FileHandle();
    auto err = cdisk->ChunkOpen(chunk_idx, true, h);
    if (err != ERROR_SUCCESS) return 1;

    auto length_bytes = (end_off - start_off) * cdisk->block_size;

    auto r = cdisk->BlockPageRange(start_off, end_off);

    if (r.start_off == 0 && r.end_off == cdisk->page_length && (recast<size_t>(buffer) % cdisk->page_size) == 0)
    {
        // aligned to page
        cdisk->RemovePages(r);  // Windows caches buffer

        if (buffer != nullptr)
        {
            auto off = LARGE_INTEGER{.QuadPart = LONGLONG(start_off * cdisk->block_size)};
            if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
            {
                SetMediumError(Status, sense);
                return 1;
            }

            auto length_written = DWORD();
            if (!WriteFile(h.get(), buffer, DWORD(length_bytes), &length_written, nullptr)
                || length_bytes != length_written)
            {
                SetMediumError(Status, sense, true,
                               chunk_idx * cdisk->chunk_length + start_off + (length_written + 1) / cdisk->block_size);
                return 2;
            }
            buffer = recast<u8*>(buffer) + length_bytes;
        }
        else
        {
            FILE_ZERO_DATA_INFORMATION zero_info;
            zero_info.FileOffset.QuadPart = LONGLONG(start_off * cdisk->block_size);
            zero_info.BeyondFinalZero.QuadPart = LONGLONG(end_off * cdisk->block_size);

            auto bytes_returned = DWORD();
            if (!DeviceIoControl(
                    h.get(), FSCTL_SET_ZERO_DATA, &zero_info, sizeof(zero_info),
                    nullptr, 0, &bytes_returned, nullptr))
            {
                SetMediumError(Status, sense);
                return 1;
            }
        }
    }
    else
    {
        // not aligned to page
        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(r.start_idx * cdisk->page_size)};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, sense);
            return 1;
        }

        auto base_idx = chunk_idx * cdisk->chunk_length / cdisk->page_length;
        err = InternalWritePage(
            cdisk, h.get(), buffer, base_idx + r.start_idx,
            r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->page_length, Status);
        if (err != ERROR_SUCCESS) return err;

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = InternalWritePage(
                    cdisk, h.get(), buffer, base_idx + i,
                    0, cdisk->page_length, Status);
                if (err != ERROR_SUCCESS) return err;
            }
            err = InternalWritePage(cdisk, h.get(), buffer, base_idx + r.end_idx,
                                   0, r.end_off, Status);
            if (err != ERROR_SUCCESS) return err;
        }
    }

    // we may discard h on error
    cdisk->ChunkClose(chunk_idx, std::move(h));
    return ERROR_SUCCESS;
}

static DWORD InternalFlushChunk(ChunkDisk* cdisk, u64 chunk_idx,
                                u64 start_off, u64 end_off, SPD_STORAGE_UNIT_STATUS* Status)
{
    if (start_off == 0 && end_off == cdisk->chunk_length)
    {
        // flush metadata
        auto h = FileHandle();
        auto err = cdisk->ChunkOpen(chunk_idx, true, h);
        if (err != ERROR_SUCCESS)
        {
            SetMediumError(Status, 2);
            return 1;
        }

        if (!FlushFileBuffers(h.get()))
        {
            SetMediumError(Status, 2);
            return 1;
        }
        // we may discard h on error
        cdisk->ChunkClose(chunk_idx, std::move(h));
    }

    // let Windows flush
    return ERROR_SUCCESS;
}

static DWORD InternalUnmapChunk(ChunkDisk* cdisk, u64 chunk_idx,
                                u64 start_off, u64 end_off, SPD_STORAGE_UNIT_STATUS* Status)
{
    if (start_off == 0 && end_off == cdisk->chunk_length) return cdisk->ChunkUnmap(chunk_idx);

    PVOID buffer = nullptr;
    return InternalWriteChunk(cdisk, buffer, chunk_idx, start_off, end_off, Status);
}

static BOOLEAN InternalFlush(SPD_STORAGE_UNIT* StorageUnit,
                             UINT64 BlockAddress, UINT32 BlockCount,
                             SPD_STORAGE_UNIT_STATUS* Status)
{
    auto* cdisk = StorageUnitChunkDisk(StorageUnit);
    if (BlockCount == 0)
    {
        // for simpliciy ignore BlockAddress % cdisk->chunk_length
        // let Windows flush
        if (cdisk->FlushAll(BlockAddress / cdisk->chunk_length) != ERROR_SUCCESS)
        {
            SetMediumError(Status, 2);
        }
        return TRUE;
    }

    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalFlushChunk(
        cdisk, r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalFlushChunk(cdisk, i, 0, cdisk->chunk_length, Status);
            if (err != ERROR_SUCCESS) return TRUE;
        }
        err = InternalFlushChunk(cdisk, r.end_idx, 0, r.end_off, Status);
        if (err != ERROR_SUCCESS) return TRUE;
    }

    return TRUE;
}

static BOOLEAN Read(SPD_STORAGE_UNIT* StorageUnit,
                    PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                    SPD_STORAGE_UNIT_STATUS* Status)
{
    WARNONCE(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    if (FlushFlag)
    {
        InternalFlush(StorageUnit, BlockAddress, BlockCount, Status);
        if (Status->ScsiStatus != SCSISTAT_GOOD)
            return TRUE;
    }

    auto* cdisk = StorageUnitChunkDisk(StorageUnit);
    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalReadChunk(
        cdisk, Buffer,
        r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalReadChunk(cdisk, Buffer, i, 0, cdisk->chunk_length, Status);
            if (err != ERROR_SUCCESS) return TRUE;
        }
        err = InternalReadChunk(cdisk, Buffer, r.end_idx, 0, r.end_off, Status);
        if (err != ERROR_SUCCESS) return TRUE;
    }

    return TRUE;
}

static BOOLEAN Write(SPD_STORAGE_UNIT* StorageUnit,
                     PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    WARNONCE(!StorageUnit->StorageUnitParams.WriteProtected);
    WARNONCE(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    auto* cdisk = StorageUnitChunkDisk(StorageUnit);
    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalWriteChunk(
        cdisk, Buffer,
        r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalWriteChunk(cdisk, Buffer, i, 0, cdisk->chunk_length, Status);
            if (err != ERROR_SUCCESS) return TRUE;
        }
        err = InternalWriteChunk(cdisk, Buffer, r.end_idx, 0, r.end_off, Status);
        if (err != ERROR_SUCCESS) return TRUE;
    }

    if (Status->ScsiStatus == SCSISTAT_GOOD && FlushFlag)
    {
        InternalFlush(StorageUnit, BlockAddress, BlockCount, Status);
    }
    return TRUE;
}

static BOOLEAN Flush(SPD_STORAGE_UNIT* StorageUnit,
                     UINT64 BlockAddress, UINT32 BlockCount,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    WARNONCE(!StorageUnit->StorageUnitParams.WriteProtected);
    WARNONCE(StorageUnit->StorageUnitParams.CacheSupported);

    return InternalFlush(StorageUnit, BlockAddress, BlockCount, Status);
}

static BOOLEAN Unmap(SPD_STORAGE_UNIT* StorageUnit,
                     SPD_UNMAP_DESCRIPTOR Descriptors[], UINT32 Count,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    WARNONCE(!StorageUnit->StorageUnitParams.WriteProtected);
    WARNONCE(StorageUnit->StorageUnitParams.UnmapSupported);

    auto* cdisk = StorageUnitChunkDisk(StorageUnit);

    for (UINT32 I = 0; I < Count; ++I)
    {
        // NOTE: a chunk gets truncated only if single block range covers it
        auto r = cdisk->BlockChunkRange(Descriptors[I].BlockAddress, Descriptors[I].BlockCount);

        // no buffer to track
        // abort zero filling a chunk if error
        InternalUnmapChunk(cdisk,
            r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length, Status);

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                InternalUnmapChunk(cdisk, i, 0, cdisk->chunk_length, Status);
            }
            InternalUnmapChunk(cdisk, r.end_idx, 0, r.end_off, Status);
        }
    }

    return TRUE;
}

static SPD_STORAGE_UNIT_INTERFACE CHUNK_DISK_INTERFACE =
{
    Read,
    Write,
    Flush,
    Unmap,
};

/*
 * read .chunkdisk file
 *
 * disk size in bytes: must be a multiple of 512
 * chunk size in bytes: must be a multiple of 512
 * number path/to/dir...: max. # of chunks in part directory
 */
static DWORD ReadChunkDiskFile(PCWSTR cdisk_path, DWORD thread_count, unique_ptr<ChunkDisk>& cdisk)
{
    try
    {
        // read .chunkdisk and convert to wstr
        auto h = FileHandle(CreateFileW(
            cdisk_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) return GetLastError();

        auto size = LARGE_INTEGER();
        if (!GetFileSizeEx(h.get(), &size)) return GetLastError();
        if (size.HighPart != 0) return ERROR_ARITHMETIC_OVERFLOW;
        if (size.LowPart == 0) return ERROR_INVALID_PARAMETER;

        auto buf = unique_ptr<u8[]>(new u8[size_t(size.LowPart)]);
        auto bytes_read = DWORD();
        if (!ReadFile(h.get(), buf.get(), size.LowPart, &bytes_read, nullptr)) return GetLastError();

        auto wbuf = wstring();
        auto err = ConvertUTF8(buf.get(), bytes_read, wbuf);
        if (err != ERROR_SUCCESS) return err;

        // parse .chunkdisk
        buf.reset();

        // disk size
        auto* state = PWSTR();
        auto* token = wcstok_s(wbuf.data(), L"\n", &state);
        auto* endp = PWSTR();
        if (!token) return ERROR_INVALID_PARAMETER;
        auto disk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // chunk size
        token = wcstok_s(nullptr, L"\n", &state);
        if (!token) return ERROR_INVALID_PARAMETER;
        auto chunk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // parts
        auto part_max = vector<u64>();
        auto part_dirname = vector<wstring>();

        token = wcstok_s(nullptr, L"\n", &state);
        for (; token; token = wcstok_s(nullptr, L"\n", &state))
        {
            auto pmax = wcstoull(token, &endp, 10);
            if (token == endp || *endp != L' ' || errno == ERANGE) return ERROR_INVALID_PARAMETER;

            auto dirname = wstring(endp + 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\r') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\\') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'/')  dirname.erase(dirname.size() - 1);
            auto dirpath = fs::path(std::move(dirname));
            if (!dirpath.is_absolute()) return ERROR_INVALID_PARAMETER;

            part_max.push_back(pmax);
            part_dirname.emplace_back(dirpath.wstring());
        }

        // check parameters
        const auto block_size = u32(512);
        if (disk_size == 0 || chunk_size == 0) return ERROR_INVALID_PARAMETER;
        if (disk_size % block_size || chunk_size > disk_size) return ERROR_INVALID_PARAMETER;
        if (chunk_size % block_size) return ERROR_INVALID_PARAMETER;

        auto chunk_count = (disk_size + (chunk_size - 1)) / chunk_size;
        if (chunk_count == 0) return ERROR_INVALID_PARAMETER;
        if (chunk_count > std::accumulate(part_max.begin(), part_max.end(), 0ull)) return ERROR_INVALID_PARAMETER;
        auto chunk_length = chunk_size / block_size;

        if (thread_count == 0)
        {
            err = GetThreadCount(&thread_count);
            if (err != ERROR_SUCCESS) return err;
        }

        auto new_disk = std::make_unique<ChunkDisk>(
            disk_size / block_size,
            block_size,
            chunk_count,
            chunk_length,
            std::move(part_max),
            std::move(part_dirname),
            max(thread_count * 32, 2048),
            max(thread_count * 2, 128));

        if (disk_size % new_disk->page_size) return ERROR_INVALID_PARAMETER;
        if (chunk_size % new_disk->page_size) return ERROR_INVALID_PARAMETER;
        if (new_disk->page_size % block_size) return ERROR_INVALID_PARAMETER;

        cdisk = std::move(new_disk);
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

// align buffer to pages
static PVOID BufferAlloc(size_t Size)
{
    return VirtualAlloc(nullptr, Size, MEM_COMMIT, PAGE_READWRITE);
}

// align buffer to pages
static void BufferFree(PVOID Pointer)
{
    VirtualFree(Pointer, 0, MEM_RELEASE);
}

static DWORD CreateChunkDiskStorageUnit(ChunkDisk* cdisk, BOOLEAN write_protected, PWSTR pipe_name)
{
    const wchar_t ProductId[] = L"ChunkDisk";
    const wchar_t ProductRevision[] = L"0.6";
    SPD_STORAGE_UNIT_PARAMS unit_params;

    memset(&unit_params, 0, sizeof unit_params);
    UuidCreate(&unit_params.Guid);
    unit_params.BlockCount = cdisk->block_count;
    unit_params.BlockLength = cdisk->block_size;
    unit_params.MaxTransferLength = 64 * 1024;
    if (WideCharToMultiByte(
            CP_UTF8, 0,
            ProductId, lstrlenW(ProductId),
            LPSTR(unit_params.ProductId), sizeof(unit_params.ProductId),
            nullptr, nullptr) == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (WideCharToMultiByte(
            CP_UTF8, 0,
            ProductRevision, lstrlenW(ProductRevision),
            LPSTR(unit_params.ProductRevisionLevel), sizeof(unit_params.ProductRevisionLevel),
            nullptr, nullptr) == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    unit_params.WriteProtected = write_protected;
    unit_params.CacheSupported = TRUE;
    unit_params.UnmapSupported = TRUE;

    SPD_STORAGE_UNIT* unit = nullptr;
    auto err = SpdStorageUnitCreate(pipe_name, &unit_params, &CHUNK_DISK_INTERFACE, &unit);
    if (err != ERROR_SUCCESS) return err;
    SpdStorageUnitSetBufferAllocator(unit, BufferAlloc, BufferFree);

    cdisk->storage_unit = unit;
    unit->UserContext = cdisk;
    return ERROR_SUCCESS;
}

static constexpr PCWSTR PROGNAME = L"chunkdisk";

[[noreturn]] static void usage()
{
    static WCHAR usage[] = L""
        "usage: %s OPTIONS\n"
        "\n"
        "options:\n"
        "    -f ChunkDiskFile                    Chunkdisk metadata file (name.chunkdisk)\n"
        "    -W 0|1                              Disable/enable writes (deflt: enable)\n"
        "    -t Number                           Number of threads (deflt: automatic)\n"
        "    -d -1                               Debug flags\n"
        "    -D DebugLogFile                     Debug log file; - for stderr\n"
        "    -p \\\\.\\pipe\\PipeName                Listen on pipe; omit to use driver\n"
        "";

    logerr(usage, PROGNAME);
    ExitProcess(ERROR_INVALID_PARAMETER);
}

static ULONG argtol(wchar_t** argp, ULONG deflt)
{
    if (argp[0] == nullptr)
        usage();

    PWSTR endp;
    ULONG ul = wcstol(argp[0], &endp, 10);
    return argp[0][0] != L'\0' && *endp == L'\0' ? ul : deflt;
}

static PWSTR argtos(wchar_t** argp)
{
    if (argp[0] == nullptr)
        usage();

    return argp[0];
}

static SPD_GUARD ConsoleCtrlGuard = SPD_GUARD_INIT;

static BOOL WINAPI ConsoleCtrlHandler(DWORD CtrlType)
{
    SpdGuardExecute(&ConsoleCtrlGuard, recast<void(*)(PVOID)>(SpdStorageUnitShutdown));
    return TRUE;
}

int wmain(int argc, wchar_t** argv)
{
    wchar_t** argp;
    PWSTR ChunkDiskFile = nullptr;
    ULONG WriteAllowed = 1;
    ULONG NumThreads = 0;
    PWSTR DebugLogFile = nullptr;
    PWSTR PipeName = nullptr;
    ULONG DebugFlags = 0;

    for (argp = argv + 1; argp[0] != nullptr; argp++)
    {
        if (argp[0][0] != L'-')
            break;
        switch (argp[0][1])
        {
        case L'?':
            usage();
        case L'f':
            ChunkDiskFile = argtos(++argp);
            break;
        case L'W':
            WriteAllowed = argtol(++argp, WriteAllowed);
            break;
        case L't':
            NumThreads = argtol(++argp, NumThreads);
            break;
        case L'd':
            DebugFlags = argtol(++argp, DebugFlags);
            break;
        case L'D':
            DebugLogFile = argtos(++argp);
            break;
        case L'p':
            PipeName = argtos(++argp);
            break;
        default:
            usage();
        }
    }

    if (argp[0] != nullptr || ChunkDiskFile == nullptr)
        usage();

    HANDLE DebugLogHandle;
    DWORD err;

    if (DebugLogFile != nullptr)
    {
        if (DebugLogFile[0] == L'-' && DebugLogFile[1] == L'\0')
            DebugLogHandle = GetStdHandle(STD_ERROR_HANDLE);
        else
            DebugLogHandle = CreateFileW(
                DebugLogFile,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
        if (INVALID_HANDLE_VALUE == DebugLogHandle) {
            err = GetLastError();
            logerr(L"error: cannot open debug log file");
            return err;
        }
        SpdDebugLogSetHandle(DebugLogHandle);
    }

    unique_ptr<ChunkDisk> cdisk;
    err = ReadChunkDiskFile(ChunkDiskFile, NumThreads, cdisk);
    if (err != ERROR_SUCCESS)
    {
        logerr(L"error: parsing failed with error %lu", err);
        return err;
    }
    err = cdisk->LockParts();
    if (err != ERROR_SUCCESS)
    {
        logerr(L"error: cannot lock parts: error %lu", err);
        return err;
    }
    err = cdisk->ReadParts();
    if (err != ERROR_SUCCESS)
    {
        logerr(L"error: cannot initialize ChunkDisk: error %lu", err);
        return err;
    }
    err = CreateChunkDiskStorageUnit(cdisk.get(), !WriteAllowed, PipeName);
    if (err != ERROR_SUCCESS)
    {
        logerr(L"error: cannot create ChunkDisk: error %lu", err);
        return err;
    }
    SpdStorageUnitSetDebugLog(cdisk->storage_unit, DebugFlags);
    err = SpdStorageUnitStartDispatcher(cdisk->storage_unit, NumThreads);
    if (err != ERROR_SUCCESS)
    {
        logerr(L"error: cannot start ChunkDisk: error %lu", err);
        return err;
    }

    info(L"%s -f %s -W %u -t %d%s%s",
        PROGNAME,
        ChunkDiskFile,
        !!WriteAllowed,
        NumThreads,
        nullptr != PipeName ? L" -p " : L"",
        nullptr != PipeName ? PipeName : L"");

    SpdGuardSet(&ConsoleCtrlGuard, cdisk->storage_unit);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    SpdStorageUnitWaitDispatcher(cdisk->storage_unit);
    SpdGuardSet(&ConsoleCtrlGuard, nullptr);

    cdisk.reset();
    return ERROR_SUCCESS;
}
