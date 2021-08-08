/**
 * @file chunkdisk.cpp
 *
 * @copyright 2021 extratype
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
#include <thread>
#include <filesystem>
#include <winspd/winspd.h>

// FIXME separate modules
// FIXME static -> anonymous namespace
// FIXME docs

template <class T, class U>
static constexpr T recast(U arg)
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
            return make_pair(std::ref(p.first), std::ref(p.second.val));
        }

        auto operator++() noexcept
        {
            // follow key_order_
            auto vit = it_->second.it;
            it_ = (++vit == end_it_) ? map_->end() : map_->find(**vit);
            return *this;
        }

        bool operator==(const iterator& other) const noexcept
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
        return make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(const KT& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(k, std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    template <class... Args>
    auto try_emplace(KT&& k, Args&&... args)
    {
        auto [it, emplaced] = map_.try_emplace(std::move(k), std::forward<Args>(args)...);
        if (emplaced) it->second.it = key_order_.emplace(key_order_.end(), &it->first);
        return make_pair(iterator(&map_, it, key_order_.end()), emplaced);
    }

    // invalidates only key_order_ iterator
    void reinsert_front(iterator it)
    {
        key_order_.splice(key_order_.begin(), key_order_, it.it_->second.it);
        it.it_->second.it = key_order_.begin();
    }

    // invalidates only key_order_ iterator
    void reinsert_back(iterator it)
    {
        key_order_.splice(key_order_.end(), key_order_, it.it_->second.it);
        it.it_->second.it = --key_order_.end();
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

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask)) return GetLastError();
    for (Result = 0; 0 != ProcessMask; ProcessMask >>= 1) Result += ProcessMask & 1;
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

template <class... Ts>
static void info(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_INFORMATION_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
static void warn(PCWSTR format, Ts&&... args)
{
    SpdServiceLog(EVENTLOG_WARNING_TYPE, const_cast<PWSTR>(format), std::forward<Ts>(args)...);
}

template <class... Ts>
static void logerr(PCWSTR format, Ts&&... args)
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
using GenericHandle = unique_ptr<void, HandleDeleter>;

// reset to INVALID_HANDLE_VALUE
using FileHandle = unique_ptr<void, FileHandleDeleter>;

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

void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc)
{
    status->ScsiStatus = SCSISTAT_CHECK_CONDITION;
    status->SenseKey = sense_key;
    status->ASC = asc;
}

void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc, u64 info)
{
    SetScsiStatus(status, sense_key, asc);
    status->Information = info;
    status->InformationValid = 1;
}

// FIXME constants
constexpr auto BLOCK_SIZE = u32(512);
constexpr auto PAGE_SIZE = u32(4096);
constexpr auto STANDBY_MS = u32(60000);
constexpr auto MAX_TRANSFER_LENGTH = u32(64 * 1024);    // FIXME must be a multiple of PAGE_SIZE
constexpr auto MAX_QD = u32(32);    // QD32

// [start_idx, end_idx], [start_off, end_off), 0 < end_off <= chunk_length
struct ChunkRange
{
    u64 start_idx;
    u64 start_off;
    u64 end_idx;
    u64 end_off;
};

// base_idx + [start_idx, end_idx], [start_off, end_off), 0 < end_off <= page_length
struct PageRange
{
    u64 base_idx;
    u64 start_idx;
    u32 start_off;
    u64 end_idx;
    u32 end_off;
};

struct PagesDeleter
{
    void operator()(LPVOID p) noexcept
    {
        VirtualFree(p, 0, MEM_RELEASE);
    }
};

using Pages = unique_ptr<void, PagesDeleter>;

struct PageEntry
{
    Pages mem;
    // acquire it while using mem
    SRWLOCK lock = SRWLOCK_INIT;
    // thread ID owning lock exclusively
    // ID 0 is in use by Windows kernel
    // not safe if compared to other threads
    DWORD owner = 0;
    // custom pointer for owning thread
    void* user = nullptr;
};

// Don't upcast a pointer to SRWLockGuard
class PageGuard : public SRWLockGuard
{
public:
    PageGuard() : SRWLockGuard() {}

    explicit PageGuard(PageEntry* entry, bool is_exclusive)
        : SRWLockGuard(&entry->lock, is_exclusive)
    {
        if (is_exclusive) entry->owner = GetCurrentThreadId();
    }

    ~PageGuard() { reset(); }

    PageGuard(PageGuard&& other) noexcept : PageGuard() { swap(*this, other); }

    void reset()
    {
        if (!*this) return;
        if (is_exclusive()) page_entry()->owner = 0;
        SRWLockGuard::reset();
    }

    // release *this and take the ownership of other
    void reset(PageGuard&& other) { swap(*this, other); }

private:
    PageEntry* page_entry() { return CONTAINING_RECORD(lock_, PageEntry, lock); }
};

// current thread only
// should be local
struct PageResult
{
    DWORD error;                    // page invalid if not ERROR_SUCCESS
    PageGuard guard;                // hold while using ptr
    LPVOID ptr = nullptr;           // size: ChunkDiskParam::PageBytes(1)
    void** user = nullptr;          // &PageEntry::user
};

struct ChunkDiskParam
{
    u32 block_size = 0;             // in bytes
    u32 page_length = 0;            // in blocks
    u64 block_count = 0;            // disk size = block_count * block_size
    u64 chunk_length = 0;           // in blocks
    u64 chunk_count = 0;            // disk size = chunk_count * chunk_length * block_size
    vector<u64> part_max;           // part index -> max. # of chunks
    vector<wstring> part_dirname;   // part index -> chunk directory

    // unit conversions

    u64 BlockBytes(u64 count) const { return block_size * count; }

    auto ByteBlock(u64 addr) const { return make_pair(addr / block_size, addr % block_size); }

    u64 PageBlocks(u64 count) const { return page_length * count; }

    u64 PageBytes(u64 count) const { return BlockBytes(PageBlocks(count)); }

    u64 ChunkBlocks(u64 count) const { return chunk_length * count; }

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

    bool IsWholeChunk(u64 start_off, u64 end_off) const { return start_off == 0 && end_off == chunk_length; }

    // start_off, end_off: block offsets
    PageRange BlockPageRange(u64 chunk_idx, u64 start_off, u64 end_off) const
    {
        auto base_idx = chunk_idx * (chunk_length / page_length);
        auto count = end_off - start_off;

        auto sidx = start_off / page_length;
        auto soff = u32(start_off % page_length);
        auto eidx = sidx;

        // sidx: [soff, page_length)
        if (count <= page_length - soff)
        {
            return PageRange{base_idx, sidx, soff, eidx, u32(soff + count)};
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
        return PageRange{base_idx, sidx, soff, eidx, eoff};
    }

    // PageRange::start_off, PageRange::end_off
    bool IsPageAligned(u64 start_off, u64 end_off, PVOID buffer = nullptr) const
    {
        return start_off == 0 && (end_off == 0 || end_off == page_length) &&
               (buffer == nullptr || recast<size_t>(buffer) % PageBytes(1) == 0);
    }
};

/*
 * read .chunkdisk file
 *
 * disk size in bytes: must be a multiple of PAGE_SIZE
 * chunk size in bytes: must be a multiple of PAGE_SIZE
 * number path/to/dir...: max. # of chunks in part directory
 */
static DWORD ReadChunkDiskParam(PCWSTR cdisk_path, ChunkDiskParam& param)
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

        if (disk_size == 0 || chunk_size == 0) return ERROR_INVALID_PARAMETER;
        if (disk_size % BLOCK_SIZE || chunk_size > disk_size) return ERROR_INVALID_PARAMETER;
        if (chunk_size % BLOCK_SIZE) return ERROR_INVALID_PARAMETER;

        auto chunk_count = (disk_size + (chunk_size - 1)) / chunk_size;
        if (chunk_count == 0) return ERROR_INVALID_PARAMETER;
        if (chunk_count > std::accumulate(part_max.begin(), part_max.end(), 0ull)) return ERROR_INVALID_PARAMETER;
        auto chunk_length = chunk_size / BLOCK_SIZE;

        if (disk_size % PAGE_SIZE) return ERROR_INVALID_PARAMETER;
        if (chunk_size % PAGE_SIZE) return ERROR_INVALID_PARAMETER;
        // if (page_size % block_size) return ERROR_INVALID_PARAMETER;

        param.block_size = BLOCK_SIZE;
        param.page_length = PAGE_SIZE / BLOCK_SIZE;
        param.block_count = disk_size / BLOCK_SIZE;
        param.chunk_length = chunk_length;
        param.chunk_count = chunk_count;
        param.part_max = std::move(part_max);
        param.part_dirname = std::move(part_dirname);
        return ERROR_SUCCESS;
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

enum ChunkOpKind : u32
{
    READ_CHUNK,
    WRITE_CHUNK,
    READ_PAGE,              // not aligned, read in pages
    WRITE_PAGE,             // not aligned, write in pages
    WRITE_PAGE_PARTIAL,     // not page aligned, read then write in pages
    UNMAP_CHUNK
};

enum ChunkOpStep : u32
{
    OP_READY = 0,       // op created
    OP_DONE,            // completed or error
    OP_HIT_PAGE,        // for WRITE_PAGE_PARTIAL, page hit, will be written
    OP_READ_PAGE        // for WRITE_PAGE_PARTIAL, page read, will be written
};

class ChunkDisk
{
public:
    // max_handles, max_pages: MUST be positive
    ChunkDisk(ChunkDiskParam param, u32 max_pages)
            : param(std::move(param)), max_pages(max_pages)
    {
        cached_pages_.reserve(max_pages);
    }

    ~ChunkDisk()
    {
        // FIXME stop workers
        FlushAll();
        if (storage_unit != nullptr) SpdStorageUnitDelete(storage_unit);
    }

    // put a lock file to prevent accidental double use
    DWORD LockParts()
    {
        auto num_parts = param.part_dirname.size();

        try
        {
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto path = param.part_dirname[i] + L"\\.lock";
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
        // from param.part_max, param.part_dirname...
        auto num_parts = param.part_dirname.size();

        try
        {
            // make sure parts exist, no dups
            auto part_ids = unordered_set<std::pair<u32, u64>, pair_hash>();
            for (size_t i = 0; i < num_parts; ++i)
            {
                auto h = FileHandle(CreateFileW(
                    (param.part_dirname[i] + L'\\').data(),
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
                for (auto& p : fs::directory_iterator(param.part_dirname[i] + L'\\'))
                {
                    auto fname = p.path().filename().wstring();
                    if (_wcsnicmp(fname.data(), L"chunk", 5) != 0) continue;

                    auto* endp = PWSTR();
                    auto idx = wcstoull(fname.data() + 5, &endp, 10);
                    if (fname.data() + 5 == endp || *endp != L'\0' || errno == ERANGE || idx >= param.chunk_count) continue;

                    if (!chunk_parts.emplace(idx, i).second) return ERROR_FILE_EXISTS;
                    if (++part_current[i] > param.part_max[i]) return ERROR_PARAMETER_QUOTA_EXCEEDED;
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

    // open chunk file HANDLE; unbuffered asynchronous I/O
    // no handle returned if chunk file is empty or does not exist if !is_write
    // create chunk file if is_write
    DWORD CreateChunk(u64 chunk_idx, bool is_write, FileHandle& handle_out)
    {
        try
        {
            // check existence
            auto g = SRWLockGuard(&lock_parts_, true);

            auto part_it = chunk_parts_.find(chunk_idx);
            auto part_found = part_it != chunk_parts_.end();
            // chunks are not deleted (truncated when unmapped) so remember the last result
            auto part_idx = part_found ? part_it->second : ([this]() -> size_t
                {
                    auto num_parts = param.part_dirname.size();
                    for (auto new_part = part_current_new_; new_part < num_parts; ++new_part)
                    {
                        if (part_current_[new_part] < param.part_max[new_part])
                        {
                            part_current_new_ = new_part;
                            return new_part;
                        }
                    }
                    for (size_t new_part = 0; new_part < part_current_new_; ++new_part)
                    {
                        if (part_current_[new_part] < param.part_max[new_part])
                        {
                            part_current_new_ = new_part;
                            return new_part;
                        }
                    }
                    // not found (should not happen)
                    return num_parts;
                })();

            auto path = param.part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
            const auto desired_access = GENERIC_READ | (is_write ? GENERIC_WRITE : 0);
            // multiple threads may use the same file
            auto h = FileHandle(CreateFileW(
                path.data(), desired_access,FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, nullptr));
            if (part_found != bool(h))
            {
                // inconsistent
                if (!part_found) return ERROR_FILE_EXISTS;
                auto err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND) return err;
            }
            if (!part_found && is_write)
            {
                h.reset(CreateFileW(
                    path.data(), desired_access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, nullptr));
                if (!h) return GetLastError();

                ++part_current_[part_idx];
                chunk_parts_[chunk_idx] = part_idx;
            }

            // check size, extend if necessary
            if (h)
            {
                auto chunk_bytes = LONGLONG(param.BlockBytes(param.ChunkBlocks(1)));
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
                        // This just reserves disk space and sets file length on NTFS.
                        // Writing to the file actually extends the physical data, but synchronously.
                        // See https://devblogs.microsoft.com/oldnewthing/20150710-00/?p=45171.
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

    // empty chunk (done immediately)
    DWORD UnmapChunk(u64 chunk_idx)
    {
        auto gp = SRWLockGuard(&lock_parts_, false);

        auto part_it = chunk_parts_.find(chunk_idx);
        if (part_it == chunk_parts_.end()) return ERROR_SUCCESS; // not present

        auto part_idx = part_it->second;
        auto path = param.part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
        auto h = FileHandle(CreateFileW(path.data(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, nullptr));
        if (!h)
        {
            auto err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
            return err;
        }
        if (!SetEndOfFile(h.get())) return GetLastError();

        return ERROR_SUCCESS;
    }

    // FIXME check busy
    // FIXME -> worker
    // release resources for all chunks >= chunk_idx
    DWORD FlushAll(u64 chunk_idx = 0)
    {
        auto gp = SRWLockGuard(&lock_pages_, true);

        for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
        {
            auto [idx, pe] = *it;
            if ((idx * param.page_length) / param.chunk_length < chunk_idx)
            {
                ++it;
                continue;
            }

            // wait for I/O to complete FIXME PageGuard
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

    // acquire shared lock for reading an existing page
    PageResult PeekPage(u64 page_idx)
    {
        auto g = SRWLockGuard(&lock_pages_, false);
        auto it = cached_pages_.find(page_idx);
        if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};

        auto& entry = (*it).second;
        if (entry.owner == GetCurrentThreadId()) return PageResult{ERROR_BUSY};
        return PageResult{
            ERROR_SUCCESS,
            PageGuard(&entry, false),
            (*it).second.mem.get()};
    }

    // set exclusive lock for updating a page
    // the calling thread must FreePage() later
    PageResult LockPage(u64 page_idx)
    {
        // try to keep < max_pages
        auto trim_pages = [this]()
        {
            while (cached_pages_.size() >= max_pages)
            {
                auto progress = false;
                for (auto it = cached_pages_.begin(); it != cached_pages_.end();)
                {
                    auto& entry = (*it).second;
                    if (entry.owner == GetCurrentThreadId())
                    {
                        ++it;
                        continue;
                    }
                    if (!TryAcquireSRWLockExclusive(&entry.lock))
                    {
                        ++it;
                        continue;
                    }
                    ReleaseSRWLockExclusive(&entry.lock);
                    auto it_next = it;
                    ++it_next;
                    cached_pages_.erase(it);
                    it = it_next;
                    progress = true;
                    break;
                }
                if (!progress) break;
            }
        };

        try
        {
            // will reinsert_back() if hit
            auto g = SRWLockGuard(&lock_pages_, true);
            auto it = cached_pages_.find(page_idx);
            auto is_hit = false;

            if (it == cached_pages_.end())
            {
                trim_pages();

                it = cached_pages_.emplace(page_idx).first;
                auto mem = VirtualAlloc(nullptr, param.PageBytes(1), MEM_COMMIT, PAGE_READWRITE);
                if (mem == nullptr) return PageResult{ERROR_NOT_ENOUGH_MEMORY};
                (*it).second.mem.reset(mem);
            }
            else
            {
                is_hit = true;
                cached_pages_.reinsert_back(it);
            }

            auto& entry = (*it).second;
            if (entry.owner == GetCurrentThreadId()) return PageResult{.error = ERROR_BUSY, .user = &entry.user};
            AcquireSRWLockExclusive(&entry.lock);
            entry.owner = GetCurrentThreadId();
            return PageResult{
                ERROR_SUCCESS,
                PageGuard(),
                entry.mem.get(),
                &entry.user};
        }
        catch (const bad_alloc&)
        {
            return PageResult{ERROR_NOT_ENOUGH_MEMORY};
        }
    }

    // get LockPage() result for the thread that have called it
    PageResult ClaimPage(u64 page_idx)
    {
        auto g = SRWLockGuard(&lock_pages_, false);
        auto it = cached_pages_.find(page_idx);
        if (it == cached_pages_.end()) return PageResult{ERROR_NOT_FOUND};
        auto& entry = (*it).second;
        if (entry.owner != GetCurrentThreadId()) return PageResult{ERROR_INVALID_STATE};
        return PageResult{ERROR_SUCCESS, PageGuard(), entry.mem.get(), &entry.user};
    }

    // clear the lock and optionally remove the page
    // the calling thread must have successfully called LockPage()
    void FreePage(u64 page_idx, bool remove=false)
    {
        auto g = SRWLockGuard(&lock_pages_, remove);
        auto it = cached_pages_.find(page_idx);
        if (it == cached_pages_.end()) return;
        auto& entry = (*it).second;
        entry.owner = 0;
        ReleaseSRWLockExclusive(&entry.lock);
        if (remove) cached_pages_.erase(it);
    }

    // may fail for pages locked by the current thread
    DWORD RemovePages(PageRange r, void** user = nullptr)
    {
        auto gp = SRWLockGuard(&lock_pages_, true);

        if (cached_pages_.empty()) return ERROR_SUCCESS;

        for (auto i = r.start_idx; i <= r.end_idx; ++i)
        {
            auto it = cached_pages_.find(r.base_idx + i);
            if (it == cached_pages_.end()) continue;

            // wait for I/O to complete
            {
                auto& entry = (*it).second;
                if (entry.owner == GetCurrentThreadId())
                {
                    if (user != nullptr) *user = entry.user;
                    return ERROR_BUSY;
                }
                auto gm = PageGuard(&entry, true);
            }
            cached_pages_.erase(it);
        }

        return ERROR_SUCCESS;
    }

    SPD_STORAGE_UNIT* storage_unit = nullptr;
    const ChunkDiskParam param;

    const u32 max_pages = 1;                 // may exceed if page is being used for I/O

private:
    vector<FileHandle> part_lock_;              // part index -> .lock

    SRWLOCK lock_parts_ = SRWLOCK_INIT;
    vector<u64> part_current_;                  // part index -> # of chunks
    size_t part_current_new_ = 0;               // part index for new chunks
    unordered_map<u64, size_t> chunk_parts_;    // chunk index -> part index

    SRWLOCK lock_pages_ = SRWLOCK_INIT;
    // BLOCK_SIZE -> PAGE_SIZE access
    // read cache, write through
    // add to back, evict from front
    Map<u64, PageEntry> cached_pages_;
};

struct ChunkOpState;

// single request
struct ChunkWork
{
    vector<ChunkOpState> ops;
    Pages buffer;               // FIXME ReturnBuffer()
    std::list<ChunkWork>::iterator it = {};        // from ChunkDiskWorker::working_ FIXME type
    u32 num_completed = 0;      // work finished when num_completed == ops.size()
    u32 num_errors = 0;         // failed ops out of num_completed

    // Status: the first reported error
    SPD_IOCTL_TRANSACT_RSP response = {};

    void SetContext(u64 hint, u8 kind)
    {
        response.Hint = hint;
        response.Kind = kind;
    }

    void SetStatusChecked(u8 sense_key, u8 asc)
    {
        if (response.Status.ScsiStatus != SCSISTAT_GOOD) return;
        SetScsiStatus(&response.Status, sense_key, asc);
    }

    void SetStatusChecked(u8 sense_key, u8 asc, u64 info)
    {
        if (response.Status.ScsiStatus != SCSISTAT_GOOD) return;
        SetScsiStatus(&response.Status, sense_key, asc, info);
    }
};

// single operation
struct ChunkOpState
{
    OVERLAPPED ovl = {};
    ChunkWork* owner;
    ChunkOpKind kind;
    ChunkOpStep step = OP_READY;
    u64 idx;                        // chunk_idx or page_idx
    u64 start_off;
    u64 end_off;
    PVOID buffer;
    ChunkOpState* next = nullptr;   // next op waiting on this

    ChunkOpState(ChunkWork* owner, ChunkOpKind kind, u64 idx, u64 start_off, u64 end_off, LONGLONG file_off, PVOID buffer)
        : owner(owner), kind(kind), idx(idx), start_off(start_off), end_off(end_off), buffer(buffer)
    {
        LARGE_INTEGER li{.QuadPart = file_off};
        ovl.Offset = li.LowPart;
        ovl.OffsetHigh = li.HighPart;
    }
};

static ChunkOpState* GetOverlappedOp(OVERLAPPED* ovl)
{
    return CONTAINING_RECORD(ovl, ChunkOpState, ovl);
}

struct ChunkFileHandle
{
    FileHandle handle_ro;   // read only, for !is_write
    FileHandle handle_rw;   // read and write, for is_write
    u32 refs = 0;
};

// for SINGLE dispatcher thread
class ChunkDiskWorker
{
public:
    explicit ChunkDiskWorker(ChunkDisk& owner) : owner_(owner) {}

    bool IsRunning()
    {
        return iocp_ != nullptr;
    }

    // stop and start to restart
    // CALL Stop() before destructed
    DWORD Start()
    {
        if (IsRunning()) return ERROR_INVALID_STATE;

        iocp_.reset(CreateIoCompletionPort(
            INVALID_HANDLE_VALUE, nullptr, 0, 1));
        if (!iocp_) return GetLastError();

        try
        {
            thread_ = std::thread(ThreadProc, this);
        }
        catch (const std::system_error& e)
        {
            iocp_.reset();
            return e.code().value();
        }

        return ERROR_SUCCESS;
    }

    DWORD Stop()
    {
        if (!IsRunning()) return ERROR_INVALID_STATE;

        // FIXME: close file handles before closing iocp_
        iocp_.reset();

        try
        {
            thread_.join();
        }
        catch (const std::system_error& e)
        {
            return e.code().value();
        }

        auto exit_code = DWORD();
        GetExitCodeThread(thread_.native_handle(), &exit_code);

        thread_ = std::thread();
        return exit_code;
    }

    // FIXME context from SpdStorageUnitGetOperationContext()
    /*
     * Asynchronous file I/O is processed using IOCP.
     * An operation is processed either immediately, synchronously, asynchronously.
     *
     * Immediately: I/O is bypassed or done using synchronous HANDLE not associated with the IOCP.
     * Synchronously: Asynchronous I/O is requested but GetLastError() is not ERROR_IO_PENDING.
     * Asynchronously: Asynchronous I/O is requested and GetLastError() is ERROR_IO_PENDING.
     *
     * op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
     * Return ERROR_SUCCESS when the request is done immediately.
     * Return ERROR_IO_PENDING when some operations are processed synchronously or asynchronously.
     */
    DWORD PostWork(SPD_STORAGE_UNIT_OPERATION_CONTEXT* context, ChunkOpKind op_kind, u64 block_addr, u32 count)
    {
        if (!IsRunning()) return ERROR_INVALID_STATE;

        // check queue depth
        // single dispatcher, no more works to be queued
        {
            auto g = SRWLockGuard(&lock_working_, false);
            if (working_.size() >= MAX_QD) return ERROR_BUSY;   // FIXME choose next worker?
        }

        // prepare buffer
        // work_buffer zero-filled, write back to ctx_buffer if done immediately.
        auto ctx_buffer = context->DataBuffer;
        auto work_buffer = Pages();     // nullptr if UNMAP_CHUNK
        if (op_kind == READ_CHUNK || op_kind == WRITE_CHUNK)
        {
            auto err = GetBuffer(work_buffer);
            if (err != ERROR_SUCCESS)
            {
                SetScsiStatus(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
                return err;
            }
            // write is never done immediately
            if (op_kind == WRITE_CHUNK) memcpy(work_buffer.get(), ctx_buffer, owner_.param.BlockBytes(count));
        }

        // prepare work
        auto work = ChunkWork();
        work.buffer = std::move(work_buffer);

        auto err = PrepareOps(work, op_kind, block_addr, count);
        if (err != ERROR_SUCCESS)
        {
            if (work.num_errors == 0)
            {
                // internal error, e.g. ERROR_NOT_ENOUGH_MEMORY
                SetScsiStatus(&context->Response->Status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
            }
            else
            {
                // the first error reported
                // same effect calling SpdStatusUnitStatusSetSense()
                context->Response->Status = work.response.Status;
            }
            return err;
        }

        if (work.num_completed == work.ops.size())
        {
            // all done immediately
            // FIXME return TRUE in SPD_STORAGE_UNIT_INTERFACE operations
            if (op_kind == READ_CHUNK) memcpy(ctx_buffer, work.buffer.get(), MAX_TRANSFER_LENGTH);
            return ERROR_SUCCESS;
        }

        // start async.
        work.SetContext(context->Response->Hint, context->Response->Kind);
        try
        {
            auto g = SRWLockGuard(&lock_working_, true);
            auto work_it = working_.emplace(working_.end(), std::move(work));
            work_it->it = work_it;

            if (!PostQueuedCompletionStatus(iocp_.get(), 0,
                                            CK_POST, recast<OVERLAPPED*>(&*work_it)))
            {
                working_.erase(work_it);
                return GetLastError();
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        // FIXME return FALSE in SPD_STORAGE_UNIT_INTERFACE operations
        return ERROR_IO_PENDING;
    }

private:
    enum IOCPKey
    {
        CK_IO = 0,      // initiated file I/O
        CK_FAIL,        // failed to initiate file I/O
        CK_POST         // disk I/O request from PostWork()
    };

    static DWORD ThreadProc(LPVOID param)
    {
        auto self = recast<ChunkDiskWorker*>(param);
        return self->Work();
    }

    // for SINGLE worker and SINGLE dispatcher thread
    // Start() creates a thread starting at Work()
    DWORD Work()
    {
        auto bytes_transmitted = DWORD();
        auto ckey = u64();
        auto overlapped = (OVERLAPPED*)(nullptr);

        while (true)
        {
            auto err = GetQueuedCompletionStatus(
                    iocp_.get(), &bytes_transmitted, &ckey, &overlapped, STANDBY_MS)
                ? ERROR_SUCCESS : GetLastError();

            if (overlapped == nullptr)
            {
                // FIXME CK_STOP: cancel HANDLE, clear working_, close HANDLE
                if (err == ERROR_ABANDONED_WAIT_0) return 0;
                if (err == WAIT_TIMEOUT)
                {
                    // FIXME close all HANDLE's IF not working_, wait indefinitely
                    // FIXME free all buffer Pages
                    continue;
                }
                continue;
            }

            // FIXME: I/O error for overlapped != nullptr

            // do work...
            if (ckey == CK_POST)
            {
                auto& work = *recast<ChunkWork*>(overlapped);

                // FIXME wait
                for (auto& op : work.ops)
                {
                    if (op.step != OP_DONE) PostOp(op);
                }
                continue;
            }
            else if (ckey == CK_IO)
            {
                auto& state = *GetOverlappedOp(overlapped);

                // FIXME check if all completed, ReturnBuffer()
                CompleteIO(state, err, bytes_transmitted);
            }
            else if (ckey == CK_FAIL)
            {
                auto& state = *recast<ChunkOpState*>(overlapped);
            }
        }
    }

    // get buffer from pool
    DWORD GetBuffer(Pages& buffer)
    {
        if (buffers_.empty())
        {
            // align buffer to pages
            auto new_buffer = Pages(VirtualAlloc(nullptr, MAX_TRANSFER_LENGTH, MEM_COMMIT, PAGE_READWRITE));
            if (!new_buffer) return GetLastError();
            buffer = std::move(new_buffer);
            return ERROR_SUCCESS;
        }
        else
        {
            buffer = std::move(buffers_.front());
            buffers_.pop_front();
            // buf was zero-filled in ReturnBuffer()
            return ERROR_SUCCESS;
        }
    }

    // return buffer to pool
    DWORD ReturnBuffer(Pages buffer)
    {
        memset(buffer.get(), 0, MAX_TRANSFER_LENGTH);
        try
        {
            buffers_.emplace_front(std::move(buffer));
        }
        catch (const bad_alloc&)
        {
            // ignore error, will retry in GetBuffer()
        }
        return ERROR_SUCCESS;
    }

    // FIXME: close old HANDLEs (keep <= MAX_QD, reinsert_back() if hit)
    DWORD OpenChunk(u64 chunk_idx, bool is_write, HANDLE& handle_out)
    {
        // check HANDLE pool
        auto it = chunk_handles_.find(chunk_idx);
        if (it != chunk_handles_.end())
        {
            auto& cfh = (*it).second;
            if (!is_write && cfh.handle_ro)
            {
                handle_out = cfh.handle_ro.get();
                ++cfh.refs;
                return ERROR_SUCCESS;
            }
            if (is_write && cfh.handle_rw)
            {
                handle_out = cfh.handle_rw.get();
                ++cfh.refs;
                return ERROR_SUCCESS;
            }
        }

        auto h = FileHandle();
        auto err = owner_.CreateChunk(chunk_idx, is_write, h);
        if (err != ERROR_SUCCESS) return err;
        if (!h) return ERROR_SUCCESS;

        // NOTE: a completion packet will also be sent even though the I/O operation successfully completed synchronously.
        // See https://docs.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o
        // Related: https://docs.microsoft.com/en-us/troubleshoot/windows/win32/asynchronous-disk-io-synchronous
        // Related: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
        if (CreateIoCompletionPort(h.get(), iocp_.get(), CK_IO, 1) == nullptr) return GetLastError();

        if (it == chunk_handles_.end())
        {
            try
            {
                it = chunk_handles_.emplace(chunk_idx).first;
            }
            catch (const bad_alloc& e)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }

        handle_out = h.get();
        auto& cfh = (*it).second;
        if (!is_write)
        {
            cfh.handle_ro = std::move(h);
        }
        else
        {
            cfh.handle_rw = std::move(h);
        }
        ++cfh.refs;
        return ERROR_SUCCESS;
    }

    // FIXME: close ALL when idle (don't close in eager, may be used later) (PageOps)
    DWORD CloseChunk(u64 chunk_idx)
    {
        auto it = chunk_handles_.find(chunk_idx);
        if (it == chunk_handles_.end()) return ERROR_NOT_FOUND;

        auto& cfh = (*it).second;
        --cfh.refs;

        return ERROR_SUCCESS;
    }

    PageResult LockPageAsync(ChunkOpState& state, u64 page_idx)
    {
        auto page = owner_.LockPage(page_idx);

        if (page.error == ERROR_SUCCESS)
        {
            *page.user = &state;
        }
        else if (page.error == ERROR_BUSY)
        {
            auto cur = recast<ChunkOpState*>(*page.user);
            for (; cur->next != nullptr; cur = cur->next) {}
            cur->next = &state;
        }

        return page;
    }

    void FreePageAsync(ChunkOpState& state, u64 page_idx, bool remove=false)
    {
        auto page = owner_.ClaimPage(page_idx);
        if (page.error != ERROR_SUCCESS) return;
        if (*page.user != &state) return;

        *page.user = nullptr;
        auto next = state.next;
        state.next = nullptr;

        owner_.FreePage(page_idx, remove);
        if (next != nullptr)
        {
            // FIXME may be canceled?
            if (next->step != OP_DONE) PostOp(*next);
        }
    }

    DWORD RemovePagesAsync(ChunkOpState& state, PageRange r)
    {
        auto user = (void*)(nullptr);
        auto err = owner_.RemovePages(r, &user);
        if (err == ERROR_SUCCESS) return err;
        if (err != ERROR_BUSY) return err;

        auto cur = recast<ChunkOpState*>(user);
        for (; cur->next != nullptr; cur = cur->next) {}
        cur->next = &state;
        return err;
    }

    void ReportOpResult(ChunkOpState& state, DWORD error = ERROR_SUCCESS)
    {
        if (state.step == OP_DONE) return;  // already reported

        state.step = OP_DONE;
        ++state.owner->num_completed;

        if (error == ERROR_SUCCESS)
        {
            return;
        }
        else if (error == ERROR_NOT_ENOUGH_MEMORY)
        {
            ++state.owner->num_errors;
            state.owner->SetStatusChecked(SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        }
        else if (error == ERROR_OPERATION_ABORTED)
        {
            ++state.owner->num_errors;
            state.owner->SetStatusChecked(SCSI_SENSE_ABORTED_COMMAND, SCSI_ADSENSE_NO_SENSE);
        }
        else
        {
            auto asc = u8(SCSI_ADSENSE_NO_SENSE);
            auto kind = state.kind;
            if (kind == READ_CHUNK || kind == READ_PAGE)
            {
                // read request
                asc = SCSI_ADSENSE_UNRECOVERED_ERROR;
            }
            else if (kind == WRITE_CHUNK || kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
            {
                // write request
                // unmap request if buffer == nullptr
                asc = (state.buffer != nullptr) ? SCSI_ADSENSE_WRITE_ERROR : SCSI_ADSENSE_NO_SENSE;
            }

            if (asc == SCSI_ADSENSE_NO_SENSE)
            {
                // unmap request
                ++state.owner->num_errors;
                state.owner->SetStatusChecked(SCSI_SENSE_MEDIUM_ERROR, asc);
            }
            else
            {
                // info available
                auto& param = owner_.param;
                auto info = u64();
                if (kind == READ_PAGE || kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
                {
                    info = param.PageBlocks(state.idx) + state.start_off;
                }
                else
                {
                    info = param.ChunkBlocks(state.idx) + state.start_off;
                }
                ++state.owner->num_errors;
                state.owner->SetStatusChecked(SCSI_SENSE_MEDIUM_ERROR, asc, info);
            }
        }
    }

    DWORD PreparePageOps(ChunkWork& work, bool is_write, u64 page_idx,
                        u32 start_off, u32 end_off, LONGLONG& file_off, PVOID& buffer)
    {
        auto& param = owner_.param;
        auto& ops = work.ops;
        auto kind = is_write ? WRITE_PAGE : READ_PAGE;
        if (is_write && !param.IsPageAligned(start_off, end_off)) kind = WRITE_PAGE_PARTIAL;

        try
        {
            auto it = ops.emplace(ops.end(), &work, kind, page_idx, start_off, end_off, file_off, buffer);
            file_off += LONGLONG(param.PageBytes(1));
            if (!(is_write && buffer == nullptr)) buffer = recast<u8*>(buffer) + param.BlockBytes(end_off - start_off);

            // try to complete immediately
            if (kind == READ_PAGE || kind == WRITE_PAGE_PARTIAL)
            {
                auto page = owner_.PeekPage(page_idx);
                if (page.error == ERROR_SUCCESS)
                {
                    auto size = param.BlockBytes(it->end_off - it->start_off);
                    memcpy(it->buffer, recast<u8*>(page.ptr) + param.BlockBytes(it->start_off), size);
                    if (kind == READ_PAGE)
                    {
                        ReportOpResult(*it);
                    }
                    else
                    {
                        // WRITE_PAGE_PARTIAL
                        it->step = OP_HIT_PAGE;
                    }
                    return ERROR_SUCCESS;
                }
            }
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        return ERROR_SUCCESS;
    }

    DWORD PrepareChunkOps(ChunkWork& work, ChunkOpKind kind, u64 chunk_idx,
                          u64 start_off, u64 end_off, PVOID& buffer)
    {
        auto& param = owner_.param;
        auto& ops = work.ops;

        // try to complete immediately
        if (kind == READ_CHUNK || kind == UNMAP_CHUNK)
        {
            if (kind == UNMAP_CHUNK && param.IsWholeChunk(start_off, end_off))
            {
                try
                {
                    auto it = ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off, 0, nullptr);
                    auto err = owner_.UnmapChunk(chunk_idx);
                    ReportOpResult(*it, err);
                    return err;
                }
                catch (const bad_alloc&)
                {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
            }

            auto h = HANDLE(INVALID_HANDLE_VALUE);
            auto err = OpenChunk(chunk_idx, false, h);
            if (err != ERROR_SUCCESS) return err;
            if (h == INVALID_HANDLE_VALUE)
            {
                try
                {
                    // buffer was zero-filled, nothing to do if READ_CHUNK
                    // nothing to zero-fill if UNMAP_CHUNK
                    auto it = ops.emplace(ops.end(), &work, kind, chunk_idx, start_off, end_off,
                                          LONGLONG(param.BlockBytes(start_off)), buffer);
                    ReportOpResult(*it);
                    return ERROR_SUCCESS;
                }
                catch (const bad_alloc&)
                {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
            }
            else
            {
                CloseChunk(chunk_idx);
            }


            if (kind == UNMAP_CHUNK)
            {
                // Unmap chunk partially, zero-fill it
                // buffer is nullptr for UNMAP_CHUNK
                kind = WRITE_CHUNK;
            }
        }

        // prepare asynchronous I/O
        auto is_write = (kind == WRITE_CHUNK);
        if (param.IsPageAligned(start_off, end_off, buffer))
        {
            // aligned to page
            try
            {
                ops.emplace_back(&work, kind, chunk_idx, start_off, end_off, LONGLONG(param.BlockBytes(start_off)), buffer);
                if (!(is_write && buffer == nullptr)) buffer = recast<u8*>(buffer) + param.BlockBytes(end_off - start_off);
            }
            catch (const bad_alloc&)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        else
        {
            // not aligned to page
            const auto r = param.BlockPageRange(chunk_idx, start_off, end_off);
            auto file_off = LONGLONG(param.PageBytes(r.start_idx));

            auto err = PreparePageOps(work, is_write, r.base_idx + r.start_idx, r.start_off,
                                      r.start_idx == r.end_idx ? r.end_off : param.page_length, file_off, buffer);
            if (err != ERROR_SUCCESS) return err;
            if (r.start_idx != r.end_idx)
            {
                for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
                {
                    err = PreparePageOps(work, is_write, r.base_idx + i, 0, param.page_length, file_off, buffer);
                    if (err != ERROR_SUCCESS) return err;
                }
                err = PreparePageOps(work, is_write, r.base_idx + r.end_idx, 0, r.end_off, file_off, buffer);
                if (err != ERROR_SUCCESS) return err;
            }
        }

        return ERROR_SUCCESS;
    }

    // kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
    // try to complete some ops immediately (abort if one of them fails)
    DWORD PrepareOps(ChunkWork& work, ChunkOpKind kind, u64 block_addr, u32 count)
    {
        auto buffer = work.buffer.get();
        const auto r = owner_.param.BlockChunkRange(block_addr, count);

        auto err = PrepareChunkOps(work, kind, r.start_idx, r.start_off,
                                   r.start_idx == r.end_idx ? r.end_off : owner_.param.chunk_length, buffer);
        if (err != ERROR_SUCCESS) return err;
        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = PrepareChunkOps(work, kind, i, 0, owner_.param.chunk_length, buffer);
                if (err != ERROR_SUCCESS) return err;
            }
            err = PrepareChunkOps(work, kind, r.end_idx, 0, r.end_off, buffer);
            if (err != ERROR_SUCCESS) return err;
        }

        return ERROR_SUCCESS;
    }

    DWORD PostReadChunk(ChunkOpState& state)
    {
        // aligned to page
        // Windows caches them
        auto& param = owner_.param;
        auto err = RemovePagesAsync(state, param.BlockPageRange(state.idx, state.start_off, state.end_off));
        if (err != ERROR_SUCCESS) return err;

        auto h = HANDLE(INVALID_HANDLE_VALUE);
        err = OpenChunk(state.idx, false, h);
        if (err != ERROR_SUCCESS) return err;
        // file has been checked in PrepareChunkOps(), h should be valid

        auto length_bytes = param.BlockBytes(state.end_off - state.start_off);
        err = ReadFile(h, state.buffer, DWORD(length_bytes), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            CloseChunk(state.idx);
            return err;
        }
        return ERROR_SUCCESS;
    }

    DWORD PostWriteChunk(ChunkOpState& state)
    {
        // aligned to page
        // Windows caches them
        auto& param = owner_.param;
        auto err = RemovePagesAsync(state, param.BlockPageRange(state.idx, state.start_off, state.end_off));
        if (err != ERROR_SUCCESS) return err;

        auto h = HANDLE(INVALID_HANDLE_VALUE);
        err = OpenChunk(state.idx, true, h);
        if (err != ERROR_SUCCESS) return err;

        if (state.buffer != nullptr)
        {
            auto length_bytes = param.BlockBytes(state.end_off - state.start_off);
            err = WriteFile(h, state.buffer, DWORD(length_bytes), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        }
        else
        {
            FILE_ZERO_DATA_INFORMATION zero_info;
            zero_info.FileOffset.QuadPart = LONGLONG(param.BlockBytes(state.start_off));
            zero_info.BeyondFinalZero.QuadPart = LONGLONG(param.BlockBytes(state.end_off));

            err = DeviceIoControl(
                h, FSCTL_SET_ZERO_DATA, &zero_info, sizeof(zero_info),
                nullptr, 0, nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        }
        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            CloseChunk(state.idx);
            return err;
        }
        return ERROR_SUCCESS;
    }

    DWORD PostReadPage(ChunkOpState& state)
    {
        auto& param = owner_.param;
        auto page = LockPageAsync(state, state.idx);
        if (page.error != ERROR_SUCCESS) return page.error;

        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunk(state.idx, false, h);
        if (err != ERROR_SUCCESS) return err;
        // file has been checked in PrepareChunkOps(), h should be valid

        err = ReadFile(h, page.ptr, u32(param.PageBytes(1)), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            CloseChunk(state.idx);
            FreePageAsync(state, state.idx, true);
            return err;
        }
        return ERROR_SUCCESS;
    }

    DWORD PostWritePage(ChunkOpState& state)
    {
        if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY) return PostReadPage(state);

        // OP_READ_PAGE: called LockPageAsync(), OP_HIT_PAGE: called PeekPage()
        // WRITE_PAGE
        auto page = (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READ_PAGE)
            ? owner_.ClaimPage(state.idx) : LockPageAsync(state, state.idx);
        if (page.error != ERROR_SUCCESS) return page.error;

        auto h = HANDLE(INVALID_HANDLE_VALUE);
        auto err = OpenChunk(state.idx, true, h);
        if (err != ERROR_SUCCESS) return err;

        auto& param = owner_.param;
        auto size = param.BlockBytes(state.end_off - state.start_off);
        if (state.buffer != nullptr)
        {
            memcpy(recast<u8*>(page.ptr) + param.BlockBytes(state.start_off), state.buffer, size);
        }
        else
        {
            memset(recast<u8*>(page.ptr) + param.BlockBytes(state.start_off), 0, size);
        }

        // write through
        err = WriteFile(h, page.ptr, u32(param.PageBytes(1)), nullptr, &state.ovl) ? ERROR_SUCCESS : GetLastError();
        if (err != ERROR_SUCCESS && err != ERROR_IO_PENDING)
        {
            CloseChunk(state.idx);
            FreePageAsync(state, state.idx, true);
            return err;
        }
        return ERROR_SUCCESS;
    }

    void PostOp(ChunkOpState& state)
    {
        auto err = DWORD();
        auto kind = state.kind;
        if (kind == READ_CHUNK)
        {
            err = PostReadChunk(state);
        }
        else if (kind == WRITE_CHUNK)
        {
            err = PostWriteChunk(state);
        }
        else if (kind == READ_PAGE)
        {
            err = PostReadPage(state);
        }
        else if (kind == WRITE_PAGE || kind == WRITE_PAGE_PARTIAL)
        {
            err = PostWritePage(state);
        }
        else
        {
            err = ERROR_INVALID_FUNCTION;
        }

        // CK_IO sent if ERROR_SUCCESS
        // FIXME comment
        if (err == ERROR_SUCCESS || err == ERROR_BUSY) return;

        ReportOpResult(state, err);

        // FIXME terminate work (send response) if this fails (out of resources)
        PostQueuedCompletionStatus(iocp_.get(), 0, CK_FAIL, recast<OVERLAPPED*>(&state));
    }

    void CompleteChunkOp(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
    {
        auto length_bytes = owner_.param.BlockBytes(state.end_off - state.start_off);
        if (error == ERROR_SUCCESS && bytes_transmitted != length_bytes) error = ERROR_INVALID_DATA;
        CloseChunk(state.idx);
        ReportOpResult(state, error);
    }

    void CompleteReadPage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
    {
        auto& param = owner_.param;
        if (error == ERROR_SUCCESS && bytes_transmitted != param.PageBytes(1)) error = ERROR_INVALID_DATA;
        CloseChunk(state.idx);
        if (error == ERROR_SUCCESS)
        {
            auto page = owner_.ClaimPage(state.idx);
            memcpy(state.buffer, recast<u8*>(page.ptr) + param.BlockBytes(state.start_off), length_bytes);
        }
        FreePageAsync(state, state.idx, error != ERROR_SUCCESS);
        ReportOpResult(state, error);
    }

    void CompleteReadPageWritePartial(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
    {
        auto& param = owner_.param;
        if (error == ERROR_SUCCESS && bytes_transmitted != param.PageBytes(1)) error = ERROR_INVALID_DATA;
        CloseChunk(state.idx);
        if (error != ERROR_SUCCESS)
        {
            FreePageAsync(state, state.idx, true);
            ReportOpResult(state, error);
        }
        else
        {
            state.step = OP_READ_PAGE;
            PostOp(state);
        }
    }

    void CompleteWritePage(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
    {
        auto& param = owner_.param;
        if (error == ERROR_SUCCESS && bytes_transmitted != param.PageBytes(1)) error = ERROR_INVALID_DATA;
        CloseChunk(state.idx);
        FreePageAsync(state, state.idx, error != ERROR_SUCCESS);
        ReportOpResult(state, error);
    }

    // Requested async I/O (it may be done schronously)
    DWORD CompleteIO(ChunkOpState& state, DWORD error, DWORD bytes_transmitted)
    {
        if (state.kind == READ_CHUNK || state.kind == WRITE_CHUNK)
        {
            CompleteChunkOp(state, error, bytes_transmitted);
        }
        else if (state.kind == READ_PAGE)
        {
            CompleteReadPage(state, error, bytes_transmitted);
        }
        else if (state.kind == WRITE_PAGE_PARTIAL && state.step == OP_READY)
        {
            CompleteReadPageWritePartial(state, error, bytes_transmitted);
        }
        else if (state.kind == WRITE_PAGE_PARTIAL || state.kind == WRITE_PAGE)
        {
            CompleteWritePage(state, error, bytes_transmitted);
        }

        return state.owner->num_completed == state.owner->ops.size() ? ERROR_SUCCESS : ERROR_IO_INCOMPLETE;
    }

    ChunkDisk& owner_;
    std::thread thread_;
    GenericHandle iocp_;

    std::list<ChunkWork> working_;
    SRWLOCK lock_working_ = SRWLOCK_INIT;   // with the dispatcher thread

    deque<Pages> buffers_;
    Map<u64, ChunkFileHandle> chunk_handles_;
};

static ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
}

// sense: 0 -> no sense, 1 -> read error, 2 -> write error
static void SetMediumError(SPD_STORAGE_UNIT_STATUS* status, u8 asc, bool addr_valid = false, u64 addr = 0)
{
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
        SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR);
        return 1;
    }

    auto& param = cdisk->param;
    if (!page.is_hit)
    {
        auto length_read = DWORD();
        if (!ReadFile(h, page.ptr, u32(param.PageBytes(1)), &length_read, nullptr)
            || length_read != param.PageBytes(1))
        {
            SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR, true,
                           param.PageBlocks(page_idx) + param.ByteBlock(length_read + 1).first);
            return 2;
        }
    }
    else
    {
        // advance pointer as if read from file
        if (!SetFilePointerEx(h, LARGE_INTEGER{.QuadPart = u32(param.PageBytes(1))}, nullptr, FILE_CURRENT))
        {
            SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR);
            return 1;
        }
    }

    auto size = param.BlockBytes(end_off - start_off);
    memcpy(buffer, recast<u8*>(page.ptr) + param.BlockBytes(start_off), size);
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
    auto asc = u8(buffer != nullptr ? SCSI_ADSENSE_WRITE_ERROR : SCSI_ADSENSE_NO_SENSE);

    auto page = cdisk->AcquirePage(page_idx, true);
    if (page.error != ERROR_SUCCESS)
    {
        SetMediumError(Status, asc);
        return 1;
    }

    auto& param = cdisk->param;
    if (!page.is_hit && !param.IsPageAligned(start_off, end_off))
    {
        // writing to page partially, read it first
        auto pos = LARGE_INTEGER();
        if (!SetFilePointerEx(h, LARGE_INTEGER(), &pos, FILE_CURRENT))
        {
            SetMediumError(Status, asc, false);
            return 1;
        }

        auto length_read = DWORD();
        if (!ReadFile(h, page.ptr, u32(param.PageBytes(1)), &length_read, nullptr)
            || length_read != param.PageBytes(1))
        {
            SetMediumError(Status, asc, true,
                           param.PageBlocks(page_idx) + param.ByteBlock(length_read + 1).first);
            return 2;
        }

        if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, asc, false);
            return 1;
        }
    }

    auto size = param.BlockBytes(end_off - start_off);
    if (buffer != nullptr)
    {
        memcpy(recast<u8*>(page.ptr) + param.BlockBytes(start_off), buffer, size);
    }
    else
    {
        memset(recast<u8*>(page.ptr) + param.BlockBytes(start_off), 0, size);
    }

    // write through
    auto length_written = DWORD();
    if (!WriteFile(h, page.ptr, u32(param.PageBytes(1)), &length_written, nullptr)
        || length_written != param.PageBytes(1))
    {
        SetMediumError(Status, asc, true,
                       param.PageBlocks(page_idx) + param.ByteBlock(length_written + 1).first);
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
    auto err = cdisk->CreateChunk(chunk_idx, false, h);
    if (err != ERROR_SUCCESS) return 1;

    auto& param = cdisk->param;
    auto length_bytes = param.BlockBytes(end_off - start_off);
    if (!h)
    {
        memset(buffer, 0, length_bytes);
        buffer = recast<u8*>(buffer) + length_bytes;
        return ERROR_SUCCESS;
    }

    const auto r = cdisk->param.BlockPageRange(chunk_idx, start_off, end_off);
    if (param.IsPageAligned(r.start_off, r.end_off, buffer))
    {
        // aligned to page
        cdisk->RemovePages(r);  // Windows caches buffer

        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(param.BlockBytes(start_off))};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR);
            return 1;
        }

        auto length_read = DWORD();
        if (!ReadFile(h.get(), buffer, DWORD(length_bytes), &length_read, nullptr)
            || length_bytes != length_read)
        {
            SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR, true,
                           param.ChunkBlocks(chunk_idx) + start_off + param.ByteBlock(length_read + 1).first);
            return 2;
        }
        buffer = recast<u8*>(buffer) + length_bytes;
    }
    else
    {
        // not aligned to page
        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(param.PageBytes(r.start_idx))};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, SCSI_ADSENSE_UNRECOVERED_ERROR);
            return 1;
        }

        err = InternalReadPage(
            cdisk, h.get(), buffer, r.base_idx + r.start_idx,
            r.start_off, r.start_idx == r.end_idx ? r.end_off : param.page_length, Status);
        if (err != ERROR_SUCCESS) return err;

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = InternalReadPage(
                    cdisk, h.get(), buffer, r.base_idx + i,
                    0, param.page_length, Status);
                if (err != ERROR_SUCCESS) return err;
            }
            err = InternalReadPage(cdisk, h.get(), buffer, r.base_idx + r.end_idx,
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
    auto asc = u8(buffer != nullptr ? SCSI_ADSENSE_WRITE_ERROR : SCSI_ADSENSE_NO_SENSE);

    auto h = FileHandle();
    auto err = cdisk->CreateChunk(chunk_idx, true, h);
    if (err != ERROR_SUCCESS) return 1;

    auto& param = cdisk->param;
    auto length_bytes = param.BlockBytes(end_off - start_off);

    const auto r = cdisk->param.BlockPageRange(chunk_idx, start_off, end_off);
    if (param.IsPageAligned(r.start_off, r.end_off, buffer))
    {
        // aligned to page
        cdisk->RemovePages(r);  // Windows caches buffer

        if (buffer != nullptr)
        {
            auto off = LARGE_INTEGER{.QuadPart = LONGLONG(param.BlockBytes(start_off))};
            if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
            {
                SetMediumError(Status, asc);
                return 1;
            }

            auto length_written = DWORD();
            if (!WriteFile(h.get(), buffer, DWORD(length_bytes), &length_written, nullptr)
                || length_bytes != length_written)
            {
                SetMediumError(Status, asc, true,
                               param.ChunkBlocks(chunk_idx) + start_off + param.ByteBlock(length_written + 1).first);
                return 2;
            }
            buffer = recast<u8*>(buffer) + length_bytes;
        }
        else
        {
            FILE_ZERO_DATA_INFORMATION zero_info;
            zero_info.FileOffset.QuadPart = LONGLONG(param.BlockBytes(start_off));
            zero_info.BeyondFinalZero.QuadPart = LONGLONG(param.BlockBytes(end_off));

            auto bytes_returned = DWORD();
            if (!DeviceIoControl(
                    h.get(), FSCTL_SET_ZERO_DATA, &zero_info, sizeof(zero_info),
                    nullptr, 0, &bytes_returned, nullptr))
            {
                SetMediumError(Status, asc);
                return 1;
            }
        }
    }
    else
    {
        // not aligned to page
        auto off = LARGE_INTEGER{.QuadPart = LONGLONG(param.PageBytes(r.start_idx))};
        if (!SetFilePointerEx(h.get(), off, nullptr, FILE_BEGIN))
        {
            SetMediumError(Status, asc);
            return 1;
        }

        err = InternalWritePage(
            cdisk, h.get(), buffer, r.base_idx + r.start_idx,
            r.start_off, r.start_idx == r.end_idx ? r.end_off : param.page_length, Status);
        if (err != ERROR_SUCCESS) return err;

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                err = InternalWritePage(
                    cdisk, h.get(), buffer, r.base_idx + i,
                    0, param.page_length, Status);
                if (err != ERROR_SUCCESS) return err;
            }
            err = InternalWritePage(cdisk, h.get(), buffer, r.base_idx + r.end_idx,
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
    if (cdisk->param.IsWholeChunk(start_off, end_off))
    {
        // flush metadata
        auto h = FileHandle();
        auto err = cdisk->CreateChunk(chunk_idx, true, h);
        if (err != ERROR_SUCCESS)
        {
            SetMediumError(Status, SCSI_ADSENSE_WRITE_ERROR);
            return 1;
        }

        if (!FlushFileBuffers(h.get()))
        {
            SetMediumError(Status, SCSI_ADSENSE_WRITE_ERROR);
            return 1;
        }
        // we may discard h on error
        cdisk->ChunkClose(chunk_idx, std::move(h));
    }

    // no buffering or write through, nothing to flush
    return ERROR_SUCCESS;
}

static DWORD InternalUnmapChunk(ChunkDisk* cdisk, u64 chunk_idx,
                                u64 start_off, u64 end_off, SPD_STORAGE_UNIT_STATUS* Status)
{
    if (cdisk->param.IsWholeChunk(start_off, end_off))
    {
        auto err = cdisk->UnmapChunk(chunk_idx);
        if (err != ERROR_SUCCESS) return err;
    }

    // done if chunk is empty or does not exist
    auto h = FileHandle();
    auto err = cdisk->CreateChunk(chunk_idx, false, h);
    if (err != ERROR_SUCCESS) return 1;

    auto done = !h;
    if (!done) cdisk->ChunkClose(chunk_idx, std::move(h));
    if (done) return ERROR_SUCCESS;

    PVOID buffer = nullptr;
    return InternalWriteChunk(cdisk, buffer, chunk_idx, start_off, end_off, Status);
}

// FIXME: no flush, metadata flushed after idling
static BOOLEAN InternalFlush(SPD_STORAGE_UNIT* StorageUnit,
                             UINT64 BlockAddress, UINT32 BlockCount,
                             SPD_STORAGE_UNIT_STATUS* Status)
{
    auto* cdisk = StorageUnitChunkDisk(StorageUnit);
    auto& param = cdisk->param;

    if (BlockCount == 0)
    {
        // for simpliciy ignore BlockAddress % cdisk->chunk_length
        // let Windows flush
        if (cdisk->FlushAll(BlockAddress / param.chunk_length) != ERROR_SUCCESS)
        {
            SetMediumError(Status, SCSI_ADSENSE_WRITE_ERROR);
        }
        return TRUE;
    }

    const auto r = param.BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalFlushChunk(
        cdisk, r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : param.chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalFlushChunk(cdisk, i, 0, param.chunk_length, Status);
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
    auto& param = cdisk->param;
    const auto r = param.BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalReadChunk(
        cdisk, Buffer,
        r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : param.chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalReadChunk(cdisk, Buffer, i, 0, param.chunk_length, Status);
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
    auto& param = cdisk->param;
    const auto r = param.BlockChunkRange(BlockAddress, BlockCount);

    auto err = InternalWriteChunk(
        cdisk, Buffer,
        r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : param.chunk_length, Status);
    if (err != ERROR_SUCCESS) return TRUE;

    if (r.start_idx != r.end_idx)
    {
        for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            err = InternalWriteChunk(cdisk, Buffer, i, 0, param.chunk_length, Status);
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

    // Descriptors is just Buffer, writable
    // merge ranges
    if (Count == 0) return TRUE;

    std::sort(Descriptors, Descriptors + Count,
              [](const auto& a, const auto& b)
              {
                  return (a.BlockAddress < b.BlockAddress) ||
                         (a.BlockAddress == b.BlockAddress) && (a.BlockCount < b.BlockCount);
              });

    auto new_count = UINT32();
    auto prev_addr = Descriptors[0].BlockAddress;
    auto prev_count = Descriptors[0].BlockCount;

    for (UINT32 I = 0; I < Count; ++I)
    {
        auto addr = Descriptors[I].BlockAddress;
        auto count = Descriptors[I].BlockCount;

        if (count == 0) continue;

        if (addr <= prev_addr + prev_count)
        {
            auto count_ext = max(addr + count, prev_addr + prev_count) - prev_addr;
            if (count_ext <= UINT32(-1))
            {
                // no overflow
                prev_count = UINT32(count_ext);
                continue;
            }
        }

        Descriptors[new_count] = {prev_addr, prev_count, 0};
        ++new_count;
        prev_addr = addr;
        prev_count = count;
    }

    Descriptors[new_count] = {prev_addr, prev_count, 0};
    ++new_count;

    auto& param = cdisk->param;
    for (UINT32 I = 0; I < new_count; ++I)
    {
        // NOTE: a chunk gets truncated only if single block range covers it
        const auto r = param.BlockChunkRange(Descriptors[I].BlockAddress, Descriptors[I].BlockCount);

        // no buffer to track
        InternalUnmapChunk(cdisk,
            r.start_idx, r.start_off, r.start_idx == r.end_idx ? r.end_off : param.chunk_length, Status);

        if (r.start_idx != r.end_idx)
        {
            for (auto i = r.start_idx + 1; i < r.end_idx; ++i)
            {
                InternalUnmapChunk(cdisk, i, 0, param.chunk_length, Status);
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
    unit_params.BlockCount = cdisk->param.block_count;
    unit_params.BlockLength = cdisk->param.block_size;
    unit_params.MaxTransferLength = MAX_TRANSFER_LENGTH;
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

    DWORD err;
    if (NumThreads == 0)
    {
        err = GetThreadCount(&NumThreads);
        if (err != ERROR_SUCCESS)
        {
            logerr(L"error: failed to get number of CPU threads with error %lu", err);
            return err;
        }
    }

    HANDLE DebugLogHandle;
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
    try
    {
        auto cdisk_param = ChunkDiskParam();
        err = ReadChunkDiskParam(ChunkDiskFile, cdisk_param);
        if (err != ERROR_SUCCESS)
        {
            logerr(L"error: parsing failed with error %lu", err);
            return err;
        }

        // FIXME constants
        cdisk = std::make_unique<ChunkDisk>(
            std::move(cdisk_param),
            max(NumThreads * 32, 2048),
            max(NumThreads * 2, 128));
    }
    catch (const bad_alloc&)
    {
        logerr(L"error: not enough memory to start");
        return ERROR_NOT_ENOUGH_MEMORY;
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
