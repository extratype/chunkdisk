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
 */

#include <type_traits>
#include <cstddef>
#include <utility>
#include <memory>
#include <cwchar>
#include <string>
#include <vector>
#include <deque>
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

typedef UINT8  u8;
typedef UINT32 u32;
typedef UINT64 u64;

using std::size_t;
using std::make_pair;
using std::unique_ptr;
using std::shared_ptr;
using std::wstring;
using std::vector;
using std::deque;
using std::unordered_set;
using std::unordered_map;

namespace fs = std::filesystem;

struct pair_hash
{
    template <class T1, class T2>
    size_t operator () (std::pair<T1, T2> const& p) const
    {
        size_t h1 = std::hash<T1>()(p.first);
        size_t h2 = std::hash<T2>()(p.second);
        return h1 ^ h2;
    }
};

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
struct FileHandle
{
    FileHandle() noexcept : handle_(INVALID_HANDLE_VALUE) {}

    explicit FileHandle(HANDLE h) noexcept : handle_(h) {}

    virtual ~FileHandle() noexcept { if (*this) CloseHandle(handle_); }

    FileHandle(const FileHandle&) = delete;

    FileHandle(FileHandle&& other) noexcept : FileHandle()
    {
        swap(*this, other);
    }

    FileHandle& operator=(FileHandle& other) = delete;

    FileHandle& operator=(FileHandle&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    operator bool() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    HANDLE get() const noexcept { return handle_; }

    void reset() noexcept
    {
        FileHandle temp;
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

struct FileMappingDeleter
{
    void operator()(LPVOID p) noexcept
    {
        FlushViewOfFile(p, 0);
        UnmapViewOfFile(p);
    }
};

// single view and mapping per file handle
struct FileMapping
{
    FileMapping() = default;

    explicit FileMapping(FileHandle&& h) noexcept : FileMapping()
    {
        file_handle_ = std::move(h);
        if (!file_handle_) return;

        mapping_handle_ = FileHandle(CreateFileMappingW(file_handle_.get(),
            nullptr, PAGE_READWRITE, 0, 0, nullptr));
        if (!mapping_handle_)
        {
            file_handle_.reset();
            return;
        }

        mapping_.reset(MapViewOfFile(mapping_handle_.get(),
            FILE_MAP_ALL_ACCESS, 0, 0, 0));
        if (!mapping_)
        {
            mapping_handle_.reset();
            file_handle_.reset();
            return;
        }
    }

    virtual ~FileMapping() noexcept
    {
        mapping_.reset();
        mapping_handle_.reset();
        // updated the last modified time,
        // let Windows handle other metadata and buffers
        if (this->is_write_) TouchFile();
        file_handle_.reset();
    }

    FileMapping(const FileMapping&) = delete;

    FileMapping(FileMapping&& other) noexcept : FileMapping()
    {
        swap(*this, other);
    }

    FileMapping& operator=(FileMapping& other) = delete;

    FileMapping& operator=(FileMapping&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    operator bool() const noexcept { return bool(mapping_); }

    auto get() const noexcept { return mapping_.get(); }

    void set_write() { this->is_write_ = true; }

    DWORD Flush(size_t off, size_t len)
    {
        if (!*this) return ERROR_INVALID_HANDLE;
        // flush dirty pages to disk
        if (!FlushViewOfFile(recast<u8*>(mapping_.get()) + off, len)) return GetLastError();
        // already set_write()

        if (off == 0 && len == 0)
        {
            TouchFile();
            // NOTE: all buffers to the file (not written by file_handle_) are flushed
            if (!FlushFileBuffers(file_handle_.get())) return GetLastError();
            return ERROR_SUCCESS;
        }

        // updated the last modified time,
        // let Windows handle other metadata and buffers
        return TouchFile();
    }

private:
    FileHandle file_handle_;
    FileHandle mapping_handle_;
    unique_ptr<void, FileMappingDeleter> mapping_;
    bool is_write_ = false;

    friend void swap(FileMapping& a, FileMapping& b) noexcept
    {
        using std::swap;
        swap(a.file_handle_, b.file_handle_);
        swap(a.mapping_handle_, b.mapping_handle_);
        swap(a.mapping_, b.mapping_);
    }

    DWORD TouchFile()
    {
        SYSTEMTIME st;
        FILETIME ft;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &ft);
        if (!SetFileTime(file_handle_.get(), nullptr, nullptr, &ft)) return GetLastError();
        return ERROR_SUCCESS;
    }
};

struct SRWLockExclusive
{
    SRWLockExclusive(PSRWLOCK lock) noexcept : lock_(lock) { AcquireSRWLockExclusive(lock_); }

    virtual ~SRWLockExclusive() noexcept { ReleaseSRWLockExclusive(lock_); }

private:
    PSRWLOCK lock_;
};

// [start_idx, end_idx], [start_off, end_off), off < off_end
struct ChunkRange
{
    const u64 start_idx;
    const u64 start_off;
    const u64 end_idx;
    const u64 end_off;
};

struct ChunkDisk
{
    SPD_STORAGE_UNIT* storage_unit = nullptr;
    const u64 block_count = 0;            // disk size = block_count * block_size
    const u32 block_size = 0;             // in bytes
    const u64 chunk_count = 0;            // disk size = chunk_count * chunk_length * block_size
    const u64 chunk_length = 0;           // in blocks
    const vector<u64> part_max;           // part index -> max. # of chunks
    const vector<wstring> part_dirname;   // part index -> chunk directory

    SRWLOCK mut = SRWLOCK_INIT;             // for write access to containers below

    vector<u64> part_current;               // part index -> # of chunks
    u32 part_current_new = 0;               // part index for new chunks
    unordered_map<u64, u32> chunk_parts;    // chunk index -> part index

    const u32 chunk_mmax = 1;                                   // max. # of FileMapping's
    unordered_map<u64, shared_ptr<FileMapping>> chunk_maps;     // chunk index -> FileMapping
    // chunk_maps insertion order
    // NOTE: elements not removed for simplicity (expect not to be reused soon), there may be duplicates!
    deque<u64> chunk_horder;

    ChunkDisk(u64 block_count, u32 block_size, u64 chunk_count, u64 chunk_length,
        vector<u64> part_max, vector<wstring> part_dirname, u32 chunk_mmax)
            : block_count(block_count), block_size(block_size), chunk_count(chunk_count), chunk_length(chunk_length),
              part_max(std::move(part_max)), part_dirname(std::move(part_dirname)), chunk_mmax(chunk_mmax) {}

    virtual ~ChunkDisk()
    {
        FlushAll();
        if (storage_unit != nullptr) SpdStorageUnitDelete(storage_unit);
    }

    ChunkRange BlockChunkRange(u64 block_addr, u32 count) const
    {
        u64 start_idx = block_addr / chunk_length;
        u64 start_off = block_addr % chunk_length;
        u64 end_idx = start_idx;
        u64 end_off;

        // start_idx: [start_off, chunk_length)
        if (count <= chunk_length - start_off)
        {
            end_off = start_off + count;
            return ChunkRange{start_idx, start_off, end_idx, end_off};
        }

        // align to the next chunk
        count -= chunk_length - start_off;
        end_idx += 1 + (count / chunk_length);
        end_off = count % chunk_length;
        return ChunkRange{start_idx, start_off, end_idx, end_off};
    }

    // chunks are not deleted (truncated when unmapped) so remember the last result
    // not thread safe
    u32 ChunkNewPart()
    {
        u32 num_parts = part_dirname.size();
        for (u32 new_part = part_current_new; new_part < num_parts; ++new_part)
        {
            if (part_current[new_part] < part_max[new_part])
            {
                part_current_new = new_part;
                return new_part;
            }
        }
        for (u32 new_part = 0; new_part < part_current_new; ++new_part)
        {
            if (part_current[new_part] < part_max[new_part])
            {
                part_current_new = new_part;
                return new_part;
            }
        }
        // not found (should not happen)
        return num_parts;
    }

    // open chunk and map it to memory
    // cached, mapping will be closed automatically
    DWORD ChunkOpen(u64 chunk_idx, bool is_write, shared_ptr<FileMapping>& mapping)
    {
        if (chunk_idx >= chunk_count) { return ERROR_INVALID_PARAMETER; }

        try
        {
            auto g = SRWLockExclusive(&mut);

            auto map_it = chunk_maps.find(chunk_idx);
            if (map_it != chunk_maps.end()) {
                // cache hit
                if (is_write) map_it->second->set_write();
                mapping = map_it->second;
                return ERROR_SUCCESS;
            }

            auto part_it = chunk_parts.find(chunk_idx);
            auto part_found = part_it != chunk_parts.end();
            u32 part_idx = part_found ? part_it->second : ChunkNewPart();

            // check existence
            auto path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
            auto h = FileHandle(CreateFileW(path.data(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (part_found != bool(h))
            {
                if (!part_found) return ERROR_FILE_EXISTS;
                DWORD err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND) return err;
            }
            if (!part_found && is_write)
            {
                h = FileHandle(CreateFileW(path.data(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ, nullptr,
                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
                if (!h) return GetLastError();

                ++part_current[part_idx];
                chunk_parts[chunk_idx] = part_idx;
            }

            // check size, extend if necessary
            if (h)
            {
                u64 chunk_bytes = chunk_length * block_size;
                LARGE_INTEGER file_size;
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

            if (!is_write && !h) {
                // empty or not present
                mapping = std::make_shared<FileMapping>();
                return ERROR_SUCCESS;
            }

            auto result = std::make_shared<FileMapping>(std::move(h));
            if (!*result) return GetLastError();
            if (is_write) result->set_write();

            while (chunk_maps.size() >= chunk_mmax)
            {
                // maps full, evict one
                u64 old = chunk_horder.front();
                chunk_horder.pop_front();
                if (chunk_maps.erase(old) != 0) break;
            }
            chunk_maps.emplace(make_pair(chunk_idx, result));
            chunk_horder.push_back(chunk_idx);

            mapping = result;
            return ERROR_SUCCESS;
        }
        catch (const std::bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    // empty chunk
    DWORD ChunkUnmap(u64 chunk_idx)
    {
        if (chunk_idx >= chunk_count) { return ERROR_INVALID_PARAMETER; }

        try
        {
            auto g = SRWLockExclusive(&mut);

            auto part_it = chunk_parts.find(chunk_idx);
            if (part_it == chunk_parts.end()) return ERROR_SUCCESS; // not present

            auto map_it = chunk_maps.find(chunk_idx);
            if (map_it != chunk_maps.end()) {
                // already in use
                if (map_it->second.use_count() > 1) return ERROR_SHARING_VIOLATION;

                chunk_maps.erase(map_it);
            }

            u32 part_idx = part_it->second;
            auto path = part_dirname[part_idx] + L"\\chunk" + std::to_wstring(chunk_idx);
            auto h = FileHandle(CreateFileW(path.data(),
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!h) return GetLastError();
            if (!SetEndOfFile(h.get())) return GetLastError();

            return ERROR_SUCCESS;
        }
        catch (const std::bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    DWORD FlushAll()
    {
        auto g = SRWLockExclusive(&mut);

        DWORD err = ERROR_SUCCESS;
        for (auto& m : chunk_maps)
        {
            if (m.second->Flush(0, 0) != ERROR_SUCCESS) err = 1;
        }
        if (err == ERROR_SUCCESS) chunk_maps.clear();

        return err;
    }
};

static ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
}

static BOOLEAN ExceptionFilter(ULONG Code, PEXCEPTION_POINTERS Pointers,
    PUINT_PTR PDataAddress)
{
    if (Code != EXCEPTION_IN_PAGE_ERROR)
        return EXCEPTION_CONTINUE_SEARCH;

    *PDataAddress = Pointers->ExceptionRecord->NumberParameters >= 2 ?
        Pointers->ExceptionRecord->ExceptionInformation[1] : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

// copy zero if src is nullptr
// sizes in bytes
// 0: success, 1: failure, 2: I/O error
static DWORD CopyBuffer(PVOID dst, size_t dst_off, PVOID src, size_t src_off, size_t length, PUINT64 err_info)
{
    PVOID ExceptionDataAddress = nullptr;

    __try
    {
        if (src != nullptr)
            memcpy(recast<u8*>(dst) + dst_off, recast<u8*>(src) + src_off, length);
        else
            memset(recast<u8*>(dst) + dst_off, 0, length);
        return ERROR_SUCCESS;
    }
    __except (ExceptionFilter(GetExceptionCode(), GetExceptionInformation(), recast<PUINT_PTR>(&ExceptionDataAddress)))
    {
        if (ExceptionDataAddress != nullptr)
        {
            if (src != nullptr)
                *err_info = recast<u8*>(ExceptionDataAddress) - recast<u8*>(src);
            else
                *err_info = recast<u8*>(ExceptionDataAddress) - recast<u8*>(dst);
            return 2;
        }
        return 1;
    }
}

static DWORD InternalReadChunk(ChunkDisk* cdisk, PVOID& buffer, SPD_STORAGE_UNIT_STATUS* status,
    u64 chunk_idx, u64 start_off, u64 end_off)
{
    shared_ptr<FileMapping> mapping;
    auto err = cdisk->ChunkOpen(chunk_idx, false, mapping);
    if (err != ERROR_SUCCESS)
    {
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_UNRECOVERED_ERROR, nullptr);
        return 1;
    }

    UINT64 Information;
    auto len = (end_off - start_off) * cdisk->block_size;
    err = CopyBuffer(buffer, 0, mapping->get(), start_off * cdisk->block_size,
        len, &Information);
    if (err != ERROR_SUCCESS)
    {
        if (err == 2) Information = chunk_idx * cdisk->chunk_length + (Information / cdisk->block_size);
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_UNRECOVERED_ERROR, (err == 2) ? &Information : nullptr);
        return 1;
    }

    buffer = recast<u8*>(buffer) + len;
    return ERROR_SUCCESS;
}

static DWORD InternalWriteChunk(ChunkDisk* cdisk, PVOID& buffer, SPD_STORAGE_UNIT_STATUS* status,
    u64 chunk_idx, u64 start_off, u64 end_off)
{
    shared_ptr<FileMapping> mapping;
    auto err = cdisk->ChunkOpen(chunk_idx, true, mapping);
    if (err != ERROR_SUCCESS)
    {
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_WRITE_ERROR, nullptr);
        return 1;
    }

    UINT64 Information;
    auto len = (end_off - start_off) * cdisk->block_size;
    err = CopyBuffer(mapping->get(), start_off * cdisk->block_size, buffer, 0,
        len, &Information);
    if (err != ERROR_SUCCESS)
    {
        if (err == 2) Information = chunk_idx * cdisk->chunk_length + (Information / cdisk->block_size);
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_WRITE_ERROR, (err == 2) ? &Information : nullptr);
        return 1;
    }

    buffer = recast<u8*>(buffer) + len;
    return ERROR_SUCCESS;
}

static DWORD InternalFlushChunk(ChunkDisk* cdisk, SPD_STORAGE_UNIT_STATUS* status,
    u64 chunk_idx, u64 start_off, u64 end_off)
{
    shared_ptr<FileMapping> mapping;
    auto err = cdisk->ChunkOpen(chunk_idx, true, mapping);
    if (err != ERROR_SUCCESS)
    {
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_WRITE_ERROR, nullptr);
        return 1;
    }

    if (start_off == 0 && end_off == cdisk->chunk_length)
    {
        err = mapping->Flush(0, 0);
    }
    else
    {
        err = mapping->Flush(start_off * cdisk->block_size, (end_off - start_off) * cdisk->block_size);
    }
    if (err != ERROR_SUCCESS)
    {
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_WRITE_ERROR, nullptr);
        return 1;
    }

    return ERROR_SUCCESS;
}

static DWORD InternalUnmapChunk(ChunkDisk* cdisk, SPD_STORAGE_UNIT_STATUS* status,
    u64 chunk_idx, u64 start_off, u64 end_off)
{
    if (start_off == 0 && end_off == cdisk->chunk_length)
    {
        DWORD err = cdisk->ChunkUnmap(chunk_idx);
        if (err == ERROR_SUCCESS) return ERROR_SUCCESS;
        if (err != ERROR_SHARING_VIOLATION) return err;
    }

    shared_ptr<FileMapping> mapping;
    auto err = cdisk->ChunkOpen(chunk_idx, true, mapping);
    if (err != ERROR_SUCCESS)
    {
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_NO_SENSE, nullptr);
        return 1;
    }

    UINT64 Information;
    err = CopyBuffer(mapping->get(), start_off * cdisk->block_size, nullptr, 0,
        (end_off - start_off) * cdisk->block_size, &Information);
    if (err != ERROR_SUCCESS)
    {
        if (err == 2) Information = chunk_idx * cdisk->chunk_length + (Information / cdisk->block_size);
        SpdStorageUnitStatusSetSense(status, SCSI_SENSE_MEDIUM_ERROR,
            SCSI_ADSENSE_NO_SENSE, (err == 2) ? &Information : nullptr);
        return 1;
    }

    return ERROR_SUCCESS;
}

static BOOLEAN InternalFlush(SPD_STORAGE_UNIT* StorageUnit,
    UINT64 BlockAddress, UINT32 BlockCount,
    SPD_STORAGE_UNIT_STATUS* Status)
{
    auto cdisk = StorageUnitChunkDisk(StorageUnit);

    if (BlockCount == 0)
    {
        // TODO: support (BlockAddress != 0) case
        if (cdisk->FlushAll() != ERROR_SUCCESS)
        {
            SpdStorageUnitStatusSetSense(Status, SCSI_SENSE_MEDIUM_ERROR,
                SCSI_ADSENSE_WRITE_ERROR, nullptr);
        }
        return TRUE;
    }

    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);
    DWORD err = InternalFlushChunk(cdisk, Status, r.start_idx,
        r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length);
    if (r.start_idx == r.end_idx) return TRUE;
    if (err != ERROR_SUCCESS) return TRUE;

    for (u64 i = r.start_idx + 1; i < r.end_idx; ++i)
    {
        err = InternalFlushChunk(cdisk, Status, i, 0, cdisk->chunk_length);
        if (err != ERROR_SUCCESS) return TRUE;
    }
    InternalFlushChunk(cdisk, Status, r.end_idx, 0, r.end_off);

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

    auto cdisk = StorageUnitChunkDisk(StorageUnit);

    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);
    DWORD err = InternalReadChunk(cdisk, Buffer, Status, r.start_idx,
        r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length);
    if (r.start_idx == r.end_idx) return TRUE;
    if (err != ERROR_SUCCESS) return TRUE;

    for (u64 i = r.start_idx + 1; i < r.end_idx; ++i)
    {
        err = InternalReadChunk(cdisk, Buffer, Status, i, 0, cdisk->chunk_length);
        if (err != ERROR_SUCCESS) return TRUE;
    }
    InternalReadChunk(cdisk, Buffer, Status, r.end_idx, 0, r.end_off);

    return TRUE;
}

static BOOLEAN Write(SPD_STORAGE_UNIT* StorageUnit,
    PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
    SPD_STORAGE_UNIT_STATUS* Status)
{
    WARNONCE(!StorageUnit->StorageUnitParams.WriteProtected);
    WARNONCE(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    auto cdisk = StorageUnitChunkDisk(StorageUnit);

    auto r = cdisk->BlockChunkRange(BlockAddress, BlockCount);
    DWORD err = InternalWriteChunk(cdisk, Buffer, Status, r.start_idx,
        r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length);
    if (r.start_idx == r.end_idx) return TRUE;
    if (err != ERROR_SUCCESS) return TRUE;

    for (u64 i = r.start_idx + 1; i < r.end_idx; ++i)
    {
        err = InternalWriteChunk(cdisk, Buffer, Status, i, 0, cdisk->chunk_length);
        if (err != ERROR_SUCCESS) return TRUE;
    }
    InternalWriteChunk(cdisk, Buffer, Status, r.end_idx, 0, r.end_off);

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

    auto cdisk = StorageUnitChunkDisk(StorageUnit);

    for (UINT32 I = 0; I < Count; ++I)
    {
        // NOTE: a chunk gets truncated only if single block range covers it
        auto r = cdisk->BlockChunkRange(Descriptors[I].BlockAddress, Descriptors[I].BlockCount);
        InternalUnmapChunk(cdisk, Status, r.start_idx,
            r.start_off, r.start_idx == r.end_idx ? r.end_off : cdisk->chunk_length);
        if (r.start_idx == r.end_idx) return TRUE;

        for (u64 i = r.start_idx + 1; i < r.end_idx; ++i)
        {
            InternalUnmapChunk(cdisk, Status, i, 0, cdisk->chunk_length);
        }
        InternalUnmapChunk(cdisk, Status, r.end_idx, 0, r.end_off);
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
static DWORD ReadChunkDiskFile(PCWSTR cdisk_path, unique_ptr<ChunkDisk>& cdisk)
{
    try
    {
        // read .chunkdisk and convert to wstr
        auto h = FileHandle(CreateFileW(cdisk_path, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr));
        if (!h) return GetLastError();

        LARGE_INTEGER size;
        if (!GetFileSizeEx(h.get(), &size)) return GetLastError();
        if (size.HighPart != 0) return ERROR_INVALID_PARAMETER;
        if (size.LowPart == 0) return ERROR_INVALID_PARAMETER;

        auto buf = unique_ptr<CHAR[]>(new CHAR[size_t(size.LowPart) + 1]());

        DWORD bytes_read;
        if (!ReadFile(h.get(), buf.get(), size.LowPart, &bytes_read, nullptr)) return GetLastError();

        int wchar_size = MultiByteToWideChar(CP_UTF8, 0, buf.get(),
            bytes_read + 1, nullptr, 0);
        if (!wchar_size) return GetLastError();

        auto wbuf = unique_ptr<WCHAR[]>(new WCHAR[wchar_size]());

        wchar_size = MultiByteToWideChar(CP_UTF8, 0, buf.get(),
            bytes_read + 1, wbuf.get(), wchar_size);
        if (!wchar_size) return GetLastError();

        // parse .chunkdisk
        buf.reset();

        // disk size
        PWSTR state;
        PWSTR token = wcstok_s(wbuf.get(), L"\n", &state);
        PWSTR endp;
        if (!token) return ERROR_INVALID_PARAMETER;
        u64 disk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // chunk size
        token = wcstok_s(nullptr, L"\n", &state);
        if (!token) return ERROR_INVALID_PARAMETER;
        u64 chunk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // parts
        vector<u64> part_max;
        vector<wstring> part_dirname;

        token = wcstok_s(nullptr, L"\n", &state);
        for (; token; token = wcstok_s(nullptr, L"\n", &state))
        {
            u64 pmax = wcstoull(token, &endp, 10);
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
        u32 block_size = 512;
        if (disk_size == 0 || chunk_size == 0 || block_size == 0) return ERROR_INVALID_PARAMETER;
        if (disk_size % block_size || chunk_size > disk_size) return ERROR_INVALID_PARAMETER;
        if (chunk_size % block_size) return ERROR_INVALID_PARAMETER;

        u64 chunk_count = (disk_size + (chunk_size - 1)) / chunk_size;
        if (chunk_count == 0) return ERROR_INVALID_PARAMETER;
        if (chunk_count > std::accumulate(part_max.begin(), part_max.end(), 0ull)) return ERROR_INVALID_PARAMETER;
        u64 chunk_length = chunk_size / block_size;

        // done, set parameters
        auto new_disk = std::make_unique<ChunkDisk>(
            disk_size / block_size,
            block_size,
            chunk_count,
            chunk_length,
            std::move(part_max),
            std::move(part_dirname),
            max(1, 0x200000 / chunk_length) /* up to 1 GB */);
        cdisk = std::move(new_disk);
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

// read parts and chunks, check consistency
static DWORD ChunkDiskInit(ChunkDisk* cdisk)
{
    u64 chunk_count = cdisk->chunk_count;
    u32 num_parts = cdisk->part_dirname.size();

    try
    {
        // make sure parts exist, no dups
        auto part_ids = unordered_set<std::pair<u32, u64>, pair_hash>();
        for (u32 i = 0; i < num_parts; ++i)
        {
            auto h = FileHandle(CreateFileW((cdisk->part_dirname[i] + L'\\').data(),
                FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!h) return GetLastError();

            BY_HANDLE_FILE_INFORMATION fileInfo;
            if (!GetFileInformationByHandle(h.get(), &fileInfo)) return GetLastError();

            auto r = part_ids.emplace(make_pair(fileInfo.dwVolumeSerialNumber,
                fileInfo.nFileIndexLow + (u64(fileInfo.nFileIndexHigh) << 32)));
            if (!std::get<bool>(r)) return ERROR_INVALID_PARAMETER;
        }
        part_ids.clear();

        // read parts
        auto part_current = vector<u64>(num_parts, 0);
        auto chunk_parts = unordered_map<u64, u32>();
        for (u32 i = 0; i < num_parts; ++i)
        {
            for (auto& p : fs::directory_iterator(cdisk->part_dirname[i] + L'\\'))
            {
                auto fname = p.path().filename().wstring();
                if (_wcsnicmp(fname.data(), L"chunk", 5) != 0) continue;

                PWSTR endp;
                u64 idx = wcstoull(fname.data() + 5, &endp, 10);
                if (fname.data() + 5 == endp || *endp != L'\0' || errno == ERANGE || idx >= chunk_count) continue;

                auto r = chunk_parts.emplace(idx, i);
                if (!std::get<bool>(r)) return ERROR_FILE_EXISTS;
                if (++part_current[i] > cdisk->part_max[i]) return ERROR_PARAMETER_QUOTA_EXCEEDED;
            }
        }
        cdisk->part_current = std::move(part_current);
        cdisk->chunk_parts = std::move(chunk_parts);
    }
    catch (const std::system_error& e)
    {
        return e.code().value();
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

static DWORD ChunkDiskCreate(ChunkDisk* cdisk, BOOLEAN write_protected, PWSTR pipe_name)
{
    const wchar_t ProductId[] = L"ChunkDisk";
    const wchar_t ProductRevision[] = L"0.1";
    SPD_STORAGE_UNIT_PARAMS unit_params;

    memset(&unit_params, 0, sizeof unit_params);
    UuidCreate(&unit_params.Guid);
    unit_params.BlockCount = cdisk->block_count;
    unit_params.BlockLength = cdisk->block_size;
    unit_params.MaxTransferLength = 64 * 1024;
    if (WideCharToMultiByte(CP_UTF8, 0,
        ProductId, lstrlenW(ProductId),
        LPSTR(unit_params.ProductId), sizeof(unit_params.ProductId),
        nullptr, nullptr) == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (WideCharToMultiByte(CP_UTF8, 0,
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
    DWORD err = SpdStorageUnitCreate(pipe_name, &unit_params, &CHUNK_DISK_INTERFACE, &unit);
    if (err != ERROR_SUCCESS) return err;

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
    err = ReadChunkDiskFile(ChunkDiskFile, cdisk);
    if (err != ERROR_SUCCESS) {
        logerr(L"error: parsing failed with error %lu", err);
        return err;
    }
    err = ChunkDiskInit(cdisk.get());
    if (err != ERROR_SUCCESS) {
        logerr(L"error: cannot initialize ChunkDisk: error %lu", err);
        return err;
    }
    err = ChunkDiskCreate(cdisk.get(), !WriteAllowed, PipeName);
    if (err != ERROR_SUCCESS) {
        logerr(L"error: cannot create ChunkDisk: error %lu", err);
        return err;
    }
    SpdStorageUnitSetDebugLog(cdisk->storage_unit, DebugFlags);
    // FIXME: issue #10
    err = SpdStorageUnitStartDispatcher(cdisk->storage_unit, 1);
    if (err != ERROR_SUCCESS) {
        logerr(L"error: cannot start ChunkDisk: error %lu", err);
        return err;
    }

    info(L"%s -f %s -W %u%s%s",
        PROGNAME,
        ChunkDiskFile,
        !!WriteAllowed,
        nullptr != PipeName ? L" -p " : L"",
        nullptr != PipeName ? PipeName : L"");

    SpdGuardSet(&ConsoleCtrlGuard, cdisk->storage_unit);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    SpdStorageUnitWaitDispatcher(cdisk->storage_unit);
    SpdGuardSet(&ConsoleCtrlGuard, nullptr);

    cdisk.reset();
    return ERROR_SUCCESS;
}
