/**
 * @file main.cpp
 *
 * @copyright 2021-2022 extratype
 */

#include "utils.hpp"
#include "base.hpp"
#include "service.hpp"
#include "worker.hpp"
#include <memory>
#include <numeric>
#include <unordered_set>
#include <atomic>
#include <filesystem>

using std::bad_alloc;
using std::unique_ptr;
using std::wstring;
using std::vector;

namespace chunkdisk
{

namespace
{

// sector size, 512 or 4096
constexpr auto BLOCK_SIZE = u32(512);

// align with the underlying hardware, 4096 will work
// like 512e with BLOCK_SIZE == 512 and PAGE_SIZE == 4096
constexpr auto PAGE_SIZE = u32(4096);

// must be a multiple of PAGE_SIZE
constexpr auto MAX_TRANSFER_LENGTH = u32(1024 * 1024);

constexpr auto MAX_WORKERS = u32(MAXIMUM_WAIT_OBJECTS);

struct FileIdInfoHash
{
    u64 operator()(const FILE_ID_INFO& id_info) const
    {
        auto h = u64(0);
        h = hash_combine_64(h, u64(id_info.VolumeSerialNumber));
        h = hash_combine_64(h, *(const u64*)(&id_info.FileId.Identifier[0]));
        h = hash_combine_64(h, *(const u64*)(&id_info.FileId.Identifier[8]));
        return h;
    }
};

struct FileIdInfoEqual
{
    bool operator()(const FILE_ID_INFO& a, const FILE_ID_INFO& b) const
    {
        return memcmp(&a, &b, sizeof(FILE_ID_INFO)) == 0;
    }
};

}

struct ChunkDisk
{
    // not movable
    ChunkDiskService service;
    // don't insert or erase after StartWorkers()
    // StopWorkers() to stop
    vector<ChunkDiskWorker> workers;

    // not movable, increment only
    std::atomic<u32> workers_assigned = 0;

    explicit ChunkDisk(vector<ChunkDiskBase> bases, SPD_STORAGE_UNIT* storage_unit, bool trim_chunk, bool zero_chunk)
        : service(std::move(bases), storage_unit, trim_chunk, zero_chunk) {}

    ~ChunkDisk()
    {
        workers.clear();    // workers may refer service.storage_unit
        SpdStorageUnitDelete(service.storage_unit);
    }
};

/*
 * read .chunkdisk file
 *
 * parent: optional, path to parent .chunkdisk file
 * disk size in bytes: must be a multiple of PAGE_SIZE
 * chunk size in bytes: must be a multiple of PAGE_SIZE
 * number path/to/dir...: max. # of chunks in part directory
 */
DWORD ReadChunkDiskFile(PCWSTR chunkdisk_file, const bool read_only, const bool move_enabled,
                        unique_ptr<ChunkDiskBase>& base, wstring& parent)
{
    try
    {
        // read .chunkdisk and convert to wstring
        auto h = FileHandle(CreateFileW(
            chunkdisk_file, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h)
        {
            auto err = GetLastError();
            SpdLogErr(L"error: opening %s failed with code %lu", chunkdisk_file, err);
            return err;
        }

        auto size = LARGE_INTEGER();
        if (!GetFileSizeEx(h.get(), &size))
        {
            auto err = GetLastError();
            SpdLogErr(L"error: reading %s failed with code %lu", chunkdisk_file, err);
            return err;
        }
        if (size.HighPart != 0 || int(size.LowPart) < 0 || size.LowPart == 0)
        {
            SpdLogErr(L"error: invalid size of file %s", chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }

        auto buf = unique_ptr<u8[]>(new u8[usize(size.LowPart)]);
        auto bytes_read = DWORD();
        if (!ReadFile(h.get(), buf.get(), size.LowPart, &bytes_read, nullptr))
        {
            auto err = GetLastError();
            SpdLogErr(L"error: reading %s failed with code %lu", chunkdisk_file, err);
            return err;
        }

        auto wbuf = wstring();
        auto err = ConvertUTF8(buf.get(), bytes_read, wbuf);
        if (err != ERROR_SUCCESS)
        {
            SpdLogErr(L"error: reading %s failed with code %lu", chunkdisk_file, err);
            return err;
        }

        // parse .chunkdisk
        buf.reset();
        auto parent_r = wstring();

        auto* state = PWSTR();
        auto* token = wcstok_s(wbuf.data(), L"\n", &state);
        auto* endp = PWSTR();
        if (!token)
        {
            SpdLogErr(L"error: missing parameters in %s", chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        auto disk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE)
        {
            // parent
            parent_r = wstring(token);
            if (!parent_r.empty() && parent_r[parent_r.size() - 1] == L'\r') parent_r.erase(parent_r.size() - 1);
            if (parent_r.empty() || !std::filesystem::path(parent_r).is_absolute())
            {
                SpdLogErr(L"error: invalid parent disk path in %s: %s", chunkdisk_file, parent_r.data());
                return ERROR_INVALID_PARAMETER;
            }

            // disk size
            token = wcstok_s(nullptr, L"\n", &state);
            if (!token)
            {
                SpdLogErr(L"error: missing parameters in %s", chunkdisk_file);
                return ERROR_INVALID_PARAMETER;
            }
            disk_size = wcstoull(token, &endp, 10);
            if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE)
            {
                SpdLogErr(L"error: invalid disk size in %s: %s", chunkdisk_file, token);
                return ERROR_INVALID_PARAMETER;
            }
        }
        else
        {
            // no parent
            parent_r = L"";
        }

        // chunk size
        token = wcstok_s(nullptr, L"\n", &state);
        if (!token)
        {
            SpdLogErr(L"error: missing parameters in %s", chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        auto chunk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE)
        {
            SpdLogErr(L"error: invalid chunk size in %s: %s", chunkdisk_file, token);
            return ERROR_INVALID_PARAMETER;
        }

        // parts
        auto part_max = vector<u64>();
        auto part_dirname = vector<wstring>();

        token = wcstok_s(nullptr, L"\n", &state);
        for (; token; token = wcstok_s(nullptr, L"\n", &state))
        {
            auto pmax = wcstoull(token, &endp, 10);
            if (token == endp || *endp != L' ' || errno == ERANGE)
            {
                SpdLogErr(L"error: invalid number of chunks in %s: %s", chunkdisk_file, token);
                return ERROR_INVALID_PARAMETER;
            }

            auto dirname = wstring(endp + 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\r') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\\') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'/')  dirname.erase(dirname.size() - 1);
            auto dirpath = std::filesystem::path(std::move(dirname));
            if (!dirpath.is_absolute())
            {
                SpdLogErr(L"error: invalid part path in %s: %s", chunkdisk_file, dirpath.c_str());
                return ERROR_INVALID_PARAMETER;
            }

            part_max.push_back(pmax);
            part_dirname.emplace_back(dirpath.wstring());
        }

        // check parameters
        if (disk_size == 0 || chunk_size == 0 || chunk_size > disk_size)
        {
            SpdLogErr(L"error: invalid disk size (%llu) and/or chunk size (%llu) in %s",
                      disk_size, chunk_size, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        if (LONGLONG(chunk_size) <= 0)
        {
            SpdLogErr(L"error: chunk size (%llu) in %s is too large", chunk_size, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;  // integer overflow in file offset
        }
        if (disk_size % BLOCK_SIZE || disk_size % PAGE_SIZE)
        {
            SpdLogErr(L"error: disk size (%llu) is not aligned in %s", disk_size, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        if (chunk_size % BLOCK_SIZE || chunk_size % PAGE_SIZE)
        {
            SpdLogErr(L"error: chunk size (%llu) is not aligned in %s", chunk_size, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        // if (PAGE_SIZE % BLOCK_SIZE) return ERROR_INVALID_PARAMETER;

        auto chunk_count = (disk_size + (chunk_size - 1)) / chunk_size;
        if (chunk_count == 0 || disk_size > chunk_size * chunk_count)
        {
            SpdLogErr(L"error: invalid chunk size (%llu) in %s", chunk_size, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }
        if (chunk_count > std::accumulate(part_max.begin(), part_max.end(), 0ull))
        {
            SpdLogErr(L"error: total number of chunks must be at least %llu in %s", chunk_count, chunkdisk_file);
            return ERROR_INVALID_PARAMETER;
        }

        // ChunkDiskBase is not move-assignable
        base = std::make_unique<ChunkDiskBase>(
            BLOCK_SIZE,
            PAGE_SIZE / BLOCK_SIZE,
            chunk_size / BLOCK_SIZE,
            disk_size / BLOCK_SIZE,
            chunk_count,
            std::move(part_max),
            std::move(part_dirname),
            read_only,
            move_enabled);
        // parent not set if err
        parent = std::move(parent_r);
    }
    catch (const bad_alloc&)
    {
        SpdLogErr(L"error: not enough memory to read %s", chunkdisk_file);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

/*
 * Read .chunkdisk file (bases[0]) and its parents (bases[1] and so on, if any).
 * read_only and move_enabled are for bases[0].
 */
DWORD ReadChunkDiskBases(PCWSTR chunkdisk_file, const bool read_only, const bool move_enabled,
                         vector<ChunkDiskBase>& bases)
{
    auto part_ids_128 = std::unordered_set<FILE_ID_INFO, FileIdInfoHash, FileIdInfoEqual>();
    auto part_ids_64 = std::unordered_set<FILE_ID_INFO, FileIdInfoHash, FileIdInfoEqual>();

    auto base = unique_ptr<ChunkDiskBase>();
    auto parent = wstring();
    auto err = ReadChunkDiskFile(chunkdisk_file, read_only, move_enabled, base, parent);
    if (err != ERROR_SUCCESS) return err;

    // read parents and add to bases
    while (true)
    {
        try
        {
            if (!bases.empty())
            {
                // same geometry
                if (bases[0].block_size != base->block_size
                    || bases[0].page_length != base->page_length
                    || bases[0].chunk_length != base->chunk_length
                    || bases[0].block_count != base->block_count
                    || bases[0].chunk_count != base->chunk_count)
                {
                    err = ERROR_INVALID_PARAMETER;
                    SpdLogErr(L"error: incompatible base disk for %s", chunkdisk_file);
                    break;
                }
            }

            // make sure parts exist, no dups
            for (const auto& dirname : base->part_dirname)
            {
                auto h = FileHandle(CreateFileW(
                    (dirname + L'\\').data(),
                    FILE_READ_ATTRIBUTES, 0, nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, nullptr));
                if (!h)
                {
                    err = GetLastError();
                    SpdLogErr(L"error: opening directory %s failed with code %lu", dirname.data(), err);
                    break;
                }

                auto id_128 = FILE_ID_INFO();
                auto id_128_valid = bool(GetFileInformationByHandleEx(
                    h.get(), FileIdInfo, &id_128, sizeof(id_128)));
                if (id_128_valid && !part_ids_128.emplace(id_128).second)
                {
                    err = ERROR_INVALID_PARAMETER; // dup found
                    SpdLogErr(L"error: duplicate part: %s", dirname.data());
                    break;
                }

                auto id_64 = FILE_ID_INFO();
                auto id_64_info = BY_HANDLE_FILE_INFORMATION();
                auto id_64_valid = bool(GetFileInformationByHandle(h.get(), &id_64_info));
                if (!id_64_valid)
                {
                    err = GetLastError();
                    SpdLogErr(L"error: checking directory %s failed with code %lu", dirname.data(), err);
                    break;
                }
                else
                {
                    id_64.VolumeSerialNumber = id_64_info.dwVolumeSerialNumber;
                    *recast<u32*>(&id_64.FileId.Identifier + 0) = id_64_info.nFileIndexLow;
                    *recast<u32*>(&id_64.FileId.Identifier + 4) = id_64_info.nFileIndexHigh;

                    if (!part_ids_64.emplace(id_64).second)
                    {
                        err = ERROR_INVALID_PARAMETER; // dup found
                        SpdLogErr(L"error: duplicate part: %s", dirname.data());
                        break;
                    }
                }
            }
            if (err != ERROR_SUCCESS) break;

            // base ok
            bases.emplace_back(std::move(*base));
            base.reset();

            if (parent.empty())
            {
                err = ERROR_SUCCESS;
                break;
            }
        }
        catch (const bad_alloc&)
        {
            err = ERROR_NOT_ENOUGH_MEMORY;
            SpdLogErr(L"error: not enough memory to read chunkdisk file(s)");
            break;
        }

        // parents are always read_only
        err = ReadChunkDiskFile(parent.data(), true, false, base, parent);
        if (err != ERROR_SUCCESS) break;
        // parent not set if err
    }

    if (err != ERROR_SUCCESS)
    {
        bases.clear();
        return err;
    }
    return ERROR_SUCCESS;
}

ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
}

ChunkDiskWorker* GetAssignedWorker(SPD_STORAGE_UNIT* StorageUnit)
{
    static thread_local auto* worker = (ChunkDiskWorker*)(nullptr);
    if (worker == nullptr)
    {
        auto* cdisk = StorageUnitChunkDisk(StorageUnit);
        auto idx = cdisk->workers_assigned.fetch_add(1, std::memory_order_acq_rel);
        worker = &cdisk->workers[idx];
    }
    return worker;
}

// SPD_STORAGE_UNIT_INTERFACE operations
// op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
BOOLEAN PostWork(SPD_STORAGE_UNIT* StorageUnit, const ChunkOpKind op_kind, u64 block_addr, u64 count)
{
    auto* worker = GetAssignedWorker(StorageUnit);
    auto* context = SpdStorageUnitGetOperationContext();
    auto& status = context->Response->Status;
    auto err = DWORD(ERROR_SUCCESS);

    while (true)
    {
        err = worker->PostWork(context, op_kind, block_addr, count);
        if (err != ERROR_BUSY || status.ScsiStatus != SCSISTAT_GOOD) break;
        err = worker->Wait();
        if (err != ERROR_SUCCESS) break;
    }
    if (err != ERROR_IO_PENDING && err != ERROR_SUCCESS && status.ScsiStatus == SCSISTAT_GOOD)
    {
        SetScsiError(&status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
    }

    return (err == ERROR_IO_PENDING) ? FALSE : TRUE;
}

BOOLEAN Read(SPD_STORAGE_UNIT* StorageUnit,
             PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
             SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return PostWork(StorageUnit, READ_CHUNK, BlockAddress, BlockCount);
}

BOOLEAN Write(SPD_STORAGE_UNIT* StorageUnit,
              PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
              SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return PostWork(StorageUnit, WRITE_CHUNK, BlockAddress, BlockCount);
}

// Flush(0, 0) requested at exit
BOOLEAN Flush(SPD_STORAGE_UNIT* StorageUnit,
                     UINT64 BlockAddress, UINT32 BlockCount,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    // SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported);

    // unbuffered, pages write through, nothing to flush
    // metadata flushed when handles are closed
    // in ChunkDiskWorker::PeriodicCheck(), ChunkDiskWorker::IdleWork()
    return TRUE;
}

BOOLEAN Unmap(SPD_STORAGE_UNIT* StorageUnit,
                     SPD_UNMAP_DESCRIPTOR Descriptors[], UINT32 Count,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.UnmapSupported);

    // Descriptors is just Buffer, writable
    // merge ranges
    if (Count == 0) return TRUE;

    std::sort(Descriptors, Descriptors + Count,
              [](const auto& a, const auto& b)
              {
                  return (a.BlockAddress < b.BlockAddress) ||
                         (a.BlockAddress == b.BlockAddress) && (a.BlockCount < b.BlockCount);
              });

    auto new_count = UINT32(0);
    auto prev_addr = Descriptors[0].BlockAddress;
    auto prev_count = Descriptors[0].BlockCount;

    for (UINT32 I = 0; I < Count; ++I)
    {
        const auto addr = Descriptors[I].BlockAddress;
        const auto count = Descriptors[I].BlockCount;
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

    return PostWork(StorageUnit, UNMAP_CHUNK, 0, new_count);
}

static SPD_STORAGE_UNIT_INTERFACE CHUNK_DISK_INTERFACE =
{
    Read,
    Write,
    Flush,
    Unmap,
};

DWORD CreateStorageUnit(PWSTR chunkdisk_file, GUID guid, const BOOLEAN write_protected,
                        const BOOLEAN trim_chunk, const BOOLEAN zero_chunk,
                        const BOOLEAN move_enabled, PWSTR pipe_name, unique_ptr<ChunkDisk>& cdisk_out)
{
    // read chunkdisk file
    auto bases = vector<ChunkDiskBase>();
    auto err = ReadChunkDiskBases(chunkdisk_file, write_protected, move_enabled, bases);
    if (err != ERROR_SUCCESS) return err;

    // create WinSpd unit
    SPD_STORAGE_UNIT* unit = nullptr;
    err = [guid, &bases, write_protected, pipe_name, &unit]() -> DWORD
    {
        constexpr wchar_t ProductId[] = L"ChunkDisk";
        constexpr wchar_t ProductRevision[] = L"1.6";
        auto unit_params = SPD_STORAGE_UNIT_PARAMS();

        unit_params.Guid = guid;
        unit_params.BlockCount = bases[0].block_count;
        unit_params.BlockLength = bases[0].block_size;
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

        auto err = SpdStorageUnitCreate(pipe_name, &unit_params, &CHUNK_DISK_INTERFACE, &unit);
        if (err != ERROR_SUCCESS) SpdLogErr(L"error: failed to create ChunkDisk unit with code %lu", err);
        return err;
    }();
    if (err != ERROR_SUCCESS) return err;

    // create ChunkDisk
    auto cdisk = unique_ptr<ChunkDisk>();
    try
    {
        // unit is deleted when cdisk is deleted
        cdisk = std::make_unique<ChunkDisk>(std::move(bases), unit, trim_chunk, zero_chunk);
        unit->UserContext = cdisk.get();
    }
    catch (const bad_alloc&)
    {
        SpdStorageUnitDelete(unit);
        SpdLogErr(L"error: not enough memory to start");
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    err = cdisk->service.Start();
    if (err != ERROR_SUCCESS) return err;

    cdisk_out = std::move(cdisk);
    return ERROR_SUCCESS;
}

DWORD StopWorkers(ChunkDisk& cdisk, const DWORD timeout_ms = INFINITE)
{
    vector<HANDLE> handles;
    auto err = [&cdisk, timeout_ms, &handles]() -> DWORD
    {
        try
        {
            handles.reserve(cdisk.workers.size());
            for (auto& worker : cdisk.workers)
            {
                auto h = HANDLE();
                auto err = worker.StopAsync(h);
                if (err != ERROR_SUCCESS) return err;
                handles.push_back(h);
            }
            if (handles.empty()) return ERROR_SUCCESS;

            auto err = WaitForMultipleObjects(handles.size(), &handles.front(), TRUE, timeout_ms);
            if (WAIT_OBJECT_0 <= err && err < WAIT_OBJECT_0 + handles.size()) return ERROR_SUCCESS;
            if (WAIT_ABANDONED_0 <= err && err < WAIT_ABANDONED_0 + handles.size()) return ERROR_ABANDONED_WAIT_0;
            if (err == WAIT_TIMEOUT) return ERROR_TIMEOUT;
            return GetLastError();
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }();

    for (auto h : handles) CloseHandle(h);
    return err;
}

// num_workers: should be positive
DWORD StartWorkers(ChunkDisk& cdisk, const u32 num_workers)
{
    auto& workers = cdisk.workers;

    auto err = DWORD(ERROR_SUCCESS);
    try
    {
        workers.reserve(num_workers);
        for (auto i = u32(0); i < num_workers; ++i)
        {
            auto& worker = workers.emplace_back(cdisk.service);
            err = worker.Start();
            if (err != ERROR_SUCCESS) break;
        }
    }
    catch (const bad_alloc&)
    {
        err = ERROR_NOT_ENOUGH_MEMORY;
    }
    if (err != ERROR_SUCCESS) StopWorkers(cdisk);
    return err;
}

// don't insert or erase
vector<ChunkDiskWorker>& GetWorkers(SPD_STORAGE_UNIT* StorageUnit)
{
    return StorageUnitChunkDisk(StorageUnit)->workers;
}

}   // namespace chunkdisk

namespace
{

struct Usage : std::exception
{
    static constexpr WCHAR PROGNAME[] = L"chunkdisk";

    // limited to 1024 elements
    static constexpr WCHAR usage1[] = L""
        "usage: %s OPTIONS\n"
        "\n"
        "options:\n"
        "    -f ChunkDiskFile                    Chunkdisk metadata file (name.chunkdisk)\n"
        "    -W 0|1                              Disable/enable writes (deflt: enable)\n"
        "                                        The .lock file will not be removed upon exit if disabled\n"
        "    -X 0|1                              Disable/enable truncating chunk if completely unmapped (deflt: enable)\n"
        "    -Z 0|1                              Disable/enable zero-filling chunk data if unmapped (deflt: enable)\n"
        "                                        Note that the LBPRZ bit is 0 for both options\n"
        "    -M 0|1                              Disable/enable support for moving chunks (deflt: disable)\n"
        "                                        Chunks must be locked exclusively to be moved\n"
        "    -t Number                           Number of threads (deflt: automatic)\n"
        "    -U GUID                             GUID as the serial number of the WinSpd disk (deflt: random)";

    static constexpr WCHAR usage2[] = L""
        "    -d -1                               Debug flags\n"
        "    -D DebugLogFile                     Debug log file; - for stderr\n"
        "    -p \\\\.\\pipe\\PipeName                Listen on pipe; omit to use driver\n"
        "";
};

ULONG argtol(wchar_t** argp, ULONG deflt)
{
    if (argp[0] == nullptr)
        throw Usage();

    PWSTR endp;
    ULONG ul = wcstol(argp[0], &endp, 10);
    return (argp[0][0] != L'\0' && *endp == L'\0') ? ul : deflt;
}

PWSTR argtos(wchar_t** argp)
{
    if (argp[0] == nullptr)
        throw Usage();

    return argp[0];
}

SPD_GUARD ConsoleCtrlGuard = SPD_GUARD_INIT;

BOOL WINAPI ConsoleCtrlHandler(DWORD CtrlType)
{
    SpdGuardExecute(&ConsoleCtrlGuard, (void(*)(PVOID))(SpdStorageUnitShutdown));
    return TRUE;
}

}   // namespace

int wmain(int argc, wchar_t** argv)
{
    wchar_t** argp;
    PWSTR ChunkDiskFile = nullptr;
    ULONG WriteAllowed = 1;
    ULONG TrimChunk = 1;
    ULONG ZeroChunk = 1;
    ULONG MoveEnabled = 0;
    ULONG NumThreads = 0;
    PWSTR Guid = nullptr;
    PWSTR DebugLogFile = nullptr;
    PWSTR PipeName = nullptr;
    ULONG DebugFlags = 0;

    try
    {
        for (argp = argv + 1; argp[0] != nullptr; argp++)
        {
            if (argp[0][0] != L'-')
                break;
            switch (argp[0][1])
            {
            case L'?':
                throw Usage();
            case L'f':
                ChunkDiskFile = argtos(++argp);
                break;
            case L'W':
                WriteAllowed = argtol(++argp, WriteAllowed);
                break;
            case L'X':
                TrimChunk = argtol(++argp, TrimChunk);
                break;
            case L'Z':
                ZeroChunk = argtol(++argp, ZeroChunk);
                break;
            case L'M':
                MoveEnabled = argtol(++argp, MoveEnabled);
                break;
            case L't':
                NumThreads = argtol(++argp, NumThreads);
                break;
            case L'U':
                Guid = argtos(++argp);
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
                throw Usage();
            }
        }

        if (argp[0] != nullptr || ChunkDiskFile == nullptr)
            throw Usage();
    }
    catch (const Usage&)
    {
        SpdLogErr(Usage::usage1, Usage::PROGNAME);
        SpdLogErr(Usage::usage2);
        return ERROR_INVALID_PARAMETER;
    }

    auto err = DWORD(ERROR_SUCCESS);
    if (NumThreads == 0)
    {
        err = chunkdisk::GetThreadCount(&NumThreads);
        if (err != ERROR_SUCCESS)
        {
            SpdLogErr(L"error: failed to get number of CPU threads with code %lu", err);
            return err;
        }
    }
    if (NumThreads > chunkdisk::MAX_WORKERS)
    {
        SpdLogWarn(L"warning: number of threads capped to %u", chunkdisk::MAX_WORKERS);
        NumThreads = chunkdisk::MAX_WORKERS;
    }

    auto UnitGuid = GUID();
    if (Guid == nullptr)
    {
        UuidCreate(&UnitGuid);
    }
    else
    {
        err = UuidFromStringW(reinterpret_cast<RPC_WSTR>(Guid), &UnitGuid);
        if (err != RPC_S_OK)
        {
            SpdLogErr(L"error: invalid disk GUID: %s", Guid);
            return ERROR_INVALID_PARAMETER;
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
            SpdLogErr(L"error: cannot open debug log file");
            return err;
        }
        SpdDebugLogSetHandle(DebugLogHandle);
    }

    auto cdisk = unique_ptr<chunkdisk::ChunkDisk>();
    err = chunkdisk::CreateStorageUnit(ChunkDiskFile, UnitGuid, !WriteAllowed,
                                       !!TrimChunk, !!ZeroChunk, !!MoveEnabled, PipeName, cdisk);
    if (err != ERROR_SUCCESS) return err;
    err = chunkdisk::StartWorkers(*cdisk, NumThreads);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: failed to start worker threads with code %lu", err);
        return err;
    }

    auto* storage_unit = cdisk->service.storage_unit;
    SpdStorageUnitSetDebugLog(storage_unit, DebugFlags);
    err = SpdStorageUnitStartDispatcher(storage_unit, NumThreads);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"failed to start ChunkDisk with code %lu", err);
        return err;
    }

    auto UnitGuidStr = RPC_WSTR();
    if (UuidToStringW(&UnitGuid, &UnitGuidStr) == RPC_S_OK)
    {
        SpdLogInfo(L"%s -f %s -W %u -X %u -Z %u -M %u -t %d -U %s%s%s",
                   Usage::PROGNAME,
                   ChunkDiskFile,
                   !!WriteAllowed,
                   !!TrimChunk,
                   !!ZeroChunk,
                   MoveEnabled,
                   NumThreads,
                   UnitGuidStr,
                   (nullptr != PipeName) ? L" -p " : L"",
                   (nullptr != PipeName) ? PipeName : L"");
        RpcStringFreeW(&UnitGuidStr);
    }

    SpdGuardSet(&ConsoleCtrlGuard, storage_unit);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    SpdStorageUnitWaitDispatcher(storage_unit);
    SpdGuardSet(&ConsoleCtrlGuard, nullptr);

    chunkdisk::StopWorkers(*cdisk);
    cdisk.reset();
    return ERROR_SUCCESS;
}
