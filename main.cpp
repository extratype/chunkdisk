/**
 * @file main.cpp
 *
 * @copyright 2021 extratype
 */

/*
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
*/
#include <winspd/winspd.h>

// FIXME static -> anonymous namespace
// FIXME docs

/*
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
*/




/*
 * read .chunkdisk file
 *
 * disk size in bytes: must be a multiple of PAGE_SIZE
 * chunk size in bytes: must be a multiple of PAGE_SIZE
 * number path/to/dir...: max. # of chunks in part directory
 */
static DWORD ReadChunkDiskParam(PCWSTR cdisk_path, ChunkDiskParams& param)
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


class ChunkDiskWorker;

class ChunkDisk
{
public:
    // num_workers, max_pages: MUST be positive
    ChunkDisk(ChunkDiskParams param, u32 num_workers, u32 max_pages)
            : param(std::move(param)), max_pages(max_pages)
    {
        workers_.reserve(num_workers);
        cached_pages_.reserve(max_pages);

        for (u32 i = 0; i < num_workers; ++i) workers_.emplace_back(*this);
    }

    ~ChunkDisk()
    {
        // FIXME stop workers
        FlushAll();
        if (storage_unit != nullptr) SpdStorageUnitDelete(storage_unit);
    }


    DWORD StartWorkers()
    {
        auto result = DWORD(ERROR_SUCCESS);

        for (auto& worker : workers_)
        {
            auto err = worker.Start();
            if (err != ERROR_SUCCESS)
            {
                result = err;
                break;
            }
        }

        if (result != ERROR_SUCCESS)
        {
            // FIXME err?
            for (auto& worker : workers_) worker.Stop();
        }

        return result;
    }

    void StopWorkers()
    {
        // FIXME err?
        // FIXME not concurrent
        for (auto& worker : workers_) worker.Stop();
    }

    // SPD_STORAGE_UNIT_INTERFACE operations
    // op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
    BOOLEAN PostWork(ChunkOpKind op_kind, u64 block_addr, u32 count)
    {
        auto context = SpdStorageUnitGetOperationContext();

        // FIXME root
        auto start = (block_addr / param.ByteBlock(1048576).first) % (workers_.size());
        auto err = DWORD(ERROR_BUSY);

        for (auto i = start; i < workers_.size(); ++i)
        {
            // FIXME err
            err = workers_[i].PostWork(context, op_kind, block_addr, count);
            if (err != ERROR_BUSY) break;
        }
        for (auto i = 0; i < start; ++i)
        {
            // FIXME err
            err = workers_[i].PostWork(context, op_kind, block_addr, count);
            if (err != ERROR_BUSY) break;
        }
        if (err == ERROR_BUSY) return err;

        if (err == ERROR_IO_PENDING) return FALSE;

        if (err == ERROR_SUCCESS) return TRUE;

        // FIXME err
        return err;
    }

    SPD_STORAGE_UNIT* storage_unit = nullptr;



};



static ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
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
        // FIXME we may discard h on error
        // cdisk->ChunkClose(chunk_idx, std::move(h));
    }

    // no buffering or write through, nothing to flush
    return ERROR_SUCCESS;
}

static BOOLEAN Read(SPD_STORAGE_UNIT* StorageUnit,
                    PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                    SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return StorageUnitChunkDisk(StorageUnit)->PostWork(READ_CHUNK, BlockAddress, BlockCount);
}

static BOOLEAN Write(SPD_STORAGE_UNIT* StorageUnit,
                     PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return StorageUnitChunkDisk(StorageUnit)->PostWork(WRITE_CHUNK, BlockAddress, BlockCount);
}

static BOOLEAN Flush(SPD_STORAGE_UNIT* StorageUnit,
                     UINT64 BlockAddress, UINT32 BlockCount,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported);

    // FIXME: no flush, metadata flushed after idling
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

    // FIXME implement
}

static BOOLEAN Unmap(SPD_STORAGE_UNIT* StorageUnit,
                     SPD_UNMAP_DESCRIPTOR Descriptors[], UINT32 Count,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.UnmapSupported);

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

        // FIXME multiple UNMAP_CHUNK in ChunkWork
        cdisk->PostWork(UNMAP_CHUNK, Descriptors[I].BlockAddress, Descriptors[I].BlockCount);
    }

    // FIXME FALSE
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

    SpdLogErr(usage, PROGNAME);
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
            SpdLogErr(L"error: failed to get number of CPU threads with error %lu", err);
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
            SpdLogErr(L"error: cannot open debug log file");
            return err;
        }
        SpdDebugLogSetHandle(DebugLogHandle);
    }

    unique_ptr<ChunkDisk> cdisk;
    try
    {
        auto cdisk_param = ChunkDiskParams();
        err = ReadChunkDiskParam(ChunkDiskFile, cdisk_param);
        if (err != ERROR_SUCCESS)
        {
            SpdLogErr(L"error: parsing failed with error %lu", err);
            return err;
        }

        // FIXME constants
        cdisk = std::make_unique<ChunkDisk>(
            std::move(cdisk_param),
            NumThreads,
            max(NumThreads * 16, 1024));
    }
    catch (const bad_alloc&)
    {
        SpdLogErr(L"error: not enough memory to start");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    err = cdisk->LockParts();
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot lock parts: error %lu", err);
        return err;
    }
    err = cdisk->ReadParts();
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot initialize ChunkDisk: error %lu", err);
        return err;
    }
    err = CreateChunkDiskStorageUnit(cdisk.get(), !WriteAllowed, PipeName);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot create ChunkDisk: error %lu", err);
        return err;
    }
    SpdStorageUnitSetDebugLog(cdisk->storage_unit, DebugFlags);

    cdisk->StartWorkers();  // FIXME err

    err = SpdStorageUnitStartDispatcher(cdisk->storage_unit, NumThreads);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot start ChunkDisk: error %lu", err);
        return err;
    }

    SpdLogInfo(L"%s -f %s -W %u -t %d%s%s",
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

    cdisk->StopWorkers();   // FIXME err

    cdisk.reset();
    return ERROR_SUCCESS;
}
